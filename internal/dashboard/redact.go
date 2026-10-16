package dashboard

import (
	"regexp"
	"strings"
)

// Redactor masks sensitive values before they are returned through the API/UI.
//
// Redaction targets:
//   - Known sensitive environment variable names (secrets, passwords, tokens, keys)
//   - Private key PEM blocks
//   - Bearer tokens / JWT-looking strings
//   - URL-embedded credentials
//
// The Redactor is applied to any string value that is about to be included in
// an API response or config display.

var (
	// PEM private key blocks.
	pePrivateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.+?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	// Bearer token pattern.
	bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`)
	// JWT pattern (three base64url segments).
	jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}`)
	// URL with embedded credentials: scheme://user:pass@host
	urlCreds = regexp.MustCompile(`(?i)(https?|ws|wss|ssh|ftps)://[^:/\s]+:[^@/\s]+@`)
)

// sensitiveVarMarkers are substrings that, when present in a config key name
// (case-insensitive), mark the key as sensitive. Any key containing one of
// these markers is NEVER displayed with its value in the API/UI.
//
// False positives are acceptable; false negatives are not.
var sensitiveVarMarkers = []string{
	"secret",
	"password",
	"passwd",
	"pass", // covers SPLIT_SOCKS_PASS, PASSWORD, PASSWD
	"token",
	"credential",
	"auth", // covers SSH_AUTH_SOCK, AUTH_TOKEN
	"private_key",
	"privatekey",
	"socks_user",
	"socks_pass",
	"apikey",
	"ssh_key",
}

// IsSensitiveKey returns true when the given env var / config key name is
// known to carry secret material and must never be displayed in the UI.
func IsSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, m := range sensitiveVarMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// RedactString returns the input with any detected secrets masked.
// It is safe to call on any string; it returns the original string unchanged
// when no sensitive pattern is detected.
func RedactString(s string) string {
	if s == "" {
		return s
	}
	// Mask PEM private key blocks.
	s = pePrivateKeyBlock.ReplaceAllString(s, "[REDACTED:PRIVATE_KEY]")
	// Mask bearer tokens.
	s = bearerPattern.ReplaceAllString(s, "Bearer [REDACTED:TOKEN]")
	// Mask JWT-like strings.
	s = jwtPattern.ReplaceAllString(s, "[REDACTED:JWT]")
	// Mask URL-embedded credentials.
	s = urlCreds.ReplaceAllStringFunc(s, func(m string) string {
		at := strings.LastIndex(m, "@")
		if at < 0 {
			return m
		}
		prefix := m[:at]
		host := m[at+1:]
		schemeEnd := strings.Index(prefix, "://")
		if schemeEnd < 0 {
			return m
		}
		return prefix[:schemeEnd+3] + "[REDACTED:USERPASS]@" + host
	})
	// Mask sensitive KEY=VALUE assignments (e.g. "SPLIT_SECRET=topsecret").
	s = maskSensitiveAssignments(s)
	return s
}

// maskSensitiveAssignments scans each line for a KEY=VALUE or KEY:VALUE
// pattern where the key name contains a sensitive marker, and masks the value.
// The key name itself is preserved; only the value is replaced.
func maskSensitiveAssignments(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Try "KEY=VALUE" (assignment)
		if eq := strings.Index(trimmed, "="); eq > 0 {
			key := trimmed[:eq]
			// Check the last underscore-separated component of the key name
			// for sensitive markers. Example: SPLIT_SECRET → "secret".
			if sensitiveKeyComponent(key) {
				lines[i] = key + " [REDACTED]"
			}
			continue
		}
		// Try "KEY: VALUE" (yaml-ish or log style)
		if colon := strings.Index(trimmed, ":"); colon > 0 {
			key := strings.TrimSpace(trimmed[:colon])
			val := strings.TrimSpace(trimmed[colon+1:])
			if val != "" && sensitiveKeyComponent(key) {
				lines[i] = key + ": [REDACTED]"
			}
		}
	}
	return strings.Join(lines, "\n")
}

// sensitiveKeyComponent checks the last underscore-separated component of a
// key name (e.g. "SPLIT_SECRET" → "secret") against the sensitive markers.
// The full key name is also checked as a fallback.
func sensitiveKeyComponent(key string) bool {
	// Check the last component (after the final underscore).
	parts := strings.Split(strings.ToLower(key), "_")
	last := parts[len(parts)-1]
	if containsMarker(last) {
		return true
	}
	// Also check the full lowercased key.
	return containsMarker(strings.ToLower(key))
}

func containsMarker(s string) bool {
	for _, m := range sensitiveVarMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// RedactValue returns the value with redaction applied and reports whether
// the value was actually redacted (i.e. contains sensitive content).
func RedactValue(s string) (string, bool) {
	redacted := RedactString(s)
	return redacted, redacted != s
}

// RedactConfigValue applies redaction to a config value based on its key name.
// It always returns a ConfigValue with the Redacted flag set appropriately.
// Keys matching IsSensitiveKey are fully masked regardless of value content.
func RedactConfigValue(key, value string, mutable, restart bool) ConfigValue {
	redacted := value
	wasRedacted := false
	if IsSensitiveKey(key) {
		// Sensitive key: fully mask the value.
		redacted = "[REDACTED]"
		wasRedacted = value != ""
	} else {
		// Non-sensitive key: apply generic redaction (catches accidental
		// embedded secrets in values like a URL with credentials).
		redacted, wasRedacted = RedactValue(value)
	}
	return ConfigValue{
		Key:             key,
		Value:           redacted,
		Redacted:        wasRedacted,
		Mutable:         mutable,
		RequiresRestart: restart,
	}
}
