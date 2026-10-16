package dashboard

import (
	"strings"
	"testing"
)

func TestRedactStringPEMKey(t *testing.T) {
	input := `some text
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7Bgx
-----END RSA PRIVATE KEY-----
more text`
	out := RedactString(input)
	if strings.Contains(out, "MIIEpAIBAAKCAQEA7Bgx") {
		t.Error("PEM private key body was not redacted")
	}
	if !strings.Contains(out, "[REDACTED:PRIVATE_KEY]") {
		t.Error("PEM block not replaced with placeholder")
	}
}

func TestRedactStringBearerToken(t *testing.T) {
	input := "Authorization: Bearer abc123def456.ghi"
	out := RedactString(input)
	if strings.Contains(out, "abc123def456.ghi") {
		t.Error("bearer token was not redacted")
	}
}

func TestRedactStringURLCredentials(t *testing.T) {
	input := "url=https://user:secretpw@cdn.example.com/upload"
	out := RedactString(input)
	if strings.Contains(out, "secretpw") {
		t.Error("URL-embedded password was not redacted: " + out)
	}
	if !strings.Contains(out, "cdn.example.com") {
		t.Error("host part should be preserved: " + out)
	}
}

func TestRedactStringSensitiveKeyValue(t *testing.T) {
	input := "SPLIT_SECRET=supersecretvalue123"
	out := RedactString(input)
	if strings.Contains(out, "supersecretvalue123") {
		t.Error("sensitive key=value was not redacted")
	}
	if !strings.Contains(out, "SPLIT_SECRET") {
		t.Error("key name should be preserved")
	}
}

func TestRedactValueCleanString(t *testing.T) {
	// A value with no sensitive patterns should pass through unchanged.
	in := "SPLIT_METRICS_PORT=9101"
	out, wasRedacted := RedactValue(in)
	if wasRedacted {
		t.Errorf("clean value was redacted: %q", out)
	}
}

func TestRedactConfigValueSecretKey(t *testing.T) {
	cv := RedactConfigValue("SPLIT_SECRET", "top-secret-abc", false, true)
	if cv.Value != "[REDACTED]" {
		t.Errorf("SPLIT_SECRET value = %q, want [REDACTED]", cv.Value)
	}
	if !cv.Redacted {
		t.Error("Redacted flag not set for secret key")
	}
	if !cv.RequiresRestart {
		t.Error("RequiresRestart should be true")
	}
}

func TestRedactConfigValueSafeKey(t *testing.T) {
	cv := RedactConfigValue("SPLIT_RELAY_BUF", "32768", true, true)
	if cv.Value != "32768" {
		t.Errorf("safe value was altered: %q", cv.Value)
	}
	if cv.Redacted {
		t.Error("safe value incorrectly flagged as redacted")
	}
	if !cv.Mutable {
		t.Error("Mutable should be true")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{
		"SPLIT_SECRET", "SPLIT_SOCKS_PASS", "SPLIT_SOCKS_USER",
		"PRIVATE_KEY", "API_TOKEN", "SSH_AUTH_SOCK",
	}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", k)
		}
	}
	safe := []string{
		"SPLIT_METRICS_PORT", "SPLIT_RELAY_BUF", "SPLIT_TARGET_ADDR_POLICY",
		"SPLIT_CARRIER_GRACE",
	}
	for _, k := range safe {
		if IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = true, want false", k)
		}
	}
}

// TestRedactedValuesNeverContainSecret asserts that for a set of known
// sensitive key names, the resulting ConfigValue.Value can never equal the
// original secret string.
func TestRedactedValuesNeverContainSecret(t *testing.T) {
	secret := "super-secret-value-xyz"
	keys := []string{"SPLIT_SECRET", "SPLIT_SOCKS_PASS", "SPLIT_SOCKS_USER", "SSH_PRIVATE_KEY"}
	for _, key := range keys {
		cv := RedactConfigValue(key, secret, false, true)
		if cv.Value == secret {
			t.Errorf("key %q: ConfigValue.Value still contains the secret", key)
		}
		if !cv.Redacted {
			t.Errorf("key %q: Redacted flag not set", key)
		}
	}
}
