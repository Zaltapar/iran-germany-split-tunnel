package xray

import "strings"

// excerptMax bounds the xray output embedded in a gate error.
const excerptMax = 2000

// excerpt returns a bounded, trimmed form of xray output for error
// display. The generated config carries only public parameters (public
// key, UUID, SNI, dest) — the tunnel secret and the Reality private key
// never reach xray — so a bounded echo is not a secret leak.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(no output)"
	}
	if len(s) > excerptMax {
		return s[:excerptMax] + " ... (truncated)"
	}
	return s
}
