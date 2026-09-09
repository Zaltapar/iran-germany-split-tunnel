package origin

import "strings"

// excerptMax bounds the caddy output embedded in a gate error.
const excerptMax = 2000

// excerpt returns a bounded, trimmed form of caddy output for error
// display. The generated Caddyfile carries only public facts (domain,
// upstream, timeouts) and `caddy validate`/`version` output never
// echoes a secret — so a bounded echo is not a secret leak (design §3.4).
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
