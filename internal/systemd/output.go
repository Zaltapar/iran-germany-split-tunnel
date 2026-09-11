package systemd

import "strings"

// excerptMax bounds external command output embedded in an error.
const excerptMax = 2000

// excerpt returns a bounded, trimmed form of command output for error
// display (T2/T3 pattern). The content that may be echoed is systemd's
// own output about UNIT files and unit STATES — env-file values are never
// arguments to any command this package runs, so a bounded echo is not a
// secret leak (asserted by test 13).
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
