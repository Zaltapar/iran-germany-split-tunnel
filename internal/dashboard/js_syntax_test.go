package dashboard

// Regression guard: the JavaScript assets embedded in the dashboard bundle
// must parse. A stray unbalanced "}" in app.js once closed the top-level
// IIFE early and made the browser reject the entire script (blank dashboard
// — subtask 13). The substring tests in static_assets_test.go cannot catch
// that class of bug, so this test performs a structural scan of every
// embedded .js asset:
//
//  1. a pure-Go balanced-delimiter scanner that skips line/block comments,
//     single/double-quoted strings, and template literals (with ${...}
//     nesting), best-effort regex literals, tracks {}/()([]) depth, and
//     requires depth to return to exactly 0 at EOF;
//  2. a "no top-level extra closing brace" check: depth must never dip
//     below 0 at any point in the file;
//  3. a real parse check via `node --check` when node is available on the
//     test machine; the node step is SKIPPED (not failed) when node is
//     absent, so CI environments without a JS runtime still run the
//     pure-Go check.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// jsScanResult is the outcome of a structural scan of a single JS asset.
type jsScanResult struct {
	// depthAtEOF is the net {}/()([]) depth at end of file. Must be 0
	// for a well-formed file.
	depthAtEOF int
	// minDepth is the lowest depth reached. Negative values indicate a
	// top-level extra closing brace.
	minDepth int
	// unbalancedLine is the 1-based line of the first point at which
	// depth went negative (0 = none).
	unbalancedLine int
	// unterminated reports a block comment that never closed before EOF.
	unterminated bool
}

// jsScan performs a structural scan of src and returns the result.
//
// Grammar the scanner is tuned for:
//   - // line comments (skipped to end-of-line)
//   - /* */ block comments (must close before EOF; otherwise the
//     unterminated flag is set and remaining text is skipped)
//   - '...' and "..." string literals (backslash-escape aware, no
//     multi-line continuation)
//   - `...` template literals with nested ${...} expressions (nested
//     delimiters inside ${...} are tracked so the close of the inner
//     scope does not consume the close of the outer one)
//   - regex literals: when the immediately preceding meaningful token is
//     one that legally precedes a regex (an operator, '(', '[', '{', or
//     a keyword), a '/' is treated as a regex start and the scanner
//     skips to the matching unescaped '/' on the same line. Otherwise
//     '/' is division. This is best-effort; a regex that spans newlines
//     is treated as division.
//
// The scanner does not parse the file (impossible from Go); it only
// verifies that visible brace/paren/bracket structure is balanced and
// never goes negative. Together with the node --check step (when
// available) this catches "an editor or patcher deleted or de-indented
// a closing brace" bugs that break the whole script.
func jsScan(src string) jsScanResult {
	var r jsScanResult
	depth := 0
	r.minDepth = 0
	line := 1
	// prevSig is the last "meaningful" rune seen outside of a string /
	// comment / regex — used for the regex-literal heuristic.
	var prevSig byte

	// isRegexContext reports whether a '/' here should be treated as the
	// start of a regex literal, based on the last meaningful token.
	isRegexContext := func() bool {
		switch prevSig {
		case '(', '[', '{', '!', '&', '|', '?', ':', ';',
			'=', '+', '-', '*', '%', '<', '>', '^', '~':
			return true
		}
		return false
	}

	skipRegex := func(start int) int {
		// start is the index of the opening '/'.
		j := start + 1
		for j < len(src) {
			ch := src[j]
			if ch == '\\' {
				j += 2
				continue
			}
			if ch == '\n' {
				// Regex cannot span newlines; fall back to division.
				return start
			}
			if ch == '/' {
				return j + 1
			}
			j++
		}
		// Unterminated regex (should not happen in valid JS);
		// treat as division.
		return start
	}

	for i := 0; i < len(src); i++ {
		c := src[i]

		if c == '\n' {
			line++
			prevSig = 0
			continue
		}

		// --- Comments ---
		if c == '/' && i+1 < len(src) {
			nxt := src[i+1]
			if nxt == '/' {
				// Line comment.
				for i+1 < len(src) && src[i+1] != '\n' {
					i++
				}
				prevSig = 0
				continue
			}
			if nxt == '*' {
				// Block comment.
				i += 2
				closed := false
				for i+1 < len(src) {
					if src[i] == '*' && src[i+1] == '/' {
						i += 2
						closed = true
						break
					}
					if src[i] == '\n' {
						line++
					}
					i++
				}
				if !closed {
					r.unterminated = true
				}
				prevSig = 0
				continue
			}
			// Division or regex.
			if isRegexContext() {
				next := skipRegex(i)
				if next > i+1 {
					// Successfully consumed a regex; advance past it.
					// Count newlines inside for line tracking (should
					// be none since regex cannot span newlines).
					for k := i + 1; k < next && k < len(src); k++ {
						if src[k] == '\n' {
							line++
						}
					}
					i = next - 1
					prevSig = 0
					continue
				}
			}
			// Division: record as meaningful token.
			prevSig = '/'
			continue
		}

		// --- String literals (' and ") ---
		if c == '\'' || c == '"' {
			quote := c
			i++
			for i < len(src) {
				ch := src[i]
				if ch == '\\' {
					i += 2
					continue
				}
				if ch == quote {
					i++
					break
				}
				if ch == '\n' {
					line++
				}
				i++
			}
			i--
			prevSig = 0
			continue
		}

		// --- Template literals (`) with ${} nesting ---
		if c == '`' {
			i++
			for i < len(src) {
				ch := src[i]
				switch {
				case ch == '\\':
					i += 2
					continue
				case ch == '`':
					i++
					goto templateEnd
				case ch == '$' && i+1 < len(src) && src[i+1] == '{':
					// ${...} expression: scan to matching '}'.
					i += 2
					exprDepth := 0
					for i < len(src) {
						e := src[i]
						if e == '{' {
							exprDepth++
						} else if e == '}' {
							if exprDepth == 0 {
								i++
								break
							}
							exprDepth--
						} else if e == '`' {
							// Nested template inside the expression.
							i++
							for i < len(src) {
								n := src[i]
								if n == '\\' {
									i += 2
									continue
								}
								if n == '`' {
									i++
									break
								}
								i++
							}
							continue
						} else if e == '\n' {
							line++
						}
						i++
					}
					continue
				case ch == '\n':
					line++
				}
				i++
			}
		templateEnd:
			i--
			prevSig = 0
			continue
		}

		// --- Delimiters and operators ---
		switch c {
		case '{', '(', '[':
			depth++
			prevSig = c
		case '}', ')', ']':
			depth--
			if depth < r.minDepth {
				r.minDepth = depth
				if r.unbalancedLine == 0 {
					r.unbalancedLine = line
				}
			}
			prevSig = c
		case ';', ',', ':', '=', '+', '-', '*', '%', '<', '>', '^', '~', '&', '|', '!', '?':
			prevSig = c
		case ' ', '\t', '\r':
			// whitespace
		default:
			// Letters, digits, '.', '@', '$', '_' — record as
			// meaningful without changing regex context.
			prevSig = c
		}
	}

	r.depthAtEOF = depth
	return r
}

// TestStaticJSParses runs the pure-Go structural scan on every embedded
// .js asset and reports unbalanced braces / unterminated comments /
// negative depth.
func TestStaticJSParses(t *testing.T) {
	files := staticFiles(t)
	jsFiles := 0
	for name, body := range files {
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		jsFiles++
		r := jsScan(body)
		if r.unterminated {
			t.Errorf("%s: block comment not terminated before EOF", name)
		}
		if r.minDepth < 0 {
			t.Errorf("%s: unbalanced extra closing brace (depth %d) first at line %d",
				name, r.minDepth, r.unbalancedLine)
		}
		if r.depthAtEOF != 0 {
			t.Errorf("%s: delimiter depth at EOF is %d, want 0", name, r.depthAtEOF)
		}
	}
	if jsFiles == 0 {
		t.Fatal("no .js assets found in embedded static FS — scanner has nothing to validate")
	}
}

// TestStaticJSBalancedKnownShapes is a synthetic regression check that the
// scanner itself is sensible: it must accept balanced input and reject the
// exact bug class that motivated this guard (a stray top-level "}" that
// pops a scope below the file's natural 0 depth, or that leaves a scope
// open at EOF).
func TestStaticJSBalancedKnownShapes(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantDepth int
		wantNeg   bool
	}{
		{"empty", "", 0, false},
		{"iife", "(function(){})()", 0, false},
		{"stray-close", "(function(){})()}", -1, true},
		{"unclosed-open", "function f(){", 1, false},
		{"template-nest", "var s=`a${1+1}b`;", 0, false},
		{"regex-context", "var m = /a/g.test('x');", 0, false},
		{"comment-braces", "// } } }\n/* { { */\nvar x = 1;", 0, false},
		{"stray-two", "})();\n}", -3, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := jsScan(tc.src)
			if r.depthAtEOF != tc.wantDepth {
				t.Errorf("depth at EOF = %d, want %d", r.depthAtEOF, tc.wantDepth)
			}
			gotNeg := r.minDepth < 0
			if gotNeg != tc.wantNeg {
				t.Errorf("minDepth<0 = %v (minDepth %d), want %v",
					gotNeg, r.minDepth, tc.wantNeg)
			}
		})
	}
}

// TestStaticJSNodeCheck runs `node --check` against every embedded .js
// asset when node is on the test machine. The test SKIPs (not fails)
// when node is absent so the pure-Go structural check above remains the
// mandatory gate.
func TestStaticJSNodeCheck(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on the test machine; pure-Go structural check in TestStaticJSParses is the mandatory gate")
	}

	files := staticFiles(t)
	for name, body := range files {
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		dir := t.TempDir()
		p := filepath.Join(dir, filepath.Base(name))
		if werr := os.WriteFile(p, []byte(body), 0o644); werr != nil {
			t.Fatalf("%s: write temp: %v", name, werr)
		}
		cmd := exec.Command(node, "--check", p)
		out, cerr := cmd.CombinedOutput()
		if cerr != nil {
			var ee *exec.ExitError
			if errors.As(cerr, &ee) {
				t.Errorf("%s: node --check failed (exit %d):\n%s",
					name, ee.ExitCode(), string(out))
			} else {
				t.Errorf("%s: node --check: %v\n%s", name, cerr, out)
			}
			continue
		}
		_ = out
	}
}

// TestStaticJSBrokenFails is a targeted regression test: it constructs the
// exact broken-file shape (IIFE with a stray extra "}" at the end) and
// asserts that jsScan detects it.
func TestStaticJSBrokenFails(t *testing.T) {
	// This is the exact pattern from the subtask-13 bug: the IIFE
	// body is closed, then one more "}" appears at top level.
	broken := "(function() {\n" +
		"  var x = 1;\n" +
		"  function f() { return x; }\n" +
		"}());\n" +
		"}\n"
	r := jsScan(broken)
	if r.minDepth >= 0 {
		t.Error("expected minDepth < 0 for stray top-level '}', got minDepth =", r.minDepth)
	}
	if r.depthAtEOF >= 0 {
		t.Error("expected depthAtEOF < 0 for stray top-level '}', got", r.depthAtEOF)
	}

	// The fixed version must pass.
	fixed := "(function() {\n" +
		"  var x = 1;\n" +
		"  function f() { return x; }\n" +
		"}());\n"
	r2 := jsScan(fixed)
	if r2.depthAtEOF != 0 || r2.minDepth < 0 {
		t.Error("fixed file should have depthAtEOF==0 and minDepth>=0, got", r2)
	}
}

// TestStaticJSAssetsPresent is a build-time assertion that the embedded
// static FS actually contains .js assets; without one, the scanner tests
// would be vacuous and a future rename/delete of app.js would silently
// drop the regression guard.
func TestStaticJSAssetsPresent(t *testing.T) {
	found := false
	for name := range staticFiles(t) {
		if strings.HasSuffix(name, ".js") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("embedded static FS contains no .js files; the JS-parse regression guard is vacuous")
	}
}
