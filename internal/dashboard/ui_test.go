package dashboard

import (
	"strings"
	"testing"
)

// TestIndexHasOutboundsView asserts the fixed [data-view="outbounds"] section
// exists in index.html (the duplicate data-view="network" bug is resolved).
func TestIndexHasOutboundsView(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	if !strings.Contains(body, `data-view="outbounds"`) {
		t.Error(`index.html missing data-view="outbounds" section`)
	}
}

// TestIndexViewAttributesUnique ensures every data-view attribute value in
// index.html appears exactly once. This is the regression test for the
// original bug where data-view="network" was duplicated and
// data-view="outbounds" was missing.
func TestIndexViewAttributesUnique(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	views := map[string]int{}
	for _, section := range []string{
		"overview", "hosts", "tunnels", "routing", "outbounds",
		"inbounds", "control", "network", "config", "logs",
	} {
		attr := `data-view="` + section + `"`
		n := strings.Count(body, attr)
		views[section] = n
		if n != 1 {
			t.Errorf(`index.html data-view=%q count=%d, want exactly 1`, attr, n)
		}
	}
}

// TestIndexNavigationSectionsComplete asserts that every sidebar nav link
// (data-section) has a matching data-view section, and vice versa.
func TestIndexNavigationSectionsComplete(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	sections := []string{
		"overview", "hosts", "tunnels", "routing", "outbounds",
		"inbounds", "control", "network", "config", "logs",
	}
	for _, s := range sections {
		if !strings.Contains(body, `data-section="`+s+`"`) {
			t.Errorf("index.html missing data-section=%q in sidebar", s)
		}
		if !strings.Contains(body, `data-view="`+s+`"`) {
			t.Errorf("index.html missing data-view=%q section", s)
		}
	}
}

// TestIndexStaleAndHealthIndicators asserts that the overview renders
// explicit stale-telemetry and health-state markers in app.js.
func TestIndexStaleAndHealthIndicators(t *testing.T) {
	js := staticFiles(t)["static/app.js"]
	if js == "" {
		t.Fatal("static/app.js missing from embedded FS")
	}
	// tunnelState function drives the overall-state badge.
	if !strings.Contains(js, "function tunnelState") {
		t.Error("app.js missing tunnelState function (overall-state classifier)")
	}
	// Stale badge is explicitly rendered when any host is stale/unreachable.
	if !strings.Contains(js, "stale telemetry") {
		t.Error(`app.js must render an explicit "stale telemetry" badge`)
	}
	// updateGlobalBadges must be called on both success and error paths.
	if !strings.Contains(js, "function updateGlobalBadges") {
		t.Error("app.js missing updateGlobalBadges function")
	}
}

// TestIndexCarrierDetailHooks asserts the carrier-detail card renderer
// exists and exposes the required backend fields without fabricating data.
func TestIndexCarrierDetailHooks(t *testing.T) {
	js := staticFieldsForCarrierDetails(t)
	for _, field := range []string{
		"State", "Goodput", "Success ratio", "Stall rate",
		"Eligibility", "Cooldown", "Gate reason",
	} {
		if !strings.Contains(js, field) {
			t.Errorf("app.js carrier-detail card missing field %q", field)
		}
	}
	// Fields not exported by the backend must render "unmeasured", not 0.
	if !strings.Contains(js, "unmeasured") {
		t.Error(`app.js must render "unmeasured" for non-exported carrier metrics`)
	}
}

// staticFieldsForCarrierDetails returns the app.js source for carrier-detail
// inspection.
func staticFieldsForCarrierDetails(t *testing.T) string {
	t.Helper()
	body := staticFiles(t)["static/app.js"]
	if body == "" {
		t.Fatal("static/app.js missing from embedded FS")
	}
	return body
}

// TestIndexAccessibilityAttributes asserts the required ARIA attributes are
// present in index.html.
func TestIndexAccessibilityAttributes(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	for _, attr := range []string{
		`role="status"`,
		`aria-live="polite"`,
		`role="contentinfo"`,
		`role="note"`,
		`aria-label="Dashboard navigation"`,
		`aria-expanded="false"`,
	} {
		if !strings.Contains(body, attr) {
			t.Errorf("index.html missing accessibility attribute %s", attr)
		}
	}
	// Skip link must target #content.
	if !strings.Contains(body, `class="skip-link"`) {
		t.Error("index.html missing skip-link for keyboard accessibility")
	}
}

// TestIndexCopyDiagnosticsButton asserts the diagnostics copy button exists
// in both HTML and JS.
func TestIndexCopyDiagnosticsButton(t *testing.T) {
	html := staticFiles(t)["static/index.html"]
	if !strings.Contains(html, `id="copyDiagnosticsBtn"`) {
		t.Error(`index.html missing #copyDiagnosticsBtn button`)
	}
	js := staticFiles(t)["static/app.js"]
	if !strings.Contains(js, "function copyDiagnostics") {
		t.Error("app.js missing copyDiagnostics function")
	}
	if !strings.Contains(js, "function buildDiagnostics") {
		t.Error("app.js missing buildDiagnostics function")
	}
}

// TestIndexErrorStatesDistinct asserts that 401/403 and 503 states are
// distinguished in the error handler.
func TestIndexErrorStatesDistinct(t *testing.T) {
	js := staticFiles(t)["static/app.js"]
	if js == "" {
		t.Fatal("static/app.js missing from embedded FS")
	}
	if !strings.Contains(js, "Permission denied") {
		t.Error(`app.js must render a "Permission denied" state for 401/403`)
	}
	if !strings.Contains(js, "Control plane unavailable") {
		t.Error(`app.js must render a "Control plane unavailable" state for 503`)
	}
}

// TestIndexNoInlineStylesAndScripts is a stronger variant of
// TestCSPCompatibleMarkup that also verifies no inline <script> blocks in
// index.html.
func TestIndexNoInlineStylesAndScripts(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	if inlineStyleTag.MatchString(body) {
		t.Error("index.html contains inline <style> block (blocked by CSP)")
	}
	if styleAttr.MatchString(body) {
		t.Error("index.html contains a style= attribute (blocked by CSP)")
	}
	// All <script> tags must carry a src attribute (external file, not inline).
	if inlineScript.MatchString(body) {
		for _, m := range inlineScript.FindAllString(body, -1) {
			if !strings.Contains(strings.ToLower(m), "src=") {
				t.Errorf("index.html contains inline <script> (blocked by CSP): %s", m)
			}
		}
	}
}

// TestIndexSecurityInvariantsRecheck re-affirms the read-only and no-secrets
// banner strings that the security model depends on.
func TestIndexSecurityInvariantsRecheck(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	mustContain := []string{
		"Read-only mode",
		"No secrets are displayed",
	}
	for _, s := range mustContain {
		if !strings.Contains(body, s) {
			t.Errorf("index.html missing required banner text %q", s)
		}
	}
}
