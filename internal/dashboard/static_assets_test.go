package dashboard

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// staticFiles returns every embedded static asset as name → contents.
func staticFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, rerr := staticFS.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded static FS: %v", err)
	}
	return out
}

var (
	attrURLPattern = regexp.MustCompile(`(?i)\b(src|href)\s*=\s*"([^"]*)"`)
	inlineScript   = regexp.MustCompile(`(?i)<script(\s[^>]*)?>`)
	inlineStyleTag = regexp.MustCompile(`(?i)<style[\s>]`)
	styleAttr      = regexp.MustCompile(`(?i)\sstyle\s*=`)
)

// TestStaticNoExternalURLs: no embedded asset may reference a remote origin.
func TestStaticNoExternalURLs(t *testing.T) {
	for name, body := range staticFiles(t) {
		for _, bad := range []string{"http://", "https://", "//cdn", "googleapis", "unpkg", "jsdelivr"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s references external resource %q", name, bad)
			}
		}
	}
}

// TestIndexAssetsAreRelative: index.html must load only same-origin relative
// assets so the bundle resolves under the random basePath.
func TestIndexAssetsAreRelative(t *testing.T) {
	body := staticFiles(t)["static/index.html"]
	if body == "" {
		t.Fatal("static/index.html missing from embedded FS")
	}
	for _, m := range attrURLPattern.FindAllStringSubmatch(body, -1) {
		v := m[2]
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		if strings.HasPrefix(v, "/") || strings.Contains(v, ":") {
			t.Errorf("index.html %s=%q is not a relative same-origin path", m[1], v)
		}
	}
}

// TestCSPCompatibleMarkup: the TLS build sends default-src 'self', which
// forbids inline script, inline <style>, and style attributes. The markup
// must not depend on any of them.
func TestCSPCompatibleMarkup(t *testing.T) {
	for name, body := range staticFiles(t) {
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		for _, m := range inlineScript.FindAllString(body, -1) {
			if !strings.Contains(strings.ToLower(m), "src=") {
				t.Errorf("%s contains an inline <script> (blocked by CSP): %s", name, m)
			}
		}
		if inlineStyleTag.MatchString(body) {
			t.Errorf("%s contains an inline <style> block (blocked by CSP)", name)
		}
		if styleAttr.MatchString(body) {
			t.Errorf("%s contains a style= attribute (blocked by CSP)", name)
		}
	}
}

// TestStaticHasRequiredSections guards the Dashboard v2 navigation contract.
func TestStaticHasRequiredSections(t *testing.T) {
	files := staticFiles(t)
	html := files["static/index.html"]
	for _, section := range []string{
		"overview", "hosts", "tunnels", "routing", "outbounds", "network", "config", "logs",
	} {
		if !strings.Contains(html, `data-section="`+section+`"`) {
			t.Errorf("index.html missing navigation for section %q", section)
		}
	}
	if !strings.Contains(html, "Read-only mode") || !strings.Contains(html, "No secrets are displayed") {
		t.Error("index.html must keep the read-only and no-secrets banner")
	}
}
