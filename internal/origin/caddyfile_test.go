package origin

// caddyfile_test.go — golden + validation matrix for the Caddyfile
// renderer (design doc plans/t4-design.md §5). Hermetic: no network,
// no real binary, fixed non-production test vectors. The committed
// goldens are the bytes validated by the pinned caddy v2.11.4 binary
// (CI "Pinned Caddy gate" re-validates them on every run).

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The single documented test-only vectors that pin the committed
// golden files (non-production domain; matches the golden set).
func goldenPlanCaddy() Plan {
	return Plan{
		Mode:         ModeCaddy,
		Domain:       "upload.example.com",
		UpstreamAddr: "127.0.0.1:9001",
	}
}

func goldenPlanALPN() Plan {
	return Plan{
		Mode:          ModeCaddy,
		Domain:        "upload.example.com",
		UpstreamAddr:  "127.0.0.1:9001",
		ACMEChallenge: ACMETLSALPN01,
	}
}

func goldenPlanCDN() Plan {
	return Plan{
		Mode:           ModeCDN,
		Domain:         "upload.example.com",
		UpstreamAddr:   "127.0.0.1:9001",
		OriginPort:     8443,
		CDNSecurity:    CDNTLSOrigin,
		CDNOriginTrust: CDNOriginTrustPullCA, // D9: declared, fail-closed
	}
}

func renderMust(t *testing.T, plan Plan) []byte {
	t.Helper()
	out, err := RenderCaddyfile(plan)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// 1. valid plans → bytes == committed goldens; trailing newline; tabs.
func TestRenderMatchesGolden(t *testing.T) {
	cases := []struct {
		name   string
		plan   Plan
		golden string
	}{
		{"caddy default (http01)", goldenPlanCaddy(), "caddy-default.golden.Caddyfile"},
		{"caddy alpn01", goldenPlanALPN(), "caddy-alpn01.golden.Caddyfile"},
		{"cdn tls-internal (mode A)", goldenPlanCDN(), "cdn-tls-internal.golden.Caddyfile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := renderMust(t, c.plan)
			want, err := os.ReadFile(filepath.Join("testdata", "golden", c.golden))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
			want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
			if string(got) != string(want) {
				t.Fatalf("render differs from golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
			if len(got) == 0 || got[len(got)-1] != '\n' {
				t.Error("golden does not end with a trailing newline")
			}
			if !strings.Contains(string(got), "\n\treverse_proxy") {
				t.Error("golden does not use tab indentation")
			}
			if !strings.HasPrefix(string(got), managedMarker+"\n") {
				t.Error("golden does not start with the managed marker")
			}
		})
	}
}

// 2. determinism: 100 renders → 1 distinct byte string (per plan).
func TestRenderIsDeterministic(t *testing.T) {
	for _, plan := range []Plan{goldenPlanCaddy(), goldenPlanALPN(), goldenPlanCDN()} {
		var first [sha256.Size]byte
		for i := 0; i < 100; i++ {
			out := renderMust(t, plan)
			sum := sha256.Sum256(out)
			if i == 0 {
				first = sum
			} else if sum != first {
				t.Fatalf("render %d produced different bytes (determinism broken)", i)
			}
		}
	}
}

// 3. D7 (load-bearing): the Caddyfile emits the per-operation
// read/write timeouts and NEVER `stream_timeout` (a total-time cap
// that would kill a long-lived carrier).
func TestRenderNeverEmitsStreamTimeout(t *testing.T) {
	for _, plan := range []Plan{goldenPlanCaddy(), goldenPlanALPN(), goldenPlanCDN()} {
		out := string(renderMust(t, plan))
		if !strings.Contains(out, "read_timeout 3600s") {
			t.Errorf("missing read_timeout: %s", out)
		}
		if !strings.Contains(out, "write_timeout 3600s") {
			t.Errorf("missing write_timeout: %s", out)
		}
		if strings.Contains(out, "stream_timeout") {
			t.Errorf("stream_timeout emitted (D7 violation — total-time cap kills carriers): %s", out)
		}
	}
}

// 4. none mode + cdn mode B generate NO Caddyfile (ErrNoCaddyfile).
func TestRenderNoCaddyfileModes(t *testing.T) {
	if _, err := RenderCaddyfile(Plan{Mode: ModeNone, UpstreamAddr: "127.0.0.1:9001"}); !errors.Is(err, ErrNoCaddyfile) {
		t.Errorf("none mode: want ErrNoCaddyfile, got %v", err)
	}
	if _, err := RenderCaddyfile(Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNPlainOrigin, OriginPort: 443}); !errors.Is(err, ErrNoCaddyfile) {
		t.Errorf("cdn mode B: want ErrNoCaddyfile, got %v", err)
	}
}

// 5. every invalid plan is rejected, names its field, and never
// panics.
func TestRenderInvalidPlansRejected(t *testing.T) {
	valid := goldenPlanCaddy()
	cases := []struct {
		name string
		plan Plan
		want string // fragment that MUST appear in the error (field name)
	}{
		{"domain empty", Plan{Mode: ModeCaddy, UpstreamAddr: "127.0.0.1:9001"}, "domain"},
		{"domain port", Plan{Mode: ModeCaddy, Domain: "upload.example.com:443", UpstreamAddr: "127.0.0.1:9001"}, "domain"},
		{"domain scheme", Plan{Mode: ModeCaddy, Domain: "wss://upload.example.com", UpstreamAddr: "127.0.0.1:9001"}, "domain"},
		{"domain single label", Plan{Mode: ModeCaddy, Domain: "localhost", UpstreamAddr: "127.0.0.1:9001"}, "domain"},
		{"domain underscore", Plan{Mode: ModeCaddy, Domain: "up_load.example.com", UpstreamAddr: "127.0.0.1:9001"}, "domain"},
		{"upstream empty", Plan{Mode: ModeCaddy, Domain: "upload.example.com"}, "upstreamAddr"},
		{"upstream public", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "203.0.113.7:9001"}, "upstreamAddr"},
		{"upstream public hostname", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "cdn.example.com:9001"}, "upstreamAddr"},
		{"upstream no port", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1"}, "upstreamAddr"},
		{"caddy port not 443", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001", OriginPort: 8443}, "originPort"},
		{"caddy bad challenge", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001", ACMEChallenge: "dns01"}, "acmeChallenge"},
		{"caddy bad email", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001", ACMEEmail: "not-an-email"}, "acmeEmail"},
		{"caddy email two ats", Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001", ACMEEmail: "a@b@c.com"}, "acmeEmail"},
		{"cdn no security", Plan{Mode: ModeCDN, Domain: "upload.example.com"}, "cdnSecurity"},
		{"cdn mode A public upstream", Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNTLSOrigin, UpstreamAddr: "203.0.113.7:9001", OriginPort: 443}, "upstreamAddr"},
		{"cdn bad port", Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNPlainOrigin, OriginPort: 70000}, "originPort"},
		{"cdn acme fields", Plan{Mode: ModeCDN, Domain: "upload.example.com", CDNSecurity: CDNPlainOrigin, OriginPort: 443, ACMEEmail: "ops@example.com"}, "acme"},
		{"none with domain", Plan{Mode: ModeNone, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001"}, "domain"},
		{"none public upstream", Plan{Mode: ModeNone, UpstreamAddr: "8.8.8.8:9001"}, "upstreamAddr"},
		{"bad mode", Plan{Mode: "nginx", Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001"}, "mode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := RenderCaddyfile(c.plan)
			if err == nil {
				t.Fatalf("expected rejection, got success")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error does not name the offending field (%q): %v", c.want, err)
			}
			if !errors.Is(err, ErrInvalidPlan) {
				t.Errorf("want ErrInvalidPlan, got %v", err)
			}
			_ = valid // baseline kept for table readability
		})
	}
}

// 6. ValidDomain delegates to the pairing rule (single source of
// truth): the wrapper and blob A acceptance agree.
func TestValidDomainDelegatesToPairing(t *testing.T) {
	if !ValidDomain("upload.example.com") {
		t.Error("valid domain rejected")
	}
	for _, bad := range []string{"", "single", "a b.com", "under_score.com", "x.com:443"} {
		if ValidDomain(bad) {
			t.Errorf("invalid domain %q accepted", bad)
		}
	}
}

// 7. the email variants render the pin-verified Caddyfile forms
// (T4-C1: validated byte-for-byte against the pinned binary).
func TestRenderEmailVariants(t *testing.T) {
	http01 := renderMust(t, Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001", ACMEEmail: "ops@example.com"})
	if !strings.Contains(string(http01), "\ttls ops@example.com\n") {
		t.Errorf("http01+email form missing: %s", http01)
	}
	alpn := renderMust(t, Plan{Mode: ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001", ACMEChallenge: ACMETLSALPN01, ACMEEmail: "ops@example.com"})
	if !strings.Contains(string(alpn), "\t\tissuer acme {\n\t\t\temail ops@example.com\n\t\t\tdisable_http_challenge\n\t\t}") {
		t.Errorf("alpn01+email form missing: %s", alpn)
	}
}
