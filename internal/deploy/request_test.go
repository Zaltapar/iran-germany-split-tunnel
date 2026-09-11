package deploy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
	"github.com/Zaltapar/iran-germany-split-tunnel/internal/origin"
)

func absoluteTestPath(name string) string {
	path, err := filepath.Abs(filepath.Join("split-tunnel-test", name))
	if err != nil {
		panic(err)
	}
	return path
}

func validIranRequest() InstallRequest {
	c := *config.Defaults()
	c.SocksListen = "127.0.0.1:10900"
	c.WsListen = "127.0.0.1:9001"
	c.DownCarrierAddr = "127.0.0.1:10802"
	c.Secret = strings.Repeat("a", 64)
	return InstallRequest{
		Role:            RoleIran,
		Config:          c,
		Origin:          origin.Plan{Mode: origin.ModeCaddy, Domain: "upload.example.com", UpstreamAddr: "127.0.0.1:9001"},
		StateRoot:       absoluteTestPath("state"),
		EnvPath:         absoluteTestPath(filepath.Join("state", "iran.env")),
		ConfigPath:      absoluteTestPath(filepath.Join("state", "iran.json")),
		SplitterVersion: "v1.0.0",
		SplitterPath:    absoluteTestPath("iran-splitter"),
		OriginVersion:   "v2.11.4",
		OriginPath:      absoluteTestPath("caddy"),
	}
}

func validGermanyRequest() InstallRequest {
	c := *config.Defaults()
	c.UpWsUrl = "wss://upload.example.com/upload"
	c.DownListen = ":9002"
	c.Secret = strings.Repeat("b", 64)
	return InstallRequest{
		Role:            RoleGermany,
		Config:          c,
		Origin:          origin.Plan{Mode: origin.ModeNone, UpstreamAddr: "127.0.0.1:9001"},
		StateRoot:       absoluteTestPath("state"),
		EnvPath:         absoluteTestPath(filepath.Join("state", "germany.env")),
		ConfigPath:      absoluteTestPath(filepath.Join("state", "xray-germany.json")),
		SplitterVersion: "v1.0.0",
		SplitterPath:    absoluteTestPath("germany-splitter"),
		XrayVersion:     "v26.3.27",
		XrayPath:        absoluteTestPath("xray"),
	}
}

func TestInstallRequestDesiredValidRoles(t *testing.T) {
	for _, request := range []InstallRequest{validIranRequest(), validGermanyRequest()} {
		desired, err := request.Desired()
		if err != nil {
			t.Fatalf("Desired(%s): %v", request.Role, err)
		}
		if desired.Role != request.Role || desired.Paths.StateRoot != request.StateRoot {
			t.Fatalf("desired = %+v", desired)
		}
		if desired.Pairing.State != "none" {
			t.Fatalf("pairing state = %q", desired.Pairing.State)
		}
	}
}

func TestInstallRequestEnvProjectionKeepsSecretOutOfDesiredState(t *testing.T) {
	r := validIranRequest()
	env, err := r.Env()
	if err != nil {
		t.Fatal(err)
	}
	if env[config.EnvSecret] != r.Config.Secret {
		t.Fatal("env projection omitted the secret")
	}
	desired, err := r.Desired()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join([]string{desired.Components.Splitter.Path, desired.Paths.Env, desired.Paths.Config}, "\n"), r.Config.Secret) {
		t.Fatal("desired state contains the tunnel secret")
	}
}

func TestInstallRequestRejectsPathEscape(t *testing.T) {
	r := validIranRequest()
	r.EnvPath = filepath.Join(filepath.Dir(r.StateRoot), "escape.env")
	if err := r.Validate(); err == nil {
		t.Fatal("path escape unexpectedly accepted")
	}
}

func TestInstallRequestRejectsUnsafeOrIncompleteInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*InstallRequest)
	}{
		{"bad role", func(r *InstallRequest) { r.Role = "other" }},
		{"missing splitter artifact", func(r *InstallRequest) { r.SplitterPath = "" }},
		{"Germany missing xray", func(r *InstallRequest) { r.XrayPath = "" }},
		{"invalid xray version", func(r *InstallRequest) { r.XrayVersion = "latest" }},
		{"invalid origin version", func(r *InstallRequest) { r.OriginVersion = "latest" }},
		{"invalid origin plan", func(r *InstallRequest) {
			r.Origin = origin.Plan{Mode: origin.ModeCaddy, Domain: "bad domain", UpstreamAddr: "127.0.0.1:9001"}
		}},
		{"relative state root", func(r *InstallRequest) { r.StateRoot = "relative" }},
		{"Iran none origin", func(r *InstallRequest) { r.Origin = origin.Plan{Mode: origin.ModeNone, UpstreamAddr: "127.0.0.1:9001"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validIranRequest()
			if tc.name == "Germany missing xray" {
				r = validGermanyRequest()
			}
			tc.mutate(&r)
			if _, err := r.Desired(); err == nil {
				t.Fatal("Desired unexpectedly succeeded")
			}
		})
	}
}
