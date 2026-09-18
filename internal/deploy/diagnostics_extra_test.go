package deploy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/systemd"
)

type diagnosticsCommandFake struct {
	output string
	err    error
	calls  []string
}

func (f *diagnosticsCommandFake) Run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	return f.output, f.err
}

func TestListenerBindsCheckPositiveNegativeAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output string
		want   Severity
	}{
		{name: "present", output: "LISTEN 0 128 127.0.0.1:9001 0.0.0.0:*\n", want: SeverityPass},
		{name: "missing", output: "LISTEN 0 128 127.0.0.1:9002 0.0.0.0:*\n", want: SeverityFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &diagnosticsCommandFake{output: tc.output}
			finding := ListenerBindsCheck(fake, []string{"127.0.0.1:9001"}).Run(context.Background())
			if finding.Severity != tc.want {
				t.Fatalf("finding = %+v, want %s", finding, tc.want)
			}
			if len(fake.calls) != 1 || fake.calls[0] != "ss -ltnH" {
				t.Fatalf("calls = %#v, want one read-only ss call", fake.calls)
			}
		})
	}
}

type diagnosticsXrayFake struct {
	version string
	testErr error
	calls   []string
}

func (f *diagnosticsXrayFake) VersionOutput(bin string) (string, error) {
	f.calls = append(f.calls, "version "+bin)
	return f.version, nil
}

func (f *diagnosticsXrayFake) RunTest(bin, config string) (string, error) {
	f.calls = append(f.calls, "test "+bin+" "+config)
	return "", f.testErr
}

func (f *diagnosticsXrayFake) Keypair(string) (string, error) { return "", nil }

func TestXrayConfigCheckPositiveNegativeAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		testErr error
		want    Severity
	}{
		{name: "valid", version: "Xray  v26.3.27", want: SeverityPass},
		{name: "bad config", version: "Xray  v26.3.27", testErr: context.Canceled, want: SeverityFail},
		{name: "wrong version", version: "Xray  v1.0.0", want: SeverityFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &diagnosticsXrayFake{version: tc.version, testErr: tc.testErr}
			binaryPath, err := filepath.Abs("xray")
			if err != nil {
				t.Fatal(err)
			}
			configPath, err := filepath.Abs("xray.json")
			if err != nil {
				t.Fatal(err)
			}
			finding := XrayConfigCheck(fake, binaryPath, configPath, "v26.3.27").Run(context.Background())
			if finding.Severity != tc.want {
				t.Fatalf("finding = %+v, want %s", finding, tc.want)
			}
			if tc.want == SeverityPass && len(fake.calls) != 2 {
				t.Fatalf("calls = %#v, want version and run-test only", fake.calls)
			}
		})
	}
}

func TestListenerBindsCheckDoesNotUseSystemdMutationMethods(t *testing.T) {
	fake := &diagnosticsCommandFake{output: "LISTEN 0 128 127.0.0.1:9001 0.0.0.0:*\n"}
	finding := ListenerBindsCheck(fake, []string{"127.0.0.1:9001"}).Run(context.Background())
	if finding.Severity != SeverityPass {
		t.Fatalf("finding = %+v", finding)
	}
	manager := systemd.NewServiceManager(fake)
	if _, err := manager.State(context.Background(), "splitter.service"); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "systemctl is-active splitter.service" {
		t.Fatalf("calls = %#v, expected only read-only commands", fake.calls)
	}
}
