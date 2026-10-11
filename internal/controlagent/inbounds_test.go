// inbounds_test.go — the C3 Reality inbound editing surface:
// validator rules (port conflict, reserved 8443/22, missing SNI, bad
// shortId, empty list, min-one-healthy, secret denylist, key-ref shape),
// the key-rotation flow (old key retained, rotation blocked without
// retainOld), blob export/import (0600 files, fingerprint only, blob-kind
// pairing), the xray -test gate (fault injection → no swap), and restart
// only the affected service. All host-facing steps are faked; no xray
// binary, no systemctl, no network.
package controlagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// fake inbound seam
// ---------------------------------------------------------------------------

type fakeInboundSeam struct {
	mu sync.Mutex

	role         string
	livePath     string
	liveContent  string
	baseInbounds []InboundSpec
	rotateKeyOut string // fingerprint returned by RotateKeypair

	calls []string

	failConfigTest error
	failRestart    error
	failVerify     error
	failRender     error
}

func newFakeInboundSeam(t *testing.T, role, liveDir string) *fakeInboundSeam {
	t.Helper()
	live := filepath.Join(liveDir, "xray.json")
	orig := `{"inbounds":[]}`
	if err := os.WriteFile(live, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeInboundSeam{
		role:         role,
		livePath:     live,
		liveContent:  orig,
		baseInbounds: []InboundSpec{{Instance: "a", Enabled: true, Port: 443, SNI: "play.google.com", ShortID: "0011223344556677", KeyRef: "aaaabbbbcccc"}},
		rotateKeyOut: "ffeeddccb222",
	}
}

func (f *fakeInboundSeam) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeInboundSeam) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeInboundSeam) hadCall(call string) bool {
	for _, c := range f.Calls() {
		if c == call {
			return true
		}
	}
	return false
}

func (f *fakeInboundSeam) LiveXrayConfigPath(role string) string {
	if role == f.role {
		return f.livePath
	}
	return ""
}

func (f *fakeInboundSeam) BaseInbounds(role string) ([]InboundSpec, error) {
	if role == f.role {
		out := make([]InboundSpec, len(f.baseInbounds))
		copy(out, f.baseInbounds)
		return out, nil
	}
	return nil, nil
}

func (f *fakeInboundSeam) WriteXrayCandidate(role string, inbounds []InboundSpec) (string, error) {
	f.record("render")
	if f.failRender != nil {
		return "", f.failRender
	}
	sandbox := f.livePath + ".c3-candidate"
	if err := os.WriteFile(sandbox, []byte(fmt.Sprintf("c3-candidate role=%s count=%d", role, len(inbounds))), 0o600); err != nil {
		return "", err
	}
	return sandbox, nil
}

func (f *fakeInboundSeam) ConfigTest(role, candidatePath string) error {
	f.record("configtest")
	if f.failConfigTest != nil {
		return f.failConfigTest
	}
	if _, err := os.Stat(candidatePath); err != nil {
		return err
	}
	return nil
}

func (f *fakeInboundSeam) RestartXray(role string) error {
	f.record("restart-" + role)
	if role != f.role {
		return fmt.Errorf("seam only handles role %q, got %q", f.role, role)
	}
	if f.failRestart != nil {
		f.mu.Lock()
		err := f.failRestart
		f.failRestart = nil
		f.mu.Unlock()
		return err
	}
	return nil
}

func (f *fakeInboundSeam) VerifyXray(role string) error {
	f.record("verify")
	if f.failVerify != nil {
		f.mu.Lock()
		err := f.failVerify
		f.failVerify = nil
		f.mu.Unlock()
		return err
	}
	return nil
}

func (f *fakeInboundSeam) RestoreXrayFile(role, livePath, backupPath string) error {
	f.record("restore")
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(livePath, data, 0o600); err != nil {
		return err
	}
	f.liveContent = string(data)
	return nil
}

func (f *fakeInboundSeam) RotateKeypair(role, instance string) (string, error) {
	f.record("rotate-" + role + "/" + instance)
	if f.rotateKeyOut == "" {
		return "", errors.New("keygen unavailable")
	}
	return f.rotateKeyOut, nil
}

func (f *fakeInboundSeam) ExportBlob(role, blobKind, outPath string) (string, error) {
	f.record("export-blob-" + role)
	body := fmt.Sprintf("splat-v1.<blob%s role=%s sni=public-only>", strings.ToUpper(blobKind), role)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, []byte(body), 0o600); err != nil {
		return "", err
	}
	return blobFingerprint(body)
}

func (f *fakeInboundSeam) ImportBlob(role, blobKind, inPath string) (string, error) {
	f.record("import-blob-" + role)
	data, err := os.ReadFile(inPath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(f.livePath, data, 0o600); err != nil {
		return "", err
	}
	f.liveContent = string(data)
	return "r-c3-import-" + blobKind, nil
}

func blobFingerprint(body string) (string, error) {
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%x", sum[:6]), nil
}

// ---------------------------------------------------------------------------
// validator tests
// ---------------------------------------------------------------------------

func validC3Inbounds(role string) InboundChange {
	if role == "germany" {
		return InboundChange{
			Role: role,
			Inbounds: []InboundSpec{
				{Instance: "a", Enabled: true, Port: 443, SNI: "play.google.com", ShortID: "0011223344556677", KeyRef: "aaaabbbbcccc"},
			},
		}
	}
	return InboundChange{
		Role: role,
		Inbounds: []InboundSpec{
			{Instance: "consumer-a", Enabled: true, Port: 10802, SNI: "play.google.com", ShortID: "0011223344556677", RemoteHost: "91.107.152.1", RemotePort: 443, KeyRef: "aaaabbbbcccc"},
		},
	}
}

func TestC3InboundsValidatorValid(t *testing.T) {
	for _, role := range []string{"germany", "iran"} {
		if errs := ValidateInboundChange(validC3Inbounds(role), nil, nil); len(errs) != 0 {
			t.Fatalf("role=%s: expected valid, got %v", role, errs)
		}
	}
}

func TestC3InboundsValidatorPortConflict(t *testing.T) {
	ch := InboundChange{
		Role: "germany",
		Inbounds: []InboundSpec{
			{Instance: "a", Enabled: true, Port: 443, SNI: "a.example.com", ShortID: "0011223344556677"},
			{Instance: "b", Enabled: true, Port: 443, SNI: "b.example.com", ShortID: "1122334455667788"},
		},
	}
	errs := ValidateInboundChange(ch, nil, nil)
	if len(errs) == 0 || !strings.Contains(errs[0], "conflicts with instance") {
		t.Fatalf("expected intra-change port conflict, got %v", errs)
	}
}

func TestC3InboundsValidatorReserved8443(t *testing.T) {
	ch := InboundChange{
		Role:     "germany",
		Inbounds: []InboundSpec{{Instance: "a", Enabled: true, Port: 8443, SNI: "a.example.com", ShortID: "0011223344556677"}},
	}
	errs := ValidateInboundChange(ch, nil, nil)
	if len(errs) == 0 || !strings.Contains(errs[0], "reserved") {
		t.Fatalf("expected reserved-port 8443 rejection, got %v", errs)
	}
}

func TestC3InboundsValidatorOperatorReservedList(t *testing.T) {
	ch := InboundChange{
		Role:     "germany",
		Inbounds: []InboundSpec{{Instance: "a", Enabled: true, Port: 7777, SNI: "a.example.com", ShortID: "0011223344556677"}},
	}
	if errs := ValidateInboundChange(ch, []int{7777}, nil); len(errs) == 0 {
		t.Fatal("expected operator-configured reserved port 7777 to be rejected")
	}
	if errs := ValidateInboundChange(ch, nil, nil); len(errs) != 0 {
		t.Fatalf("port 7777 without a reserved list must pass, got %v", errs)
	}
}

func TestC3InboundsValidatorMissingSNI(t *testing.T) {
	ch := validC3Inbounds("germany")
	ch.Inbounds[0].SNI = ""
	errs := ValidateInboundChange(ch, nil, nil)
	if len(errs) == 0 || !strings.Contains(errs[0], "sni") {
		t.Fatalf("expected missing-SNI rejection, got %v", errs)
	}
}

func TestC3InboundsValidatorBadShortID(t *testing.T) {
	ch := validC3Inbounds("iran")
	ch.Inbounds[0].ShortID = "001122334455667"
	if errs := ValidateInboundChange(ch, nil, nil); len(errs) == 0 {
		t.Fatal("expected 15-hex shortId rejection")
	}
	ch.Inbounds[0].ShortID = "001122334455667A"
	if errs := ValidateInboundChange(ch, nil, nil); len(errs) == 0 {
		t.Fatal("expected uppercase shortId rejection")
	}
	ch.Inbounds[0].ShortID = "00112233445566778"
	if errs := ValidateInboundChange(ch, nil, nil); len(errs) == 0 {
		t.Fatal("expected 17-hex shortId rejection")
	}
}

func TestC3InboundsValidatorEmptyList(t *testing.T) {
	ch := InboundChange{Role: "germany", Inbounds: []InboundSpec{}}
	errs := ValidateInboundChange(ch, nil, nil)
	if len(errs) == 0 || !strings.Contains(errs[0], "at least one inbound") {
		t.Fatalf("expected empty-list rejection, got %v", errs)
	}
}

func TestC3InboundsValidatorMinOneHealthy(t *testing.T) {
	ch := validC3Inbounds("germany")
	ch.Inbounds[0].Enabled = false
	errs := ValidateInboundChange(ch, nil, nil)
	if len(errs) == 0 || !strings.Contains(errs[0], "enabled") {
		t.Fatalf("expected min-one-healthy rejection when nothing is enabled, got %v", errs)
	}
}

func TestC3InboundsValidatorSecretDenylist(t *testing.T) {
	ch := validC3Inbounds("germany")
	errs := ValidateInboundChange(ch, nil, []string{"SPLIT_SECRET", "realityPrivateKey"})
	if len(errs) == 0 {
		t.Fatal("expected secret-denylist rejection")
	}
}

func TestC3InboundsValidatorBadKeyRef(t *testing.T) {
	ch := validC3Inbounds("germany")
	ch.Inbounds[0].KeyRef = "AAECAw==" // looks like key material, not a fingerprint
	if errs := ValidateInboundChange(ch, nil, nil); len(errs) == 0 || !strings.Contains(errs[0], "keyRef") {
		t.Fatalf("expected key-ref shape rejection, got %v", errs)
	}
}

func TestC3InboundsValidatorBadRole(t *testing.T) {
	ch := validC3Inbounds("germany")
	ch.Role = "both"
	if errs := ValidateInboundChange(ch, nil, nil); len(errs) == 0 {
		t.Fatal("expected role rejection")
	}
}

// ---------------------------------------------------------------------------
// agent-level: apply with the xray -test gate + fault injection
// ---------------------------------------------------------------------------

type c3Harness struct {
	agent *Agent
	seam  *fakeInboundSeam
	root  string
}

func newC3Harness(t *testing.T, role string) *c3Harness {
	t.Helper()
	root := t.TempDir()
	a, err := NewAgent(root, nil, defaultConfigBuilder)
	if err != nil {
		t.Fatal(err)
	}
	seam := newFakeInboundSeam(t, role, t.TempDir())
	a.InboundSeam = seam
	return &c3Harness{agent: a, seam: seam, root: root}
}

func (h *c3Harness) runInboundApply(change InboundChange, faults Faults) (TxResult, string, string) {
	op := InboundApplyOp{Change: change, Actor: "test-operator"}
	return h.agent.runInboundApply(op, faults)
}

func (h *c3Harness) liveContent() string {
	data, _ := os.ReadFile(h.seam.livePath)
	return string(data)
}

func TestC3InboundApplySuccess(t *testing.T) {
	h := newC3Harness(t, "germany")
	original := h.liveContent()
	res, code, msg := h.runInboundApply(validC3Inbounds("germany"), nil)
	if code != "" {
		t.Fatalf("apply failed: code=%s msg=%s", code, msg)
	}
	if res.Outcome != "committed" {
		t.Fatalf("outcome = %q, want committed", res.Outcome)
	}
	if h.liveContent() == original {
		t.Fatal("live xray config was not swapped")
	}
	if !h.seam.hadCall("restart-germany") {
		t.Fatalf("expected restart-germany, calls=%v", h.seam.Calls())
	}
	if _, inFlight, _ := h.agent.Journal.Read(); inFlight {
		t.Fatal("journal still in-flight after success")
	}
}

func TestC3InboundApplyRestartOnlyAffectedService(t *testing.T) {
	h := newC3Harness(t, "iran")
	res, code, msg := h.runInboundApply(validC3Inbounds("iran"), nil)
	if code != "" {
		t.Fatalf("apply failed: code=%s msg=%s", code, msg)
	}
	if res.Outcome != "committed" {
		t.Fatalf("outcome = %q", res.Outcome)
	}
	if !h.seam.hadCall("restart-iran") {
		t.Fatalf("expected restart-iran, calls=%v", h.seam.Calls())
	}
}

func TestC3InboundConfigTestFailureNoSwap(t *testing.T) {
	h := newC3Harness(t, "germany")
	original := h.liveContent()
	faults := Faults{"configtest": errors.New("xray run -test: dest port 0 out of range")}
	res, code, _ := h.runInboundApply(validC3Inbounds("germany"), faults)
	if code != ErrCodeConfigTestFailed {
		t.Fatalf("code = %q, want %q", code, ErrCodeConfigTestFailed)
	}
	if res.Outcome != "config-test-failed" {
		t.Fatalf("outcome = %q", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live config must be untouched when xray -test fails (no swap)")
	}
	for _, banned := range []string{"swap", "restart-germany", "verify"} {
		if h.seam.hadCall(banned) {
			t.Fatalf("no %s may occur before a passing xray -test: %v", banned, h.seam.Calls())
		}
	}
	if _, inFlight, _ := h.agent.Journal.Read(); inFlight {
		t.Fatal("journal must be cleared after a config-test failure")
	}
}

func TestC3InboundRestartFaultAutoRollback(t *testing.T) {
	h := newC3Harness(t, "germany")
	original := h.liveContent()
	h.seam.failRestart = errors.New("systemctl restart xray-germany refused")
	res, _, _ := h.runInboundApply(validC3Inbounds("germany"), nil)
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live config was not restored after restart failure")
	}
	if !h.seam.hadCall("restore") {
		t.Fatalf("rollback must restore the pre copy: %v", h.seam.Calls())
	}
}

func TestC3InboundVerifyFaultAutoRollback(t *testing.T) {
	h := newC3Harness(t, "germany")
	original := h.liveContent()
	h.seam.failVerify = errors.New("listener on 443 not up")
	res, _, _ := h.runInboundApply(validC3Inbounds("germany"), nil)
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live config was not restored after verify failure")
	}
}

func TestC3InboundCommitFaultAutoRollback(t *testing.T) {
	h := newC3Harness(t, "germany")
	original := h.liveContent()
	faults := Faults{"commit": errors.New("store write refused")}
	res, _, _ := h.runInboundApply(validC3Inbounds("germany"), faults)
	if res.Outcome != "rolled-back" {
		t.Fatalf("outcome = %q, want rolled-back", res.Outcome)
	}
	if h.liveContent() != original {
		t.Fatal("live config was not restored after commit failure")
	}
}

func TestC3InboundApplyValidationRefused(t *testing.T) {
	h := newC3Harness(t, "germany")
	original := h.liveContent()
	ch := validC3Inbounds("germany")
	ch.Inbounds[0].Port = 8443 // reserved
	_, code, _ := h.runInboundApply(ch, nil)
	if code != ErrCodeValidation {
		t.Fatalf("code = %q, want %q", code, ErrCodeValidation)
	}
	if h.liveContent() != original {
		t.Fatal("invalid candidate must not touch the live config")
	}
	if h.seam.hadCall("render") {
		t.Fatal("validation runs before render: no sandbox write expected")
	}
}

// ---------------------------------------------------------------------------
// key rotation
// ---------------------------------------------------------------------------

func TestC3RotateBlockedWithoutRetainOld(t *testing.T) {
	h := newC3Harness(t, "germany")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = h.agent.serveC3Op(server, OpInboundsRotate, &RotateRequest{Role: "germany", Instance: "a", RetainOld: false})
	}()
	code, msg := readC3Reply(t, client)
	if code != ErrCodeRotationBlocked {
		t.Fatalf("code = %q, want %q (msg=%s)", code, ErrCodeRotationBlocked, msg)
	}
	if h.seam.hadCall("rotate-germany/a") {
		t.Fatal("keygen must not run when rotation is blocked")
	}
}

func TestC3RotateKeypairRetainsOldKey(t *testing.T) {
	h := newC3Harness(t, "germany")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = h.agent.serveC3Op(server, OpInboundsRotate, &RotateRequest{Role: "germany", Instance: "a", RetainOld: true, ChangeID: "c3-rot"})
	}()
	code, resp := readC3ReplyData(t, client)
	if code != "" {
		t.Fatalf("code = %q, want success", code)
	}
	data, ok := resp.(map[string]any)
	if !ok {
		t.Fatalf("response type = %T, want map[string]any", resp)
	}
	if data["newKeyFingerprint"] == "" || data["newKeyFingerprint"] == nil {
		t.Fatal("newKeyFingerprint must be set")
	}
	if data["oldKeyRetained"] != true {
		t.Fatal("old key must be retained in the revision store")
	}
	if !h.seam.hadCall("rotate-germany/a") {
		t.Fatalf("keygen was not called: %v", h.seam.Calls())
	}
	// The revision's pre/ copy retains the live config holding the old
	// private key (root-only 0600 — never returned by the API).
	head, _ := h.agent.Store.Head()
	if head == "" {
		t.Fatal("head not set after rotation commit")
	}
	pre, err := h.agent.Store.LoadPreCopies(head)
	if err != nil || len(pre) == 0 {
		t.Fatalf("pre/ snapshot missing (old key retention): err=%v len=%d", err, len(pre))
	}
}

func TestC3RotateNilSeamFailsClosed(t *testing.T) {
	root := t.TempDir()
	a, err := NewAgent(root, nil, defaultConfigBuilder)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = a.serveC3Op(server, OpInboundsRotate, &RotateRequest{Role: "germany", Instance: "a", RetainOld: true})
	}()
	code, _ := readC3Reply(t, client)
	if code != ErrCodeInboundNotConfigured {
		t.Fatalf("code = %q, want %q", code, ErrCodeInboundNotConfigured)
	}
}

// ---------------------------------------------------------------------------
// blob export / import round trip
// ---------------------------------------------------------------------------

func TestC3BlobExportWrites0600FileFingerprintOnly(t *testing.T) {
	h := newC3Harness(t, "germany")
	outPath := filepath.Join(t.TempDir(), "blobB.txt")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = h.agent.serveC3Op(server, OpInboundsExportBlob, &BlobExportRequest{Role: "germany", BlobKind: "b", OutPath: outPath, ChangeID: "c3-exp"})
	}()
	code, resp := readC3ReplyData(t, client)
	if code != "" {
		t.Fatalf("export code = %q", code)
	}
	er, ok := resp.(map[string]any)
	if !ok {
		t.Fatalf("response type = %T, want map[string]any", resp)
	}
	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("export file missing: %v", err)
	}
	// The 0600 mode is asserted on Unix (the production target); Windows
	// ACL semantics don't map file modes 1:1, so skip there.
	if fi.Mode().Perm() != 0o600 {
		if runtime.GOOS != "windows" {
			t.Fatalf("export file mode = %o, want 0600", fi.Mode().Perm())
		}
	}
	if fp, ok := er["fingerprint"].(string); !ok || fp == "" {
		t.Fatalf("fingerprint must be set, got %v", er["fingerprint"])
	}
	// The blob body carries no secret material.
	body, _ := os.ReadFile(outPath)
	for _, marker := range []string{"privateKey", "secret", "AAECAw=="} {
		if strings.Contains(string(body), marker) {
			t.Fatalf("blob file contains forbidden material %q", marker)
		}
	}
}

func TestC3BlobExportImportPairingAndAbsPath(t *testing.T) {
	h := newC3Harness(t, "germany")

	// Wrong role/kind pairing must be refused (Germany pairs with blob b).
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = h.agent.serveC3Op(server, OpInboundsExportBlob, &BlobExportRequest{Role: "germany", BlobKind: "a", OutPath: "/abs/blob.txt"})
	}()
	if code, _ := readC3Reply(t, client); code != ErrCodeInvalidJSON {
		t.Fatalf("blob-kind pairing violation must be a 400-class error, got %q", code)
	}

	// Non-absolute outPath must be refused.
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	go func() {
		_ = h.agent.serveC3Op(server2, OpInboundsExportBlob, &BlobExportRequest{Role: "germany", BlobKind: "b", OutPath: "relative/blobB.txt"})
	}()
	if code, _ := readC3Reply(t, client2); code != ErrCodeInvalidJSON {
		t.Fatalf("relative outPath must be refused, got %q", code)
	}

	// Iran-side import of a Blob B is refused by the pairing check
	// (Iran pairs with blob a).
	hIran := newC3Harness(t, "iran")
	client3, server3 := net.Pipe()
	defer client3.Close()
	defer server3.Close()
	go func() {
		_ = hIran.agent.serveC3Op(server3, OpInboundsImportBlob, &BlobImportRequest{Role: "iran", BlobKind: "b", InPath: "/abs/blobB.txt"})
	}()
	if code, _ := readC3Reply(t, client3); code != ErrCodeInvalidJSON {
		t.Fatalf("import pairing violation must be refused, got %q", code)
	}
}

// ---------------------------------------------------------------------------
// apply over the wire (confirm token + peer-coupling note)
// ---------------------------------------------------------------------------

func TestC3InboundApplyViaSocket(t *testing.T) {
	h := newC3Harness(t, "germany")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ch := validC3Inbounds("germany")
	ch.ChangeID = "c3-1"
	ch.ConfirmToken = c3ConfirmToken
	go func() {
		_ = h.agent.serveC3Op(server, OpInboundsApply, &ch)
	}()
	code, resp := readC3ReplyData(t, client)
	if code != "" {
		t.Fatalf("code = %q", code)
	}
	if m, ok := resp.(map[string]any); !ok || m["outcome"] != "committed" {
		t.Fatalf("response = %v", resp)
	}
	if !h.seam.hadCall("restart-germany") {
		t.Fatalf("xray service not restarted: %v", h.seam.Calls())
	}
}

func TestC3InboundValidateOverSocket(t *testing.T) {
	h := newC3Harness(t, "germany")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ch := validC3Inbounds("germany")
	go func() {
		_ = h.agent.serveC3Op(server, OpInboundsValidate, &ch)
	}()
	code, resp := readC3ReplyData(t, client)
	if code != "" {
		t.Fatalf("code = %q", code)
	}
	data, ok := resp.(map[string]any)
	if !ok {
		t.Fatalf("response type = %T", resp)
	}
	if data["valid"] != true {
		t.Fatalf("valid = %v, want true", data["valid"])
	}
	if data["restartRequired"] != true {
		t.Fatalf("restartRequired = %v, want true", data["restartRequired"])
	}
	if data["peerChangeRequired"] == "" {
		t.Fatal("peerChangeRequired note must be present (D10)")
	}
}

// ---------------------------------------------------------------------------
// wire helpers
// ---------------------------------------------------------------------------

// serveC3Op drives one C3 op through the agent's op dispatch WITHOUT the
// SO_PEERCRED peer check (that check is Linux-gated and covered by the C2
// peercheck tests). It is test-only.
func (a *Agent) serveC3Op(conn net.Conn, op string, payload any) error {
	defer conn.Close()
	frame := &Frame{V: ProtocolVersion, Op: op, ReqID: "test-req", Payload: payload}
	switch op {
	case OpInboundsValidate:
		return a.opInboundsValidate(conn, frame)
	case OpInboundsApply:
		return a.opInboundsApply(conn, frame)
	case OpInboundsRotate:
		return a.opInboundsRotate(conn, frame)
	case OpInboundsExportBlob:
		return a.opInboundsExportBlob(conn, frame)
	case OpInboundsImportBlob:
		return a.opInboundsImportBlob(conn, frame)
	}
	return errors.New("unknown test op " + op)
}

func readC3Reply(t *testing.T, conn net.Conn) (string, string) {
	t.Helper()
	buf := make([]byte, 16<<10+1)
	n, err := conn.Read(buf)
	if err != nil {
		return "transport-error", err.Error()
	}
	var fr Frame
	dec := json.NewDecoder(bytes.NewReader(buf[:n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fr); err != nil {
		return "bad-frame", err.Error()
	}
	if fr.Error != nil {
		return fr.Error.Code, fr.Error.Message
	}
	return "", ""
}

func readC3ReplyData(t *testing.T, conn net.Conn) (string, any) {
	t.Helper()
	buf := make([]byte, 16<<10+1)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var fr Frame
	dec := json.NewDecoder(bytes.NewReader(buf[:n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fr); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if fr.Error != nil {
		return fr.Error.Code, nil
	}
	return "", fr.Data
}
