//go:build linux

package systemd

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

func TestPermissionChainConvergence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for real chown/user provisioning")
	}
	redirectPaths(t)
	if _, err := user.Lookup(ServiceUser); err != nil {
		t.Skipf("service user %q unavailable: %v", ServiceUser, err)
	}
	if _, err := user.LookupGroup(ServiceGroup); err != nil {
		t.Skipf("service group %q unavailable: %v", ServiceGroup, err)
	}
	live := stateDir + "/xray-germany.json"
	caddy := stateDir + "/Caddyfile"
	env := stateDir + "/iran.env"
	prev := stateDir + "/xray-germany.json.prev"
	caddyPrev := stateDir + "/Caddyfile.prev"
	writeRaw(t, live, []byte("{}\n"))
	writeRaw(t, caddy, []byte(":443\n"))
	writeRaw(t, env, []byte("SPLIT_SECRET=private\n"))
	writeRaw(t, prev, []byte("previous private material\n"))
	writeRaw(t, caddyPrev, []byte("previous private material\n"))
	for _, path := range []string{live, caddy, env, prev, caddyPrev} {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(live, 0, 0); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{caddy, env, prev, caddyPrev} {
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
	}

	if err := EnsureUser(context.Background(), OSExecutor{}); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateDir(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := EnsureLogDir(context.Background(), OSExecutor{}); err != nil {
		t.Fatal(err)
	}

	assertModeOwner(t, stateDir, 0o750, 0, ServiceGroup)
	assertModeOwner(t, live, 0o640, 0, ServiceGroup)
	assertModeOwner(t, caddy, 0o640, 0, ServiceGroup)
	assertModeOwner(t, env, 0o600, 0, "root")
	assertModeOwner(t, prev, 0o600, 0, "root")
	assertModeOwner(t, caddyPrev, 0o600, 0, "root")
	if err := runAsServiceGroup(caddy); err != nil {
		t.Fatalf("service account cannot read converged Caddyfile: %v", err)
	}
	assertModeOwner(t, logDir, 0o775, 0, ServiceGroup)
}

func runAsServiceGroup(path string) error {
	return exec.Command("runuser", "-u", ServiceUser, "--", "test", "-r", path).Run()
}

func assertModeOwner(t *testing.T, path string, wantMode os.FileMode, wantUID int, wantGroup string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != wantMode {
		t.Fatalf("%s mode=%o, want %o", path, st.Mode().Perm(), wantMode)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s has unexpected stat type", path)
	}
	if int(sys.Uid) != wantUID {
		t.Fatalf("%s uid=%d, want %d", path, sys.Uid, wantUID)
	}
	if wantGroup != "root" {
		g, err := user.LookupGroup(wantGroup)
		if err != nil {
			t.Fatal(err)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			t.Fatal(err)
		}
		if int(sys.Gid) != gid {
			t.Fatalf("%s gid=%d, want %d", path, sys.Gid, gid)
		}
	} else if int(sys.Gid) != 0 {
		t.Fatalf("%s gid=%d, want root", path, sys.Gid)
	}
}
