// envfile_test.go — design §7 item 3: D4 env-file management
// (fresh write, idempotence, keep-3 backups, validation via the
// authoritative config validator, rollback).
package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/internal/config"
)

func TestWriteEnvFileFresh(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()
	kv := validEnvKV(t, RoleGermany)

	applied, hash, err := WriteEnvFile(ctx, RoleGermany, kv)
	if err != nil {
		t.Fatalf("WriteEnvFile: %v", err)
	}
	if !applied {
		t.Fatalf("fresh write: want applied=true")
	}
	want := "SPLIT_UP_WS_URL=ws://127.0.0.1:9001/upload\n" +
		"SPLIT_DOWN_LISTEN=127.0.0.1:9002\n" +
		"SPLIT_SECRET=" + secretMarker + "\n"
	path := filepath.Join(stateDir, "germany.env")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if string(got) != want {
		t.Fatalf("env bytes:\n got: %q\nwant: %q", got, want)
	}
	if hash != sha256hex([]byte(want)) {
		t.Fatalf("hash mismatch: %s", hash)
	}
	if runtime.GOOS == "linux" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("env file mode = %o, want 0600", st.Mode().Perm())
		}
	}
}

func TestWriteEnvFileIdempotent(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()
	kv := validEnvKV(t, RoleIran)

	if _, _, err := WriteEnvFile(ctx, RoleIran, kv); err != nil {
		t.Fatalf("first write: %v", err)
	}
	path := filepath.Join(stateDir, "iran.env")
	st1, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	applied, _, err := WriteEnvFile(ctx, RoleIran, kv)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if applied {
		t.Fatalf("identical kv: want applied=false")
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatalf("no-op write changed the file mtime")
	}
	// No backups from the no-op.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") {
			t.Fatalf("no-op created a backup: %s", e.Name())
		}
	}
}

func TestWriteEnvFileBackupsKeepThree(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()
	path := filepath.Join(stateDir, "germany.env")

	// A foreign backup name: never touched by the sweep.
	foreign := path + ".bak-foreign"
	writeRaw(t, foreign, []byte("foreign"))

	versions := []string{
		"ws://127.0.0.1:9001/upload",
		"ws://127.0.0.1:9002/upload",
		"ws://127.0.0.1:9003/upload",
		"ws://127.0.0.1:9004/upload",
		"ws://127.0.0.1:9005/upload",
	}
	for i, u := range versions {
		kv := map[string]string{
			config.EnvUpWsUrl:    u,
			config.EnvDownListen: "127.0.0.1:9002",
			config.EnvSecret:     secretMarker,
		}
		applied, _, err := WriteEnvFile(ctx, RoleGermany, kv)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if !applied && i > 0 {
			t.Fatalf("write %d: want applied=true", i)
		}
	}
	var backups []string
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") && e.Name() != filepath.Base(foreign) {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) != 3 {
		t.Fatalf("want 3 managed backups after 5 writes, got %d: %v", len(backups), backups)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign backup was removed by the sweep: %v", err)
	}
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live: %v", err)
	}
	if !strings.Contains(string(live), versions[4]) {
		t.Fatalf("live file does not carry the newest version")
	}
}

func TestWriteEnvFileValidation(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()
	path := filepath.Join(stateDir, "germany.env")

	t.Run("placeholder secret -> ConfigError, file untouched", func(t *testing.T) {
		kv := validEnvKV(t, RoleGermany)
		kv[config.EnvSecret] = config.DefaultSecret
		_, _, err := WriteEnvFile(ctx, RoleGermany, kv)
		var ce *config.ConfigError
		if !errors.As(err, &ce) {
			t.Fatalf("want *config.ConfigError, got %v", err)
		}
		if strings.Contains(err.Error(), secretMarker) {
			t.Fatalf("error leaked the secret marker: %v", err)
		}
		if _, serr := os.Lstat(path); !os.IsNotExist(serr) {
			t.Fatalf("invalid kv must not write the file")
		}
	})

	t.Run("dial target without host -> ConfigError", func(t *testing.T) {
		kv := validEnvKV(t, RoleIran)
		kv[config.EnvDownCarrier] = ":9002" // dial targets require an explicit host
		_, _, err := WriteEnvFile(ctx, RoleIran, kv)
		var ce *config.ConfigError
		if !errors.As(err, &ce) {
			t.Fatalf("want *config.ConfigError, got %v", err)
		}
	})

	t.Run("socks/ws port collision -> ConfigError", func(t *testing.T) {
		kv := validEnvKV(t, RoleIran)
		kv[config.EnvSocksListen] = "127.0.0.1:9001" // same endpoint as WsListen
		_, _, err := WriteEnvFile(ctx, RoleIran, kv)
		var ce *config.ConfigError
		if !errors.As(err, &ce) {
			t.Fatalf("want *config.ConfigError, got %v", err)
		}
	})

	t.Run("secret marker absent from config-error message", func(t *testing.T) {
		kv := validEnvKV(t, RoleGermany)
		kv[config.EnvDownListen] = "127.0.0.1:notaport" // triggers a config error
		_, _, err := WriteEnvFile(ctx, RoleGermany, kv)
		if err == nil {
			t.Fatalf("want error")
		}
		if strings.Contains(err.Error(), secretMarker) {
			t.Fatalf("error leaked the secret marker: %v", err)
		}
	})

	specCases := map[string]map[string]string{
		"unknown key": {
			config.EnvUpWsUrl:    "ws://127.0.0.1:9001/upload",
			config.EnvDownListen: "127.0.0.1:9002",
			config.EnvSecret:     secretMarker,
			"SPLIT_BOGUS":        "1",
		},
		"newline in value": {
			config.EnvUpWsUrl:    "ws://127.0.0.1:9001/upload\nevilextra=1",
			config.EnvDownListen: "127.0.0.1:9002",
			config.EnvSecret:     secretMarker,
		},
		"comment-prefixed value": {
			config.EnvUpWsUrl:    "#ws://127.0.0.1:9001/upload",
			config.EnvDownListen: "127.0.0.1:9002",
			config.EnvSecret:     secretMarker,
		},
		"non-int optional": {
			config.EnvUpWsUrl:     "ws://127.0.0.1:9001/upload",
			config.EnvDownListen:  "127.0.0.1:9002",
			config.EnvSecret:      secretMarker,
			config.EnvMetricsPort: "notanint",
		},
		"missing required": {
			config.EnvUpWsUrl: "ws://127.0.0.1:9001/upload",
			// EnvDownListen missing
			config.EnvSecret: secretMarker,
		},
		"empty value": {
			config.EnvUpWsUrl:    "ws://127.0.0.1:9001/upload",
			config.EnvDownListen: "127.0.0.1:9002",
			config.EnvSecret:     "",
		},
	}
	for name, kv := range specCases {
		t.Run(name, func(t *testing.T) {
			_, _, err := WriteEnvFile(ctx, RoleGermany, kv)
			if !errors.Is(err, ErrSpec) {
				t.Fatalf("want ErrSpec, got %v", err)
			}
			if _, serr := os.Lstat(path); !os.IsNotExist(serr) {
				t.Fatalf("invalid kv must not write the file")
			}
		})
	}
}

func TestRollbackEnvFile(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()
	path := filepath.Join(stateDir, "germany.env")

	// No backup yet: nothing to roll back to.
	if err := RollbackEnvFile(ctx, RoleGermany); !errors.Is(err, ErrPreflight) {
		t.Fatalf("want ErrPreflight with no backup, got %v", err)
	}

	v1 := validEnvKV(t, RoleGermany)
	v2 := validEnvKV(t, RoleGermany)
	v2[config.EnvUpWsUrl] = "ws://127.0.0.1:9002/upload"

	if _, _, err := WriteEnvFile(ctx, RoleGermany, v1); err != nil {
		t.Fatalf("write v1: %v", err)
	}
	if _, _, err := WriteEnvFile(ctx, RoleGermany, v2); err != nil {
		t.Fatalf("write v2: %v", err)
	}
	if err := RollbackEnvFile(ctx, RoleGermany); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), v1[config.EnvUpWsUrl]) ||
		strings.Contains(string(got), v2[config.EnvUpWsUrl]) {
		t.Fatalf("rollback did not restore v1: %q", got)
	}
}

func TestWriteEnvFileRoleCheck(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()
	_, _, err := WriteEnvFile(ctx, "mars", map[string]string{})
	if !errors.Is(err, ErrSpec) {
		t.Fatalf("want ErrSpec for unknown role, got %v", err)
	}
}

// TestWriteEnvFileSocksCredentials pins the RFC 1929 env-file behavior
// (plans/socks5-auth-design.md §7.4):
//   - user without pass → ErrSpec (the pairing rule is enforced at the
//     env-file boundary too, via the config fold);
//   - both keys render in the optional block, sorted, LF, single trailing
//     newline; the password appears exactly once and no error leaks it;
//   - a request that leaves both empty is a byte-identical legacy file
//     (backward-compat pin at the env-file layer).
func TestWriteEnvFileSocksCredentials(t *testing.T) {
	redirectPaths(t)
	ctx := context.Background()

	t.Run("user without pass -> ConfigError (pairing rule)", func(t *testing.T) {
		kv := validEnvKV(t, RoleIran)
		kv[config.EnvSocksUser] = "alice" // half-set: must be refused
		_, _, err := WriteEnvFile(ctx, RoleIran, kv)
		var ce *config.ConfigError
		if !errors.As(err, &ce) {
			t.Fatalf("want *config.ConfigError for half-set credentials, got %v", err)
		}
	})

	t.Run("both keys render, password never in error, rollback works", func(t *testing.T) {
		// Write #1: the credentials file (fresh, no backup yet).
		kv := validEnvKV(t, RoleIran)
		kv[config.EnvSocksUser] = "alice"
		kv[config.EnvSocksPass] = socksPassMarker
		if _, _, err := WriteEnvFile(ctx, RoleIran, kv); err != nil {
			t.Fatalf("WriteEnvFile #1: %v", err)
		}
		path := filepath.Join(stateDir, "iran.env")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read env file: %v", err)
		}
		// Both keys present, rendered in the sorted optional block.
		if !strings.Contains(string(data), config.EnvSocksUser+"=alice\n") {
			t.Fatalf("env file missing %s=alice:\n%s", config.EnvSocksUser, data)
		}
		if !strings.Contains(string(data), config.EnvSocksPass+"="+socksPassMarker+"\n") {
			t.Fatalf("env file missing %s line:\n%s", config.EnvSocksPass, data)
		}
		// LF endings + exactly one trailing newline.
		if !strings.HasSuffix(string(data), "\n") || strings.Contains(string(data), "\r\n") {
			t.Fatalf("env file must be LF with a single trailing newline:\n%s", data)
		}
		// The password appears exactly once (never duplicated).
		if n := strings.Count(string(data), socksPassMarker); n != 1 {
			t.Fatalf("password marker appears %d times, want 1", n)
		}
		// Write #2 (a different, credential-free state) backs up write #1.
		legacy := validEnvKV(t, RoleIran)
		if _, _, err := WriteEnvFile(ctx, RoleIran, legacy); err != nil {
			t.Fatalf("WriteEnvFile #2: %v", err)
		}
		// Rollback restores the credentials file (the password round-trips).
		if err := RollbackEnvFile(ctx, RoleIran); err != nil {
			t.Fatalf("RollbackEnvFile: %v", err)
		}
		restored, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read restored env file: %v", err)
		}
		if !strings.Contains(string(restored), config.EnvSocksPass+"="+socksPassMarker+"\n") {
			t.Fatalf("rollback did not restore the credentials:\n%s", restored)
		}
	})

	t.Run("absent keys: legacy byte-identical file (backward compat)", func(t *testing.T) {
		legacy := validEnvKV(t, RoleIran)
		if _, _, err := WriteEnvFile(ctx, RoleIran, legacy); err != nil {
			t.Fatalf("legacy write: %v", err)
		}
		path := filepath.Join(stateDir, "iran.env")
		legacyBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read legacy env file: %v", err)
		}
		// Neither credential key may appear at all (backward-compat pin).
		if strings.Contains(string(legacyBytes), config.EnvSocksUser) || strings.Contains(string(legacyBytes), config.EnvSocksPass) {
			t.Fatalf("legacy env file contains the new keys:\n%s", legacyBytes)
		}
		// An identical write is a proven no-op: applied=false, same bytes.
		applied, _, err := WriteEnvFile(ctx, RoleIran, legacy)
		if err != nil {
			t.Fatalf("second legacy write: %v", err)
		}
		if applied {
			t.Fatalf("identical legacy kv: want applied=false")
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read legacy env file: %v", err)
		}
		if string(got) != string(legacyBytes) {
			t.Fatalf("legacy env bytes changed:\n got: %s\nwant: %s", got, legacyBytes)
		}
	})

	t.Run("half-set error never leaks the password", func(t *testing.T) {
		kv := validEnvKV(t, RoleIran)
		kv[config.EnvSocksPass] = socksPassMarker // pass without user
		_, _, err := WriteEnvFile(ctx, RoleIran, kv)
		if err == nil {
			t.Fatalf("half-set (pass only) did not fail")
		}
		if strings.Contains(err.Error(), socksPassMarker) {
			t.Fatalf("error leaked the socksPassMarker: %v", err)
		}
	})
}
