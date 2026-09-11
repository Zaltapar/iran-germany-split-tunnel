package systemd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWaitActiveSemantics(t *testing.T) {
	old := waitPollInterval
	waitPollInterval = time.Millisecond
	t.Cleanup(func() { waitPollInterval = old })

	t.Run("activating then active", func(t *testing.T) {
		i := 0
		ex := &fakeExec{handler: func(args []string) (string, error) {
			if args[0] == "systemctl" && args[1] == "is-active" {
				i++
				if i <= 3 {
					return "activating (auto-restart)", errors.New("inactive")
				}
				return "active", nil
			}
			return "", nil
		}}
		m := newTestManager(ex)
		if err := m.WaitActive(context.Background(), "germany-splitter.service", 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if i != 4 {
			t.Fatalf("polls=%d, want 4", i)
		}
	})

	t.Run("failed immediate", func(t *testing.T) {
		ex := &fakeExec{handler: func(args []string) (string, error) { return "failed", errors.New("inactive") }}
		m := newTestManager(ex)
		err := m.WaitActive(context.Background(), "germany-splitter.service", time.Second)
		if !errors.Is(err, ErrUnitState) {
			t.Fatalf("error=%v, want ErrUnitState", err)
		}
		if ex.count() != 1 {
			t.Fatalf("calls=%d, want 1", ex.count())
		}
	})

	t.Run("deadline", func(t *testing.T) {
		ex := &fakeExec{handler: func(args []string) (string, error) { return "activating", errors.New("inactive") }}
		m := newTestManager(ex)
		err := m.WaitActive(context.Background(), "germany-splitter.service", 50*time.Millisecond)
		if !errors.Is(err, ErrWaitNotActive) {
			t.Fatalf("error=%v, want ErrWaitNotActive", err)
		}
		if ex.count() < 2 || ex.count() >= 200 {
			t.Fatalf("polls=%d, want 2..199", ex.count())
		}
	})

	t.Run("pre-cancelled", func(t *testing.T) {
		ex := &fakeExec{}
		m := newTestManager(ex)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.WaitActive(ctx, "germany-splitter.service", time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
		if ex.count() != 0 {
			t.Fatalf("calls=%d, want 0", ex.count())
		}
	})
}

func TestStateFirstWord(t *testing.T) {
	cases := []struct {
		name, out, want string
		execErr         bool
	}{
		{"active", "active", "active", false},
		{"activating", "activating (auto-restart)", "activating", true},
		{"failed", "failed", "failed", true},
		{"inactive", "inactive", "inactive", true},
		{"unknown", "weird state", "unknown", true},
		{"empty", "", "unknown", true},
		{"nonzero active", "active", "active", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := &fakeExec{handler: func([]string) (string, error) {
				if tc.execErr {
					return tc.out, errors.New("systemctl status")
				}
				return tc.out, nil
			}}
			m := newTestManager(ex)
			got, err := m.State(context.Background(), "germany-splitter.service")
			if err != nil {
				t.Fatalf("State error=%v", err)
			}
			if got != tc.want {
				t.Fatalf("state=%q, want %q", got, tc.want)
			}
			if ex.count() != 1 {
				t.Fatalf("calls=%d, want 1", ex.count())
			}
		})
	}
}

func TestHealthCheck(t *testing.T) {
	t.Run("metrics 200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/metrics" {
				t.Errorf("path=%q", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		port := srv.Listener.Addr().(*net.TCPAddr).Port
		m := newTestManager(&fakeExec{handler: func([]string) (string, error) { return "active", nil }})
		h, err := HealthCheck(context.Background(), m, "germany-splitter.service", port)
		if err != nil {
			t.Fatal(err)
		}
		if !h.Active || !h.Probed || !h.MetricsOK || h.State != "active" {
			t.Fatalf("health=%+v", h)
		}
	})

	t.Run("connection refused is finding", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		m := newTestManager(&fakeExec{handler: func([]string) (string, error) { return "active", nil }})
		h, err := HealthCheck(context.Background(), m, "germany-splitter.service", port)
		if err != nil {
			t.Fatal(err)
		}
		if !h.Probed || h.MetricsOK || h.Error == "" {
			t.Fatalf("health=%+v", h)
		}
	})

	t.Run("port zero skips", func(t *testing.T) {
		m := newTestManager(&fakeExec{handler: func([]string) (string, error) { return "inactive", errors.New("inactive") }})
		h, err := HealthCheck(context.Background(), m, "germany-splitter.service", 0)
		if err != nil {
			t.Fatal(err)
		}
		if h.Probed || h.MetricsOK || h.State != "inactive" {
			t.Fatalf("health=%+v", h)
		}
	})
}

func TestJournalTailBoundsAndNoSecret(t *testing.T) {
	ex := &fakeExec{handler: func(args []string) (string, error) { return "journal marker", nil }}
	m := newTestManager(ex)
	out, err := m.JournalTail(context.Background(), "germany-splitter.service", 500)
	if err != nil || out != "journal marker" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if !ex.has("journalctl -u germany-splitter.service -n 200 --no-pager -q -o short-iso") {
		t.Fatalf("calls=%v", ex.calls)
	}
	_, err = m.JournalTail(context.Background(), "germany-splitter.service", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ex.has("journalctl -u germany-splitter.service -n 20 --no-pager -q -o short-iso") {
		t.Fatalf("calls=%v", ex.calls)
	}
	for _, call := range ex.calls {
		if strings.Contains(call, ".env") || strings.Contains(call, secretMarker) {
			t.Fatalf("secret/path leaked in call %q", call)
		}
	}
}

func TestEnsureUserArgv(t *testing.T) {
	ctx := context.Background()
	t.Run("exists", func(t *testing.T) {
		redirectPaths(t)
		ex := &fakeExec{handler: func([]string) (string, error) { return "1001", nil }}
		if err := EnsureUser(ctx, ex); err != nil {
			t.Fatal(err)
		}
		if len(ex.calls) != 1 || ex.calls[0] != "id -u split-tunnel" {
			t.Fatalf("calls=%v", ex.calls)
		}
	})
	t.Run("absent creates exact user", func(t *testing.T) {
		redirectPaths(t)
		ex := &fakeExec{handler: func(args []string) (string, error) {
			if args[0] == "id" {
				return "", errors.New("not found")
			}
			return "", nil
		}}
		if err := EnsureUser(ctx, ex); err != nil {
			t.Fatal(err)
		}
		want := "id -u split-tunnel|useradd --system --group --shell /usr/sbin/nologin --home-dir /nonexistent --comment split-tunnel service user split-tunnel"
		if len(ex.calls) != 2 || ex.calls[0] != "id -u split-tunnel" {
			t.Fatalf("calls=%v", ex.calls)
		}
		if !strings.HasPrefix(ex.calls[1], "useradd --system --group --shell /usr/sbin/nologin --home-dir /nonexistent --comment") {
			t.Fatalf("calls=%v want prefix=%q", ex.calls, want)
		}
	})
	t.Run("useradd failure", func(t *testing.T) {
		redirectPaths(t)
		ex := &fakeExec{handler: func(args []string) (string, error) {
			if args[0] == "id" {
				return "", errors.New("missing")
			}
			return "", errors.New("denied")
		}}
		if err := EnsureUser(ctx, ex); !errors.Is(err, ErrPreflight) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestServiceUnitNameGuard(t *testing.T) {
	ex := &fakeExec{}
	m := newTestManager(ex)
	if err := m.Start(context.Background(), "../x.service"); !errors.Is(err, ErrSpec) {
		t.Fatalf("error=%v", err)
	}
	if ex.count() != 0 {
		t.Fatalf("calls=%d", ex.count())
	}
}
