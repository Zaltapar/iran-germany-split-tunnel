package testutil

import (
	"testing"
	"time"
)

// TestMemConnDeadlineMinimal verifies the queue deadline fires while blocked
// in a read (minimal repro for auth-timeout behavior).
func TestMemConnDeadlineMinimal(t *testing.T) {
	a, b := NewMemPipe()
	defer a.Close()
	defer b.Close()
	_ = b
	a.SetDeadline(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	_, err := a.Read(make([]byte, 4096))
	el := time.Since(start)
	if err == nil {
		t.Fatal("read on a silent peer with deadline returned nil error")
	}
	if el > time.Second {
		t.Fatalf("deadline took %v to fire", el)
	}
	t.Logf("deadline fired after %v with %v", el, err)
}
