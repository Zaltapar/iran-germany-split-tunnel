package main

import (
	"io"
	"log"
	"strings"
	"testing"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/node"
)

func TestMetricsListenAddrLoopbackOnly(t *testing.T) {
	if got := metricsListenAddr(1); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("metricsListenAddr(1) = %q, want loopback prefix", got)
	}
}

func TestRunMetricsRefusesNonLoopback(t *testing.T) {
	n := node.NewNode(node.Config{Role: node.RoleGermany}, log.New(io.Discard, "", 0), nil)
	defer n.Close()
	s := &Splitter{node: n}
	if err := s.runMetrics("0.0.0.0:0"); err == nil {
		t.Fatal("runMetrics accepted a non-loopback listener")
	}
}
