package config

import (
	"strings"
	"testing"
)

func TestMetricsPortNeverPublic(t *testing.T) {
	isolatedEnv(t)
	if Defaults().MetricsPort != 0 {
		t.Fatalf("MetricsPort default = %d, want disabled (0)", Defaults().MetricsPort)
	}

	c := validIran()
	c.MetricsPort = 1
	if err := c.Validate(RoleIran); err != nil {
		t.Fatalf("non-colliding metrics port rejected: %v", err)
	}

	t.Setenv(EnvMetricsPort, "0.0.0.0")
	var problems []string
	if got := envInt(&problems, EnvMetricsPort, 0, 0, MaxPort); got != 0 {
		t.Fatalf("public-address metrics value parsed as %d, want default 0", got)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], EnvMetricsPort) {
		t.Fatalf("public-address metrics value problems = %v, want one named parse problem", problems)
	}
}
