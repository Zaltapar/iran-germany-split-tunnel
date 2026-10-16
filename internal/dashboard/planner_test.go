package dashboard

import (
	"testing"
)

func TestPlanChangesValidEnum(t *testing.T) {
	plan, err := PlanChanges("iran", "iran", "p1", []ChangeRequest{
		{Key: "SPLIT_TARGET_ADDR_POLICY", Value: "prefer-ipv4"},
	})
	if err != nil {
		t.Fatalf("PlanChanges: %v", err)
	}
	if plan.PlanID != "p1" {
		t.Errorf("planID = %q, want p1", plan.PlanID)
	}
	if plan.ServerID != "iran" {
		t.Errorf("serverID = %q, want iran", plan.ServerID)
	}
	if len(plan.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(plan.Changes))
	}
	if plan.Changes[0].After != "prefer-ipv4" {
		t.Errorf("after = %q, want prefer-ipv4", plan.Changes[0].After)
	}
	if plan.RestartRequired {
		t.Error("prefer-ipv4 should not require restart")
	}
	if len(plan.AffectedUnits) == 0 {
		t.Error("no affected units reported")
	}
}

func TestPlanChangesIPv4OnlyWarning(t *testing.T) {
	plan, err := PlanChanges("germany", "germany", "p2", []ChangeRequest{
		{Key: "SPLIT_TARGET_ADDR_POLICY", Value: "ipv4-only"},
	})
	if err != nil {
		t.Fatalf("PlanChanges: %v", err)
	}
	if len(plan.Warnings) == 0 {
		t.Error("ipv4-only change should produce a warning")
	}
	found := false
	for _, w := range plan.Warnings {
		if len(w) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("no warning text present")
	}
}

func TestPlanChangesInvalidEnum(t *testing.T) {
	_, err := PlanChanges("iran", "iran", "p3", []ChangeRequest{
		{Key: "SPLIT_TARGET_ADDR_POLICY", Value: "prefer-ipv6"},
	})
	if err == nil {
		t.Fatal("expected error for invalid enum value")
	}
}

func TestPlanChangesOutOfRangeInt(t *testing.T) {
	_, err := PlanChanges("iran", "iran", "p4", []ChangeRequest{
		{Key: "SPLIT_METRICS_PORT", Value: "99999"},
	})
	if err == nil {
		t.Fatal("expected range error for port 99999")
	}
}

func TestPlanChangesValidInt(t *testing.T) {
	plan, err := PlanChanges("iran", "iran", "p5", []ChangeRequest{
		{Key: "SPLIT_METRICS_PORT", Value: "9101"},
	})
	if err != nil {
		t.Fatalf("PlanChanges: %v", err)
	}
	if !plan.RestartRequired {
		t.Error("SPLIT_METRICS_PORT change should require restart")
	}
}

func TestPlanChangesNonInteger(t *testing.T) {
	_, err := PlanChanges("iran", "iran", "p6", []ChangeRequest{
		{Key: "SPLIT_METRICS_PORT", Value: "abc"},
	})
	if err == nil {
		t.Fatal("expected error for non-integer value")
	}
}

func TestPlanChangesNotInAllowlist(t *testing.T) {
	// SPLIT_SECRET must NEVER be accepted through the dashboard planner.
	_, err := PlanChanges("iran", "iran", "p7", []ChangeRequest{
		{Key: "SPLIT_SECRET", Value: "new-secret"},
	})
	if err == nil {
		t.Fatal("SPLIT_SECRET must be rejected by the safe allowlist")
	}
}

func TestPlanChangesUnknownKey(t *testing.T) {
	_, err := PlanChanges("iran", "iran", "p8", []ChangeRequest{
		{Key: "SPLIT_ARBITRARY_KEY", Value: "1"},
	})
	if err == nil {
		t.Fatal("unknown key must be rejected")
	}
}

func TestPlanChangesNoChanges(t *testing.T) {
	_, err := PlanChanges("iran", "iran", "p9", nil)
	if err == nil {
		t.Fatal("empty change list must be rejected")
	}
}

func TestPlanChangesInvalidRole(t *testing.T) {
	_, err := PlanChanges("x", "france", "p10", []ChangeRequest{
		{Key: "SPLIT_METRICS_PORT", Value: "9101"},
	})
	if err == nil {
		t.Fatal("invalid role must be rejected")
	}
}

func TestPlanChangesContradictoryPair(t *testing.T) {
	// SPLIT_TARGET_ONLY_IPV4=true with SPLIT_TARGET_ADDR_POLICY=prefer-ipv4
	// is a documented conflict.
	_, err := PlanChanges("germany", "germany", "p11", []ChangeRequest{
		{Key: "SPLIT_TARGET_ONLY_IPV4", Value: "true"},
		{Key: "SPLIT_TARGET_ADDR_POLICY", Value: "prefer-ipv4"},
	})
	if err == nil {
		t.Fatal("contradictory policy pair must be rejected")
	}
}

func TestPlanChangesComprehensive(t *testing.T) {
	// Multiple valid changes in one plan, including a restart-required key
	// and a non-restart key.
	plan, err := PlanChanges("iran", "iran", "p12", []ChangeRequest{
		{Key: "SPLIT_RELAY_BUF", Value: "65536"},
		{Key: "SPLIT_TARGET_ADDR_POLICY", Value: "default"},
		{Key: "SPLIT_TARGET_ONLY_IPV4", Value: "false"},
	})
	if err != nil {
		t.Fatalf("PlanChanges: %v", err)
	}
	if !plan.RestartRequired {
		t.Error("plan with SPLIT_RELAY_BUF must require restart")
	}
	// Verify all three changes are in the plan.
	if len(plan.Changes) != 3 {
		t.Errorf("expected 3 changes, got %d", len(plan.Changes))
	}
}

func TestPlanChangesRedactedOutput(t *testing.T) {
	// Even for safe keys, if the value would look secret-ish, it gets
	// redacted in the plan output. This is a belt-and-suspenders check.
	plan, err := PlanChanges("iran", "iran", "p13", []ChangeRequest{
		{Key: "SPLIT_METRICS_PORT", Value: "9101"},
	})
	if err != nil {
		t.Fatalf("PlanChanges: %v", err)
	}
	for _, c := range plan.Changes {
		if c.Redacted {
			t.Errorf("safe key %q was incorrectly flagged as redacted", c.Key)
		}
	}
}

func TestSafeConfigKeysNoSecrets(t *testing.T) {
	// Every key in the allowlist must NOT be a secret key.
	for _, spec := range SafeConfigKeys {
		if IsSensitiveKey(spec.EnvVar) {
			t.Errorf("SafeConfigKeys contains sensitive key %q — this must never happen", spec.EnvVar)
		}
	}
}

func TestAffectedUnitsForRole(t *testing.T) {
	iran := affectedUnitsForRole("iran")
	if len(iran) == 0 {
		t.Error("no affected units for iran role")
	}
	germany := affectedUnitsForRole("germany")
	if len(germany) == 0 {
		t.Error("no affected units for germany role")
	}
}

// --- Audit log tests ---

func TestAuditLogBounded(t *testing.T) {
	log := NewAuditLog(5)
	for i := 0; i < 10; i++ {
		log.Add(AuditEvent{Detail: "event"})
	}
	events := log.Events()
	if len(events) != 5 {
		t.Errorf("expected at most 5 events, got %d", len(events))
	}
}

func TestAuditLogLastN(t *testing.T) {
	log := NewAuditLog(100)
	for i := 0; i < 10; i++ {
		log.Add(AuditEvent{Detail: "event"})
	}
	last3 := log.LastN(3)
	if len(last3) != 3 {
		t.Errorf("LastN(3) returned %d events", len(last3))
	}
}
