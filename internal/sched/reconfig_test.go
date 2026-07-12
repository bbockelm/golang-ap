package sched

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-ap/internal/policy"
)

// TestSchedulerReconfigSetters exercises the live-reconfig setters and the
// ShadowsRunning gauge without starting the core (the setters only touch atomics
// and the coalescing reset channels).
func TestSchedulerReconfigSetters(t *testing.T) {
	s := New(Options{}) // defaults: advertise 300s, periodic 60s

	if got := s.advInterval(); got != 300*time.Second {
		t.Fatalf("default advertise interval = %v, want 300s", got)
	}
	if got := s.periodicInterval(); got != 60*time.Second {
		t.Fatalf("default periodic interval = %v, want 60s", got)
	}

	s.SetAdvertiseInterval(11 * time.Second)
	if got := s.advInterval(); got != 11*time.Second {
		t.Fatalf("advertise interval after set = %v, want 11s", got)
	}
	// A second set with a pending (unconsumed) reset must still update the value
	// and must not block on the depth-1 channel.
	s.SetAdvertiseInterval(12 * time.Second)
	if got := s.advInterval(); got != 12*time.Second {
		t.Fatalf("advertise interval after second set = %v, want 12s", got)
	}
	// Non-positive is ignored.
	s.SetAdvertiseInterval(0)
	if got := s.advInterval(); got != 12*time.Second {
		t.Fatalf("advertise interval after set(0) = %v, want 12s unchanged", got)
	}

	s.SetPeriodicInterval(7 * time.Second)
	if got := s.periodicInterval(); got != 7*time.Second {
		t.Fatalf("periodic interval after set = %v, want 7s", got)
	}
	s.SetPeriodicInterval(-1)
	if got := s.periodicInterval(); got != 7*time.Second {
		t.Fatalf("periodic interval after set(-1) = %v, want 7s unchanged", got)
	}

	// SysPolicy swap: nil-safe both ways.
	if p := s.sysPolicy.Load(); !p.Empty() {
		t.Fatalf("initial sys policy should be empty")
	}
	sys := policy.NewSystem(policy.SystemConfig{RemoveExpr: "true"})
	s.SetSysPolicy(sys)
	if p := s.sysPolicy.Load(); p.Empty() {
		t.Fatalf("sys policy should be non-empty after SetSysPolicy")
	}
	s.SetSysPolicy(nil)
	if p := s.sysPolicy.Load(); !p.Empty() {
		t.Fatalf("sys policy should be empty after SetSysPolicy(nil)")
	}

	// ShadowsRunning gauge tracks the atomic.
	if got := s.ShadowsRunning(); got != 0 {
		t.Fatalf("ShadowsRunning = %d, want 0", got)
	}
	s.runningGauge.Add(3)
	if got := s.ShadowsRunning(); got != 3 {
		t.Fatalf("ShadowsRunning = %d, want 3", got)
	}
}
