package stats

import (
	"sync"
	"testing"
)

func TestCollectorNilSafe(t *testing.T) {
	var c *Collector // nil
	// None of these must panic on a nil receiver.
	c.IncMatchesReceived()
	c.IncNegotiationCycles()
	c.IncJobsStarted()
	c.IncJobsExited()
	c.IncJobsCompleted()
	c.IncShadowExceptions()
	c.AddJobsMaterialized(5)
	c.SetGauges(GaugeSources{})
	if got := c.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("nil Snapshot = %+v, want zero value", got)
	}
}

func TestCollectorCounters(t *testing.T) {
	c := New()
	c.IncJobsStarted()
	c.IncJobsStarted()
	c.IncJobsExited()
	c.IncJobsCompleted()
	c.IncShadowExceptions()
	c.IncMatchesReceived()
	c.IncMatchesReceived()
	c.IncMatchesReceived()
	c.IncNegotiationCycles()
	c.AddJobsMaterialized(4)
	c.AddJobsMaterialized(0) // ignored
	c.AddJobsMaterialized(-3) // ignored

	s := c.Snapshot()
	if s.JobsStarted != 2 {
		t.Errorf("JobsStarted = %d, want 2", s.JobsStarted)
	}
	if s.JobsExited != 1 {
		t.Errorf("JobsExited = %d, want 1", s.JobsExited)
	}
	if s.JobsCompleted != 1 {
		t.Errorf("JobsCompleted = %d, want 1", s.JobsCompleted)
	}
	if s.ShadowExceptions != 1 {
		t.Errorf("ShadowExceptions = %d, want 1", s.ShadowExceptions)
	}
	if s.MatchesReceived != 3 {
		t.Errorf("MatchesReceived = %d, want 3", s.MatchesReceived)
	}
	if s.NegotiationCycles != 1 {
		t.Errorf("NegotiationCycles = %d, want 1", s.NegotiationCycles)
	}
	if s.JobsMaterialized != 4 {
		t.Errorf("JobsMaterialized = %d, want 4", s.JobsMaterialized)
	}
	if s.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds = %d, want >= 0", s.UptimeSeconds)
	}
}

func TestCollectorGauges(t *testing.T) {
	c := New()
	c.SetGauges(GaugeSources{
		Counts: func() Counts {
			return Counts{Total: 10, Idle: 4, Running: 3, Held: 2, Removed: 1, Users: 2}
		},
		ShadowsRunning:   func() int { return 3 },
		FactoriesActive:  func() int { return 1 },
		UserlogFilesOpen: func() int { return 7 },
		UserlogDropped:   func() int64 { return 9 },
	})
	s := c.Snapshot()
	if s.Counts.Total != 10 || s.Counts.Idle != 4 || s.Counts.Running != 3 ||
		s.Counts.Held != 2 || s.Counts.Removed != 1 || s.Counts.Users != 2 {
		t.Errorf("Counts = %+v, unexpected", s.Counts)
	}
	if s.ShadowsRunning != 3 {
		t.Errorf("ShadowsRunning = %d, want 3", s.ShadowsRunning)
	}
	if s.FactoriesActive != 1 {
		t.Errorf("FactoriesActive = %d, want 1", s.FactoriesActive)
	}
	if s.UserlogFilesOpen != 7 {
		t.Errorf("UserlogFilesOpen = %d, want 7", s.UserlogFilesOpen)
	}
	if s.UserlogDropped != 9 {
		t.Errorf("UserlogDropped = %d, want 9", s.UserlogDropped)
	}
}

// TestCollectorConcurrentIncrements exercises the lock-free increment path under
// the race detector.
func TestCollectorConcurrentIncrements(t *testing.T) {
	c := New()
	const goroutines, each = 8, 1000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				c.IncJobsStarted()
				c.AddJobsMaterialized(1)
			}
		}()
	}
	wg.Wait()
	s := c.Snapshot()
	if want := int64(goroutines * each); s.JobsStarted != want {
		t.Errorf("JobsStarted = %d, want %d", s.JobsStarted, want)
	}
	if want := int64(goroutines * each); s.JobsMaterialized != want {
		t.Errorf("JobsMaterialized = %d, want %d", s.JobsMaterialized, want)
	}
}
