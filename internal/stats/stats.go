// Package stats is the SchedD's single source of runtime statistics, shared by
// the Prometheus /metrics endpoint and the Scheduler ClassAd so both report the
// same numbers. It holds two kinds of value:
//
//   - Cumulative lifetime counters (JobsStarted, JobsCompleted, JobsExited,
//     ShadowExceptions, MatchesReceived, NegotiationCycles, JobsMaterialized),
//     incremented at the real scheduler events. Increments are lock-free atomics
//     so a hot event path (a match arriving, a job starting) never contends.
//
//   - Live gauges (running shadows, per-status queue tallies, active factories,
//     user-log backlog), read on demand from concurrency-safe sources supplied by
//     the wiring in cmd/schedd. Reading them on Snapshot (rather than mirroring
//     into atomics) keeps them exact and avoids double-bookkeeping.
//
// All the Inc*/Add* methods are nil-receiver safe, so a component can be handed a
// nil *Collector (e.g. in a unit test that does not care about stats) and simply
// no-op its increments.
package stats

import (
	"sync/atomic"
	"time"
)

// Counts mirrors the queue's live job-status tallies (queue.Counts) so this
// package carries no dependency on internal/queue. The wiring adapts one to the
// other.
type Counts struct {
	Total, Idle, Running, Held, Removed, Completed, Users int
}

// GaugeSources supplies the point-in-time values Snapshot reads. Each function is
// invoked from the scrape / advertise goroutine, so it must be safe for
// concurrent use; every source wired in cmd/schedd already is. A nil function is
// treated as "0".
type GaugeSources struct {
	// Counts returns the live per-status job tallies (queue.Counts adapted).
	Counts func() Counts
	// ShadowsRunning returns the number of jobs the core is currently running.
	ShadowsRunning func() int
	// FactoriesActive returns the number of live job-factory clusters.
	FactoriesActive func() int
	// UserlogFilesOpen returns how many user-log files the writer pool holds open.
	UserlogFilesOpen func() int
	// UserlogDropped returns the cumulative count of user-log events dropped
	// (backpressure / hung log filesystem).
	UserlogDropped func() int64
}

// Collector holds the schedd's cumulative counters and references to the live
// gauge sources. Construct once with New, share the pointer with every component
// that reports an event, the /metrics handler, and the advertiser.
type Collector struct {
	start time.Time

	jobsStarted       atomic.Int64
	jobsCompleted     atomic.Int64
	jobsExited        atomic.Int64
	shadowExceptions  atomic.Int64
	matchesReceived   atomic.Int64
	negotiationCycles atomic.Int64
	jobsMaterialized  atomic.Int64

	gauges GaugeSources
}

// New builds a Collector, stamping the start time used for the uptime gauge.
func New() *Collector { return &Collector{start: time.Now()} }

// SetGauges wires the live gauge sources. Call once at startup, before the
// /metrics endpoint or the advertiser reads a Snapshot.
func (c *Collector) SetGauges(g GaugeSources) {
	if c != nil {
		c.gauges = g
	}
}

// IncMatchesReceived counts one match delivered by the negotiator (PERMISSION_AND_AD).
func (c *Collector) IncMatchesReceived() {
	if c != nil {
		c.matchesReceived.Add(1)
	}
}

// IncNegotiationCycles counts one NEGOTIATE round the schedd handled.
func (c *Collector) IncNegotiationCycles() {
	if c != nil {
		c.negotiationCycles.Add(1)
	}
}

// IncJobsStarted counts one job transitioning into Running (shadow started).
func (c *Collector) IncJobsStarted() {
	if c != nil {
		c.jobsStarted.Add(1)
	}
}

// IncJobsExited counts one job whose shadow reported an exit (ran to completion),
// regardless of the terminal action (complete / requeue / hold-on-exit).
func (c *Collector) IncJobsExited() {
	if c != nil {
		c.jobsExited.Add(1)
	}
}

// IncJobsCompleted counts one job that terminated normally and left the queue.
func (c *Collector) IncJobsCompleted() {
	if c != nil {
		c.jobsCompleted.Add(1)
	}
}

// IncShadowExceptions counts one shadow exception (an abnormal run failure charged
// against the job's failure budget).
func (c *Collector) IncShadowExceptions() {
	if c != nil {
		c.shadowExceptions.Add(1)
	}
}

// AddJobsMaterialized counts n procs materialized by a job factory.
func (c *Collector) AddJobsMaterialized(n int) {
	if c != nil && n > 0 {
		c.jobsMaterialized.Add(int64(n))
	}
}

// Snapshot is a consistent read of every statistic: the cumulative counters plus
// the live gauges (sampled from their sources at call time).
type Snapshot struct {
	UptimeSeconds int64

	JobsStarted       int64
	JobsCompleted     int64
	JobsExited        int64
	ShadowExceptions  int64
	MatchesReceived   int64
	NegotiationCycles int64
	JobsMaterialized  int64

	ShadowsRunning   int
	FactoriesActive  int
	UserlogFilesOpen int
	UserlogDropped   int64

	Counts Counts
}

// Snapshot reads all counters and samples the live gauges. Safe to call from any
// goroutine. On a nil Collector it returns the zero value.
func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	s := Snapshot{
		UptimeSeconds:     int64(time.Since(c.start).Seconds()),
		JobsStarted:       c.jobsStarted.Load(),
		JobsCompleted:     c.jobsCompleted.Load(),
		JobsExited:        c.jobsExited.Load(),
		ShadowExceptions:  c.shadowExceptions.Load(),
		MatchesReceived:   c.matchesReceived.Load(),
		NegotiationCycles: c.negotiationCycles.Load(),
		JobsMaterialized:  c.jobsMaterialized.Load(),
	}
	if c.gauges.Counts != nil {
		s.Counts = c.gauges.Counts()
	}
	if c.gauges.ShadowsRunning != nil {
		s.ShadowsRunning = c.gauges.ShadowsRunning()
	}
	if c.gauges.FactoriesActive != nil {
		s.FactoriesActive = c.gauges.FactoriesActive()
	}
	if c.gauges.UserlogFilesOpen != nil {
		s.UserlogFilesOpen = c.gauges.UserlogFilesOpen()
	}
	if c.gauges.UserlogDropped != nil {
		s.UserlogDropped = c.gauges.UserlogDropped()
	}
	return s
}
