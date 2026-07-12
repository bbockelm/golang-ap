// Package sched implements the SchedD's single-writer scheduler core: one
// goroutine owns all mutable scheduler state (the running-job registry and every
// job-queue transition) and processes work serially from a fan-in event channel
// plus periodic timers. External producers -- the NEGOTIATE handler, the
// condor_rm/condor_hold teardown hook, the RESCHEDULE command, and the async
// claim/shadow goroutines -- only ever Submit() events; they never touch queue
// or registry state directly. That keeps all job-attribute writes lock-free on
// one goroutine.
//
// Flow for one job:
//
//	negotiator PERMISSION_AND_AD -> evMatch -> spawn runJob goroutine
//	  runJob: CreateFromClaim, REQUEST_CLAIM, ACTIVATE_CLAIM
//	  -> evStarted (core writes JobStatus=2, RemoteHost, JobStartDate, ...)
//	  runJob: shadow.Run (serves the starter incl. file transfer, then releases)
//	  -> evExited (core writes ExitCode/CompletionDate, JobStatus=4, archives)
//
// Stage 7 hardening:
//
//   - A panic anywhere in the per-job goroutine (including the shadow serve
//     loop) is recovered, logged with its stack, and turned into evFailed: the
//     core releases the claim best-effort, drops the match record, and requeues
//     the job -- unless it has accumulated MaxShadowExceptions failures, in
//     which case it is held with HoldReasonCode 1002 (ShadowException).
//   - A run that dies mid-flight (starter killed, syscall socket EOF) requeues
//     the same way, with the same exception accounting.
//   - An expired claim lease (startd keepalives stopped) cancels the shadow and
//     requeues the running job.
//   - condor_rm/condor_hold of a running job vacates it synchronously: the
//     shadow's context is canceled, its vacate path sends
//     DEACTIVATE_CLAIM_FORCIBLY + RELEASE_CLAIM, and the queue's status write
//     waits (bounded) for the teardown to finish.
//   - Drain() implements graceful shutdown: stop accepting matches, vacate all
//     shadows, requeue their jobs, and wait (bounded) for every claim release.
package sched

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/internal/match"
	"github.com/bbockelm/golang-ap/internal/negotiate"
	"github.com/bbockelm/golang-ap/internal/policy"
	"github.com/bbockelm/golang-ap/internal/queue"
	"github.com/bbockelm/golang-ap/internal/stats"
	"github.com/bbockelm/golang-ap/internal/userlog"
	"github.com/bbockelm/golang-ap/shadow"
)

// holdCodeShadowException is CONDOR_HOLD_CODE::ShadowException
// (src/condor_utils/condor_holdcodes.h), the code the C++ schedd records when a
// shadow dies abnormally. We use it both as the VacateReasonCode on each
// counted failure (mirroring Scheduler::child_exit) and as the HoldReasonCode
// when a job exhausts its failure budget.
const holdCodeShadowException = 1002

// DefaultMaxShadowExceptions is how many shadow failures a job may accumulate
// before it is held instead of requeued (config knob MAX_SHADOW_EXCEPTIONS).
const DefaultMaxShadowExceptions = 3

// DefaultDrainGrace bounds how long Stop waits for the vacate/release of every
// running shadow during a graceful shutdown.
const DefaultDrainGrace = 10 * time.Second

// advertiseTimeout bounds a single collector-advertise pass. Advertising is
// blocking network I/O (dial + authenticate + send); this cap ensures a slow or
// wedged collector can never wedge the advertiser goroutine indefinitely. It is
// deliberately generous -- a healthy collector answers in well under a second.
const advertiseTimeout = 30 * time.Second

// DefaultJobLeaseDuration is the JobLeaseDuration (seconds) stamped onto a
// running job that carries none, matching HTCondor's JOB_DEFAULT_LEASE_DURATION
// (submit_utils.cpp / param_info.in). A restarted schedd reconnects to a job
// only while (now - LastJobLeaseRenewal) < JobLeaseDuration.
const DefaultJobLeaseDuration = 2400

// DefaultPeriodicInterval is how often the periodic-policy evaluator scans the
// queue (config knob PERIODIC_EXPR_INTERVAL), matching the C++ schedd's
// param_integer("PERIODIC_EXPR_INTERVAL", 60).
const DefaultPeriodicInterval = 60 * time.Second

// Event is a unit of work delivered to the scheduler's event loop.
type Event interface{ isEvent() }

// Options configures a Scheduler.
type Options struct {
	Logger *logging.Logger
	// AdvertiseInterval is how often the SchedD/Submitter ads are refreshed.
	AdvertiseInterval time.Duration
	// Advertise pushes the SchedD + Submitter ads. Called at startup, on each
	// advertise tick, and on a RESCHEDULE nudge, from the event-loop goroutine.
	Advertise func(context.Context)

	// Queue is the job-queue authority (the single source of job state).
	Queue *queue.Queue
	// Matches is the claimed-slot table shared with the ALIVE handler.
	Matches *match.Table
	// Endpoint is the shared file-transfer router (hosted on the schedd's
	// command server); each shadow registers its TransferKey with it.
	Endpoint *shadow.Endpoint

	// ScheddName / ScheddAddr identify this schedd to the startd (claim scheduler
	// address for ALIVE, ATTR_SCHEDD_NAME) and starter (ShadowIpAddr). ScheddAddr
	// is a sinful string ("<host:port?sock=...>").
	ScheddName    string
	ScheddAddr    string
	UIDDomain     string
	ShadowVersion string
	// AliveInterval is the keepalive interval (seconds) proposed to the startd.
	AliveInterval int
	// SweepInterval is how often expired-lease matches are swept (0 disables).
	SweepInterval time.Duration

	// MaxShadowExceptions is how many shadow failures a job may accumulate
	// before being held (<=0 means DefaultMaxShadowExceptions).
	MaxShadowExceptions int
	// DrainGrace bounds the graceful-shutdown drain (<=0 means
	// DefaultDrainGrace).
	DrainGrace time.Duration
	// PanicJob is a test hook ("cluster.proc"): the first shadow run for that
	// job panics when the starter reports begin_execution, exercising the
	// panic/requeue policy end-to-end. Empty disables the hook.
	PanicJob string

	// WinddownFailJob is a test hook ("cluster.proc"): every shadow run for that
	// job reports a claim wind-down failure after the job exits cleanly, so the
	// core sees a completed job whose best-effort claim release failed. Proves
	// (HTCONDOR-3828) such a job is still completed, not requeued/held. Empty
	// disables the hook.
	WinddownFailJob string

	// ReconnectDisabled turns off shadow/claim reconnect (SCHEDD_RECONNECT=false):
	// running jobs are requeued to Idle on shutdown (the old drain behavior) and
	// no startup recovery is attempted. Default (false) keeps the C++-faithful
	// reconnect semantics: leave running jobs Running across a restart and
	// re-attach to their starters.
	ReconnectDisabled bool
	// DefaultJobLease is the JobLeaseDuration (seconds) stamped onto a running
	// job that has none, so a restarted schedd can judge whether the lease is
	// still alive. <=0 means DefaultJobLeaseDuration.
	DefaultJobLease int

	// UserLog, if set, writes the run-side user-job-log events (EXECUTE,
	// JOB_TERMINATED, JOB_EVICTED, and the reconnect events) at the matching
	// transitions so condor_wait / DAGMan can follow the job. nil disables them.
	UserLog *userlog.Manager

	// Privsep, if set, is threaded into every shadow so the job's input/output
	// sandbox file ops run as the job Owner. nil lets the shadow default to the
	// process-wide native Privsep (run as the current user).
	Privsep droppriv.Privsep

	// PeriodicInterval is how often the periodic-policy evaluator scans the queue
	// (PERIODIC_EXPR_INTERVAL). <=0 means DefaultPeriodicInterval.
	PeriodicInterval time.Duration
	// SysPolicy carries the SYSTEM_PERIODIC_HOLD/RELEASE/REMOVE (+ _REASON /
	// _SUBCODE) expressions applied to every job in addition to its own
	// Periodic* expressions. nil (the default) means no system policy.
	SysPolicy *policy.System

	// OnJobLeftIdle, if set, is invoked (non-blocking) whenever a job leaves the
	// Idle state -- it starts running or terminates -- so the late-materialization
	// engine can promptly top up a factory back to max_idle. nil disables the
	// nudge (the engine still runs on its own timer).
	OnJobLeftIdle func()

	// Stats, if set, receives the core's cumulative event counts (JobsStarted,
	// JobsExited, JobsCompleted, ShadowExceptions, MatchesReceived) surfaced by
	// the /metrics endpoint and the Scheduler ad. nil disables stats (the Inc*
	// calls are nil-safe no-ops).
	Stats *stats.Collector
}

// jobKey identifies a job proc.
type jobKey struct{ c, p int }

func (k jobKey) String() string { return fmt.Sprintf("%d.%d", k.c, k.p) }

// runInfo tracks one claimed/running job the core is supervising.
type runInfo struct {
	claimID  string
	slotName string
	cancel   context.CancelFunc
	// vacated is set when the job is being torn down deliberately (condor_rm,
	// condor_hold, lease expiry, shutdown drain): the exit event must not write
	// job state, the teardown initiator already did (or will).
	vacated bool
	// detached is set when the job's shadow was told to step away for reconnect
	// (a reconnect-preserving schedd shutdown): the run's exit/failure event must
	// leave the job Running (JobStatus=2) so the next start re-attaches.
	detached bool
	// detach is the flag the shadow reads to skip its claim wind-down. It is the
	// same *atomic.Bool passed into the shadow's Config.Detach.
	detach *atomic.Bool
	// reconnect marks a run recovered at startup (RunReconnect) rather than a
	// fresh activation; its start attributes are already persisted, so a
	// successful reconnect must not re-stamp NumJobStarts/JobRunCount.
	reconnect bool
	// waiters are closed once the job's run is fully reaped (shadow finished,
	// match record dropped); TeardownJobAndWait blocks on one.
	waiters []chan struct{}
}

// Scheduler is the SchedD core. Construct with New, drive with Start/Stop.
type Scheduler struct {
	log       *logging.Logger
	advertise func(context.Context)

	// intervalNS / periodicNS hold the advertise and periodic-policy intervals as
	// nanosecond atomics so condor_reconfig can retune them live: SetAdvertiseInterval
	// / SetPeriodicInterval store the new value and signal the owning loop, which
	// resets its ticker (see advertiseLoop / periodicLoop).
	intervalNS atomic.Int64
	periodicNS atomic.Int64
	// advReset / periodicReset wake the advertise / periodic loops to re-read their
	// interval after a reconfig. Buffered depth 1: a pending reset coalesces.
	advReset      chan struct{}
	periodicReset chan struct{}

	q        *queue.Queue
	matches  *match.Table
	endpoint *shadow.Endpoint

	scheddName    string
	scheddAddr    string
	uidDomain     string
	shadowVersion string
	aliveInterval int
	sweepInterval time.Duration
	maxExceptions int
	drainGrace    time.Duration

	reconnectDisabled bool
	defaultJobLease   int
	userlog           *userlog.Manager
	privsep           droppriv.Privsep

	// sysPolicy is the pool-wide SYSTEM_PERIODIC_* policy, held behind an atomic
	// pointer so condor_reconfig can swap in a recompiled policy while the core and
	// periodic evaluator read it concurrently (both are nil-safe on *policy.System).
	sysPolicy     atomic.Pointer[policy.System]
	onJobLeftIdle func()

	// stats receives the core's cumulative event counts (nil-safe).
	stats *stats.Collector
	// runningGauge tracks len(running) as an atomic so ShadowsRunning() can be read
	// safely off the core goroutine (the map itself is core-goroutine-only). It is
	// mutated only on the core goroutine, alongside every running-map add/delete.
	runningGauge atomic.Int64

	events chan Event
	// advertiseNudge asks the (separate) advertiser goroutine to push ads now,
	// e.g. on RESCHEDULE. Buffered depth 1 so a pending nudge coalesces requests
	// and the core never blocks handing one off.
	advertiseNudge chan struct{}

	// Core-goroutine-only state.
	running   map[jobKey]*runInfo
	draining  bool
	drainDone chan struct{}
	// policyPending dedupes in-flight periodic-policy actions: a job is added
	// when the core dispatches its (off-core) hold/release/remove and removed on
	// the evPolicyDone that the apply goroutine posts back, so a job firing on
	// consecutive ticks before its action lands is not acted on twice.
	policyPending map[jobKey]bool

	// Panic test hook (accessed from shadow goroutines; mutex-guarded).
	panicMu    sync.Mutex
	panicJob   jobKey
	panicArmed bool

	// winddownFailJob/-Armed: test hook forcing a claim wind-down failure for a
	// finished job (HTCONDOR-3828 regression). See Options.WinddownFailJob.
	winddownFailJob   jobKey
	winddownFailArmed bool

	cancel   context.CancelFunc
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New builds a Scheduler.
func New(opts Options) *Scheduler {
	interval := opts.AdvertiseInterval
	if interval <= 0 {
		interval = 300 * time.Second
	}
	alive := opts.AliveInterval
	if alive <= 0 {
		alive = 300
	}
	maxExc := opts.MaxShadowExceptions
	if maxExc <= 0 {
		maxExc = DefaultMaxShadowExceptions
	}
	grace := opts.DrainGrace
	if grace <= 0 {
		grace = DefaultDrainGrace
	}
	jobLease := opts.DefaultJobLease
	if jobLease <= 0 {
		jobLease = DefaultJobLeaseDuration
	}
	periodic := opts.PeriodicInterval
	if periodic <= 0 {
		periodic = DefaultPeriodicInterval
	}
	s := &Scheduler{
		log:               opts.Logger,
		advertise:         opts.Advertise,
		q:                 opts.Queue,
		matches:           opts.Matches,
		endpoint:          opts.Endpoint,
		scheddName:        opts.ScheddName,
		scheddAddr:        opts.ScheddAddr,
		uidDomain:         opts.UIDDomain,
		shadowVersion:     opts.ShadowVersion,
		aliveInterval:     alive,
		sweepInterval:     opts.SweepInterval,
		maxExceptions:     maxExc,
		drainGrace:        grace,
		reconnectDisabled: opts.ReconnectDisabled,
		defaultJobLease:   jobLease,
		userlog:           opts.UserLog,
		privsep:           opts.Privsep,
		onJobLeftIdle:     opts.OnJobLeftIdle,
		stats:             opts.Stats,
		advReset:          make(chan struct{}, 1),
		periodicReset:     make(chan struct{}, 1),
		events:            make(chan Event, 256),
		advertiseNudge:    make(chan struct{}, 1),
		running:           map[jobKey]*runInfo{},
		policyPending:     map[jobKey]bool{},
	}
	s.intervalNS.Store(int64(interval))
	s.periodicNS.Store(int64(periodic))
	s.sysPolicy.Store(opts.SysPolicy)
	if opts.PanicJob != "" {
		var c, p int
		if n, err := fmt.Sscanf(opts.PanicJob, "%d.%d", &c, &p); n == 2 && err == nil {
			s.panicJob = jobKey{c, p}
			s.panicArmed = true
			s.log.Warn(logging.DestinationGeneral,
				"shadow panic test hook armed", "job", s.panicJob.String())
		}
	}
	if opts.WinddownFailJob != "" {
		var c, p int
		if n, err := fmt.Sscanf(opts.WinddownFailJob, "%d.%d", &c, &p); n == 2 && err == nil {
			s.winddownFailJob = jobKey{c, p}
			s.winddownFailArmed = true
			s.log.Warn(logging.DestinationGeneral,
				"shadow wind-down-failure test hook armed", "job", s.winddownFailJob.String())
		}
	}
	return s
}

// advInterval / periodicInterval read the currently configured intervals.
func (s *Scheduler) advInterval() time.Duration      { return time.Duration(s.intervalNS.Load()) }
func (s *Scheduler) periodicInterval() time.Duration { return time.Duration(s.periodicNS.Load()) }

// SetAdvertiseInterval retunes the SchedD/Submitter ad refresh interval live
// (condor_reconfig of SCHEDD_INTERVAL). Non-positive values are ignored. Safe to
// call from any goroutine; the advertise loop resets its ticker on the next tick.
func (s *Scheduler) SetAdvertiseInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	s.intervalNS.Store(int64(d))
	select {
	case s.advReset <- struct{}{}:
	default:
	}
}

// SetPeriodicInterval retunes the periodic-policy evaluator interval live
// (condor_reconfig of PERIODIC_EXPR_INTERVAL). Non-positive values are ignored.
func (s *Scheduler) SetPeriodicInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	s.periodicNS.Store(int64(d))
	select {
	case s.periodicReset <- struct{}{}:
	default:
	}
}

// SetSysPolicy swaps in a recompiled pool-wide SYSTEM_PERIODIC_* policy live
// (condor_reconfig). A nil policy clears it. The core and periodic evaluator read
// the pointer atomically.
func (s *Scheduler) SetSysPolicy(p *policy.System) { s.sysPolicy.Store(p) }

// ShadowsRunning reports how many jobs the core is currently running (one shadow
// each). Read from the atomic gauge so it is safe off the core goroutine.
func (s *Scheduler) ShadowsRunning() int { return int(s.runningGauge.Load()) }

// Submit enqueues an event for the loop. Safe to call from any goroutine.
func (s *Scheduler) Submit(ev Event) {
	select {
	case s.events <- ev:
	default:
		s.log.Warn(logging.DestinationGeneral, "scheduler event queue full; dropping event",
			"event", fmt.Sprintf("%T", ev))
	}
}

// Start launches the event-loop goroutine and the (separate) advertiser
// goroutine. Advertising is kept OFF the core so a slow collector can never
// stall job-state processing.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(3)
	go s.loop(ctx)
	go s.advertiseLoop(ctx)
	go s.periodicLoop(ctx)
}

// Stop gracefully shuts the core down: it drains (stops accepting matches,
// vacates every running shadow so its claim is released and the job requeued,
// waiting up to DrainGrace), then stops the event loop. Idempotent.
func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.Drain(s.drainGrace)
			s.cancel()
		}
	})
	s.wg.Wait()
}

// Drain asks the core to stop accepting matches and vacate every running
// shadow (requeueing the jobs to Idle so a restarted schedd re-runs them),
// then waits up to grace for all claims to be released.
func (s *Scheduler) Drain(grace time.Duration) {
	if grace <= 0 {
		grace = DefaultDrainGrace
	}
	done := make(chan struct{})
	s.Submit(evDrain{done})
	select {
	case <-done:
		s.log.Info(logging.DestinationGeneral, "drain complete: all shadows reaped, claims released")
	case <-time.After(grace):
		s.log.Warn(logging.DestinationGeneral, "drain grace expired with shadows still running",
			"grace", grace.String())
	}
}

// --- external producers -----------------------------------------------------

// OnMatch is the callback the NEGOTIATE handler hands each granted match.
func (s *Scheduler) OnMatch(m negotiate.Match) {
	s.stats.IncMatchesReceived()
	s.Submit(evMatch{m})
}

// Reschedule nudges the core to advertise immediately (the RESCHEDULE command).
func (s *Scheduler) Reschedule() { s.Submit(evReschedule{}) }

// Recover scans the persistent queue for jobs a previous incarnation left
// Running and, on the core goroutine, re-attaches to (or requeues) each. Call it
// once at startup after Start. It blocks until the scan has been dispatched
// (each reconnect then proceeds asynchronously), or until timeout elapses.
func (s *Scheduler) Recover(timeout time.Duration) {
	if s.reconnectDisabled {
		s.log.Info(logging.DestinationGeneral, "SCHEDD_RECONNECT disabled; skipping startup recovery scan")
		return
	}
	done := make(chan struct{})
	s.Submit(evRecover{done})
	select {
	case <-done:
	case <-time.After(timeout):
		s.log.Warn(logging.DestinationGeneral, "startup recovery scan did not finish dispatching in time",
			"timeout", timeout.String())
	}
}

// TeardownJobAndWait vacates a running job's shadow/claim (condor_rm or
// condor_hold of a running job) and blocks until the teardown fully completes
// (shadow reaped, match record dropped) or timeout elapses. Returns true when
// the teardown finished within the timeout (or the job was not running at all).
func (s *Scheduler) TeardownJobAndWait(c, p int, timeout time.Duration) bool {
	done := make(chan struct{})
	s.Submit(evTeardown{c, p, done})
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		s.log.Warn(logging.DestinationGeneral, "teardown wait timed out",
			"job", jobKey{c, p}.String(), "timeout", timeout.String())
		return false
	}
}

// --- events -----------------------------------------------------------------

type evMatch struct{ m negotiate.Match }
type evStarted struct {
	c, p     int
	slotName string
	// claimID is the claim the activation actually went to (the dslot claim
	// when a partitionable slot handed back a different id).
	claimID string
}
type evExited struct {
	c, p int
	res  *shadow.Result
	err  error
}
type evFailed struct {
	c, p int
	err  error
	// panicked marks a recovered panic (counts as a shadow exception).
	panicked bool
	// claimID identifies the claim to clean up ("" = use the registry's).
	claimID string
	// released is set when runJob already released the claim itself.
	released bool
}
type evReschedule struct{}
type evTeardown struct {
	c, p int
	done chan struct{} // closed when the teardown fully completes (may be nil)
}
type evDrain struct {
	done chan struct{} // closed when no running jobs remain
}

// evReconnectFailed reports that a recovered run could not re-attach to its
// starter (CA_LOCATE_STARTER / CA_RECONNECT_JOB failed). The job is requeued to
// Idle WITHOUT counting a shadow exception.
type evReconnectFailed struct {
	c, p    int
	claimID string
	err     error
}

// evRecover asks the core to scan the persistent queue for jobs left Running by
// a previous incarnation and re-attach to (or requeue) each. done is closed once
// the scan has been dispatched.
type evRecover struct {
	done chan struct{}
}

// The periodic-policy evaluator (off the core) submits one of these when a
// PeriodicRemove/Hold/Release expression (per-job or SYSTEM_PERIODIC_*) fires
// for a job. The core re-validates the job's status and applies the action via
// the SAME path condor_rm/condor_hold/condor_release use (queue.ApplyAction),
// which for a RUNNING job first tears down the shadow through the vacate hook.
type evPolicyRemove struct {
	c, p   int
	reason string
}
type evPolicyHold struct {
	c, p      int
	reason    string
	code, sub int
}
type evPolicyRelease struct {
	c, p   int
	reason string
}

// evPolicyDone clears a job from the in-flight policy set once its (off-core)
// action goroutine has finished applying.
type evPolicyDone struct{ key jobKey }

func (evMatch) isEvent()           {}
func (evStarted) isEvent()         {}
func (evExited) isEvent()          {}
func (evFailed) isEvent()          {}
func (evReschedule) isEvent()      {}
func (evTeardown) isEvent()        {}
func (evDrain) isEvent()           {}
func (evReconnectFailed) isEvent() {}
func (evRecover) isEvent()         {}
func (evPolicyRemove) isEvent()    {}
func (evPolicyHold) isEvent()      {}
func (evPolicyRelease) isEvent()   {}
func (evPolicyDone) isEvent()      {}

// --- event loop -------------------------------------------------------------

func (s *Scheduler) loop(ctx context.Context) {
	defer s.wg.Done()

	var sweep *time.Ticker
	var sweepC <-chan time.Time
	if s.sweepInterval > 0 {
		sweep = time.NewTicker(s.sweepInterval)
		defer sweep.Stop()
		sweepC = sweep.C
	}

	s.log.Info(logging.DestinationGeneral, "scheduler core started", "advertise_interval", s.advInterval().String())

	for {
		select {
		case <-ctx.Done():
			s.log.Info(logging.DestinationGeneral, "scheduler core stopping")
			return
		case <-sweepC:
			s.sweepExpired()
		case ev := <-s.events:
			s.handle(ctx, ev)
		}
	}
}

// advertiseLoop owns ALL collector advertising, deliberately OFF the
// single-writer core goroutine. Advertising dials/authenticates to the collector
// (blocking network I/O); doing it inline on the core meant a slow or wedged
// collector would stall every queued job-state transition (evStarted, evExited,
// evFailed, evTeardown, ...) for as long as the dial hung -- so a running job
// could miss its completion event and appear to hang in the queue indefinitely.
// Here advertising runs independently: a periodic tick (s.interval) plus a
// coalesced nudge (RESCHEDULE), each pass bounded by advertiseTimeout so even
// this goroutine cannot wedge forever. It reads queue counts through the
// thread-safe CountsFn/SubmittersFn, so it needs no core serialization.
func (s *Scheduler) advertiseLoop(ctx context.Context) {
	defer s.wg.Done()
	if s.advertise == nil {
		return
	}
	s.doAdvertise(ctx)

	ticker := time.NewTicker(s.advInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.doAdvertise(ctx)
		case <-s.advertiseNudge:
			s.doAdvertise(ctx)
		case <-s.advReset:
			// SCHEDD_INTERVAL was reconfigured: adopt the new cadence immediately.
			ticker.Reset(s.advInterval())
			s.log.Info(logging.DestinationGeneral, "advertise interval reconfigured",
				"interval", s.advInterval().String())
		}
	}
}

// doAdvertise runs one advertise pass under a bounded context so a wedged
// collector connection can never block advertising indefinitely.
func (s *Scheduler) doAdvertise(ctx context.Context) {
	actx, cancel := context.WithTimeout(ctx, advertiseTimeout)
	defer cancel()
	s.advertise(actx)
}

// nudgeAdvertise asks the advertiser to push fresh ads now (RESCHEDULE). It
// never blocks: a pending nudge already covers a concurrent request.
func (s *Scheduler) nudgeAdvertise() {
	select {
	case s.advertiseNudge <- struct{}{}:
	default:
	}
}

func (s *Scheduler) handle(ctx context.Context, ev Event) {
	switch e := ev.(type) {
	case evMatch:
		s.handleMatch(ctx, e.m)
	case evStarted:
		s.handleStarted(e)
	case evExited:
		s.handleExited(e)
	case evFailed:
		s.handleFailed(e)
	case evReschedule:
		s.log.Info(logging.DestinationGeneral, "RESCHEDULE: advertising immediately")
		s.nudgeAdvertise()
	case evTeardown:
		s.handleTeardown(e)
	case evDrain:
		s.handleDrain(e)
	case evReconnectFailed:
		s.handleReconnectFailed(e)
	case evRecover:
		s.handleRecover(ctx, e)
	case evPolicyRemove:
		s.handlePolicyAction(e.c, e.p, queue.ActionRequest{
			Kind: queue.ActRemove, Actor: policyActor, System: true, Reason: e.reason})
	case evPolicyHold:
		s.handlePolicyAction(e.c, e.p, queue.ActionRequest{
			Kind: queue.ActHold, Actor: policyActor, System: true, Reason: e.reason,
			HoldReasonCode: e.code, HoldReasonSub: e.sub})
	case evPolicyRelease:
		s.handlePolicyAction(e.c, e.p, queue.ActionRequest{
			Kind: queue.ActRelease, Actor: policyActor, System: true, Reason: e.reason})
	case evPolicyDone:
		delete(s.policyPending, e.key)
	default:
		s.log.Debug(logging.DestinationGeneral, "scheduler received unknown event")
	}
}

// handleMatch turns a negotiator match into a claim+run. Ignores matches for jobs
// that are no longer idle (or already being run), releasing the surplus claim.
func (s *Scheduler) handleMatch(ctx context.Context, m negotiate.Match) {
	if s.draining {
		s.log.Info(logging.DestinationGeneral, "draining; releasing new match",
			"job", fmt.Sprintf("%d.%d", m.Cluster, m.Proc))
		go releaseClaim(m.ClaimID)
		return
	}
	if s.q == nil || m.Cluster < 0 || m.Proc < 0 || m.ClaimID == "" {
		s.log.Warn(logging.DestinationGeneral, "ignoring malformed match", "job", fmt.Sprintf("%d.%d", m.Cluster, m.Proc))
		go releaseClaim(m.ClaimID)
		return
	}
	key := jobKey{m.Cluster, m.Proc}
	if _, busy := s.running[key]; busy {
		s.log.Debug(logging.DestinationGeneral, "match for already-claimed job; releasing surplus claim", "job", key.String())
		go releaseClaim(m.ClaimID)
		return
	}
	if s.q.JobStatus(m.Cluster, m.Proc) != queue.StatusIdle {
		s.log.Debug(logging.DestinationGeneral, "match for non-idle job; releasing claim", "job", key.String())
		go releaseClaim(m.ClaimID)
		return
	}
	job, ok := s.q.Get(m.Cluster, m.Proc)
	if !ok {
		go releaseClaim(m.ClaimID)
		return
	}

	runCtx, cancel := context.WithCancel(ctx)
	detach := &atomic.Bool{}
	s.running[key] = &runInfo{claimID: m.ClaimID, slotName: m.SlotName, cancel: cancel, detach: detach}
	s.runningGauge.Add(1)
	s.log.Info(logging.DestinationGeneral, "claiming slot for job", "job", key.String(), "slot", m.SlotName)
	go s.runJob(runCtx, m, job, detach)
}

// consumePanicHook reports (once) whether the injected-panic test hook fires
// for this job. Called from shadow goroutines.
func (s *Scheduler) consumePanicHook(c, p int) bool {
	s.panicMu.Lock()
	defer s.panicMu.Unlock()
	if !s.panicArmed || s.panicJob != (jobKey{c, p}) {
		return false
	}
	s.panicArmed = false
	return true
}

// runJob (off the core goroutine) performs the blocking claim/activate/serve
// sequence and reports progress back via events. It never touches queue state.
// A panic anywhere in the sequence (including the shadow serve loop) is
// recovered here and reported as evFailed{panicked}; the core then applies the
// requeue-or-hold policy.
func (s *Scheduler) runJob(ctx context.Context, m negotiate.Match, job *classad.ClassAd, detach *atomic.Bool) {
	c, p := m.Cluster, m.Proc
	var activated *startd.ActivatedClaim
	defer func() {
		if r := recover(); r != nil {
			s.log.Error(logging.DestinationGeneral, "shadow goroutine panic; failing the run",
				"job", jobKey{c, p}.String(), "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			if activated != nil {
				_ = activated.Close()
			}
			s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("panic: %v", r), panicked: true})
		}
	}()

	// Register the match so the schedd's ALIVE handler renews this claim's lease.
	if _, err := s.matches.CreateFromClaim(m.ClaimID, m.MatchAd, s.aliveInterval); err != nil {
		s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("import claim session: %w", err), claimID: m.ClaimID})
		return
	}

	sc, err := startd.New(m.ClaimID, nil)
	if err != nil {
		s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("startd client: %w", err), claimID: m.ClaimID})
		return
	}

	res, err := sc.RequestClaim(ctx, &startd.ClaimRequest{
		RequestAd:     job,
		SchedulerAddr: s.scheddAddr,
		AliveInterval: s.aliveInterval,
		ScheddName:    s.scheddName,
	})
	if err != nil || res == nil || !res.OK {
		s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("REQUEST_CLAIM failed: err=%v res=%+v", err, res), claimID: m.ClaimID})
		return
	}

	// Partitionable-slot handling: when the request went to a pslot, the reply
	// carries the carved dynamic slot(s) (SEND_CLAIMED_AD). In the normal case
	// the first claimed slot keeps the very claim id we sent (the startd moves
	// the claim onto the dslot and re-keys the pslot's leftovers), so the ALIVE
	// session we imported above stays valid; we refresh the match record's ad
	// and use the dslot's name. If a claimed slot came back with a different id
	// (defensive; multi-dslot replies do this for slots after the first), re-key
	// the client and match record onto it so activation and keepalives track the
	// dslot's claim.
	claimID := m.ClaimID
	slotName := m.SlotName
	client := sc
	if len(res.ClaimedSlots) > 0 {
		cs := res.ClaimedSlots[0]
		for _, cand := range res.ClaimedSlots {
			if cand.ClaimID == m.ClaimID {
				cs = cand
				break
			}
		}
		if cs.SlotAd != nil {
			if name, ok := cs.SlotAd.EvaluateAttrString("Name"); ok && name != "" {
				slotName = name
			}
		}
		if cs.ClaimID != m.ClaimID {
			newSc, err := startd.New(cs.ClaimID, nil)
			if err != nil {
				s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("dslot startd client: %w", err), claimID: m.ClaimID})
				return
			}
			s.matches.Remove(m.ClaimID)
			if _, err := s.matches.CreateFromClaim(cs.ClaimID, cs.SlotAd, s.aliveInterval); err != nil {
				s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("import dslot claim session: %w", err), claimID: cs.ClaimID})
				return
			}
			client = newSc
			claimID = cs.ClaimID
			s.log.Info(logging.DestinationGeneral, "claimed slot returned a new claim id; re-keyed match",
				"job", jobKey{c, p}.String(), "slot", slotName)
		} else {
			// Same claim id: refresh the stored slot ad to describe the dslot.
			s.matches.UpdateSlotAd(claimID, cs.SlotAd)
		}
		s.log.Info(logging.DestinationGeneral, "claimed slot for activation",
			"job", jobKey{c, p}.String(), "slot", slotName, "claimed_slots", len(res.ClaimedSlots))
	}
	if res.HasLeftovers {
		leftName := ""
		if res.LeftoverSlotAd != nil {
			leftName, _ = res.LeftoverSlotAd.EvaluateAttrString("Name")
		}
		s.log.Info(logging.DestinationGeneral,
			"pslot claim returned leftovers; leaving them unclaimed (one job per match)",
			"job", jobKey{c, p}.String(), "leftover_slot", leftName)
	}

	ac, err := client.ActivateClaim(ctx, job, &startd.ActivateOptions{WantFailureAd: true})
	if err != nil {
		s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("ACTIVATE_CLAIM failed: %w", err), claimID: claimID})
		return
	}
	activated = ac

	// Job is now running on the slot.
	s.Submit(evStarted{c, p, slotName, claimID})

	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
		JobAd:             job,
		ClaimID:           claimID,
		TransferEndpoint:  s.endpoint,
		ShadowAddr:        s.scheddAddr,
		ShadowVersion:     s.shadowVersion,
		UIDDomain:         s.uidDomain,
		Startd:            client,
		Detach:            detach,
		Privsep:           s.privsep,
		ForceWinddownFail: s.winddownFailArmed && s.winddownFailJob == jobKey{c, p},
		OnEvent: func(ev shadow.Event) {
			if ev.Type == shadow.EventBeginExecution && s.consumePanicHook(c, p) {
				panic(fmt.Sprintf("test hook: injected shadow panic for job %d.%d "+
					"(GOLANG_AP_SHADOW_PANIC_AFTER_ACTIVATE)", c, p))
			}
		},
		Logf: func(format string, args ...any) {
			s.log.Debug(logging.DestinationGeneral, fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		_ = ac.Close()
		s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("shadow.New: %w", err), claimID: claimID})
		return
	}

	result, runErr := sh.Run(ctx)
	s.Submit(evExited{c, p, result, runErr})
}

// handleStarted writes the running-state job attributes condor_q -run needs.
func (s *Scheduler) handleStarted(e evStarted) {
	key := jobKey{e.c, e.p}
	claimID := e.claimID
	if ri, ok := s.running[key]; ok {
		ri.slotName = e.slotName
		if e.claimID != "" {
			ri.claimID = e.claimID
		}
		claimID = ri.claimID
	}
	now := time.Now().Unix()
	ok := s.q.Modify(e.c, e.p, func(ad *classad.ClassAd) {
		last, _ := ad.EvaluateAttrInt("JobStatus")
		_ = ad.Set("LastJobStatus", last)
		_ = ad.Set("JobStatus", int64(queue.StatusRunning))
		_ = ad.Set("EnteredCurrentStatus", now)
		_ = ad.Set("RemoteHost", e.slotName)
		_ = ad.Set("JobCurrentStartDate", now)
		if _, has := ad.Lookup("JobStartDate"); !has {
			_ = ad.Set("JobStartDate", now)
		}
		starts, _ := ad.EvaluateAttrInt("NumJobStarts")
		_ = ad.Set("NumJobStarts", starts+1)
		shadowStarts, _ := ad.EvaluateAttrInt("NumShadowStarts")
		_ = ad.Set("NumShadowStarts", shadowStarts+1)
		runs, _ := ad.EvaluateAttrInt("JobRunCount")
		_ = ad.Set("JobRunCount", runs+1)
		_ = ad.Set("ShadowBday", now)
		// Reconnect bookkeeping: persist everything a restarted schedd needs to
		// re-attach to this run instead of requeueing it. ClaimId is a private
		// attribute (redacted from condor_q like the C++ ATTR_CLAIM_ID), stored so
		// the reconnect handshake can resume the claim/reconnect session; the lease
		// attributes let a restart judge whether the run is still alive.
		if claimID != "" {
			_ = ad.Set("ClaimId", claimID)
			if sinful := claimStartdSinful(claimID); sinful != "" {
				_ = ad.Set("StartdIpAddr", sinful)
			}
		}
		if _, has := ad.Lookup("JobLeaseDuration"); !has {
			_ = ad.Set("JobLeaseDuration", int64(s.defaultJobLease))
		}
		_ = ad.Set("LastJobLeaseRenewal", now)
	})
	if !ok {
		s.log.Warn(logging.DestinationGeneral, "job vanished before running attrs written", "job", key.String())
		return
	}
	s.stats.IncJobsStarted()
	// EXECUTE user-log event (like the C++ shadow's logExecuteEvent). Use the
	// startd's sinful as the execute host (falling back to the slot name), and
	// pass the slot name as SlotName. Read the flattened ad so UserLog/Iwd
	// resolve. Skip on a reconnected run: its EXECUTE was logged the first time.
	if s.userlog != nil {
		if ri, ok := s.running[key]; !ok || !ri.reconnect {
			if ad, ok := s.q.Get(e.c, e.p); ok {
				host := e.slotName
				if sinful, ok := ad.EvaluateAttrString("StartdIpAddr"); ok && sinful != "" {
					host = sinful
				}
				s.userlog.Execute(ad, host, e.slotName)
			}
		}
	}
	s.log.Info(logging.DestinationGeneral, "job running", "job", key.String(), "slot", e.slotName)
	// A job just left Idle: nudge the factory engine to top up to max_idle.
	s.nudgeMaterialize()
}

// nudgeMaterialize invokes the late-materialization trigger if one is installed.
// Never blocks the core (the engine's Nudge is non-blocking).
func (s *Scheduler) nudgeMaterialize() {
	if s.onJobLeftIdle != nil {
		s.onJobLeftIdle()
	}
}

// handleExited reaps a finished (or failed) job: on a normal exit it writes the
// terminal attributes, moves the job to Completed, and archives it; on a failure
// it applies the requeue-or-hold policy. Vacated runs (condor_rm/hold, lease
// expiry, drain) skip all queue writes -- the teardown initiator owns those.
func (s *Scheduler) handleExited(e evExited) {
	key := jobKey{e.c, e.p}
	ri := s.running[key]
	delete(s.running, key)
	if ri != nil {
		s.runningGauge.Add(-1)
		ri.cancel()
		s.matches.Remove(ri.claimID)
		defer s.reapWaiters(ri)
	}
	defer s.maybeFinishDrain()
	// A job just left the queue/Idle set: top up its factory (if any).
	defer s.nudgeMaterialize()

	if ri != nil && ri.detached {
		s.log.Info(logging.DestinationGeneral,
			"job's shadow detached for reconnect; leaving it Running", "job", key.String())
		return
	}

	if ri != nil && ri.vacated {
		s.log.Info(logging.DestinationGeneral, "vacated job's shadow finished", "job", key.String())
		return
	}

	// A shadow that detached (reconnect-preserving shutdown) reports
	// ErrDetached; never treat that as a failure/requeue.
	if errors.Is(e.err, shadow.ErrDetached) {
		s.log.Info(logging.DestinationGeneral,
			"shadow detached for reconnect; leaving job Running", "job", key.String())
		return
	}

	if e.res == nil {
		// No job result: a genuine run failure (claim/activate error, the serve loop
		// died before job_exit, or a recovered panic). Apply the requeue-or-hold
		// policy and count it as a shadow exception.
		s.log.Warn(logging.DestinationGeneral, "shadow run failed",
			"job", key.String(), "err", errStr(e.err))
		s.jobFailed(e.c, e.p, errStr(e.err), true)
		return
	}
	if e.err != nil {
		// The job ran to completion (we have its exit Result) but the shadow's
		// best-effort claim wind-down -- JOB_DONE / RELEASE_CLAIM to the startd --
		// failed, typically a transient startd RPC timeout under load ("DaemonCore:
		// Can't receive command request ..." on the startd). The job is DONE;
		// completing it must NOT depend on releasing the claim (the startd reclaims
		// it via its own lease/keepalive expiry). Treating this as a run failure was
		// the HTCONDOR-3828 flake: under load a finished factory proc got requeued
		// and re-run, and after MAX_SHADOW_EXCEPTIONS wind-down failures was HELD --
		// so it never left the queue. Log and fall through to normal completion.
		s.log.Warn(logging.DestinationGeneral,
			"shadow claim wind-down failed after job completed; completing job anyway",
			"job", key.String(), "err", errStr(e.err))
	}

	// The shadow reported an exit: the job ran to completion this attempt,
	// whatever terminal action the policy below selects.
	s.stats.IncJobsExited()
	res := e.res
	now := time.Now().Unix()
	s.q.Modify(e.c, e.p, func(ad *classad.ClassAd) {
		if host, ok := ad.EvaluateAttrString("RemoteHost"); ok && host != "" {
			_ = ad.Set("LastRemoteHost", host)
		}
		ad.Delete("RemoteHost")
		stripReconnectAttrs(ad)
		if code, ok := res.ExitCode(); ok {
			_ = ad.Set("ExitCode", int64(code))
			_ = ad.Set("ExitBySignal", false)
			_ = ad.Set("ExitStatus", int64(code))
		} else if sig, ok := res.TermSignal(); ok {
			_ = ad.Set("ExitBySignal", true)
			_ = ad.Set("ExitSignal", int64(sig))
		} else {
			// UserPolicy requires OnExitBySignal to be present to evaluate the
			// on-exit expressions; default to a clean (non-signal, code 0) exit.
			_ = ad.Set("ExitBySignal", false)
			_ = ad.Set("ExitCode", int64(0))
			_ = ad.Set("ExitStatus", int64(0))
		}
		if start, ok := ad.EvaluateAttrInt("JobCurrentStartDate"); ok && start > 0 {
			prev, _ := ad.EvaluateAttrInt("RemoteWallClockTime")
			_ = ad.Set("RemoteWallClockTime", prev+(now-start))
		}
		// NumJobCompletions counts each execution that ran to completion (like the
		// C++ schedd), whether the job then terminates, is held on exit, or is
		// requeued -- so on_exit_remove expressions can gate on the run count.
		completions, _ := ad.EvaluateAttrInt("NumJobCompletions")
		_ = ad.Set("NumJobCompletions", completions+1)
		_ = ad.Set("LastJobStatus", int64(queue.StatusRunning))
	})

	// On-exit user policy (OnExitHold / OnExitRemove, plus any Periodic* that
	// fires at exit): decide whether the job terminates, is held, is requeued for
	// re-run, or is removed. Evaluate against a private copy of the just-updated
	// ad with CurrentTime bound to now; the job is still JobStatus=Running here.
	d := policy.Decision{Action: policy.Complete}
	if ad, ok := s.q.Get(e.c, e.p); ok {
		_ = ad.Set("CurrentTime", now)
		d = policy.Analyze(ad, policy.PeriodicThenExit, s.sysPolicy.Load(), queue.StatusRunning)
	}
	code, _ := res.ExitCode()

	switch d.Action {
	case policy.Hold:
		// OnExitHold (or a Periodic* hold) fired: hold the job in place; do NOT
		// archive it. HoldReasonCode is JobPolicy(3)/SystemPolicy(26) per policy.
		s.holdOnExit(e.c, e.p, d, now)
		s.log.Info(logging.DestinationGeneral, "job held on exit by policy",
			"job", key.String(), "exit_code", code, "firing", d.Firing, "hold_code", d.HoldCode)

	case policy.Requeue:
		// OnExitRemove evaluated false: return the job to Idle for re-run (the
		// substrate max_retries builds on). NOT counted as a shadow failure.
		s.requeueOnExit(e.c, e.p, now, d.Reason)
		s.log.Info(logging.DestinationGeneral, "job requeued on exit by policy (OnExitRemove=false)",
			"job", key.String(), "exit_code", code)

	case policy.Remove:
		// A Periodic*/exit remove fired: archive the job as Removed (status 3)
		// via the same off-core ApplyAction path condor_rm uses (the shadow is
		// already gone, so its teardown hook is a no-op).
		s.Submit(evPolicyRemove{e.c, e.p, d.Reason})
		s.log.Info(logging.DestinationGeneral, "job removed on exit by policy",
			"job", key.String(), "exit_code", code, "firing", d.Firing)

	default: // policy.Complete
		// Normal termination (OnExitRemove true / default): JOB_TERMINATED
		// user-log event, then move to Completed (JobStatus=4 + CompletionDate)
		// and archive out of the live queue.
		if s.userlog != nil {
			if ad, ok := s.q.Get(e.c, e.p); ok {
				if c2, ok := res.ExitCode(); ok {
					s.userlog.Terminated(ad, false, c2)
				} else if sig, ok := res.TermSignal(); ok {
					s.userlog.Terminated(ad, true, sig)
				} else {
					s.userlog.Terminated(ad, false, 0)
				}
			}
		}
		s.q.Complete(e.c, e.p)
		s.stats.IncJobsCompleted()
		s.log.Info(logging.DestinationGeneral, "job completed",
			"job", key.String(), "exit_code", code, "reason", res.Reason)
	}
}

// holdOnExit holds a just-exited job in place (OnExitHold or a Periodic* hold
// firing at exit). Runs on the core goroutine: the shadow is already reaped, so
// no teardown is needed and we write the Held state directly (via q.Modify),
// using the non-blocking HeldCore user-log path so a hung log FS cannot freeze
// the core.
func (s *Scheduler) holdOnExit(c, p int, d policy.Decision, now int64) {
	reason := d.Reason
	if reason == "" {
		reason = "Job held by policy on exit"
	}
	code := d.HoldCode
	if code == 0 {
		code = policy.HoldCodeJobPolicy
	}
	s.q.Modify(c, p, func(ad *classad.ClassAd) {
		_ = ad.Set("LastJobStatus", int64(queue.StatusRunning))
		_ = ad.Set("JobStatus", int64(queue.StatusHeld))
		_ = ad.Set("EnteredCurrentStatus", now)
		_ = ad.Set("HoldReason", reason)
		_ = ad.Set("HoldReasonCode", int64(code))
		_ = ad.Set("HoldReasonSubCode", int64(d.HoldSubCode))
		numHolds, _ := ad.EvaluateAttrInt("NumHolds")
		_ = ad.Set("NumHolds", numHolds+1)
	})
	if s.userlog != nil {
		if ad, ok := s.q.Get(c, p); ok {
			s.userlog.HeldCore(ad, reason, code, d.HoldSubCode)
		}
	}
}

// requeueOnExit returns a just-exited job to Idle for re-run (OnExitRemove
// evaluated false). Runs on the core goroutine (shadow already reaped). Writes a
// JOB_EVICTED (terminate-and-requeued) user-log event, matching the C++ shadow's
// logRequeueEvent.
func (s *Scheduler) requeueOnExit(c, p int, now int64, reason string) {
	s.q.Modify(c, p, func(ad *classad.ClassAd) {
		_ = ad.Set("LastJobStatus", int64(queue.StatusRunning))
		_ = ad.Set("JobStatus", int64(queue.StatusIdle))
		_ = ad.Set("EnteredCurrentStatus", now)
	})
	if s.userlog != nil {
		if ad, ok := s.q.Get(c, p); ok {
			if reason == "" {
				reason = "Job requeued (OnExitRemove is false)"
			}
			s.userlog.Evicted(ad, reason)
		}
	}
}

// handleFailed reaps a run that failed before (or instead of) producing a
// shadow result: claim/activate errors and recovered panics. The core releases
// the claim best-effort, drops the match record, and applies the
// requeue-or-hold policy (panics count as shadow exceptions; pre-activation
// claim failures do not -- the job never left Idle, so jobFailed leaves it
// untouched).
func (s *Scheduler) handleFailed(e evFailed) {
	key := jobKey{e.c, e.p}
	ri, ok := s.running[key]
	if ok {
		s.runningGauge.Add(-1)
		ri.cancel()
		delete(s.running, key)
		defer s.reapWaiters(ri)
	}
	defer s.maybeFinishDrain()

	// A detached shadow (reconnect-preserving shutdown) reports ErrDetached and
	// deliberately left its claim intact: drop the in-memory match record but do
	// NOT release the claim (the starter is holding the job for reconnect) and do
	// NOT rewrite the job -- it stays Running for the next start to re-attach.
	if (ri != nil && ri.detached) || errors.Is(e.err, shadow.ErrDetached) {
		if ri != nil {
			s.matches.Remove(ri.claimID)
		}
		s.log.Info(logging.DestinationGeneral,
			"shadow detached for reconnect; leaving job Running", "job", key.String())
		return
	}

	claimID := e.claimID
	if claimID == "" && ri != nil {
		claimID = ri.claimID
	}
	if claimID != "" {
		s.matches.Remove(claimID)
		if !e.released {
			// Best-effort, from a fresh goroutine: never block the core on the
			// startd, and never trust the failed run's connection state.
			go releaseClaim(claimID)
		}
	}

	if ri != nil && ri.vacated {
		s.log.Info(logging.DestinationGeneral, "vacated job's run wound down", "job", key.String())
		return
	}

	s.log.Warn(logging.DestinationGeneral, "job run failed",
		"job", key.String(), "panicked", e.panicked, "err", errStr(e.err))
	s.jobFailed(e.c, e.p, errStr(e.err), e.panicked)
}

// jobFailed applies the failure policy to a job whose run died: requeue to
// Idle for re-matching, unless (when counted) it has accumulated
// MaxShadowExceptions failures, in which case hold it with HoldReasonCode
// 1002 (ShadowException), mirroring the C++ schedd's shadow-exception
// accounting (NumShadowExceptions / VacateReasonCode in Scheduler::child_exit).
// Jobs that are no longer Running (e.g. a claim failed while the job was still
// Idle, or a race with condor_rm) are left untouched.
func (s *Scheduler) jobFailed(c, p int, why string, count bool) {
	if s.q.JobStatus(c, p) != queue.StatusRunning {
		return
	}
	now := time.Now().Unix()
	held := false
	var excepts int64
	s.q.Modify(c, p, func(ad *classad.ClassAd) {
		if host, ok := ad.EvaluateAttrString("RemoteHost"); ok && host != "" {
			_ = ad.Set("LastRemoteHost", host)
		}
		ad.Delete("RemoteHost")
		stripReconnectAttrs(ad)
		_ = ad.Set("LastJobStatus", int64(queue.StatusRunning))
		_ = ad.Set("EnteredCurrentStatus", now)
		if count {
			s.stats.IncShadowExceptions()
			excepts, _ = ad.EvaluateAttrInt("NumShadowExceptions")
			excepts++
			_ = ad.Set("NumShadowExceptions", excepts)
			_ = ad.Set("VacateReason", "Shadow exception: "+why)
			_ = ad.Set("VacateReasonCode", int64(holdCodeShadowException))
			_ = ad.Set("VacateReasonSubCode", int64(0))
		}
		if count && int(excepts) >= s.maxExceptions {
			held = true
			_ = ad.Set("JobStatus", int64(queue.StatusHeld))
			_ = ad.Set("HoldReason", fmt.Sprintf("Job has failed %d times; last failure: %s", excepts, why))
			_ = ad.Set("HoldReasonCode", int64(holdCodeShadowException))
			_ = ad.Set("HoldReasonSubCode", int64(0))
			numHolds, _ := ad.EvaluateAttrInt("NumHolds")
			_ = ad.Set("NumHolds", numHolds+1)
		} else {
			_ = ad.Set("JobStatus", int64(queue.StatusIdle))
		}
	})
	// User-log event: a requeued run is an EVICTED event (C++ shadow's
	// logRequeueEvent); a run that exhausts its failure budget is HELD (the
	// schedd's shadow-exception hold). Read the flattened ad for UserLog/Iwd.
	if s.userlog != nil {
		if ad, ok := s.q.Get(c, p); ok {
			if held {
				// Core goroutine: use the non-blocking HeldCore so a hung log FS
				// can never freeze scheduling (the queue-action Held backpressures).
				s.userlog.HeldCore(ad,
					fmt.Sprintf("Job has failed %d times; last failure: %s", excepts, why),
					holdCodeShadowException, 0)
			} else {
				s.userlog.Evicted(ad, why)
			}
		}
	}
	if held {
		s.log.Warn(logging.DestinationGeneral, "job exhausted its failure budget; holding",
			"job", jobKey{c, p}.String(), "exceptions", excepts, "max", s.maxExceptions)
	} else {
		s.log.Warn(logging.DestinationGeneral, "job requeued for re-matching",
			"job", jobKey{c, p}.String(), "exceptions", excepts, "counted", count)
	}
}

// handleTeardown vacates a running job's shadow (condor_rm/condor_hold of a
// running job). The queue owns the job's status transition; here we cancel the
// shadow so its vacate path (DEACTIVATE_CLAIM_FORCIBLY + RELEASE_CLAIM) frees
// the slot, and arrange for e.done to be closed once the run is fully reaped.
func (s *Scheduler) handleTeardown(e evTeardown) {
	key := jobKey{e.c, e.p}
	ri, ok := s.running[key]
	if !ok {
		if e.done != nil {
			close(e.done)
		}
		return
	}
	ri.vacated = true
	if e.done != nil {
		ri.waiters = append(ri.waiters, e.done)
	}
	s.log.Info(logging.DestinationGeneral, "vacating running job (rm/hold)", "job", key.String())
	ri.cancel()
}

// handleDrain begins a graceful shutdown: refuse new matches, vacate every
// running shadow (requeueing its job to Idle so a restarted schedd re-runs
// it), and close done once all runs are reaped.
func (s *Scheduler) handleDrain(e evDrain) {
	s.draining = true
	if len(s.running) == 0 {
		close(e.done)
		return
	}
	s.drainDone = e.done

	// C++-faithful default (SCHEDD_RECONNECT enabled): step away from every
	// running shadow WITHOUT vacating -- the claim/starter keep the job alive and
	// the job stays Running in the queue, so the next start re-attaches. The
	// escape hatch (SCHEDD_RECONNECT=false) restores the old drain: vacate every
	// shadow and requeue its job to Idle.
	if s.reconnectDisabled {
		s.log.Info(logging.DestinationGeneral, "draining: vacating running shadows (reconnect disabled)",
			"running", len(s.running))
		for key, ri := range s.running {
			if ri.vacated {
				continue
			}
			ri.vacated = true
			s.requeueToIdle(key.c, key.p)
			ri.cancel()
		}
		return
	}

	s.log.Info(logging.DestinationGeneral,
		"draining: detaching from running shadows for reconnect (jobs left Running)",
		"running", len(s.running))
	for _, ri := range s.running {
		if ri.vacated || ri.detached {
			continue
		}
		ri.detached = true
		if ri.detach != nil {
			ri.detach.Store(true)
		}
		ri.cancel()
	}
}

// maybeFinishDrain closes the drain-completion channel once the last running
// job has been reaped.
func (s *Scheduler) maybeFinishDrain() {
	if s.draining && s.drainDone != nil && len(s.running) == 0 {
		close(s.drainDone)
		s.drainDone = nil
	}
}

// requeueToIdle returns a Running job to Idle (teardown paths where the run is
// being abandoned deliberately: lease expiry, shutdown drain).
func (s *Scheduler) requeueToIdle(c, p int) {
	if s.q.JobStatus(c, p) != queue.StatusRunning {
		return
	}
	now := time.Now().Unix()
	s.q.Modify(c, p, func(ad *classad.ClassAd) {
		if host, ok := ad.EvaluateAttrString("RemoteHost"); ok && host != "" {
			_ = ad.Set("LastRemoteHost", host)
		}
		ad.Delete("RemoteHost")
		stripReconnectAttrs(ad)
		_ = ad.Set("LastJobStatus", int64(queue.StatusRunning))
		_ = ad.Set("JobStatus", int64(queue.StatusIdle))
		_ = ad.Set("EnteredCurrentStatus", now)
	})
}

// --- startup recovery / reconnect ------------------------------------------

// handleRecover scans the persistent queue for jobs a previous incarnation left
// Running and decides, per job, whether to re-attach (spawn a reconnect-mode
// shadow) or requeue to Idle. It runs on the core goroutine, so the running-job
// registry and queue writes stay single-writer. Mirrors the C++ schedd's
// init-time mark_jobs_idle scan (qmgmt.cpp): reconnect iff the claim is known
// and the lease is still theoretically alive; otherwise stop the job (requeue).
func (s *Scheduler) handleRecover(ctx context.Context, e evRecover) {
	defer func() {
		if e.done != nil {
			close(e.done)
		}
	}()
	if s.draining {
		return
	}
	now := time.Now().Unix()
	type recovered struct {
		c, p     int
		claimID  string
		slotName string
		job      *classad.ClassAd
	}
	var toReconnect []recovered
	for ad := range s.q.Scan() {
		st, _ := ad.EvaluateAttrInt("JobStatus")
		if int(st) != queue.StatusRunning {
			continue
		}
		c, _ := ad.EvaluateAttrInt("ClusterId")
		p, _ := ad.EvaluateAttrInt("ProcId")
		key := jobKey{int(c), int(p)}
		if _, busy := s.running[key]; busy {
			continue
		}
		claimID, _ := ad.EvaluateAttrString("ClaimId")
		slotName, _ := ad.EvaluateAttrString("RemoteHost")
		if claimID == "" {
			s.log.Warn(logging.DestinationGeneral,
				"recovering: running job has no stored claim; requeueing", "job", key.String())
			s.requeueToIdle(key.c, key.p)
			continue
		}
		if !leaseAlive(ad, now) {
			s.log.Warn(logging.DestinationGeneral,
				"recovering: running job's lease has expired; requeueing", "job", key.String())
			s.requeueToIdle(key.c, key.p)
			continue
		}
		// Snapshot the job ad for the reconnect goroutine (Scan yields shared ads).
		job := copyAd(ad)
		toReconnect = append(toReconnect, recovered{key.c, key.p, claimID, slotName, job})
	}

	if len(toReconnect) == 0 {
		s.log.Info(logging.DestinationGeneral, "startup recovery: no running jobs to reconnect")
		return
	}
	s.log.Info(logging.DestinationGeneral, "startup recovery: reconnecting to running jobs",
		"count", len(toReconnect))
	for _, r := range toReconnect {
		key := jobKey{r.c, r.p}
		runCtx, cancel := context.WithCancel(ctx)
		s.running[key] = &runInfo{
			claimID:   r.claimID,
			slotName:  r.slotName,
			cancel:    cancel,
			detach:    &atomic.Bool{},
			reconnect: true,
		}
		s.runningGauge.Add(1)
		s.log.Info(logging.DestinationGeneral, "reconnecting to running job",
			"job", key.String(), "slot", r.slotName)
		// JOB_DISCONNECTED user-log event (like the C++ shadow's
		// logDisconnectedEvent): the previous incarnation's shadow is gone and we
		// are re-attaching. Paired with a later RECONNECTED or RECONNECT_FAILED.
		if s.userlog != nil {
			startdAddr, _ := r.job.EvaluateAttrString("StartdIpAddr")
			s.userlog.Disconnected(r.job, "Connection to starter lost (schedd restarted)",
				r.slotName, startdAddr)
		}
		go s.reconnectJob(runCtx, r.c, r.p, r.claimID, r.job, s.running[key].detach)
	}
}

// reconnectJob (off the core goroutine) re-attaches to a job already running on
// its starter: it re-imports the claim session so ALIVE keepalives resume,
// re-establishes the syscall socket via CA_LOCATE_STARTER + CA_RECONNECT_JOB, and
// serves the starter until job_exit. Reconnect-establishment failures come back
// as evReconnectFailed (requeue, no exception); anything after a successful
// reconnect follows the normal exit/failure path.
func (s *Scheduler) reconnectJob(ctx context.Context, c, p int, claimID string, job *classad.ClassAd, detach *atomic.Bool) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error(logging.DestinationGeneral, "reconnect goroutine panic; failing the run",
				"job", jobKey{c, p}.String(), "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			s.Submit(evFailed{c: c, p: p, err: fmt.Errorf("panic: %v", r), panicked: true})
		}
	}()

	// Re-import the claim session so the schedd's ALIVE handler renews the lease
	// again (the in-memory match table was lost with the previous incarnation).
	if _, err := s.matches.CreateFromClaim(claimID, nil, s.aliveInterval); err != nil {
		s.Submit(evReconnectFailed{c: c, p: p, claimID: claimID, err: fmt.Errorf("import claim session: %w", err)})
		return
	}

	sc, err := startd.New(claimID, nil)
	if err != nil {
		s.Submit(evReconnectFailed{c: c, p: p, claimID: claimID, err: fmt.Errorf("startd client: %w", err)})
		return
	}

	gjid, _ := job.EvaluateAttrString("GlobalJobId")
	sh, err := shadow.NewReconnect(shadow.Config{
		JobAd:            job,
		ClaimID:          claimID,
		GlobalJobID:      gjid,
		ScheddPublicAddr: s.scheddAddr,
		TransferEndpoint: s.endpoint,
		ShadowAddr:       s.scheddAddr,
		ShadowVersion:    s.shadowVersion,
		UIDDomain:        s.uidDomain,
		Startd:           sc,
		Detach:           detach,
		Privsep:          s.privsep,
		Logf: func(format string, args ...any) {
			s.log.Debug(logging.DestinationGeneral, fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		s.Submit(evReconnectFailed{c: c, p: p, claimID: claimID, err: fmt.Errorf("shadow.NewReconnect: %w", err)})
		return
	}

	result, runErr := sh.RunReconnect(ctx)
	if errors.Is(runErr, shadow.ErrReconnectFailed) {
		s.Submit(evReconnectFailed{c: c, p: p, claimID: claimID, err: runErr})
		return
	}
	// Reconnect established (RunReconnect only returns a non-ErrReconnectFailed
	// result once it has re-attached to the starter): log the RECONNECTED event
	// that pairs with the DISCONNECTED written at recover, before the shared exit
	// path logs TERMINATED/EVICTED. We lack the starter's own address here, so use
	// the startd sinful for both (the field is informational).
	if s.userlog != nil {
		startdName, _ := job.EvaluateAttrString("RemoteHost")
		startdAddr, _ := job.EvaluateAttrString("StartdIpAddr")
		s.userlog.Reconnected(job, startdName, startdAddr, startdAddr)
	}
	// From here the run behaves like any other (normal completion, mid-run
	// failure, or a shutdown detach), so use the shared path.
	s.Submit(evExited{c, p, result, runErr})
}

// handleReconnectFailed requeues a job whose reconnect could not be established.
// Unlike a shadow exception this is not counted against the job (the run never
// re-attached), matching the C++ schedd's reconnect-failure fallback: requeue to
// Idle for re-matching, leaving NumShadowExceptions untouched.
func (s *Scheduler) handleReconnectFailed(e evReconnectFailed) {
	key := jobKey{e.c, e.p}
	ri, ok := s.running[key]
	if ok {
		s.runningGauge.Add(-1)
		ri.cancel()
		delete(s.running, key)
		defer s.reapWaiters(ri)
	}
	defer s.maybeFinishDrain()

	claimID := e.claimID
	if claimID == "" && ri != nil {
		claimID = ri.claimID
	}
	if claimID != "" {
		s.matches.Remove(claimID)
	}
	if ri != nil && (ri.vacated || ri.detached) {
		return
	}
	s.log.Warn(logging.DestinationGeneral, "reconnect to running job failed; requeueing to Idle",
		"job", key.String(), "err", errStr(e.err))
	// JOB_RECONNECT_FAILED user-log event (like the C++ shadow's
	// logReconnectFailedEvent), paired with the DISCONNECTED written at recover.
	// Written before jobFailed strips RemoteHost / requeues the job.
	if s.userlog != nil {
		if ad, ok := s.q.Get(e.c, e.p); ok {
			startdName, _ := ad.EvaluateAttrString("RemoteHost")
			s.userlog.ReconnectFailed(ad, errStr(e.err), startdName)
		}
	}
	// count=false: a reconnect failure is not a shadow exception.
	s.jobFailed(e.c, e.p, "reconnect failed: "+errStr(e.err), false)
}

// --- periodic policy engine -------------------------------------------------

// policyActor labels a queue action the schedd itself initiates from a policy
// firing (System actions bypass the per-user owner check; the label only feeds
// default reason strings / user-log fields).
const policyActor = "condor_schedd"

// periodicLoop is the periodic-policy evaluator, run OFF the core goroutine (to
// honor the core-responsiveness rule) on a PERIODIC_EXPR_INTERVAL ticker. Each
// tick it snapshot-scans the live queue and, for every job whose PeriodicRemove/
// Hold/Release (per-job or SYSTEM_PERIODIC_*) fires, submits an action event to
// the core. It never mutates queue or registry state itself. Mirrors the C++
// Scheduler::PeriodicExprHandler / WalkJobQueue(PeriodicExprEval).
func (s *Scheduler) periodicLoop(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.periodicInterval())
	defer ticker.Stop()
	s.log.Info(logging.DestinationGeneral, "periodic-policy evaluator started",
		"interval", s.periodicInterval().String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluatePeriodic()
		case <-s.periodicReset:
			// PERIODIC_EXPR_INTERVAL was reconfigured: adopt the new cadence.
			ticker.Reset(s.periodicInterval())
			s.log.Info(logging.DestinationGeneral, "periodic-policy interval reconfigured",
				"interval", s.periodicInterval().String())
		}
	}
}

// evaluatePeriodic scans the live queue once and dispatches a policy action for
// each firing job. It runs on the evaluator goroutine and touches only the
// concurrency-safe queue snapshot (Scan) and Submit.
//
// Scale: this is O(live jobs) every interval. That is fine for now, but a large
// queue would want an ordered index of the soonest-firing time-based expressions
// or a dirty-set of jobs whose inputs changed, so we do not re-evaluate every
// job every tick. Not prematurely optimized here (see ROADMAP scale note).
func (s *Scheduler) evaluatePeriodic() {
	now := time.Now().Unix()
	sysPolicy := s.sysPolicy.Load()
	haveSys := !sysPolicy.Empty()
	for shared := range s.q.Scan() {
		// Only Idle/Running/Held jobs live in the queue (terminal jobs are
		// archived out); skip anything without a candidate expression fast.
		st, _ := shared.EvaluateAttrInt("JobStatus")
		state := int(st)
		if !haveSys && !hasPeriodicExpr(shared, state) {
			continue
		}
		// Evaluate against a private copy with CurrentTime bound to now, so an
		// expression referencing CurrentTime resolves and we never mutate the
		// shared snapshot ad (Scan yields ads shared with the store).
		ad := copyAd(shared)
		_ = ad.Set("CurrentTime", now)
		c, _ := ad.EvaluateAttrInt("ClusterId")
		p, _ := ad.EvaluateAttrInt("ProcId")
		d := policy.Analyze(ad, policy.PeriodicOnly, sysPolicy, state)
		switch d.Action {
		case policy.Remove:
			s.Submit(evPolicyRemove{int(c), int(p), d.Reason})
		case policy.Hold:
			s.Submit(evPolicyHold{int(c), int(p), d.Reason, d.HoldCode, d.HoldSubCode})
		case policy.Release:
			s.Submit(evPolicyRelease{int(c), int(p), d.Reason})
		}
	}
}

// hasPeriodicExpr reports whether a job carries any periodic expression relevant
// to its state, so the evaluator can skip the copy+eval of jobs that have none
// (the overwhelming common case). PeriodicRelease matters only for Held jobs.
func hasPeriodicExpr(ad *classad.ClassAd, state int) bool {
	if _, ok := ad.Lookup("PeriodicRemove"); ok {
		return true
	}
	if _, ok := ad.Lookup("PeriodicHold"); ok {
		return true
	}
	if state == queue.StatusHeld {
		if _, ok := ad.Lookup("PeriodicRelease"); ok {
			return true
		}
	}
	return false
}

// handlePolicyAction applies a periodic-policy firing on the core goroutine. It
// re-validates the job's CURRENT status (the evaluator saw a snapshot that may
// be stale) and, for an applicable action, hands the queue mutation to an
// off-core goroutine calling queue.ApplyAction -- the SAME entry point
// condor_rm/condor_hold/condor_release use. For a RUNNING job ApplyAction
// invokes the onVacateRunning hook (TeardownJobAndWait), which submits an
// evTeardown the core must process; running it inline here would DEADLOCK the
// core (the core cannot both block on and service that event), so it must be
// off-core. The core-owned policyPending set dedupes a job that fires on
// consecutive ticks before its action lands.
func (s *Scheduler) handlePolicyAction(c, p int, req queue.ActionRequest) {
	key := jobKey{c, p}
	if s.policyPending[key] {
		return
	}
	status := s.q.JobStatus(c, p)
	if !policyApplicable(req.Kind, status) {
		return
	}
	s.policyPending[key] = true
	s.log.Info(logging.DestinationGeneral, "applying periodic policy action",
		"job", key.String(), "action", int(req.Kind), "reason", req.Reason)
	go func() {
		s.q.ApplyAction(c, p, req)
		s.Submit(evPolicyDone{key})
	}()
}

// policyApplicable reports whether a policy action still applies to a job in the
// given current status (mirrors PeriodicExprEval's status guards: don't re-remove
// a Removed job, don't re-hold a Held/terminal job, only release a Held job).
func policyApplicable(kind queue.ActionKind, status int) bool {
	switch kind {
	case queue.ActRemove:
		return status != 0 && status != queue.StatusRemoved
	case queue.ActHold:
		return status == queue.StatusIdle || status == queue.StatusRunning
	case queue.ActRelease:
		return status == queue.StatusHeld
	}
	return false
}

// copyAd returns a shallow attribute-by-attribute copy of ad, safe to hand to a
// goroutine (the queue's Scan yields ads shared with the store).
func copyAd(ad *classad.ClassAd) *classad.ClassAd {
	out := classad.New()
	for _, name := range ad.GetAttributes() {
		if expr, ok := ad.Lookup(name); ok {
			out.InsertExpr(name, expr)
		}
	}
	return out
}

// leaseAlive reports whether a running job's claim lease is still theoretically
// valid: JobLeaseDuration and LastJobLeaseRenewal are present and
// (now - LastJobLeaseRenewal) < JobLeaseDuration. Mirrors jobLeaseIsValid
// (qmgmt.cpp).
func leaseAlive(ad *classad.ClassAd, now int64) bool {
	dur, ok := ad.EvaluateAttrInt("JobLeaseDuration")
	if !ok || dur <= 0 {
		return false
	}
	renewal, ok := ad.EvaluateAttrInt("LastJobLeaseRenewal")
	if !ok || renewal <= 0 {
		return false
	}
	return now-renewal < dur
}

// stripReconnectAttrs removes the per-run reconnect bookkeeping from a job ad
// (called when a run ends or is requeued, so a stale claim id / lease never
// lingers on an Idle or terminal job).
func stripReconnectAttrs(ad *classad.ClassAd) {
	ad.Delete("ClaimId")
	ad.Delete("StartdIpAddr")
	ad.Delete("LastJobLeaseRenewal")
}

// claimStartdSinful returns the startd command sinful at the head of a claim id
// (everything before the first '#').
func claimStartdSinful(claimID string) string {
	for i := 0; i < len(claimID); i++ {
		if claimID[i] == '#' {
			return claimID[:i]
		}
	}
	return ""
}

// reapWaiters wakes everyone blocked on this run's teardown.
func (s *Scheduler) reapWaiters(ri *runInfo) {
	for _, ch := range ri.waiters {
		close(ch)
	}
	ri.waiters = nil
}

// sweepExpired maintains claim leases. Two halves, mirroring the C++
// Scheduler::sendAlives (schedd.cpp):
//
// First, every claim backing a live (non-vacated) run gets its lease renewed:
// we send _condor_StartdHandlesAlives, so the startd deliberately does NOT
// send ALIVE while a starter is active -- the shadow's live syscall connection
// is the health signal (its death surfaces as evExited/evFailed), exactly like
// the C++ schedd renewing ATTR_LAST_JOB_LEASE_RENEWAL while a shadow process
// exists. Without this, any job outrunning the lease would be falsely
// requeued.
//
// Then expired leases are swept: the startd's keepalives stopped on a claim
// with no live run backing it (or a wedged one), so the startd is presumed
// gone. The match record is dropped, and if a running job somehow still holds
// the claim its shadow is canceled (the vacate wind-down is best-effort
// against the dead startd) and the job requeued to Idle for re-matching.
// Runs on the core goroutine.
func (s *Scheduler) sweepExpired() {
	now := time.Now().Unix()
	for key, ri := range s.running {
		if ri.vacated || ri.detached {
			continue
		}
		// Renew comfortably past the next sweep tick, NOT just by the record's own
		// alive-interval lease. That lease is AlivesMissed*AliveInterval, which can
		// be far shorter than the sweep interval (e.g. 6s vs 30s), and this sweep is
		// the ONLY thing renewing a live run's match (the startd sends no ALIVE while
		// a starter is active). Renewing by only the short lease would leave the
		// record "expired" for most of the gap between sweeps, so any wall-clock slip
		// between the renew below and the ExpireSweep() that follows could reap a
		// perfectly healthy running job's match and falsely requeue it. Renewing for
		// several sweep intervals removes that race entirely: a live run's match
		// stays valid until the next sweep renews it again.
		s.matches.RenewLeaseFor(ri.claimID, 3*s.sweepInterval)
		// Keep the persisted lease fresh so a schedd restart judges this run
		// alive (mirrors the C++ schedd renewing ATTR_LAST_JOB_LEASE_RENEWAL
		// while a shadow exists). Only for jobs still Running.
		if s.q.JobStatus(key.c, key.p) == queue.StatusRunning {
			s.q.Modify(key.c, key.p, func(ad *classad.ClassAd) {
				_ = ad.Set("LastJobLeaseRenewal", now)
			})
		}
	}
	expired := s.matches.ExpireSweep(time.Now())
	for _, rec := range expired {
		s.log.Warn(logging.DestinationGeneral, "match lease expired; dropping record", "slot", recSlot(rec))
		for key, ri := range s.running {
			if ri.vacated || claimPublicID(ri.claimID) != rec.PublicID() {
				continue
			}
			s.log.Warn(logging.DestinationGeneral,
				"lease expired for running job; canceling shadow and requeueing",
				"job", key.String(), "slot", ri.slotName)
			ri.vacated = true
			s.requeueToIdle(key.c, key.p)
			ri.cancel()
			break
		}
	}
}

// claimPublicID maps a secret claim id to the public/session id match records
// are keyed by.
func claimPublicID(claimID string) string {
	public := security.ParseClaimIDStrict(claimID).SecSessionID()
	if public == "" {
		public = claimID
	}
	return public
}

// releaseClaim best-effort releases a surplus/unusable claim so the slot is freed.
func releaseClaim(claimID string) {
	sc, err := startd.New(claimID, nil)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = sc.ReleaseClaim(ctx)
}

func recSlot(rec *match.MatchRec) string {
	if rec == nil || rec.SlotAd == nil {
		return ""
	}
	name, _ := rec.SlotAd.EvaluateAttrString("Name")
	return name
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
