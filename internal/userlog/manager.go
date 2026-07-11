// Package userlog is the schedd-side glue that writes standard HTCondor
// user-job-log events (the file a submit description names with `log =
// ...`) so condor_wait and DAGMan can follow a job's lifecycle.
//
// It is a thin adapter over github.com/bbockelm/golang-htcondor/userlog
// (the byte-compatible classic-format Writer): the Manager resolves a
// job's log path from its ClassAd (the UserLog attribute, honoring
// absolute vs Iwd-relative paths, matching getPathToUserLog in
// src/condor_utils/write_user_log.cpp) and emits the right event at each
// job-state transition. Every method is a no-op when the job ad has no
// UserLog, so jobs submitted without `log = ...` cost nothing.
//
// Which side writes which event mirrors the C++ daemons for a vanilla
// job (verified against the HTCondor source):
//
//   - SUBMIT: the SCHEDD, at commit of the job into the queue
//     (qmgmt.cpp CommitTransaction -> Scheduler::WriteSubmitToUserLog),
//     NOT condor_submit. So the Go schedd writes it at queue commit.
//   - EXECUTE / TERMINATED / EVICTED: the shadow. The Go schedd embeds
//     the shadow role, so it writes these at the run transitions.
//   - HELD / RELEASED / ABORTED: the SCHEDD, on condor_hold / _release /
//     _rm (schedd.cpp actOnJobs / abort_job_myself). The Go schedd
//     writes these in the queue-action path.
//   - DISCONNECTED / RECONNECTED / RECONNECT_FAILED: the shadow, around
//     a reconnect. The Go schedd writes these on its reconnect path.
//
// # Asynchronous, off-core writes (ROADMAP.md item #1, steps 1-2)
//
// User logs routinely live on a slow/flaky shared filesystem (NFS or
// worse) while the queue DB is on fast local disk. A synchronous write
// from the scheduler-core goroutine (EXECUTE/TERMINATED/EVICTED) would
// freeze ALL scheduling when that FS hangs -- the classic HTCondor
// lockup. So the Manager never writes on the caller's goroutine: it
// buffers each event into a bounded per-file FIFO and hands the blocking
// filesystem I/O to a FIXED, BOUNDED pool of worker goroutines.
//
// Architecture:
//
//   - Fixed pool of Config.Workers goroutines (default 32), regardless of
//     how many distinct log files exist. A `log = job_$(Process).log`
//     cluster of 100k jobs is 100k tiny buffers drained by those workers,
//     NOT 100k goroutines/FDs.
//   - Per-file state (path -> {bounded channel, owned/enqueued flags,
//     last-activity, per-proc Writer cache}) preserves per-file FIFO
//     order and per-file backpressure without a goroutine per file.
//   - A "ready" queue of files that have buffered events and no owner.
//     Workers pop a ready file, take exclusive ownership (so at most one
//     worker ever touches a file -> per-file order), drain its buffer via
//     the synchronous hlog.Writer, then release it. Open FDs at any
//     instant are bounded by the pool size (each worker opens one file at
//     a time inside WriteEvent).
//   - Idle files are reaped after Config.IdleTimeout; the total number of
//     tracked files is capped at Config.MaxFiles (memory bound).
//
// Degradation is bounded and best-effort (the queue DB is the source of
// truth; DAGMan and friends reconcile from it): if a file's FS hangs, the
// one worker draining it blocks, and that file's buffer fills. Core
// producers then DROP (never block the schedd), non-core producers
// BACKPRESSURE (bounded block) -- see enqueue. You would need Workers
// distinct hung filesystems at once to stall throughput, versus today's
// single-file freeze of the whole daemon. Step 3 (durable/recoverable
// intents in the queue transaction) remains future work; see ROADMAP.md.
package userlog

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	hlog "github.com/bbockelm/golang-htcondor/userlog"
)

// Config tunes the async writer pool. Zero values get sensible defaults
// (see withDefaults); the schedd wires these to SCHEDD_USERLOG_* knobs.
type Config struct {
	// Workers is the fixed number of writer goroutines (total, not per
	// file). Default 32.
	Workers int
	// QueueDepth bounds each file's in-memory event buffer. Default 1024.
	QueueDepth int
	// SubmitTimeout bounds a backpressure (non-core) enqueue when a file's
	// buffer is full before the event is dropped. Default 5s.
	SubmitTimeout time.Duration
	// IdleTimeout reaps a file's state after it has had no activity for this
	// long. Default 60s.
	IdleTimeout time.Duration
	// MaxFiles caps the number of files tracked at once (memory bound). When
	// exceeded, an idle file is evicted, else the event is dropped. Default
	// 8192.
	MaxFiles int
}

func (c Config) withDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = 32
	}
	if c.QueueDepth <= 0 {
		c.QueueDepth = 1024
	}
	if c.SubmitTimeout <= 0 {
		c.SubmitTimeout = 5 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 60 * time.Second
	}
	if c.MaxFiles <= 0 {
		c.MaxFiles = 8192
	}
	return c
}

// eventWriter is the minimal surface of hlog.Writer the workers call. An
// interface so tests can inject a slow/blocking fake (see newWithFactory).
type eventWriter interface {
	WriteEvent(rec hlog.EventRecord) error
}

// writerFactory builds an eventWriter for a (path, job-id) tuple.
type writerFactory func(path string, cluster, proc, subproc int) eventWriter

func defaultWriterFactory(path string, cluster, proc, subproc int) eventWriter {
	return hlog.NewWriter(path, cluster, proc, subproc)
}

// procKey identifies a job proc so one file shared by several jobs (a
// common `log = shared.log`) writes each event with the right header.
type procKey struct {
	cluster, proc, subproc int
}

// queuedEvent is one buffered event awaiting its file's worker.
type queuedEvent struct {
	key procKey
	rec hlog.EventRecord
}

// fileState is the per-log-file buffer and ownership bookkeeping. It is NOT
// a goroutine -- workers borrow it from the ready queue.
type fileState struct {
	path string
	ch   chan queuedEvent // bounded FIFO buffer (cap == Config.QueueDepth)

	mu         sync.Mutex // guards owned, enqueued, lastActive
	owned      bool       // a worker currently owns/drains this file
	enqueued   bool       // present (once) in Manager.ready, not yet claimed
	lastActive time.Time

	// writers caches an hlog.Writer per proc. Only the owning worker touches
	// it (single-owner invariant), so it needs no lock.
	writers map[procKey]eventWriter

	dropped atomic.Int64 // per-file dropped-event counter (observability)
}

// Manager writes user-log events asynchronously via a bounded worker pool.
// It is safe for concurrent use from every schedd goroutine.
type Manager struct {
	// scheddSinful is this schedd's address, used as the SUBMIT event's
	// submit host (C++ uses daemonCore->privateNetworkIpAddr).
	scheddSinful string
	logf         func(format string, args ...any)
	cfg          Config
	newWriter    writerFactory

	mu      sync.Mutex            // guards files + closing
	files   map[string]*fileState // resolved-path -> state
	closing bool

	ready chan *fileState // files with pending events and no owner
	quit  chan struct{}   // closed on shutdown to stop workers/reaper
	wg    sync.WaitGroup  // workers + reaper

	closeOnce sync.Once

	dropped  atomic.Int64 // global dropped-event counter
	lastWarn atomic.Int64 // unix-nanos of last throttled warning
}

// New builds a Manager with the default writer factory and starts its
// worker pool. scheddSinful is the schedd's sinful string (the SUBMIT
// event's "submitted from host"); logf, if non-nil, receives best-effort
// warnings (write errors and drops). Call Close on shutdown to drain.
func New(scheddSinful string, cfg Config, logf func(format string, args ...any)) *Manager {
	return newWithFactory(scheddSinful, cfg, logf, defaultWriterFactory)
}

// newWithFactory is New with an injectable writer factory (test seam).
func newWithFactory(scheddSinful string, cfg Config, logf func(format string, args ...any), factory writerFactory) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	cfg = cfg.withDefaults()
	m := &Manager{
		scheddSinful: scheddSinful,
		logf:         logf,
		cfg:          cfg,
		newWriter:    factory,
		files:        make(map[string]*fileState),
		ready:        make(chan *fileState, cfg.MaxFiles),
		quit:         make(chan struct{}),
	}
	m.wg.Add(cfg.Workers + 1)
	for i := 0; i < cfg.Workers; i++ {
		go m.worker()
	}
	go m.reapLoop()
	return m
}

// --- worker pool -------------------------------------------------------------

// worker pops ready files and drains them until shutdown.
func (m *Manager) worker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.quit:
			return
		case fs := <-m.ready:
			fs.mu.Lock()
			fs.enqueued = false
			fs.owned = true
			fs.mu.Unlock()
			m.drainFile(fs)
		}
	}
}

// drainFile writes every buffered event for fs in FIFO order, then releases
// ownership. ALL filesystem blocking happens here (one file, one worker).
func (m *Manager) drainFile(fs *fileState) {
	for {
		select {
		case ev := <-fs.ch:
			m.write(fs, ev)
		default:
			// Buffer momentarily empty. Re-check under the lock and, if still
			// empty, release ownership atomically with the check so a producer
			// that enqueues concurrently either sees owned==true (and relies on
			// us to drain, since we re-loop) or, if we have released, re-signals
			// the ready queue. No lost wakeups either way.
			fs.mu.Lock()
			if len(fs.ch) == 0 {
				fs.owned = false
				fs.lastActive = time.Now()
				fs.mu.Unlock()
				return
			}
			fs.mu.Unlock()
			// A producer raced in an event; keep draining.
		}
	}
}

// write performs the one synchronous, possibly-blocking filesystem write.
func (m *Manager) write(fs *fileState, ev queuedEvent) {
	w := fs.writers[ev.key]
	if w == nil {
		w = m.newWriter(fs.path, ev.key.cluster, ev.key.proc, ev.key.subproc)
		fs.writers[ev.key] = w
	}
	if err := w.WriteEvent(ev.rec); err != nil {
		m.logf("userlog: %v", err)
	}
}

// reapLoop periodically drops file state that has been idle past IdleTimeout,
// bounding memory when a burst of unique log files goes quiet.
func (m *Manager) reapLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.cfg.IdleTimeout)
	defer t.Stop()
	for {
		select {
		case <-m.quit:
			return
		case now := <-t.C:
			m.mu.Lock()
			for p, fs := range m.files {
				fs.mu.Lock()
				idle := !fs.owned && !fs.enqueued && len(fs.ch) == 0 &&
					now.Sub(fs.lastActive) >= m.cfg.IdleTimeout
				fs.mu.Unlock()
				if idle {
					delete(m.files, p)
				}
			}
			m.mu.Unlock()
		}
	}
}

// --- enqueue -----------------------------------------------------------------

// fileFor returns the (created-on-demand) state for path, or nil when the
// Manager is closing or the file cap is reached and nothing idle can be
// evicted. Lock order is always m.mu -> fileState.mu (never the reverse).
func (m *Manager) fileFor(path string) *fileState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return nil
	}
	if fs, ok := m.files[path]; ok {
		return fs
	}
	if len(m.files) >= m.cfg.MaxFiles && !m.evictIdleLocked() {
		return nil
	}
	fs := &fileState{
		path:       path,
		ch:         make(chan queuedEvent, m.cfg.QueueDepth),
		writers:    make(map[procKey]eventWriter),
		lastActive: time.Now(),
	}
	m.files[path] = fs
	return fs
}

// evictIdleLocked removes one idle file to make room under the cap. Caller
// holds m.mu.
func (m *Manager) evictIdleLocked() bool {
	for p, fs := range m.files {
		fs.mu.Lock()
		idle := !fs.owned && !fs.enqueued && len(fs.ch) == 0
		fs.mu.Unlock()
		if idle {
			delete(m.files, p)
			return true
		}
	}
	return false
}

// enqueue buffers rec for path's file under one of two disciplines:
//
//   - block == false (scheduler-core producers Execute/Terminated/Evicted and
//     the core shadow-exception Held): a NON-BLOCKING send. If the buffer is
//     full (worker stuck on a hung FS) the event is DROPPED and counted; the
//     core returns instantly and scheduling never freezes.
//   - block == true (Submit, the queue-action Held/Released/Aborted, and the
//     reconnect trio): a BOUNDED-BLOCKING send (SubmitTimeout). Blocking the
//     submitter/tool goroutine while that user's writer is behind is the
//     intended backpressure; on timeout the event is dropped (best-effort).
//
// The send happens first, then the file is signaled onto the ready queue if it
// has no owner -- send-before-signal so a worker never sleeps on a non-empty
// file (see drainFile).
func (m *Manager) enqueue(path string, key procKey, rec hlog.EventRecord, block bool) {
	fs := m.fileFor(path)
	if fs == nil {
		m.drop(path, "file cap reached or shutting down")
		return
	}
	ev := queuedEvent{key: key, rec: rec}

	if block {
		t := time.NewTimer(m.cfg.SubmitTimeout)
		defer t.Stop()
		select {
		case fs.ch <- ev:
		case <-t.C:
			fs.dropped.Add(1)
			m.drop(path, "backpressure timeout")
			return
		case <-m.quit:
			fs.dropped.Add(1)
			m.drop(path, "shutting down")
			return
		}
	} else {
		select {
		case fs.ch <- ev:
		default:
			fs.dropped.Add(1)
			m.drop(path, "buffer full")
			return
		}
	}

	// Signal: put the file on the ready queue if no worker owns it and it is
	// not already queued. Exactly one ready-queue slot per file at a time, so
	// the cap==MaxFiles channel never blocks.
	fs.mu.Lock()
	needReady := !fs.owned && !fs.enqueued
	if needReady {
		fs.enqueued = true
	}
	fs.mu.Unlock()
	if needReady {
		select {
		case m.ready <- fs:
		default:
			// Should be unreachable (ready is sized to MaxFiles). Undo the flag
			// so a later event can re-signal, and drop this one.
			fs.mu.Lock()
			fs.enqueued = false
			fs.mu.Unlock()
			m.drop(path, "ready queue full")
		}
	}
}

// drop records a dropped event and emits a throttled (<=1/s) warning. The
// queue DB remains the source of truth, so a dropped user-log event degrades
// condor_wait/DAGMan observability but never loses job state.
func (m *Manager) drop(path, why string) {
	n := m.dropped.Add(1)
	now := time.Now().UnixNano()
	last := m.lastWarn.Load()
	if now-last >= int64(time.Second) && m.lastWarn.CompareAndSwap(last, now) {
		m.logf("userlog: dropping event for %s (%s); %d dropped total — user-log FS slow/hung; queue remains source of truth", path, why, n)
	}
}

// Dropped returns the total number of user-log events dropped due to a
// full/hung log filesystem (observability).
func (m *Manager) Dropped() int64 { return m.dropped.Load() }

// NumFiles returns the number of log files currently tracked (observability).
func (m *Manager) NumFiles() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.files)
}

// --- shutdown ----------------------------------------------------------------

// Close stops accepting new events, drains what is already buffered up to
// ctx's deadline, then stops the worker pool. Events still buffered when ctx
// expires are dropped (the queue DB is authoritative). Safe to call once from
// the schedd shutdown path; idempotent.
func (m *Manager) Close(ctx context.Context) {
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return
	}
	m.closing = true
	// Make sure every file with buffered events is queued for draining.
	for _, fs := range m.files {
		fs.mu.Lock()
		if !fs.owned && !fs.enqueued && len(fs.ch) > 0 {
			fs.enqueued = true
			select {
			case m.ready <- fs:
			default:
				fs.enqueued = false
			}
		}
		fs.mu.Unlock()
	}
	m.mu.Unlock()

	// Wait for buffers to drain, bounded by ctx.
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for m.buffered() > 0 {
		select {
		case <-ctx.Done():
			goto stop
		case <-tick.C:
		}
	}
stop:
	m.closeOnce.Do(func() { close(m.quit) })
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// buffered approximates the number of in-flight events (buffered + being
// written). A file whose worker is stuck on a hung FS counts as busy, so Close
// waits for it only up to ctx's deadline.
func (m *Manager) buffered() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, fs := range m.files {
		n += len(fs.ch)
		fs.mu.Lock()
		if fs.owned {
			n++
		}
		fs.mu.Unlock()
	}
	return n
}

// --- resolution + event methods ----------------------------------------------

// resolve returns the job's absolute log path and proc key, or ok==false when
// the job has no UserLog attribute (the no-op case).
func (m *Manager) resolve(ad *classad.ClassAd) (string, procKey, bool) {
	if ad == nil {
		return "", procKey{}, false
	}
	path, ok := ad.EvaluateAttrString("UserLog")
	if !ok || path == "" {
		return "", procKey{}, false
	}
	if !filepath.IsAbs(path) {
		if iwd, ok := ad.EvaluateAttrString("Iwd"); ok && iwd != "" {
			path = filepath.Join(iwd, path)
		}
	}
	c, _ := ad.EvaluateAttrInt("ClusterId")
	p, _ := ad.EvaluateAttrInt("ProcId")
	return path, procKey{cluster: int(c), proc: int(p), subproc: 0}, true
}

// emitCore enqueues rec with the non-blocking (drop-on-full) discipline for
// producers running on the scheduler core.
func (m *Manager) emitCore(ad *classad.ClassAd, rec hlog.EventRecord) {
	if path, key, ok := m.resolve(ad); ok {
		m.enqueue(path, key, rec, false)
	}
}

// emitBackpressure enqueues rec with the bounded-blocking backpressure
// discipline for non-core producers (submit/action/reconnect goroutines).
func (m *Manager) emitBackpressure(ad *classad.ClassAd, rec hlog.EventRecord) {
	if path, key, ok := m.resolve(ad); ok {
		m.enqueue(path, key, rec, true)
	}
}

// Submit writes the SUBMIT event (000) at job commit. Called from the QMGMT
// commit goroutine AFTER the queue transaction has committed and released its
// collection locks, so this backpressure block never stalls other writers.
func (m *Manager) Submit(ad *classad.ClassAd) {
	m.emitBackpressure(ad, hlog.SubmitEvent(time.Now(), m.scheddSinful))
}

// Execute writes the EXECUTE event (001). executeHost is the startd's
// address (falling back to the slot name); slotName, if set, adds the
// SlotName line. Called from the scheduler core -> non-blocking.
func (m *Manager) Execute(ad *classad.ClassAd, executeHost, slotName string) {
	m.emitCore(ad, hlog.ExecuteEvent(time.Now(), executeHost, slotName))
}

// Terminated writes the JOB_TERMINATED event (005). On a normal exit pass
// bySignal=false and code=exit status; on a signal exit pass bySignal=true
// and code=signal number. Called from the scheduler core -> non-blocking.
func (m *Manager) Terminated(ad *classad.ClassAd, bySignal bool, code int) {
	m.emitCore(ad, hlog.TerminatedEvent(time.Now(), bySignal, code))
}

// Evicted writes the JOB_EVICTED event (004) for a run that was requeued
// (starter death, lease loss, panic requeue). Called from the scheduler
// core -> non-blocking.
func (m *Manager) Evicted(ad *classad.ClassAd, reason string) {
	m.emitCore(ad, hlog.EvictedEvent(time.Now(), reason))
}

// Aborted writes the JOB_ABORTED event (009) on condor_rm.
func (m *Manager) Aborted(ad *classad.ClassAd, reason string) {
	m.emitBackpressure(ad, hlog.AbortedEvent(time.Now(), reason))
}

// Held writes the JOB_HELD event (012) on condor_hold (or a policy hold) from
// the queue-action path -> backpressure. For the scheduler core's
// shadow-exception hold use HeldCore.
func (m *Manager) Held(ad *classad.ClassAd, reason string, code, subcode int) {
	m.emitBackpressure(ad, hlog.HeldEvent(time.Now(), reason, code, subcode))
}

// HeldCore writes the JOB_HELD event (012) from the scheduler-core goroutine
// (a job exhausting its shadow-exception budget). It uses the non-blocking
// core discipline so a hung log FS can never freeze the core; the C++ shadow
// likewise holds such a job from the daemon core.
func (m *Manager) HeldCore(ad *classad.ClassAd, reason string, code, subcode int) {
	m.emitCore(ad, hlog.HeldEvent(time.Now(), reason, code, subcode))
}

// Released writes the JOB_RELEASED event (013) on condor_release.
func (m *Manager) Released(ad *classad.ClassAd, reason string) {
	m.emitBackpressure(ad, hlog.ReleasedEvent(time.Now(), reason))
}

// Disconnected writes the JOB_DISCONNECTED event (022) when the schedd
// loses its starter connection and begins a reconnect.
func (m *Manager) Disconnected(ad *classad.ClassAd, reason, startdName, startdAddr string) {
	if startdName == "" || startdAddr == "" || reason == "" {
		return // C++ formatBody refuses to write with any field empty
	}
	m.emitBackpressure(ad, hlog.DisconnectedEvent(time.Now(), reason, startdName, startdAddr))
}

// Reconnected writes the JOB_RECONNECTED event (023) on a successful
// reconnect.
func (m *Manager) Reconnected(ad *classad.ClassAd, startdName, startdAddr, starterAddr string) {
	if startdName == "" || startdAddr == "" || starterAddr == "" {
		return
	}
	m.emitBackpressure(ad, hlog.ReconnectedEvent(time.Now(), startdName, startdAddr, starterAddr))
}

// ReconnectFailed writes the JOB_RECONNECT_FAILED event (024) when a
// reconnect could not be established.
func (m *Manager) ReconnectFailed(ad *classad.ClassAd, reason, startdName string) {
	if reason == "" || startdName == "" {
		return
	}
	m.emitBackpressure(ad, hlog.ReconnectFailedEvent(time.Now(), reason, startdName))
}
