# golang-ap roadmap

Post-MVP work items, most load-bearing first.

## 1. Decouple user-log writes from the scheduler core (+ make them durable)

**Status: steps 1 & 2 DONE** (async off-core writes + backpressure, in
`internal/userlog`). Step 3 (durable/recoverable intents) remains future work;
it is safely deferrable because everything that watches the user log (DAGMan,
condor_wait) reconciles from the queue DB, which is the source of truth — so a
dropped/degraded user-log event under extreme FS congestion loses observability,
never job state.

**Why.** User job logs (`log = ...`) routinely live on slow, flaky shared
filesystems (NFS or worse), while the queue database sits on fast local disk.
This asymmetry is a well-known source of schedd lockups in production HTCondor:
a stalled log write on a bad mount freezes the daemon. We already hit the same
failure *class* once (an unbounded collector-advertise dial blocking the core;
fixed) — user-log writes are the remaining instance, and the one the HTCondor
dev team has historically been bitten by.

**Current behavior.** `internal/userlog.Manager.emit` does a synchronous
`open(O_APPEND)` + `flock` + `write` + `close` to the user's log path. Call
sites by goroutine:

- **On the scheduler-core goroutine (acute):** EXECUTE, TERMINATED, EVICTED
  (`sched.handleStarted` / `handleExited`). A hung log FS here stalls the single
  goroutine that reaps finished jobs and drives all scheduling — a full daemon
  freeze, exactly like the advertise bug.
- On the QMGMT commit goroutine: SUBMIT. A slow FS blocks that one submitter's
  `condor_submit` and ties up a network goroutine, but does not freeze the core.
- On the actOnJobs network goroutine: HELD / RELEASED / ABORTED.
- On per-job reconnect goroutines: DISCONNECTED / RECONNECTED / RECONNECT_FAILED.

**Step 1 — get log writes off the core (and off any shared serialization
point). [DONE]** The core (and every handler) enqueues an event and returns; a
FIXED, BOUNDED pool of writer goroutines (default 32, `SCHEDD_USERLOG_WORKERS`)
performs the blocking FS I/O. Scheduling never blocks on a user's log
filesystem. Implementation note: the pool work-steals over a "ready" queue of
files-with-pending-events, taking exclusive per-file ownership so per-file (and
thus per-job) FIFO order is preserved; goroutines and open FDs are bounded by
the pool size regardless of file count (a `log = job_$(Process).log` cluster of
100k jobs is 100k tiny buffers, NOT 100k goroutines/FDs). See
`internal/userlog/manager.go`.

**Step 2 — backpressure and per-submitter fairness. [DONE]** Writes are bounded
**per log file** (`SCHEDD_USERLOG_QUEUE_DEPTH`, default 1024) with a global file
cap (`SCHEDD_USERLOG_MAX_FILES`) and idle reaping (`SCHEDD_USERLOG_IDLE_TIMEOUT`)
for memory bounds. Two enqueue disciplines:

- **Core producers (EXECUTE/TERMINATED/EVICTED, and the core shadow-exception
  HELD): non-blocking.** If the file's buffer is full (a worker wedged on a hung
  FS), the event is DROPPED and counted with a throttled warning; the core
  returns instantly. Justified by the queue being the source of truth.
- **Non-core producers (SUBMIT, action HELD/RELEASED/ABORTED, reconnect trio):
  bounded backpressure.** A blocking enqueue bounded by
  `SCHEDD_USERLOG_BACKPRESSURE_TIMEOUT` (default 5s) — blocking that one
  submitter/tool while their writer is behind, without touching anyone else — then
  drop-with-warning on timeout so a hung FS can never tie a goroutine up forever.
  SUBMIT is the primary backpressure point, and its enqueue happens AFTER the
  queue transaction commits and releases its collection locks (see the CRITICAL
  note in `internal/queue/txn.go`), so a slow log FS throttles only that submitter,
  never stalls commits for others on the same shard.

Degradation is bounded: you would need `SCHEDD_USERLOG_WORKERS` distinct hung
filesystems at once to stall throughput, versus the old single-file freeze of the
whole daemon. Terminal events are best-effort (queue authoritative), not
guaranteed — the relaxation that makes the non-blocking core path safe.

The remaining relaxation vs. the original "never drop terminal events" wording:
under a genuinely hung FS we DO drop (with a counter + warning) rather than
freeze or grow memory unboundedly. This is the explicit best-effort semantics —
consumers reconcile from the queue.

**Step 3 (harder, deferred) — transactional / recoverable log writes.** Today
the queue commit and the log write are independent, so a crash between them
leaves the log and the queue disagreeing (a missing SUBMIT/EXECUTE/TERMINATED,
or a duplicate on naive replay). The durable design: write the *intent* to emit
each event into the queue transaction (fast local disk = source of truth), mark
it flushed once the real write to the user's log lands, and on restart replay
any unflushed intents. The user log becomes a best-effort projection of durable
queue state.

Caveat (why this is deferred): recovery is expensive and racy. Idempotent replay
means detecting already-written events in a file we do not control — users can
truncate, rotate, or point several jobs at one log — and reconciliation on
restart re-reads potentially many slow, remote log files. Worth doing, but only
after steps 1–2, which remove the acute freeze risk on their own.

## 2. (add future items here)
