# golang-ap roadmap

Open, post-MVP work items — most load-bearing first. Shipped features (runs
under condor_master; claims/activates real startd slots; stock
submit/q/hold/rm; negotiation with RRL batching; reconnect across restart;
`-spool`; async off-core user-log writes with backpressure; supervision/chaos)
are in `git log`, not here.

## 1. Privilege separation — running work as separate Unix users

**Where we are.** The schedd is effectively single-uid. `UID_DOMAIN` is only a
string suffix that forms the `User` attribute; `Owner`/`User` is enforced as
*authorization*, never mapped to a Unix uid. Spool sandboxes and transferred
files are written with plain `os.OpenFile` as the one schedd process uid, so in
a shared pool every user's job data is owned by the condor account — a
cross-user exposure problem. In-process goroutine-shadows can't each hold a uid
(a process has one euid), so per-shadow user switching needs help.

**What already exists (golang-htcondor `droppriv`).** On **Linux**, `runAsUser`
does `runtime.LockOSThread()` + `setfsuid`/`setfsgid` so a single goroutine
performs filesystem operations as a specific user without affecting other
goroutines, surfaced as `Open/OpenFile/MkdirAll/Chown(user, …)`. On **non-Linux
it is a stub** (no switching). It covers file ops only — no process launching,
no FD passing.

**Plan.**
- **Abstraction layer.** Define a backend-neutral privilege-separation interface
  in terms of concrete, RPC-able operations (open→FD, mkdir, chown, stat,
  remove, rename, and launch-process-as-user) rather than arbitrary Go
  closures — a closure can't cross a helper process. Two backends behind it:
  - **Native (Linux, privileged):** the existing thread-lock + `setfsuid` path,
    plus process launch via `SysProcAttr.Credential`. Expand to cover process
    launching.
  - **Pooled helper (non-Linux e.g. darwin, and a forced test mode):** a fixed
    number of simultaneous helper processes, one per UID/GID, driven over an RPC
    the same interface maps onto. Helpers open files under the target
    credentials and **pass FDs back** (SCM_RIGHTS) so the parent does the I/O on
    a correctly-owned descriptor; they can also fork/exec processes as the user.
    The parent reaps idle/unneeded helpers; helpers exit automatically if the
    parent dies. A mode uses this path **even when not actually switching users**
    so unprivileged CI exercises the RPC/pool/FD machinery.
- **Adapt schedd/shadow to the abstraction.** Route the spool sandbox writes
  (`internal/spool`) and file-transfer landing (`shadow/transfer.go`) through it
  so input/output/executable files land owned by the job owner, and chown spool
  dirs appropriately. This is the concrete correctness fix a shared AP needs.
- Fuller shadow-level isolation (out-of-process setuid shadows for the strict
  multi-user case vs. goroutine-shadows for the personal-AP fast path) is a
  later sub-item; the FS-ownership fix above is the first, highest-value step.

## 2. Job policy expressions

`periodic_hold` / `periodic_release` / `periodic_remove`, `on_exit_hold` /
`on_exit_remove`, `max_retries`, and allowed-job-duration limits — evaluated
per job on a timer (the C++ `PERIODIC_EXPR_INTERVAL` loop). The schedd runs a
fixed state machine today, so jobs can't retry on failure, self-hold on a bad
exit code, or time out. Core SchedD behavior; self-contained.

## 3. Late materialization / job factories

Submitting 100k jobs materializes 100k proc ads up front (memory + a giant
SUBMIT/QMGMT burst). HTCondor's job factory materializes lazily up to
`max_idle`/`max_materialize`. The QMGMT ops (`SetJobFactory`,
`SendMaterializeData`) are currently stubbed to close the connection politely,
and the collections engine already has the factory-attr hooks — so this is
building the materialization engine on scaffolding that exists. Directly
improves large-cluster scale.

## 4. Remote-submit auth & per-attribute authorization

Everything is tested with FS auth (same host). A shared AP needs IDTOKENS /
SCITOKENS submit (cedar implements the verify side), the QMGMT
protected-attribute / superuser model (users can't set `Owner`, accounting
attrs, or protected fields on each other's jobs), and secure spool file
permissions. Pairs with #1.

## 5. Observability & operability

The schedd exposes no metrics (the collector already has a Prometheus surface
to copy), no statistics ad, and the new user-log drop/backpressure counters
aren't surfaced. Add: a schedd stats ad + Prometheus endpoint, exposure of the
drop/queue-depth counters, `D_*` debug categories, `condor_q -better-analyze`
support, and live `SIGHUP` reconfig of the `SCHEDD_*` knobs (several are read
only at startup today).

## 6. Durable / recoverable user-log writes (was item #1 step 3)

The queue commit and the log write are independent, so a crash between them
leaves the log and queue disagreeing (a missing SUBMIT/EXECUTE/TERMINATED, or a
duplicate on naive replay). Durable design: write the *intent* to emit each
event into the queue transaction (fast local disk = source of truth), mark it
flushed once the real write lands, replay unflushed intents on restart.
Deferred because consumers (DAGMan, condor_wait) reconcile from the queue, so a
degraded log loses observability, never job state. Expensive/racy recovery
(idempotent replay against files users can truncate/rotate) is why it's last.
