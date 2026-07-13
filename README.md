# golang-ap

A pure-Go HTCondor **access point** — a `condor_schedd` (plus its shadows)
implemented in Go, run under `condor_master` as a drop-in replacement for the
C++ `condor_schedd`. It speaks the stock HTCondor wire protocols, so ordinary
users keep using `condor_submit`, `condor_q`, `condor_rm`, and friends
unchanged, and it matchmakes against the stock C++ `condor_negotiator`,
`condor_startd`, and `condor_starter`.

Shadows run as **supervised goroutines inside the schedd process** rather than
separate `condor_shadow` processes; a shadow cannot crash the daemon. The job
queue and history are kept in an embedded, crash-safe ClassAd store (the
`classad/collections` engine) instead of `job_queue.log` and the flat history
file.

## What works

Vanilla-universe jobs run end-to-end — submit → negotiate → claim a real C++
startd slot → in-process shadow runs the job (with file transfer) → complete →
history. Specifically:

- **Stock client tools:** `condor_submit` (incl. `-spool`), `condor_q`
  (`-factory` supported), `condor_rm` / `condor_hold` / `condor_release`,
  `condor_qedit`, `condor_transfer_data`, `condor_reschedule`,
  `condor_reconfig`, `condor_off`, `condor_ping`.
- **Vanilla universe with file transfer** (`transfer_input_files` /
  output / executable), including `should_transfer_files = NO` on a shared FS.
- **Matchmaking** against the stock negotiator/startd/starter, including
  partitionable slots and resource-request-list (batched) negotiation.
- **Reconnect across a schedd restart:** running jobs are reattached, not
  requeued, when the schedd bounces (`condor_restart`, upgrades).
- **Late materialization / job factories:** a large `queue N` or
  `queue … from <items>` submits a compact factory; procs materialize lazily up
  to `max_idle`, capped by `max_materialize`.
- **Job policy expressions:** `periodic_hold` / `periodic_release` /
  `periodic_remove`, `on_exit_hold` / `on_exit_remove`, and the pool-wide
  `SYSTEM_PERIODIC_*`.
- **User job log** (`log = …`) written in the standard format, so `condor_wait`
  and log-watchers work.
- **Multi-user safety:** per-attribute authorization (immutable / protected /
  secure attributes, per-job ownership), and — where the schedd runs
  privileged — spooled and transferred files land owned by the job owner.
- **Remote submit auth:** `IDTOKENS` (and `SCITOKENS`) in addition to `FS`; the
  token identity becomes the job `Owner`.
- **Observability:** a Prometheus `/metrics` endpoint, an enriched `Scheduler`
  statistics ad (`condor_status -schedd -long`), and live `condor_reconfig` of
  the `SCHEDD_*` knobs below.

### Not yet supported

DAGMan, grid/Condor-C, local/scheduler universe, container/docker universe, and
custom/GPU resource requests beyond cpu/memory/disk are not implemented.
Flocking to multiple pools is not supported. The user log is written
best-effort (the queue is the authoritative record). Per-user file ownership
requires a privileged schedd; run as a single-user personal AP otherwise.

## Requirements

- **HTCondor** binaries for the rest of the pool (master, collector,
  negotiator, startd, starter) and the client tools. Tested against a recent
  (24.x/25.x) build.
- **`USE_SHARED_PORT = True`.** The daemon adopts the master's inherited
  shared-port endpoint; with shared port off it would try to re-bind its
  command port and crash-loop.
- **Security:** the pool must offer an authentication method this daemon
  implements — `FS` (same host), `IDTOKENS`/`SCITOKENS` (remote) — and **`AES`**
  crypto (AES-GCM is the only cipher implemented). The claim/file-transfer
  match-password sessions used with the startd/starter are handled
  automatically.

## Install

Build the daemon and point `condor_master` at it as the pool's `SCHEDD`:

```sh
go build -o /opt/condor/sbin/golang-ap-schedd ./cmd/schedd
```

Minimal config (drop-in under an otherwise normal HTCondor config):

```
# Run the Go schedd as the pool's SCHEDD, under shared port.
SCHEDD          = /opt/condor/sbin/golang-ap-schedd
USE_SHARED_PORT = True
DAEMON_LIST     = $(DAEMON_LIST)          # keep SCHEDD in the list

# Auth this daemon implements. FS for same-host tools; add IDTOKENS for remote.
SEC_DEFAULT_AUTHENTICATION         = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, IDTOKENS
SEC_DEFAULT_CRYPTO_METHODS         = AES

# Optional: expose Prometheus metrics.
SCHEDD_METRICS_ADDRESS = :9721
```

For **remote token submit**, list `IDTOKENS` before `FS` in
`SEC_DEFAULT_AUTHENTICATION_METHODS` (the server picks the first of *its*
methods the client also offers, and same-host clients always also offer FS),
and configure the pool's token trust (`SEC_TOKEN_POOL_SIGNING_KEY_FILE` /
`TRUST_DOMAIN`) as usual.

The daemon writes its address to `SCHEDD_ADDRESS_FILE` and advertises to
`COLLECTOR_HOST`, so it appears in `condor_status -schedd` once running.

`condor_reconfig -daemon schedd` re-reads the `SCHEDD_*` knobs below live.

## Storage

Everything the schedd owns lives under `$(SPOOL)`:

- `$(SPOOL)/queue` — the live job queue (embedded crash-safe ClassAd store; no
  `job_queue.log`).
- `$(SPOOL)/history` — completed/removed jobs (append-only archive; queryable,
  not the flat C++ history file).
- `$(SPOOL)/<cluster%10000>/…` — per-job sandbox spool for `-spool` submits.

## Configuration

Standard knobs (`SPOOL`, `COLLECTOR_HOST`, `SCHEDD_NAME`, `UID_DOMAIN`,
`MAX_JOBS_RUNNING`, `QUEUE_SUPER_USERS`, `IMMUTABLE_JOB_ATTRS` /
`PROTECTED_JOB_ATTRS` / `SECURE_JOB_ATTRS`, `QUEUE_ALL_USERS_TRUSTED`,
`SYSTEM_PERIODIC_HOLD` / `_RELEASE` / `_REMOVE`, `ALIVE_INTERVAL`,
`JOB_DEFAULT_LEASE_DURATION`, `MAX_SHADOW_EXCEPTIONS`, the `SEC_*` family) are
honored with their usual meaning.

Daemon-specific knobs:

| Knob | Default | Meaning |
|---|---|---|
| `SCHEDD_METRICS_ADDRESS` | *(off)* | `host:port` to serve Prometheus `/metrics` (also `-metrics` flag). |
| `SCHEDD_INTERVAL` | 300s | How often the Scheduler/Submitter ads are advertised. |
| `PERIODIC_EXPR_INTERVAL` | 60s | How often `periodic_*` / `SYSTEM_PERIODIC_*` are evaluated. |
| `SCHEDD_MATERIALIZE_INTERVAL` | 5s | Backstop timer for factory materialization (also driven by job events). |
| `SCHEDD_LEASE_SWEEP_INTERVAL` | 30s | Claim-lease sweep / self-renewal interval. |
| `SCHEDD_RECONNECT` | true | Reattach running jobs across a restart; false = requeue on shutdown (old behavior). |
| `SCHEDD_SHUTDOWN_DRAIN_GRACE` | 10s | Time to drain shadows on graceful shutdown. |
| `SCHEDD_PRIVSEP_MODE` | native | Privilege-separation backend for per-owner file I/O: `native` (Linux `setfsuid`), `pool` (helper processes, e.g. macOS/multi-user), `auto`. |
| `SCHEDD_PRIVSEP_MAX_HELPERS` / `_IDLE_TIMEOUT` / `_FORCE_UNPRIVILEGED` | 16 / 60s / false | Pool-backend tuning (last is a test/dev knob). |
| `SCHEDD_USERLOG_WORKERS` | 32 | Worker goroutines writing user job logs (bounded; not one per file). |
| `SCHEDD_USERLOG_QUEUE_DEPTH` / `_MAX_FILES` / `_IDLE_TIMEOUT` | 1024 / 8192 / 60s | User-log buffer/file bounds. |
| `SCHEDD_USERLOG_BACKPRESSURE_TIMEOUT` | 5s | How long a submit blocks when a user's (slow) log FS is backed up before dropping the event (best-effort log). |

## Building & tests

```sh
go build ./...
go vet ./...
```

The integration tests launch a real personal HTCondor pool, so they need the
HTCondor binaries on `PATH` (they skip otherwise):

```sh
export PATH=/path/to/condor/build/release_dir/sbin:/path/to/condor/build/release_dir/bin:$PATH
go test ./... -parallel 4 -timeout 900s
```
