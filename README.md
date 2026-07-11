# golang-ap

A pure-Go HTCondor **access point**: a `condor_schedd` implemented in Go, meant
to run under `condor_master` as a drop-in replacement for the C++ schedd, with
job execution eventually driven by in-process shadows.

This is being built up in stages. **Stage 1 (current)** is lifecycle only:

- boots like any DaemonCore daemon under `condor_master` (adopts the inherited
  shared-port endpoint, sends `DC_SET_READY`, runs the `DC_CHILDALIVE`
  keepalive loop, handles `SIGTERM`/`SIGHUP`);
- answers the standard DaemonCore commands (`condor_ping`,
  `condor_reconfig -daemon`, `condor_off -daemon`) and registers `RESCHEDULE`
  as a logged no-op;
- periodically advertises a `Scheduler` ClassAd to the collector(s) so it
  appears in `condor_status -schedd`.

No job handling yet: the queue counters in the ad are all zero.

## Layout

- `cmd/schedd/` — the daemon entry point (`main.go`): config, logging,
  security, command server, shared-port listener, `SCHEDD_ADDRESS_FILE`, and
  the run loop, wiring in the scheduler core.
- `internal/sched/` — the single-writer scheduler core: one goroutine owns all
  state and processes a fan-in event channel plus periodic timers. Stage 1's
  only timer is the collector-advertise ticker (`SCHEDD_INTERVAL`).
- `internal/advertise/` — builds the `Scheduler` ad and pushes it to every
  collector in `COLLECTOR_HOST`.
- `integration/` — end-to-end test running the schedd under a real
  `condor_master` + C++ collector.

## Requirements

- Runs under `USE_SHARED_PORT = True` (the daemon adopts the master's inherited
  shared-port endpoint; with shared port off it would try to re-bind and
  crash-loop).
- Pool security must offer `FS` authentication and `AES` crypto — cedar
  implements AES-GCM only.

## Building

```sh
go build ./...
go vet ./...
```

## Tests

The integration test launches a real HTCondor pool, so it needs the HTCondor
binaries (`condor_master`, `condor_status`, `condor_off`, ...) on `PATH`; it
skips otherwise. Point `PATH` at an HTCondor build's `sbin` and `bin`, e.g.:

```sh
export PATH=/path/to/condor/build/release_dir/sbin:/path/to/condor/build/release_dir/bin:$PATH
go test ./integration/ -run Stage1 -v -timeout 600s
```
