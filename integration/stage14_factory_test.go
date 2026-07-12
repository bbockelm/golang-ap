// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage14Factory exercises late materialization (job factories) end to end
// against the pure-Go schedd with stock condor_submit/condor_q:
//
//   - `queue 10` with `max_idle = 3`: stock condor_submit sends a factory (not 10
//     proc ads); the Go schedd's engine materializes lazily, keeping <= max_idle
//     idle at once. We prove laziness by sampling condor_q: the queue never holds
//     all 10 procs at once (bounded by max_idle + running slots), yet all 10 run
//     to completion and land in the history archive.
//   - `queue <fruit> from (5 items)`: each materialized proc reflects its own
//     $(fruit) (a per-item output file), and all 5 complete.
func TestStage14Factory(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ap-schedd14-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	const uidDomain = "golang-ap.test"
	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
# Sweep factories fast so the test does not wait on the backstop timer.
SCHEDD_MATERIALIZE_INTERVAL = 1

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

# One partitionable slot with several CPUs so multiple factory procs run at once.
NUM_CPUS = 6
MEMORY = 3072
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = 10
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = TRUE

# Negotiate frequently so lazily-materialized procs are matched promptly; this is
# the dominant wait in this test, so a short interval keeps the runtime down.
NEGOTIATOR_INTERVAL = 2
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1

SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, scheddBin, uidDomain)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()

	dumpAllLogs := func() {
		for _, name := range []string{"ScheddLog", "NegotiatorLog", "MatchLog", "StartLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
	}
	fail := func(format string, args ...any) {
		t.Helper()
		dumpAllLogs()
		t.Fatalf(format, args...)
	}

	if !waitForFile(filepath.Join(logDir, ".schedd_address"), 60*time.Second) {
		fail("Go schedd never wrote its address file")
	}

	// A short job that records that it ran (per-tag file) and sleeps briefly so
	// the test has a window to sample the bounded idle/running counts.
	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"echo \"ran tag=$1\" > \"ran.$1\"\n" +
		"sleep 1\n" +
		"exit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	// ===== Factory A: queue 10 with max_idle = 3 (prove lazy materialization) =====
	subA := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = false
should_transfer_files = NO
initialdir = %s
arguments = A$(Process)
output = out.A$(Process)
error = err.A$(Process)
request_cpus = 1
request_memory = 128
request_disk = 1024
max_idle = 3
queue 10
`, scriptPath, iwd)
	subAFile := filepath.Join(tmp, "facA.sub")
	if err := os.WriteFile(subAFile, []byte(subA), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", subAFile)
	if err != nil {
		fail("condor_submit factory A failed: %v\n%s", err, out)
	}
	t.Logf("condor_submit A:\n%s", out)
	clusterA := parseClusterID(out)
	if clusterA <= 0 {
		fail("could not parse cluster id for factory A: %q", out)
	}

	// Sample condor_q rapidly: the queue must never hold all 10 procs at once,
	// and idle must stay ~<= max_idle. This is the laziness proof. While procs are
	// outstanding we also exercise stock `condor_q -factory` (checked here, not
	// after the loop, since the factory cluster ad is reclaimed once it drains).
	maxTotal, maxIdle := 0, 0
	sawFactoryAttr := false
	sawFactoryListing := false
	var factoryListingErr string
	deadline := time.Now().Add(40 * time.Second)
	completedSamples := 0
	for time.Now().Before(deadline) {
		row, qerr := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers",
			"-af", "ProcId", "JobStatus", "JobMaterializeMaxIdle",
			"-constraint", fmt.Sprintf("ClusterId==%d", clusterA))
		if qerr != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		lines := nonEmptyLines(row)
		total, idle := 0, 0
		for _, ln := range lines {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			total++
			if f[1] == "1" {
				idle++
			}
			// The factory attr is inherited by proc ads via cluster-ad chaining;
			// its presence proves the cluster ad carries the factory bookkeeping.
			if len(f) >= 3 && f[2] == "3" {
				sawFactoryAttr = true
			}
		}
		if total > maxTotal {
			maxTotal = total
		}
		if idle > maxIdle {
			maxIdle = idle
		}
		// While factory A has procs outstanding its cluster ad is live: stock
		// condor_q -factory must surface exactly that cluster ad (with its
		// JobMaterialize* bookkeeping + computed live counts), never the procs.
		if total > 0 && !sawFactoryListing {
			if ok, detail := checkFactoryListing(cfgFile, clusterA); ok {
				sawFactoryListing = true
			} else {
				factoryListingErr = detail
			}
		}
		if len(lines) == 0 && maxTotal > 0 {
			// Only after we have seen procs materialize does an empty queue mean
			// "drained" (not "not yet materialized").
			completedSamples++
			if completedSamples >= 3 {
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !sawFactoryListing {
		fail("condor_q -factory never listed factory cluster %d while it had procs outstanding: %s", clusterA, factoryListingErr)
	}
	t.Logf("condor_q -factory listed factory cluster %d correctly", clusterA)
	t.Logf("factory A: observed maxTotalInQueue=%d maxIdle=%d (max_idle=3, slots=6)", maxTotal, maxIdle)
	if maxTotal == 0 {
		fail("never observed any materialized procs for factory A")
	}
	if maxTotal >= 10 {
		fail("factory A materialized eagerly: saw %d procs in queue at once (want < 10, bounded by max_idle+slots)", maxTotal)
	}
	if maxIdle > 4 { // max_idle=3, allow 1 sampling slack
		fail("factory A idle count %d exceeded max_idle=3 (not bounded)", maxIdle)
	}
	if !sawFactoryAttr {
		t.Logf("warning: never sampled JobMaterializeMaxIdle==3 on a proc ad (timing); relying on lazy-count proof")
	}

	// All 10 must eventually leave the queue (complete).
	if !waitClusterEmpty(cfgFile, clusterA, 90*time.Second) {
		fail("factory A: not all 10 procs completed / left the queue")
	}
	t.Logf("factory A: all 10 procs completed")

	// ===== Factory B: queue <fruit> from (5 items) — per-item materialization ====
	fruits := []string{"apple", "banana", "cherry", "date", "elderberry"}
	subB := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = false
should_transfer_files = NO
initialdir = %s
arguments = $(fruit)
output = out.$(fruit)
error = err.$(fruit)
request_cpus = 1
request_memory = 128
request_disk = 1024
max_idle = 2
queue fruit from (
%s
)
`, scriptPath, iwd, strings.Join(fruits, "\n"))
	subBFile := filepath.Join(tmp, "facB.sub")
	if err := os.WriteFile(subBFile, []byte(subB), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = runTool(cfgFile, 60*time.Second, "condor_submit", subBFile)
	if err != nil {
		fail("condor_submit factory B failed: %v\n%s", err, out)
	}
	t.Logf("condor_submit B:\n%s", out)
	clusterB := parseClusterID(out)
	if clusterB <= 0 {
		fail("could not parse cluster id for factory B: %q", out)
	}
	// Each item must produce its own per-fruit "ran.<fruit>" file, proving each
	// materialized proc expanded its own $(fruit) and ran to completion. Waiting
	// on the files (not an empty queue) avoids treating a not-yet-materialized
	// factory as "done".
	deadlineB := time.Now().Add(120 * time.Second)
	for _, fr := range fruits {
		p := filepath.Join(iwd, "ran."+fr)
		for {
			data, rerr := os.ReadFile(p)
			if rerr == nil {
				if want := "ran tag=" + fr + "\n"; string(data) != want {
					fail("factory B: %s = %q, want %q", p, string(data), want)
				}
				break
			}
			if time.Now().After(deadlineB) {
				fail("factory B: per-item file %s never appeared (item did not materialize/run)", p)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if !waitClusterEmpty(cfgFile, clusterB, 90*time.Second) {
		fail("factory B: procs did not all leave the queue after completing")
	}
	t.Logf("factory B: all 5 items materialized with distinct $(fruit) and completed")

	// ===== History: stop the schedd and verify all 15 jobs archived Completed ====
	runCondor(t, cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitGone(binName, 30*time.Second) {
		fail("schedd did not exit after condor_off")
	}
	histDir := filepath.Join(h.GetSpoolDir(), "history")
	arc, err := collections.OpenArchive(collections.ArchiveOptions{Dir: histDir})
	if err != nil {
		fail("opening history archive at %s: %v", histDir, err)
	}
	defer func() { _ = arc.Close() }()
	for _, tc := range []struct {
		cluster, n int
	}{{clusterA, 10}, {clusterB, 5}} {
		q, perr := vm.Parse(fmt.Sprintf("ClusterId == %d", tc.cluster))
		if perr != nil {
			t.Fatal(perr)
		}
		count := 0
		for ad := range arc.Query(q) {
			count++
			if st, _ := ad.EvaluateAttrInt("JobStatus"); st != 4 {
				fail("history record for cluster %d has JobStatus %d, want 4 (Completed)", tc.cluster, st)
			}
		}
		if count != tc.n {
			fail("cluster %d: history holds %d Completed records, want %d", tc.cluster, count, tc.n)
		}
	}
	t.Logf("history archive holds all 15 completed factory jobs (10 + 5)")

	if t.Failed() {
		dumpAllLogs()
	}
}

// TestWinddownFailureStillCompletes is the HTCONDOR-3828 regression test. It
// pins down the ROOT CAUSE of the intermittent stage14 failure: a factory proc
// that ran to completion but whose shadow's best-effort claim wind-down
// (JOB_DONE / RELEASE_CLAIM to the startd) failed -- a transient startd RPC
// timeout under load -- was treated as a shadow FAILURE and requeued, then, after
// MAX_SHADOW_EXCEPTIONS such failures, HELD. A held/looping proc never leaves the
// queue, so waitClusterEmpty timed out ("procs did not all leave").
//
// We force the wind-down failure deterministically (GOLANG_AP_SHADOW_WINDDOWN_FAIL
// hook) with MAX_SHADOW_EXCEPTIONS=1, so on the buggy code the job would be held
// after its first run. The fix completes a job whenever it produced an exit
// result, regardless of a wind-down error, so the job must reach Completed and
// leave the queue. (Pre-fix, this test fails: the job is Held, not Completed.)
func TestWinddownFailureStillCompletes(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ap-schedd14b-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	const uidDomain = "golang-ap.test"
	// Force the completed job's (cluster 1, proc 0) wind-down to fail, and hold
	// after a single shadow exception so the buggy behavior would be an immediate,
	// deterministic hold rather than a slow requeue loop.
	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
GOLANG_AP_SHADOW_WINDDOWN_FAIL = 1.0
MAX_SHADOW_EXCEPTIONS = 1

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

NUM_CPUS = 2
MEMORY = 2048
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = 10

NEGOTIATOR_INTERVAL = 2
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1

SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, scheddBin, uidDomain)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()
	fail := func(format string, args ...any) {
		t.Helper()
		for _, name := range []string{"ScheddLog", "NegotiatorLog", "StartLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		t.Fatalf(format, args...)
	}
	if !waitForFile(filepath.Join(logDir, ".schedd_address"), 60*time.Second) {
		fail("Go schedd never wrote its address file")
	}

	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho ran > ran.out\nexit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = false
should_transfer_files = NO
initialdir = %s
output = out.0
error = err.0
request_cpus = 1
request_memory = 128
request_disk = 1024
queue 1
`, scriptPath, iwd)
	subFile := filepath.Join(tmp, "job.sub")
	if err := os.WriteFile(subFile, []byte(sub), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", subFile)
	if err != nil {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster != 1 {
		// The hook targets 1.0; the harness starts from a fresh spool so the first
		// cluster is 1. Guard against a surprise.
		fail("expected first cluster id 1 (wind-down hook targets 1.0), got %d", cluster)
	}

	// The job must run (its script writes ran.out) and then, despite the forced
	// wind-down failure, be COMPLETED and leave the queue -- not held, not looping.
	if !waitForFile(filepath.Join(iwd, "ran.out"), 60*time.Second) {
		fail("job never ran (ran.out missing)")
	}
	if !waitClusterEmpty(cfgFile, cluster, 60*time.Second) {
		st, _ := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ProcId", "JobStatus", "HoldReasonCode",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
		fail("job did not leave the queue after completing (wind-down failure requeued/held it). condor_q:\n%s", st)
	}

	runCondor(t, cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitGone(binName, 30*time.Second) {
		fail("schedd did not exit after condor_off")
	}
	histDir := filepath.Join(h.GetSpoolDir(), "history")
	arc, err := collections.OpenArchive(collections.ArchiveOptions{Dir: histDir})
	if err != nil {
		fail("opening history archive at %s: %v", histDir, err)
	}
	defer func() { _ = arc.Close() }()
	q, perr := vm.Parse(fmt.Sprintf("ClusterId == %d", cluster))
	if perr != nil {
		t.Fatal(perr)
	}
	count, completed := 0, 0
	for ad := range arc.Query(q) {
		count++
		if st, _ := ad.EvaluateAttrInt("JobStatus"); st == 4 {
			completed++
		} else {
			fail("history record for cluster %d has JobStatus %d, want 4 (Completed)", cluster, st)
		}
	}
	if count != 1 || completed != 1 {
		fail("cluster %d: history holds %d records (%d Completed), want exactly 1 Completed", cluster, count, completed)
	}
	t.Logf("job completed despite forced claim wind-down failure (HTCONDOR-3828 regression)")
}

// checkFactoryListing runs stock `condor_q -factory` once and verifies it returns
// exactly the factory CLUSTER ad for `cluster` (proc -1, normally hidden), with
// its JobMaterialize* bookkeeping and the computed live-proc counts -- and NOT the
// individual materialized procs (which have a defined ProcId, filtered out by the
// tool's `ProcId is undefined` requirement). Returns (false, detail) when the
// listing is not yet exactly right, so the caller can retry while the factory is
// mid-flight. condor_q -factory sends IncludeClusterAd plus a Requirements of
// `(ProcId is undefined) && (JobMaterializeDigestFile isnt undefined)`.
func checkFactoryListing(cfgFile string, cluster int) (bool, string) {
	out, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-factory",
		"-af", "ClusterId", "JobMaterializeMaxIdle", "JobMaterializeNextProcId",
		"JobsIdle", "JobsRunning", "JobMaterializeDigestFile")
	if err != nil {
		return false, fmt.Sprintf("condor_q -factory error: %v\n%s", err, out)
	}
	lines := nonEmptyLines(out)
	if len(lines) != 1 {
		return false, fmt.Sprintf("expected exactly 1 factory row, got %d:\n%s", len(lines), out)
	}
	f := strings.Fields(lines[0])
	if len(f) < 6 {
		return false, fmt.Sprintf("factory row has %d fields, want >=6: %q", len(f), lines[0])
	}
	if f[0] != fmt.Sprintf("%d", cluster) {
		return false, fmt.Sprintf("ClusterId %q, want %d: %q", f[0], cluster, lines[0])
	}
	if f[1] != "3" { // JobMaterializeMaxIdle (max_idle=3 for factory A)
		return false, fmt.Sprintf("JobMaterializeMaxIdle=%q, want 3: %q", f[1], lines[0])
	}
	// JobsIdle / JobsRunning are computed live counts on the cluster ad.
	if f[3] == "undefined" || f[4] == "undefined" {
		return false, fmt.Sprintf("missing computed JobsIdle/JobsRunning: %q", lines[0])
	}
	// The digest file path proves the factory bookkeeping is present.
	if !strings.Contains(lines[0], ".digest") {
		return false, fmt.Sprintf("row lacks a digest file path: %q", lines[0])
	}
	return true, ""
}

// waitClusterEmpty polls condor_q until the given cluster has no jobs left.
func waitClusterEmpty(cfgFile string, cluster int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ProcId",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
		if err == nil && len(nonEmptyLines(row)) == 0 {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
