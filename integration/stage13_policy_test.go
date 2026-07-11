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

// stage13 exercises HTCondor job policy (ROADMAP #2): periodic + on-exit
// expressions that let a job self-manage. Each test stands up the pure-Go
// schedd as the pool's SCHEDD with stock C++ master/collector/negotiator/startd
// and a SHORT PERIODIC_EXPR_INTERVAL, submits a job with the policy under test,
// and asserts the resulting queue/slot/history transition.

// policyPool builds the Go schedd and stands up a harness with a short periodic
// interval. startExpr is the startd START expression: "TRUE" to let jobs run,
// "FALSE" to keep them Idle (so periodic policy on idle jobs can be observed
// without the negotiator matching them). Returns the harness plus the schedd's
// pid-tagged binary basename (for waitGone).
func policyPool(t *testing.T, tag, startExpr string) (*htcondor.CondorTestHarness, string) {
	t.Helper()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_status", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}
	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ap-schedd13-%s-%d", tag, os.Getpid())
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

# Evaluate periodic policy aggressively so the tests stay fast.
PERIODIC_EXPR_INTERVAL = 2

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

NUM_CPUS = 1
MEMORY = 512
START = %s
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = 10
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = FALSE

NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1

SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, scheddBin, uidDomain, startExpr)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	if !waitForFile(filepath.Join(h.GetLogDir(), ".schedd_address"), 60*time.Second) {
		h.Shutdown()
		t.Fatal("Go schedd never wrote its address file")
	}
	return h, binName
}

// writeSleepJob writes a submit file for a job that sleeps then exits with the
// given code, plus any extra submit lines (the policy expressions). Returns the
// submit file path.
func writeSleepJob(t *testing.T, dir string, sleepSecs, exitCode int, extraLines string) string {
	t.Helper()
	iwd := filepath.Join(dir, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nsleep %d\nexit %d\n", sleepSecs, exitCode)
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
initialdir = %s
output = job.out
error = job.err
request_cpus = 1
request_memory = 128
request_disk = 1024
%s
queue
`, scriptPath, iwd, extraLines)
	subPath := filepath.Join(dir, "job.sub")
	if err := os.WriteFile(subPath, []byte(sub), 0o644); err != nil {
		t.Fatal(err)
	}
	return subPath
}

// afField returns one condor_q autoformat field for a job (trimmed), or "".
func afField(cfgFile string, cluster, proc int, attr string) string {
	out, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", attr,
		"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==%d", cluster, proc))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// historyStatus stops the schedd and returns the archived job's JobStatus and a
// getter for any int attribute on the record.
func historyRecord(t *testing.T, h *htcondor.CondorTestHarness, binName, cfgFile string, cluster int) map[string]int64 {
	t.Helper()
	runCondor(t, cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitGone(binName, 30*time.Second) {
		t.Fatal("schedd did not exit after condor_off")
	}
	histDir := filepath.Join(h.GetSpoolDir(), "history")
	arc, err := collections.OpenArchive(collections.ArchiveOptions{Dir: histDir})
	if err != nil {
		t.Fatalf("opening history archive: %v", err)
	}
	defer func() { _ = arc.Close() }()
	q, err := vm.Parse(fmt.Sprintf("ClusterId == %d && ProcId == 0", cluster))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	found := false
	for ad := range arc.Query(q) {
		found = true
		for _, attr := range []string{"JobStatus", "NumJobCompletions", "JobRunCount", "ExitCode"} {
			if v, ok := ad.EvaluateAttrInt(attr); ok {
				out[attr] = v
			}
		}
	}
	if !found {
		t.Fatalf("job %d.0 not found in history archive %s", cluster, histDir)
	}
	return out
}

// TestStage13PeriodicRemoveIdle: an idle job with periodic_remove =
// (time()-QDate) > N leaves the queue after ~N seconds and lands in history as
// Removed (status 3). START=FALSE keeps the job Idle so nothing runs it.
func TestStage13PeriodicRemoveIdle(t *testing.T) {
	t.Parallel()
	h, binName := policyPool(t, "premove", "FALSE")
	defer h.Shutdown()
	cfgFile := h.GetConfigFile()

	sub := writeSleepJob(t, t.TempDir(), 0, 0, "periodic_remove = (time() - QDate) > 3")
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", sub)
	if err != nil {
		t.Fatalf("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		t.Fatalf("could not parse cluster id: %q", out)
	}
	if !waitForJobStatus(cfgFile, cluster, 0, "1", 30*time.Second) {
		t.Fatalf("job %d.0 never showed Idle", cluster)
	}
	if !waitJobGone(cfgFile, cluster, 60*time.Second) {
		t.Fatalf("job %d.0 was never removed by periodic_remove", cluster)
	}
	rec := historyRecord(t, h, binName, cfgFile, cluster)
	if rec["JobStatus"] != 3 {
		t.Fatalf("history JobStatus = %d, want 3 (Removed)", rec["JobStatus"])
	}
	t.Logf("periodic_remove: job %d.0 removed and archived with JobStatus=3", cluster)
}

// TestStage13PeriodicHoldRunning: periodic_hold fires on a RUNNING job; the job
// is Held (status 5, HoldReason set) AND its slot is released (returns to
// Unclaimed), proving the running-job vacate path fires.
func TestStage13PeriodicHoldRunning(t *testing.T) {
	t.Parallel()
	h, _ := policyPool(t, "phold", "TRUE")
	defer h.Shutdown()
	cfgFile := h.GetConfigFile()

	// Long sleep so the job is comfortably Running when the hold fires ~5s in.
	sub := writeSleepJob(t, t.TempDir(), 120, 0,
		"periodic_hold = (JobStatus == 2) && ((time() - JobCurrentStartDate) > 4)\n"+
			`periodic_hold_reason = "held by periodic policy test"`)
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", sub)
	if err != nil {
		t.Fatalf("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		t.Fatalf("could not parse cluster id: %q", out)
	}
	// Wait for Running.
	if !waitForJobStatus(cfgFile, cluster, 0, "2", 150*time.Second) {
		t.Fatalf("job %d.0 never ran", cluster)
	}
	// Wait for Held (status 5).
	if !waitForJobStatus(cfgFile, cluster, 0, "5", 60*time.Second) {
		t.Fatalf("job %d.0 was never held by periodic_hold (status=%s)",
			cluster, afField(cfgFile, cluster, 0, "JobStatus"))
	}
	reason := afField(cfgFile, cluster, 0, "HoldReason")
	if !strings.Contains(reason, "held by periodic policy test") {
		t.Fatalf("HoldReason = %q, want it to contain the periodic_hold_reason", reason)
	}
	if code := afField(cfgFile, cluster, 0, "HoldReasonCode"); code != "3" {
		t.Fatalf("HoldReasonCode = %q, want 3 (JobPolicy)", code)
	}
	// The slot must return to Unclaimed (the shadow/claim was torn down).
	unclaimed := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := runTool(cfgFile, 20*time.Second, "condor_status", "-af", "State")
		states := nonEmptyLines(st)
		if len(states) > 0 {
			allUnclaimed := true
			for _, s := range states {
				if strings.TrimSpace(s) != "Unclaimed" {
					allUnclaimed = false
				}
			}
			if allUnclaimed {
				unclaimed = true
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
	if !unclaimed {
		st, _ := runTool(cfgFile, 20*time.Second, "condor_status", "-af", "Name", "State", "Activity")
		t.Fatalf("slot never returned to Unclaimed after periodic_hold vacate:\n%s", st)
	}
	t.Logf("periodic_hold: job %d.0 held (status 5, code 3) and slot released", cluster)
}

// TestStage13OnExitRemoveRequeue: on_exit_remove = (NumJobCompletions >= 2)
// keeps a cleanly-exiting job in the queue after its first run (requeued to
// Idle) and completes it after the second, proving OnExitRemove=false requeues.
func TestStage13OnExitRemoveRequeue(t *testing.T) {
	t.Parallel()
	h, binName := policyPool(t, "oerequeue", "TRUE")
	defer h.Shutdown()
	cfgFile := h.GetConfigFile()

	sub := writeSleepJob(t, t.TempDir(), 2, 0, "on_exit_remove = (NumJobCompletions >= 2)")
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", sub)
	if err != nil {
		t.Fatalf("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		t.Fatalf("could not parse cluster id: %q", out)
	}
	// Observe the run count climb to 2 (the job runs, requeues, runs again). Poll
	// while the job is in the queue; capture the max JobRunCount seen.
	maxRun := int64(0)
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		rc := afField(cfgFile, cluster, 0, "JobRunCount")
		if rc != "" && rc != "undefined" {
			var n int64
			fmt.Sscanf(rc, "%d", &n)
			if n > maxRun {
				maxRun = n
			}
		}
		if len(nonEmptyLines(afField(cfgFile, cluster, 0, "ClusterId"))) == 0 {
			break // job left the queue (completed after 2nd run)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !waitJobGone(cfgFile, cluster, 60*time.Second) {
		t.Fatalf("job %d.0 never completed (stuck requeueing?)", cluster)
	}
	rec := historyRecord(t, h, binName, cfgFile, cluster)
	if rec["JobStatus"] != 4 {
		t.Fatalf("history JobStatus = %d, want 4 (Completed)", rec["JobStatus"])
	}
	if rec["NumJobCompletions"] < 2 {
		t.Fatalf("NumJobCompletions = %d, want >= 2 (job should have run twice)", rec["NumJobCompletions"])
	}
	t.Logf("on_exit_remove: job %d.0 ran %d time(s) then completed (NumJobCompletions=%d)",
		cluster, maxRun, rec["NumJobCompletions"])
}

// TestStage13OnExitHold: on_exit_hold = (ExitCode =!= 0) holds a job that exits
// non-zero, with the right HoldReason.
func TestStage13OnExitHold(t *testing.T) {
	t.Parallel()
	h, _ := policyPool(t, "oehold", "TRUE")
	defer h.Shutdown()
	cfgFile := h.GetConfigFile()

	sub := writeSleepJob(t, t.TempDir(), 1, 17, "on_exit_hold = (ExitCode =!= 0)\n"+
		`on_exit_hold_reason = "job exited non-zero"`)
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", sub)
	if err != nil {
		t.Fatalf("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		t.Fatalf("could not parse cluster id: %q", out)
	}
	// The job should run once then land Held (status 5) on its non-zero exit.
	if !waitForJobStatus(cfgFile, cluster, 0, "5", 180*time.Second) {
		t.Fatalf("job %d.0 was never held on exit (status=%s)",
			cluster, afField(cfgFile, cluster, 0, "JobStatus"))
	}
	reason := afField(cfgFile, cluster, 0, "HoldReason")
	if !strings.Contains(reason, "job exited non-zero") {
		t.Fatalf("HoldReason = %q, want it to contain the on_exit_hold_reason", reason)
	}
	if code := afField(cfgFile, cluster, 0, "HoldReasonCode"); code != "3" {
		t.Fatalf("HoldReasonCode = %q, want 3 (JobPolicy)", code)
	}
	t.Logf("on_exit_hold: job %d.0 held on non-zero exit with the expected reason", cluster)
}
