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
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/userlog"
)

// TestStage10UserLog exercises the standard user-job-log (`log = ...` in the
// submit file) written by the pure-Go schedd, validated with the stock C++
// condor_wait and the Go userlog parser:
//
//	(1) a vanilla transfer job with `log = job.log` runs to completion; stock
//	    `condor_wait` on the log exits 0 promptly, and the parsed log shows
//	    exactly one SUBMIT, then EXECUTE, then JOB_TERMINATED (normal, exit 0)
//	    with the right cluster/proc ids;
//	(2) an idle (never-matching) job is held, released, and removed; the log
//	    gains JOB_HELD / JOB_RELEASED / JOB_ABORTED, and `condor_wait` treats
//	    the aborted job as done (exits 0).
func TestStage10UserLog(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q",
		"condor_wait", "condor_hold", "condor_release", "condor_rm", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	binName := fmt.Sprintf("golang-ap-schedd10-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	const uidDomain = "golang-ap.test"
	extra := fmt.Sprintf(`
# --- Run golang-ap's schedd as the pool's SCHEDD; C++ negotiator + startd ---
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

# One STATIC slot (a pslot would carve a dslot instead of going Claimed).
NUM_CPUS = 1
MEMORY = 512
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = 10
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = FALSE

# Negotiate quickly so the test does not wait long for a cycle.
NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1

# Claim sessions require match-password auth + AES (cedar's only cipher).
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

	// ---------------------------------------------------------------------
	// Scenario 1: vanilla transfer job with `log = job.log` runs to
	// completion; condor_wait exits 0 promptly; parsed log shows
	// SUBMIT -> EXECUTE -> JOB_TERMINATED (exit 0).
	// ---------------------------------------------------------------------
	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho hello\nexit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	logPath := filepath.Join(iwd, "job.log")
	submitFile := filepath.Join(tmp, "job.sub")
	subDesc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
initialdir = %s
log = job.log
output = job.out
error = job.err
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`, scriptPath, iwd)
	if err := os.WriteFile(submitFile, []byte(subDesc), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", submitFile)
	if err != nil {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}
	t.Logf("submitted job %d.0 with log = %s", cluster, logPath)

	// Wait for the job to run and leave the queue (completed).
	gone := false
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		row, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
		if err == nil && len(nonEmptyLines(row)) == 0 {
			gone = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !gone {
		fail("job %d.0 never left the queue (never completed)", cluster)
	}
	t.Logf("job %d.0 completed and left the queue", cluster)

	// condor_wait must accept the log and exit 0 promptly: the terminal
	// JOB_TERMINATED event is already in the file, so even with a generous
	// -wait budget it should return in seconds, not block.
	start := time.Now()
	waitOut, err := runTool(cfgFile, 60*time.Second, "condor_wait", "-wait", "60", logPath)
	elapsed := time.Since(start)
	if err != nil {
		fail("condor_wait rejected the Go-written log: %v\n%s", err, waitOut)
	}
	if elapsed > 30*time.Second {
		fail("condor_wait took %s; expected a prompt return on a completed log", elapsed)
	}
	t.Logf("condor_wait exited 0 in %s: %q", elapsed, waitOut)

	// Parse with the Go parser and assert the SUBMIT/EXECUTE/TERMINATED
	// sequence with correct ids and exit code 0.
	events := parseUserLog(t, logPath)
	var kinds []userlog.EventKind
	for _, ev := range events {
		kinds = append(kinds, ev.Kind)
		if ev.ClusterID != cluster || ev.ProcID != 0 {
			fail("event %s has job id %d.%d, want %d.0", ev.Kind, ev.ClusterID, ev.ProcID, cluster)
		}
	}
	t.Logf("job log events: %v", kinds)
	if n := countKind(events, userlog.KindSubmit); n != 1 {
		fail("log has %d Submit events, want exactly 1 (schedd-side write, no double-write)", n)
	}
	iSub := indexKind(events, userlog.KindSubmit)
	iExe := indexKind(events, userlog.KindExecute)
	iTerm := indexKind(events, userlog.KindJobTerminated)
	if iSub < 0 || iExe < 0 || iTerm < 0 || iSub >= iExe || iExe >= iTerm {
		fail("expected Submit -> Execute -> JobTerminated in order, got %v", kinds)
	}
	term := events[iTerm]
	if !term.TerminatedNormally {
		fail("JobTerminated not marked as normal termination: %+v", term)
	}
	if term.ReturnValue == nil || *term.ReturnValue != 0 {
		fail("JobTerminated return value = %v, want 0", term.ReturnValue)
	}
	if events[iExe].ExecuteHost == "" {
		fail("Execute event has no execute host: %+v", events[iExe])
	}
	t.Logf("scenario 1 OK: Submit -> Execute -> JobTerminated(rc=0) on host %s", events[iExe].ExecuteHost)

	// ---------------------------------------------------------------------
	// Scenario 2: hold -> release -> rm an idle job; HELD/RELEASED/ABORTED
	// events appear and condor_wait treats the aborted job as done.
	// ---------------------------------------------------------------------
	iwd2 := filepath.Join(tmp, "job2")
	if err := os.MkdirAll(iwd2, 0o755); err != nil {
		t.Fatal(err)
	}
	log2Path := filepath.Join(iwd2, "job2.log")
	submit2 := filepath.Join(tmp, "job2.sub")
	// requirements = False keeps the job Idle forever (never matched).
	sub2Desc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
initialdir = %s
log = job2.log
requirements = False
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`, scriptPath, iwd2)
	if err := os.WriteFile(submit2, []byte(sub2Desc), 0o644); err != nil {
		t.Fatal(err)
	}
	out2, err := runTool(cfgFile, 60*time.Second, "condor_submit", submit2)
	if err != nil {
		fail("condor_submit (job2) failed: %v\n%s", err, out2)
	}
	cluster2 := parseClusterID(out2)
	if cluster2 <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out2)
	}
	jobID2 := fmt.Sprintf("%d.0", cluster2)
	if !waitForJobStatus(cfgFile, cluster2, 0, "1", 30*time.Second) {
		fail("job %s never showed Idle", jobID2)
	}

	if o, err := runTool(cfgFile, 30*time.Second, "condor_hold", jobID2); err != nil {
		fail("condor_hold %s failed: %v\n%s", jobID2, err, o)
	}
	if !waitForJobStatus(cfgFile, cluster2, 0, "5", 30*time.Second) {
		fail("job %s never showed Held", jobID2)
	}
	if o, err := runTool(cfgFile, 30*time.Second, "condor_release", jobID2); err != nil {
		fail("condor_release %s failed: %v\n%s", jobID2, err, o)
	}
	if !waitForJobStatus(cfgFile, cluster2, 0, "1", 30*time.Second) {
		fail("job %s never returned to Idle after release", jobID2)
	}
	if o, err := runTool(cfgFile, 30*time.Second, "condor_rm", jobID2); err != nil {
		fail("condor_rm %s failed: %v\n%s", jobID2, err, o)
	}
	// Removed jobs are archived out of the live queue.
	gone = false
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		row, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster2))
		if err == nil && len(nonEmptyLines(row)) == 0 {
			gone = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !gone {
		fail("job %s never left the queue after condor_rm", jobID2)
	}

	// condor_wait on the aborted job's log must terminate (abort is terminal).
	start = time.Now()
	waitOut2, err := runTool(cfgFile, 60*time.Second, "condor_wait", "-wait", "60", log2Path)
	elapsed = time.Since(start)
	if err != nil {
		fail("condor_wait did not treat the aborted job as done: %v\n%s", err, waitOut2)
	}
	if elapsed > 30*time.Second {
		fail("condor_wait on aborted log took %s; expected a prompt return", elapsed)
	}
	t.Logf("condor_wait (aborted job) exited 0 in %s: %q", elapsed, waitOut2)

	events2 := parseUserLog(t, log2Path)
	var kinds2 []userlog.EventKind
	for _, ev := range events2 {
		kinds2 = append(kinds2, ev.Kind)
		if ev.ClusterID != cluster2 || ev.ProcID != 0 {
			fail("event %s has job id %d.%d, want %s", ev.Kind, ev.ClusterID, ev.ProcID, jobID2)
		}
	}
	t.Logf("job2 log events: %v", kinds2)
	iSub2 := indexKind(events2, userlog.KindSubmit)
	iHeld := indexKind(events2, userlog.KindJobHeld)
	iRel := indexKind(events2, userlog.KindJobReleased)
	iAb := indexKind(events2, userlog.KindJobAborted)
	if iSub2 < 0 || iHeld < 0 || iRel < 0 || iAb < 0 ||
		iSub2 >= iHeld || iHeld >= iRel || iRel >= iAb {
		fail("expected Submit -> JobHeld -> JobReleased -> JobAborted in order, got %v", kinds2)
	}
	held := events2[iHeld]
	if held.HoldReasonCode == nil || *held.HoldReasonCode != 1 {
		fail("JobHeld hold reason code = %v, want 1 (UserRequest)", held.HoldReasonCode)
	}
	t.Logf("scenario 2 OK: Submit -> JobHeld(code=1) -> JobReleased -> JobAborted")

	if t.Failed() {
		dumpAllLogs()
	}
}

// parseUserLog parses the user log at path with the Go parser, failing the
// test on error.
func parseUserLog(t *testing.T, path string) []userlog.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening user log %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	events, err := userlog.Parse(f)
	if err != nil {
		t.Fatalf("parsing user log %s: %v", path, err)
	}
	return events
}

func countKind(events []userlog.Event, kind userlog.EventKind) int {
	n := 0
	for _, ev := range events {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

// indexKind returns the index of the first event of the given kind, or -1.
func indexKind(events []userlog.Event, kind userlog.EventKind) int {
	for i, ev := range events {
		if ev.Kind == kind {
			return i
		}
	}
	return -1
}
