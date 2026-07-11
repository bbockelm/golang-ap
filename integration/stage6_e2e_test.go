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

// TestStage6EndToEnd is the marquee stage-6 test: the full pipeline with the
// pure-Go schedd as the pool's SCHEDD and stock C++ master/collector/negotiator/
// startd/starter around it. A stock `condor_submit` of a vanilla job (with file
// transfer) leads to:
//
//	condor_submit -> Go schedd queue (Idle)
//	  -> collector sees the Submitter ad
//	  -> C++ negotiator NEGOTIATEs with the Go schedd
//	  -> Go schedd claims + activates the C++ startd, runs an in-process shadow
//	     (serving the starter's syscalls AND file transfer)
//	  -> job runs (Idle -> Running with RemoteHost set -> gone)
//	  -> output file lands back in the submit dir
//	  -> job archived to history with JobStatus=4, ExitCode=0.
func TestStage6EndToEnd(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build the Go schedd with a pid-tagged basename (see stage1 for why).
	binName := fmt.Sprintf("golang-ap-schedd6-%d", os.Getpid())
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
NEGOTIATOR_DEBUG = D_FULLDEBUG D_MATCH

# Claim sessions require match-password auth + AES (cedar's only cipher).
SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS

STARTD_DEBUG = D_SECURITY:2 D_COMMAND:2 D_FULLDEBUG
STARTER_DEBUG = D_SECURITY:2 D_SYSCALLS:2 D_FULLDEBUG
`, scheddBin, uidDomain)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()

	dumpAllLogs := func() {
		for _, name := range []string{"ScheddLog", "NegotiatorLog", "MatchLog", "StartLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		matches, _ := filepath.Glob(filepath.Join(logDir, "StarterLog*"))
		for _, m := range matches {
			dumpLog(t, m)
		}
	}
	fail := func(format string, args ...any) {
		t.Helper()
		dumpAllLogs()
		t.Fatalf(format, args...)
	}

	// Wait for the Go schedd to publish its address.
	if !waitForFile(filepath.Join(logDir, ".schedd_address"), 60*time.Second) {
		fail("Go schedd never wrote its address file")
	}

	// Build the job's submit directory: a fresh script executable (transferred),
	// one input file, and a submit description with file transfer. No `log =`
	// (the userlog is not implemented). The job verifies its transferred input,
	// writes stdout + one explicit output file, sleeps so the test can observe
	// Running, then exits 0.
	const inputContent = "hello-from-shadow"
	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"expected='" + inputContent + "'\n" +
		"got=$(cat input.dat)\n" +
		"if [ \"$got\" != \"$expected\" ]; then\n" +
		"  echo \"MISMATCH: got [$got] want [$expected]\" 1>&2\n" +
		"  exit 17\n" +
		"fi\n" +
		"echo \"job stdout ok: $got\"\n" +
		"printf 'RESULT:%s\\n' \"$got\" > result.txt\n" +
		"sleep 8\n" +
		"exit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	submitFile := filepath.Join(tmp, "job.sub")
	subDesc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = %s
initialdir = %s
output = job.out
error = job.err
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`, scriptPath, filepath.Join(iwd, "input.dat"), iwd)
	if err := os.WriteFile(submitFile, []byte(subDesc), 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- (1) stock condor_submit ----
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", submitFile)
	if err != nil {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	t.Logf("condor_submit:\n%s", out)
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}

	// ---- (2) Idle -> Running (RemoteHost set) ----
	if !waitForJobStatus(cfgFile, cluster, 0, "1", 30*time.Second) {
		fail("job %d.0 never showed Idle", cluster)
	}
	t.Logf("job %d.0 is Idle; waiting for the negotiator to match it", cluster)

	sawRunning := false
	remoteHost := ""
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		row, _ := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "JobStatus", "RemoteHost",
			"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
		f := strings.Fields(strings.TrimSpace(row))
		if len(f) >= 2 && f[0] == "2" && f[1] != "undefined" && f[1] != "" {
			sawRunning = true
			remoteHost = f[1]
			break
		}
		if len(nonEmptyLines(row)) == 0 {
			// Job may have already completed and left the queue.
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !sawRunning {
		// The job might run and finish faster than we poll; only hard-fail if it
		// also never completed (checked below). Record the miss for diagnostics.
		t.Logf("warning: never observed the job in Running with RemoteHost via condor_q polling")
	} else {
		t.Logf("job %d.0 is Running on %s", cluster, remoteHost)
	}

	// ---- (3) job leaves the queue (completed) ----
	gone := false
	deadline = time.Now().Add(120 * time.Second)
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

	// ---- (4) output files landed back in the submit dir ----
	resultFile := filepath.Join(iwd, "result.txt")
	gotResult, err := os.ReadFile(resultFile)
	if err != nil {
		fail("explicit output file %s not returned: %v", resultFile, err)
	}
	if want := "RESULT:" + inputContent + "\n"; string(gotResult) != want {
		fail("result.txt = %q, want %q", string(gotResult), want)
	}
	stdoutFile := filepath.Join(iwd, "job.out")
	gotStdout, err := os.ReadFile(stdoutFile)
	if err != nil {
		fail("captured stdout %s not returned: %v", stdoutFile, err)
	}
	if want := "job stdout ok: " + inputContent; !strings.Contains(string(gotStdout), want) {
		fail("job.out = %q, want it to contain %q", string(gotStdout), want)
	}
	t.Logf("output files returned to the submit dir with expected content")

	// ---- (5) history archive holds the job, JobStatus=4, ExitCode=0 ----
	// Stop the schedd cleanly so we open the archive without a live writer.
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
	q, err := vm.Parse(fmt.Sprintf("ClusterId == %d && ProcId == 0", cluster))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for ad := range arc.Query(q) {
		found = true
		if st, _ := ad.EvaluateAttrInt("JobStatus"); st != 4 {
			fail("history record for %d.0 has JobStatus %d, want 4 (Completed)", cluster, st)
		}
		if code, ok := ad.EvaluateAttrInt("ExitCode"); !ok || code != 0 {
			fail("history record for %d.0 has ExitCode %d (ok=%v), want 0", cluster, code, ok)
		}
	}
	if !found {
		fail("completed job %d.0 not found in history archive %s", cluster, histDir)
	}
	t.Logf("job %d.0 present in history archive with JobStatus=4, ExitCode=0", cluster)

	if t.Failed() {
		dumpAllLogs()
	}
}
