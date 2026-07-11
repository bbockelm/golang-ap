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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// Stage 8: shadow/claim RECONNECT. A schedd restart (or transient failure) must
// re-attach to a job still running on its C++ starter instead of requeueing it.
//
//	(a) TestStage8Reconnect        - submit a ~45s transfer job; once Running,
//	    restart the schedd (condor_restart -schedd => DC_OFF_GRACEFUL to the
//	    schedd + master auto-restart). The SAME job instance continues: it is
//	    never re-executed (a start-marker file gains exactly one line;
//	    NumJobStarts/JobRunCount stay 1), the StarterLog records "Accepted request
//	    to reconnect", the job completes exit 0, output lands, history JobStatus=4.
//	(b) TestStage8ReconnectStartdGone - stop the schedd, then stop the startd
//	    during the outage, then restart the schedd. Reconnect cannot re-establish
//	    contact, so the job is requeued to Idle (JobStatus 1) with
//	    NumShadowExceptions untouched.

// stage8ReconnectConfig speeds the master's restart of a gracefully-stopped
// daemon and negotiates quickly. Appended to the stage-7 pool config.
const stage8ReconnectConfig = `
MASTER_BACKOFF_CONSTANT = 2
MASTER_BACKOFF_FACTOR = 1
MASTER_BACKOFF_CEILING = 4
MASTER_NEW_BINARY_DELAY = 1
JOB_DEFAULT_LEASE_DURATION = 2400
`

// writeStage8Job writes a ~sleepSecs transfer job that appends one line to an
// absolute start-marker file each time its script runs. Because the pool is
// single-machine (the execute sandbox shares the filesystem with the marker's
// directory), a clean reconnect -- where the starter never re-execs the job --
// leaves the marker with exactly one line, whereas a requeue+re-run would add a
// second. Returns the submit file, the job dir (Iwd), and the marker path.
func writeStage8Job(t *testing.T, tmp string, sleepSecs int) (submitFile, iwd, marker string) {
	t.Helper()
	const inputContent = "hello-from-stage8"
	iwd = filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	marker = filepath.Join(tmp, "starts.log")
	script := "#!/bin/sh\n" +
		"printf 'start pid=%s\\n' \"$$\" >> '" + marker + "'\n" +
		"expected='" + inputContent + "'\n" +
		"got=$(cat input.dat)\n" +
		"if [ \"$got\" != \"$expected\" ]; then\n" +
		"  echo \"MISMATCH: got [$got] want [$expected]\" 1>&2\n" +
		"  exit 17\n" +
		"fi\n" +
		"echo \"job stdout ok: $got\"\n" +
		"printf 'RESULT:%s\\n' \"$got\" > result.txt\n" +
		fmt.Sprintf("sleep %d\n", sleepSecs) +
		"exit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	submitFile = filepath.Join(tmp, "job.sub")
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
	return submitFile, iwd, marker
}

// scheddPIDs returns the live pids whose command line matches binName.
func scheddPIDs(binName string) map[int]bool {
	out, _ := exec.Command("pgrep", "-f", binName).CombinedOutput()
	pids := map[int]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
			pids[pid] = true
		}
	}
	return pids
}

// waitForNewSchedd waits until a schedd process appears whose pid is not in the
// old set, returning the new pid (0 on timeout).
func waitForNewSchedd(binName string, old map[int]bool, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for pid := range scheddPIDs(binName) {
			if !old[pid] {
				return pid
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0
}

// waitForAllGone waits until none of the given pids are alive.
func waitForAllGone(pids map[int]bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive := false
		for pid := range pids {
			if exec.Command("kill", "-0", strconv.Itoa(pid)).Run() == nil {
				alive = true
				break
			}
		}
		if !alive {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// waitMarker polls until the file at path has at least want non-empty lines.
func waitMarker(path string, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if countLines(path) >= want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// countLines returns the number of non-empty lines in the file at path.
func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return len(nonEmptyLines(string(data)))
}

// latestStarterLog returns the newest StarterLog* under logDir (the starter of
// the most recent activation), or "" if none.
func latestStarterLog(logDir string) string {
	matches, _ := filepath.Glob(filepath.Join(logDir, "StarterLog*"))
	newest, newestMod := "", time.Time{}
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.ModTime().After(newestMod) {
			newest, newestMod = m, fi.ModTime()
		}
	}
	return newest
}

// ---------------------------------------------------------------------------
// (a) Schedd restart mid-run: reconnect to the running job, no re-execution.
// ---------------------------------------------------------------------------

func TestStage8Reconnect(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "reconnect", stage7SlotStatic, stage8ReconnectConfig)
	defer env.h.Shutdown()

	// The job must still be running when the restarted schedd reconnects, so keep
	// it comfortably longer than the schedd-restart window (condor_restart ->
	// master re-spawn), but far shorter than the original 45s.
	submitFile, iwd, marker := writeStage8Job(t, env.tmp, 25)
	cluster := submitStage7Job(t, env, submitFile)

	host, ok := waitRunningWithHost(env.cfgFile, cluster, 90*time.Second)
	if !ok {
		env.fail("job %d.0 never showed Running", cluster)
	}
	t.Logf("job %d.0 running on %s; waiting for it to begin executing", cluster, host)

	// Wait until the job's script has actually started (marker has one line), so
	// the restart lands mid-execution -- the real reconnect scenario. RemoteHost
	// is set at activation, before input transfer + exec, so polling the marker
	// avoids that race.
	if !waitMarker(marker, 1, 60*time.Second) {
		env.fail("job %d.0 never began executing (start-marker empty)", cluster)
	}
	t.Logf("job %d.0 executing; restarting the schedd mid-run", cluster)

	oldPIDs := scheddPIDs(env.binName)
	if len(oldPIDs) == 0 {
		env.fail("could not find the running schedd pid")
	}

	// condor_restart -schedd sends DC_OFF_GRACEFUL to the schedd; the master then
	// restarts it (computeRealAction in condor_tools/tool.cpp). Our graceful
	// shutdown detaches from the running shadow, leaving the job Running for the
	// restarted schedd to reconnect.
	runCondor(t, env.cfgFile, 30*time.Second, "condor_restart", "-schedd")

	if !waitForAllGone(oldPIDs, 30*time.Second) {
		env.fail("old schedd process(es) did not exit after condor_restart")
	}
	newPID := waitForNewSchedd(env.binName, oldPIDs, 90*time.Second)
	if newPID == 0 {
		env.fail("master did not restart the schedd after condor_restart")
	}
	t.Logf("schedd restarted (new pid %d); waiting for reconnect + completion", newPID)

	// The restarted schedd must re-attach and run the SAME instance to
	// completion -- never requeue and re-run it.
	if !waitJobGone(env.cfgFile, cluster, 180*time.Second) {
		env.fail("job %d.0 never completed after the schedd restart", cluster)
	}

	// Exactly one execution across the whole run.
	if n := countLines(marker); n != 1 {
		env.fail("start-marker has %d lines after completion, want 1 (job was re-executed)", n)
	}
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		env.fail("result.txt not returned after reconnect: %v", err)
	}
	if want := "RESULT:hello-from-stage8\n"; string(gotResult) != want {
		env.fail("result.txt = %q, want %q", string(gotResult), want)
	}
	gotStdout, err := os.ReadFile(filepath.Join(iwd, "job.out"))
	if err != nil {
		env.fail("captured stdout not returned: %v", err)
	}
	if !strings.Contains(string(gotStdout), "job stdout ok: hello-from-stage8") {
		env.fail("job.out = %q, missing expected content", string(gotStdout))
	}

	// The starter logged the reconnect acceptance.
	if sl := latestStarterLog(env.logDir); sl == "" || !grepFile(sl, "Accepted request to reconnect") {
		env.dump()
		t.Fatalf("StarterLog does not record %q (no reconnect happened)", "Accepted request to reconnect")
	}

	// History proves the single-instance continuation: JobStatus=4, ExitCode=0,
	// and exactly one start (NumJobStarts/JobRunCount == 1).
	stopScheddAndCheckHistoryReconnect(t, env, cluster)
	t.Logf("schedd restart mid-run: reconnected to the running job; one instance, exit 0")
}

// stopScheddAndCheckHistoryReconnect shuts the schedd down and asserts the
// completed job's history record: JobStatus=4, ExitCode=0, and a single start.
func stopScheddAndCheckHistoryReconnect(t *testing.T, env *stage7Env, cluster int) {
	t.Helper()
	runCondor(t, env.cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitGone(env.binName, 30*time.Second) {
		env.fail("schedd did not exit after condor_off")
	}
	histDir := filepath.Join(env.h.GetSpoolDir(), "history")
	arc, err := collections.OpenArchive(collections.ArchiveOptions{Dir: histDir})
	if err != nil {
		env.fail("opening history archive at %s: %v", histDir, err)
	}
	defer func() { _ = arc.Close() }()
	q, err := vm.Parse(fmt.Sprintf("ClusterId == %d && ProcId == 0", cluster))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for ad := range arc.Query(q) {
		found = true
		if st, _ := ad.EvaluateAttrInt("JobStatus"); int(st) != 4 {
			env.fail("history JobStatus = %d, want 4", st)
		}
		if code, ok := ad.EvaluateAttrInt("ExitCode"); !ok || code != 0 {
			env.fail("history ExitCode = %d (ok=%v), want 0", code, ok)
		}
		if runs, _ := ad.EvaluateAttrInt("JobRunCount"); runs != 1 {
			env.fail("history JobRunCount = %d, want 1 (job was requeued/re-run instead of reconnected)", runs)
		}
		if starts, _ := ad.EvaluateAttrInt("NumJobStarts"); starts != 1 {
			env.fail("history NumJobStarts = %d, want 1 (job was requeued/re-run instead of reconnected)", starts)
		}
		// The stored claim secret must not survive into the terminal record.
		if _, ok := ad.Lookup("ClaimId"); ok {
			env.fail("history record still carries the private ClaimId attribute")
		}
	}
	if !found {
		env.fail("job %d.0 not found in history archive %s", cluster, histDir)
	}
}

// ---------------------------------------------------------------------------
// (b) Startd gone during the outage: reconnect fails, job requeued to Idle.
// ---------------------------------------------------------------------------

func TestStage8ReconnectStartdGone(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "reconn-gone", stage7SlotStatic, stage8ReconnectConfig)
	defer env.h.Shutdown()

	// Must outlive the stop-schedd / stop-startd / restart-schedd sequence so the
	// reconnect attempt actually races a still-running job; 22s is ample.
	submitFile, _, _ := writeStage8Job(t, env.tmp, 22)
	cluster := submitStage7Job(t, env, submitFile)

	if _, ok := waitRunningWithHost(env.cfgFile, cluster, 90*time.Second); !ok {
		env.fail("job %d.0 never showed Running", cluster)
	}

	// Controlled outage: stop the schedd (master will NOT restart it after a
	// condor_off), stop the startd during the outage, then bring the schedd back.
	oldPIDs := scheddPIDs(env.binName)
	runCondor(t, env.cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitForAllGone(oldPIDs, 30*time.Second) {
		env.fail("schedd did not exit after condor_off")
	}
	t.Logf("schedd down; stopping the startd so reconnect cannot succeed")
	runCondor(t, env.cfgFile, 30*time.Second, "condor_off", "-daemon", "startd")
	// Give the startd a moment to actually exit so the reconnect connect fails.
	time.Sleep(3 * time.Second)

	runCondor(t, env.cfgFile, 30*time.Second, "condor_on", "-daemon", "schedd")
	newPID := waitForNewSchedd(env.binName, oldPIDs, 90*time.Second)
	if newPID == 0 {
		env.fail("schedd did not come back after condor_on")
	}
	t.Logf("schedd back (pid %d); reconnect must fail and requeue the job to Idle", newPID)

	// Reconnect to the (now absent) starter fails, so the job is requeued to Idle.
	// The startd is off, so it stays Idle rather than being re-matched.
	if !waitJobAttr(env.cfgFile, cluster, 0, "JobStatus", "1", 90*time.Second) {
		out, _ := runTool(env.cfgFile, 20*time.Second, "condor_q", "-allusers", "-af",
			"JobStatus", "NumShadowExceptions", "-constraint",
			fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
		env.fail("job %d.0 was not requeued to Idle after a failed reconnect (attrs=%q)", cluster, strings.TrimSpace(out))
	}

	// A reconnect failure is NOT a shadow exception: NumShadowExceptions must be
	// untouched (undefined / 0).
	out, _ := runTool(env.cfgFile, 20*time.Second, "condor_q", "-allusers", "-af",
		"NumShadowExceptions", "-constraint",
		fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
	if v := strings.TrimSpace(out); v != "undefined" && v != "0" && v != "" {
		env.fail("NumShadowExceptions = %q after a reconnect failure, want untouched (undefined/0)", v)
	}
	t.Logf("startd gone during outage: reconnect failed, job requeued to Idle, no shadow exception counted")
}
