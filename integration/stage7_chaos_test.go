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
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// Stage 7 chaos tests: the Go schedd must survive everything a shadow, starter,
// or startd can do to it.
//
//	(a) TestStage7ShadowPanic          - injected shadow panic mid-run: schedd
//	    stays up, job requeues (NumShadowExceptions=1) and re-runs to completion.
//	(b) TestStage7PanicHoldsJob        - same injection with MAX_SHADOW_EXCEPTIONS=1:
//	    the job is held with HoldReasonCode 1002 (ShadowException).
//	(c) TestStage7StarterKill          - kill -9 the condor_starter mid-run: the
//	    syscall socket EOF is treated as a failure, the job requeues and re-runs
//	    to completion.
//	(d) TestStage7RemoveRunning        - condor_rm of a running job: slot back to
//	    Unclaimed within ~15s, job archived with JobStatus=3.
//	(e) TestStage7PartitionableSlot    - the stage-6 happy path against a default
//	    partitionable slot: the activation goes to the carved dslot (RemoteHost
//	    is slot1_1@...) and a transfer job runs to completion.

// stage7SlotStatic is the stage-6 single static slot.
const stage7SlotStatic = `
NUM_CPUS = 1
MEMORY = 512
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%
SLOT_TYPE_1_PARTITIONABLE = FALSE
`

// stage7SlotPartitionable is one partitionable slot covering the machine
// (HTCondor's modern default layout).
const stage7SlotPartitionable = `
NUM_CPUS = 4
MEMORY = 2048
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%
SLOT_TYPE_1_PARTITIONABLE = TRUE
`

// stage7Env is one booted stage-7 pool: C++ master/collector/negotiator/startd
// with the Go schedd, plus the failure-dump helper.
type stage7Env struct {
	h       *htcondor.CondorTestHarness
	tmp     string
	binName string
	cfgFile string
	logDir  string
	fail    func(format string, args ...any)
	dump    func()
}

// setupStage7 builds the Go schedd and boots a harness around it. slotConfig
// selects the startd slot layout; extraConfig is appended verbatim (e.g. the
// panic test hook).
func setupStage7(t *testing.T, tag, slotConfig, extraConfig string) *stage7Env {
	t.Helper()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_rm", "condor_status", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ap-schedd7%s-%d", tag, os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	extra := fmt.Sprintf(`
# --- Run golang-ap's schedd as the pool's SCHEDD; C++ negotiator + startd ---
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

UID_DOMAIN = golang-ap.test
TRUST_UID_DOMAIN = True

START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = 10
%s

# Negotiate quickly so requeued jobs re-match fast.
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

STARTD_DEBUG = D_FULLDEBUG
STARTER_DEBUG = D_FULLDEBUG
%s
`, scheddBin, slotConfig, extraConfig)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	env := &stage7Env{
		h:       h,
		tmp:     tmp,
		binName: binName,
		cfgFile: h.GetConfigFile(),
		logDir:  h.GetLogDir(),
	}
	env.dump = func() {
		for _, name := range []string{"ScheddLog", "NegotiatorLog", "MatchLog", "StartLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(env.logDir, name))
		}
		matches, _ := filepath.Glob(filepath.Join(env.logDir, "StarterLog*"))
		for _, m := range matches {
			dumpLog(t, m)
		}
	}
	env.fail = func(format string, args ...any) {
		t.Helper()
		env.dump()
		t.Fatalf(format, args...)
	}

	if !waitForFile(filepath.Join(env.logDir, ".schedd_address"), 60*time.Second) {
		env.fail("Go schedd never wrote its address file")
	}
	return env
}

// writeStage7Job writes a transfer job (input verification + explicit output +
// sleep) and its submit file; returns the submit-file path and the job dir.
func writeStage7Job(t *testing.T, tmp string, sleepSecs int) (submitFile, iwd string) {
	t.Helper()
	const inputContent = "hello-from-stage7"
	iwd = filepath.Join(tmp, "job")
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
	return submitFile, iwd
}

// submitStage7Job submits and returns the cluster id.
func submitStage7Job(t *testing.T, env *stage7Env, submitFile string) int {
	t.Helper()
	out, err := runTool(env.cfgFile, 60*time.Second, "condor_submit", submitFile)
	if err != nil {
		env.fail("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		env.fail("could not parse cluster id from condor_submit output: %q", out)
	}
	return cluster
}

// waitJobAttr polls one job attribute (via condor_q -af) until it equals want.
func waitJobAttr(cfgFile string, cluster, proc int, attr, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	constraint := fmt.Sprintf("ClusterId==%d && ProcId==%d", cluster, proc)
	for time.Now().Before(deadline) {
		out, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers",
			"-af", attr, "-constraint", constraint)
		if err == nil && strings.TrimSpace(out) == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// waitRunningWithHost polls until the job is Running with a RemoteHost, and
// returns the host. ok=false on timeout (the job may have raced to completion;
// callers decide whether that is fatal).
func waitRunningWithHost(cfgFile string, cluster int, timeout time.Duration) (string, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row, _ := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "JobStatus", "RemoteHost",
			"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
		f := strings.Fields(strings.TrimSpace(row))
		if len(f) >= 2 && f[0] == "2" && f[1] != "undefined" && f[1] != "" {
			return f[1], true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", false
}

// waitJobGone polls until the job has left the live queue.
func waitJobGone(cfgFile string, cluster int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
		if err == nil && len(nonEmptyLines(row)) == 0 {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// stopScheddAndCheckHistory shuts the schedd down cleanly and asserts the job's
// history record carries the wanted JobStatus (and, if wantExitCode0, ExitCode 0).
func stopScheddAndCheckHistory(t *testing.T, env *stage7Env, cluster, wantStatus int, wantExitCode0 bool) {
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
		if st, _ := ad.EvaluateAttrInt("JobStatus"); int(st) != wantStatus {
			env.fail("history record for %d.0 has JobStatus %d, want %d", cluster, st, wantStatus)
		}
		if wantExitCode0 {
			if code, ok := ad.EvaluateAttrInt("ExitCode"); !ok || code != 0 {
				env.fail("history record for %d.0 has ExitCode %d (ok=%v), want 0", cluster, code, ok)
			}
		}
	}
	if !found {
		env.fail("job %d.0 not found in history archive %s", cluster, histDir)
	}
}

// grepFile reports whether any line of path contains needle.
func grepFile(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}

// ---------------------------------------------------------------------------
// (a) Injected shadow panic mid-run: requeue + re-run to completion.
// ---------------------------------------------------------------------------

func TestStage7ShadowPanic(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "panic", stage7SlotStatic,
		"GOLANG_AP_SHADOW_PANIC_AFTER_ACTIVATE = 1.0\n")
	defer env.h.Shutdown()

	submitFile, iwd := writeStage7Job(t, env.tmp, 6)
	cluster := submitStage7Job(t, env, submitFile)
	if cluster != 1 {
		env.fail("expected the first cluster id (1) so the panic hook targets it; got %d", cluster)
	}

	// The first run panics at begin_execution; the failure policy requeues the
	// job with NumShadowExceptions=1 (the attribute persists across the re-run,
	// so polling it is race-free).
	if !waitJobAttr(env.cfgFile, cluster, 0, "NumShadowExceptions", "1", 90*time.Second) {
		env.fail("job %d.0 never recorded NumShadowExceptions=1 after the injected panic", cluster)
	}
	t.Logf("job %d.0 recorded the shadow exception; waiting for the re-run to complete", cluster)

	if !waitJobGone(env.cfgFile, cluster, 120*time.Second) {
		env.fail("job %d.0 never completed after the injected shadow panic", cluster)
	}

	// The re-run transferred output back.
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		env.fail("result.txt not returned after the re-run: %v", err)
	}
	if want := "RESULT:hello-from-stage7\n"; string(gotResult) != want {
		env.fail("result.txt = %q, want %q", string(gotResult), want)
	}

	// The panic (with stack) made it to the log, and the schedd survived it
	// (it just ran the job to completion, but assert the log evidence too).
	scheddLog := filepath.Join(env.logDir, "ScheddLog")
	if !grepFile(scheddLog, "shadow goroutine panic") {
		env.fail("ScheddLog does not record the recovered shadow panic")
	}

	stopScheddAndCheckHistory(t, env, cluster, 4, true)
	t.Logf("panic mid-run: schedd stayed up, job requeued and re-ran to completion (history JobStatus=4, ExitCode=0)")
}

// ---------------------------------------------------------------------------
// (b) Panic with MAX_SHADOW_EXCEPTIONS=1: the job is held with code 1002.
// ---------------------------------------------------------------------------

func TestStage7PanicHoldsJob(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "panichold", stage7SlotStatic,
		"GOLANG_AP_SHADOW_PANIC_AFTER_ACTIVATE = 1.0\nMAX_SHADOW_EXCEPTIONS = 1\n")
	defer env.h.Shutdown()

	submitFile, _ := writeStage7Job(t, env.tmp, 6)
	cluster := submitStage7Job(t, env, submitFile)
	if cluster != 1 {
		env.fail("expected cluster id 1 for the panic hook; got %d", cluster)
	}

	if !waitJobAttr(env.cfgFile, cluster, 0, "JobStatus", "5", 90*time.Second) {
		env.fail("job %d.0 never went Held after exhausting its failure budget", cluster)
	}
	out, _ := runTool(env.cfgFile, 20*time.Second, "condor_q", "-allusers",
		"-af", "HoldReasonCode", "NumShadowExceptions", "HoldReason",
		"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) < 2 || f[0] != "1002" || f[1] != "1" {
		env.fail("held job attrs = %q, want HoldReasonCode=1002 NumShadowExceptions=1", out)
	}
	t.Logf("job held after 1 failure with HoldReasonCode=1002 (ShadowException): %s", strings.TrimSpace(out))

	// The slot must not be left Claimed by the failed run.
	if !waitForSlotState(t, env.cfgFile, "", "Unclaimed", 30*time.Second) {
		env.fail("slot did not return to Unclaimed after the failed run was held")
	}
}

// ---------------------------------------------------------------------------
// (c) kill -9 the condor_starter mid-run: requeue + re-run to completion.
// ---------------------------------------------------------------------------

// findStartdPid parses the startd's pid out of the harness MasterLog.
func findStartdPid(logDir string) int {
	data, err := os.ReadFile(filepath.Join(logDir, "MasterLog"))
	if err != nil {
		return 0
	}
	re := regexp.MustCompile(`condor_startd["']?, pid and pgroup = (\d+)`)
	m := re.FindAllStringSubmatch(string(data), -1)
	if len(m) == 0 {
		return 0
	}
	pid, _ := strconv.Atoi(m[len(m)-1][1]) // last spawn wins
	return pid
}

// findStarterPid returns the condor_starter child of the given startd, or 0.
// The name filter matters: the startd may have other children (procd, hooks),
// and killing one of those would leave the job running.
func findStarterPid(startdPid int) int {
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(startdPid), "-f", "condor_starter").Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

func TestStage7StarterKill(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "kill", stage7SlotStatic, "")
	defer env.h.Shutdown()

	submitFile, iwd := writeStage7Job(t, env.tmp, 10)
	cluster := submitStage7Job(t, env, submitFile)

	if _, ok := waitRunningWithHost(env.cfgFile, cluster, 90*time.Second); !ok {
		env.fail("job %d.0 never showed Running", cluster)
	}
	startdPid := findStartdPid(env.logDir)
	if startdPid <= 0 {
		env.fail("could not determine the startd pid from MasterLog")
	}
	var starterPid int
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if starterPid = findStarterPid(startdPid); starterPid > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if starterPid <= 0 {
		env.fail("could not find a condor_starter child of startd pid %d", startdPid)
	}
	t.Logf("killing condor_starter pid %d (child of startd %d) with SIGKILL", starterPid, startdPid)
	if out, err := exec.Command("kill", "-9", strconv.Itoa(starterPid)).CombinedOutput(); err != nil {
		env.fail("kill -9 %d failed: %v\n%s", starterPid, err, out)
	}

	// The shadow's syscall socket EOFs -> counted failure -> requeue. Unlike the
	// post-job_exit ExpectedClose, this failure records a shadow exception.
	if !waitJobAttr(env.cfgFile, cluster, 0, "NumShadowExceptions", "1", 60*time.Second) {
		env.fail("job %d.0 never recorded NumShadowExceptions=1 after the starter was killed", cluster)
	}
	t.Logf("job %d.0 requeued after the starter kill; waiting for the re-run", cluster)

	if !waitJobGone(env.cfgFile, cluster, 180*time.Second) {
		env.fail("job %d.0 never completed after the starter kill", cluster)
	}
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		env.fail("result.txt not returned after the re-run: %v", err)
	}
	if want := "RESULT:hello-from-stage7\n"; string(gotResult) != want {
		env.fail("result.txt = %q, want %q", string(gotResult), want)
	}
	stopScheddAndCheckHistory(t, env, cluster, 4, true)
	t.Logf("starter kill mid-run: job requeued and re-ran to completion")
}

// ---------------------------------------------------------------------------
// (d) condor_rm of a running job: slot Unclaimed within ~15s, history status 3.
// ---------------------------------------------------------------------------

func TestStage7RemoveRunning(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "rm", stage7SlotStatic, "")
	defer env.h.Shutdown()

	submitFile, _ := writeStage7Job(t, env.tmp, 120)
	cluster := submitStage7Job(t, env, submitFile)

	host, ok := waitRunningWithHost(env.cfgFile, cluster, 90*time.Second)
	if !ok {
		env.fail("job %d.0 never showed Running", cluster)
	}
	t.Logf("job %d.0 running on %s; removing it", cluster, host)

	rmStart := time.Now()
	if out, err := runTool(env.cfgFile, 30*time.Second, "condor_rm", fmt.Sprintf("%d.0", cluster)); err != nil {
		env.fail("condor_rm failed: %v\n%s", err, out)
	}

	if !waitJobGone(env.cfgFile, cluster, 15*time.Second) {
		env.fail("removed job %d.0 did not leave the queue", cluster)
	}
	// The vacate path (forcible deactivate + release) must free the slot fast.
	if !waitForSlotState(t, env.cfgFile, "", "Unclaimed", 15*time.Second) {
		env.fail("slot did not return to Unclaimed within 15s of condor_rm")
	}
	t.Logf("slot Unclaimed %.1fs after condor_rm", time.Since(rmStart).Seconds())

	if !grepFile(filepath.Join(env.logDir, "ScheddLog"), "vacating running job") {
		env.fail("ScheddLog does not record the running-job vacate")
	}

	stopScheddAndCheckHistory(t, env, cluster, 3, false)
	t.Logf("condor_rm of a running job: teardown before archive, history JobStatus=3")
}

// ---------------------------------------------------------------------------
// Lease renewal: a job outrunning the claim lease is NOT falsely requeued.
// ---------------------------------------------------------------------------

// The schedd proposes _condor_StartdHandlesAlives, so the startd sends no
// ALIVE while a starter is active; the scheduler core must renew the lease of
// every live run itself (mirroring the C++ schedd's sendAlives). With
// ALIVE_INTERVAL=1 the lease is only 6s; driving the lease sweep every 3s
// (SCHEDD_LEASE_SWEEP_INTERVAL) means a 12s job still crosses ~4 sweep ticks --
// each of which must renew, not requeue, the live run -- so the job completes on
// its first (and only) run.
func TestStage7LongJobLeaseRenewal(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "lease", stage7SlotStatic,
		"ALIVE_INTERVAL = 1\nSCHEDD_LEASE_SWEEP_INTERVAL = 3\n")
	defer env.h.Shutdown()

	submitFile, iwd := writeStage7Job(t, env.tmp, 12)
	cluster := submitStage7Job(t, env, submitFile)

	if _, ok := waitRunningWithHost(env.cfgFile, cluster, 90*time.Second); !ok {
		env.fail("job %d.0 never showed Running", cluster)
	}
	if !waitJobGone(env.cfgFile, cluster, 180*time.Second) {
		env.fail("job %d.0 never completed", cluster)
	}
	if _, err := os.ReadFile(filepath.Join(iwd, "result.txt")); err != nil {
		env.fail("result.txt not returned: %v", err)
	}

	// One run, zero exceptions: the lease sweep must not have requeued it.
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
		if st, _ := ad.EvaluateAttrInt("JobStatus"); st != 4 {
			env.fail("history JobStatus = %d, want 4", st)
		}
		if code, ok := ad.EvaluateAttrInt("ExitCode"); !ok || code != 0 {
			env.fail("history ExitCode = %d (ok=%v), want 0", code, ok)
		}
		if runs, _ := ad.EvaluateAttrInt("JobRunCount"); runs != 1 {
			env.fail("history JobRunCount = %d, want 1 (job was falsely requeued mid-lease)", runs)
		}
		if excepts, ok := ad.EvaluateAttrInt("NumShadowExceptions"); ok && excepts != 0 {
			env.fail("history NumShadowExceptions = %d, want none", excepts)
		}
	}
	if !found {
		env.fail("job %d.0 not found in history archive %s", cluster, histDir)
	}
	t.Logf("12s job with a 6s claim lease (swept every 3s) ran once to completion (lease renewed for the live shadow)")
}

// ---------------------------------------------------------------------------
// (e) Partitionable slot: the happy path activates the carved dslot.
// ---------------------------------------------------------------------------

func TestStage7PartitionableSlot(t *testing.T) {
	t.Parallel()
	env := setupStage7(t, "pslot", stage7SlotPartitionable, "")
	defer env.h.Shutdown()

	submitFile, iwd := writeStage7Job(t, env.tmp, 8)
	cluster := submitStage7Job(t, env, submitFile)

	host, sawRunning := waitRunningWithHost(env.cfgFile, cluster, 90*time.Second)
	if sawRunning {
		// The activation must land on the dynamic slot the pslot carved, not the
		// pslot itself.
		if !strings.Contains(host, "slot1_") {
			env.fail("RemoteHost = %q, want a dynamic slot (slot1_N@...)", host)
		}
		t.Logf("job %d.0 running on dynamic slot %s", cluster, host)
	} else {
		t.Logf("warning: never observed Running via condor_q polling (job may have raced to completion)")
	}

	if !waitJobGone(env.cfgFile, cluster, 120*time.Second) {
		env.fail("job %d.0 never completed on the partitionable slot", cluster)
	}
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		env.fail("result.txt not returned: %v", err)
	}
	if want := "RESULT:hello-from-stage7\n"; string(gotResult) != want {
		env.fail("result.txt = %q, want %q", string(gotResult), want)
	}
	gotStdout, err := os.ReadFile(filepath.Join(iwd, "job.out"))
	if err != nil {
		env.fail("captured stdout not returned: %v", err)
	}
	if !strings.Contains(string(gotStdout), "job stdout ok: hello-from-stage7") {
		env.fail("job.out = %q, missing expected content", string(gotStdout))
	}
	if !sawRunning {
		// Completion is proof enough, but require the dslot evidence from the log.
		if !grepFile(filepath.Join(env.logDir, "ScheddLog"), "claimed slot for activation") {
			env.fail("ScheddLog does not record the dslot activation")
		}
	}

	// Evidence for the dslot-claim-id question: the startd's keepalives must
	// resolve against the claim session the schedd imported (found=true), i.e.
	// the dslot ALIVE arrives on the claim id the schedd requested with.
	if data, err := os.ReadFile(filepath.Join(env.logDir, "ScheddLog")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "ALIVE received") {
				t.Logf("schedd keepalive: %s", strings.TrimSpace(line))
			}
		}
	}

	stopScheddAndCheckHistory(t, env, cluster, 4, true)
	t.Logf("partitionable slot: transfer job ran on the carved dslot to completion")
}
