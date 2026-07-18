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
	"syscall"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/userlog"
)

// TestStage12UserLogBackpressure is the isolation proof for ROADMAP #1 steps
// 1-2: a job whose `log = ...` points at a HUNG filesystem must not freeze the
// schedd or block other users' jobs.
//
// Job A's log is a named pipe (mkfifo) with no reader: the schedd's user-log
// writer blocks forever on open(O_WRONLY), the classic hung-NFS analog, tying
// up ONE goroutine of the bounded writer pool. Job B has a normal log on fast
// local disk. The test asserts, WHILE job A's log is stuck:
//
//   - job B submits, runs, and COMPLETES, with its log getting the full
//     Submit -> Execute -> JobTerminated sequence (condor_wait exits 0);
//   - job A also leaves the queue (the scheduler core reaps it despite its
//     hung log -- core producers drop-on-full and never block);
//   - the schedd stays responsive the whole time (condor_q keeps answering).
func TestStage12UserLogBackpressure(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q",
		"condor_wait", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	binName := fmt.Sprintf("golang-ap-schedd12-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	const uidDomain = "golang-ap.test"
	// Two slots so job A and job B run concurrently; short intervals to keep the
	// test fast. A small drain grace bounds shutdown (a worker is stuck on the
	// hung FIFO and can never be reaped).
	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
SCHEDD_SHUTDOWN_DRAIN_GRACE = 3
SCHEDD_USERLOG_WORKERS = 8
SCHEDD_USERLOG_BACKPRESSURE_TIMEOUT = 2

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

NUM_CPUS = 2
MEMORY = 1024
START = TRUE
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

	// A tiny sleep job (fast: keep the whole ladder well under 5 min).
	script := "#!/bin/sh\nsleep 2\nexit 0\n"
	scriptPath := filepath.Join(tmp, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	submitJob := func(name, logName string, iwd string) int {
		t.Helper()
		if err := os.MkdirAll(iwd, 0o755); err != nil {
			t.Fatal(err)
		}
		subFile := filepath.Join(tmp, name+".sub")
		desc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
initialdir = %s
log = %s
output = %s.out
error = %s.err
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`, scriptPath, iwd, logName, name, name)
		if err := os.WriteFile(subFile, []byte(desc), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := runTool(cfgFile, 60*time.Second, "condor_submit", subFile)
		if err != nil {
			fail("condor_submit (%s) failed: %v\n%s", name, err, out)
		}
		c := parseClusterID(out)
		if c <= 0 {
			fail("could not parse cluster id for %s from: %q", name, out)
		}
		return c
	}

	// --- Job A: log is a HUNG named pipe (no reader -> writer blocks on open) --
	iwdA := filepath.Join(tmp, "jobA")
	if err := os.MkdirAll(iwdA, 0o755); err != nil {
		t.Fatal(err)
	}
	fifoA := filepath.Join(iwdA, "jobA.log")
	if err := syscall.Mkfifo(fifoA, 0o644); err != nil {
		t.Fatalf("mkfifo %s: %v (needed to simulate a hung log FS)", fifoA, err)
	}
	// Sanity: opening the FIFO for write with no reader would block, so we do
	// NOT open it here; the schedd's writer will, and hang -- that is the point.
	clusterA := submitJob("jobA", "jobA.log", iwdA)
	t.Logf("job A %d.0 submitted with a HUNG log (FIFO %s, no reader)", clusterA, fifoA)

	// --- Job B: normal log on fast local disk ---------------------------------
	iwdB := filepath.Join(tmp, "jobB")
	logB := filepath.Join(iwdB, "jobB.log")
	clusterB := submitJob("jobB", "jobB.log", iwdB)
	t.Logf("job B %d.0 submitted with a normal log %s", clusterB, logB)

	// The schedd must stay responsive throughout: condor_q keeps answering
	// promptly even though a writer goroutine is wedged on the hung FIFO.
	stopPing := make(chan struct{})
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		for {
			select {
			case <-stopPing:
				return
			default:
			}
			start := time.Now()
			if _, err := runTool(cfgFile, 15*time.Second, "condor_q", "-allusers", "-totals"); err != nil {
				t.Errorf("condor_q did not answer while a log FS was hung (schedd unresponsive): %v", err)
				return
			}
			if el := time.Since(start); el > 15*time.Second {
				t.Errorf("condor_q took %s while a log FS was hung; schedd may be stalling", el)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Job B must run and COMPLETE (leave the queue) despite job A's hung log.
	waitGone := func(cluster int, d time.Duration) bool {
		deadline := time.Now().Add(d)
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

	if !waitGone(clusterB, 120*time.Second) {
		close(stopPing)
		<-pingDone
		fail("job B %d.0 never completed while job A's log FS was hung — isolation FAILED", clusterB)
	}
	t.Logf("job B %d.0 completed while job A's log stayed hung", clusterB)

	// Job B's log must have the full lifecycle (its writer ran on a healthy
	// worker, unaffected by job A's stuck worker).
	start := time.Now()
	waitOut, err := runTool(cfgFile, 60*time.Second, "condor_wait", "-wait", "60", logB)
	if err != nil {
		close(stopPing)
		<-pingDone
		fail("condor_wait on job B's log failed: %v\n%s", err, waitOut)
	}
	if el := time.Since(start); el > 30*time.Second {
		fail("condor_wait on job B took %s; expected prompt return", el)
	}
	events := parseUserLog(t, logB)
	iSub := indexKind(events, userlog.KindSubmit)
	iExe := indexKind(events, userlog.KindExecute)
	iTerm := indexKind(events, userlog.KindJobTerminated)
	if iSub < 0 || iExe < 0 || iTerm < 0 || iSub >= iExe || iExe >= iTerm {
		fail("job B log missing Submit->Execute->JobTerminated; events=%v", kindsOf(events))
	}
	t.Logf("job B log OK: Submit -> Execute -> JobTerminated (written by a healthy worker)")

	// The scheduler core must also reap job A out of the queue even though its
	// log write is wedged (core producers drop-on-full, never block).
	if !waitGone(clusterA, 60*time.Second) {
		close(stopPing)
		<-pingDone
		fail("job A %d.0 never left the queue — the core is blocked on the hung log FS", clusterA)
	}
	t.Logf("job A %d.0 left the queue despite its hung log — the core never froze", clusterA)

	close(stopPing)
	<-pingDone

	if t.Failed() {
		dumpAllLogs()
	}
}

// kindsOf lists the event kinds for a failure message.
func kindsOf(events []userlog.Event) []userlog.EventKind {
	var ks []userlog.EventKind
	for _, ev := range events {
		ks = append(ks, ev.Kind)
	}
	return ks
}
