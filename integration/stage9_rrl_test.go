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
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage9ResourceRequestList exercises real resource-request-list (RRL)
// batching in the Go schedd's NEGOTIATE handler. It submits 8 idle jobs that fold
// into 3 significant-attribute groups:
//
//	6 jobs with RequestMemory=128  (one group of 6)
//	1 job  with RequestMemory=200  (a group of 1)
//	1 job  with RequestMemory=300  (a group of 1)
//
// It asserts two things:
//
//  1. correctness: all 8 jobs run to completion and leave the queue across
//     negotiation cycles; and
//  2. batching actually happened: the ScheddLog shows a resource request offered
//     with count>=4 (the group of 6), i.e. the schedd did NOT fall back to 8
//     one-job-per-request singletons.
//
// A partitionable slot with 8 CPUs lets several matches for the batched request
// land in a single cycle (the stage-7 pslot layout).
func TestStage9ResourceRequestList(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	binName := fmt.Sprintf("golang-ap-schedd9-%d", os.Getpid())
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

# One partitionable slot with room for all 8 request_cpus=1 jobs at once, so a
# batched request can yield several matches in one cycle.
NUM_CPUS = 8
MEMORY = 4096
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = 10
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = TRUE

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

STARTD_DEBUG = D_COMMAND:2 D_FULLDEBUG
STARTER_DEBUG = D_FULLDEBUG
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

	// Build a lightweight job: sleep briefly then exit 0. File transfer is on (as
	// in stage 6/7) so the shadow serves a real activation.
	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nsleep 3\nexit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	// One cluster, three queue blocks -> procs 0..7 with the memory ladder above.
	submitFile := filepath.Join(tmp, "jobs.sub")
	subDesc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
initialdir = %s
output = job.$(Cluster).$(Process).out
error = job.$(Cluster).$(Process).err
request_cpus = 1
request_disk = 1024

request_memory = 128
queue 6

request_memory = 200
queue 1

request_memory = 300
queue 1
`, scriptPath, iwd)
	if err := os.WriteFile(submitFile, []byte(subDesc), 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- submit ----
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", submitFile)
	if err != nil {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	t.Logf("condor_submit:\n%s", out)
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}

	// ---- all 8 procs run to completion and leave the queue ----
	deadline := time.Now().Add(240 * time.Second)
	for {
		row, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
		if err == nil && len(nonEmptyLines(row)) == 0 {
			break
		}
		if time.Now().After(deadline) {
			remaining, _ := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ProcId", "JobStatus",
				"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
			fail("not all jobs completed within deadline; still in queue:\n%s", remaining)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("all 8 jobs of cluster %d completed and left the queue", cluster)

	// ---- batching actually happened: ScheddLog shows a request with count>=4 ----
	// (Real RRL: the 6 identical jobs were offered as ONE request, not 6 singletons.)
	maxCount := maxResourceRequestCount(t, filepath.Join(logDir, "ScheddLog"))
	if maxCount < 4 {
		fail("no batched resource request observed in ScheddLog (max count seen = %d); "+
			"expected a request with count>=4 for the 6 identical jobs", maxCount)
	}
	t.Logf("observed a batched resource request with count=%d in ScheddLog (RRL grouping confirmed)", maxCount)

	// Clean shutdown.
	runCondor(t, cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitGone(binName, 30*time.Second) {
		t.Logf("warning: schedd did not exit promptly after condor_off")
	}

	if t.Failed() {
		dumpAllLogs()
	}
}

// reqCountRe matches the count= field of a "sent resource request" ScheddLog line.
var reqCountRe = regexp.MustCompile(`sent resource request.*?count=(\d+)`)

// maxResourceRequestCount scans the ScheddLog for the largest ResourceRequestCount
// the schedd offered the negotiator. Returns 0 if no such line is found.
func maxResourceRequestCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("reading ScheddLog %s: %v", path, err)
		return 0
	}
	max := 0
	for _, line := range strings.Split(string(data), "\n") {
		m := reqCountRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n := 0
		fmt.Sscanf(m[1], "%d", &n)
		if n > max {
			max = n
		}
	}
	return max
}
