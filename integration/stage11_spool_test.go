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
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage11Spool exercises sandbox spooling end to end against the pure-Go
// schedd, both via the stock C++ tools and via the golang-htcondor client:
//
// Part A (stock tools):
//
//	condor_submit -spool a transfer job whose executable AND input file live in
//	a directory that is DELETED right after submit — proving the job runs from
//	the schedd's spool copy. Assert the code-16 ("Spooling input data files")
//	hold/release lifecycle (LastJobStatus=5, LastHoldReasonCode=16,
//	StageInFinish set), the rewriteSpooledJobAd semantics (Iwd -> spool
//	sandbox, Cmd -> basename), the run to completion, and finally
//	condor_transfer_data retrieving the outputs (with correct content) into
//	the job's original initialdir.
//
// Part B (Go client, the loopback oracle):
//
//	SubmitRemote (job arrives Held with HoldReasonCode 16, directly observed) +
//	SpoolJobFilesFromFS (job released) -> runs -> completes ->
//	ReceiveJobSandbox streams the output sandbox back as a tar; assert content.
func TestStage11Spool(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q",
		"condor_transfer_data", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build the Go schedd with a pid-tagged basename (see stage1 for why).
	binName := fmt.Sprintf("golang-ap-schedd11-%d", os.Getpid())
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
	spoolDir := h.GetSpoolDir()

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
	addrFile := filepath.Join(logDir, ".schedd_address")
	if !waitForFile(addrFile, 60*time.Second) {
		fail("Go schedd never wrote its address file")
	}
	addrBytes, err := os.ReadFile(addrFile)
	if err != nil {
		t.Fatal(err)
	}
	// First line is the sinful; the file also carries the $CondorVersion$ /
	// $CondorPlatform$ banner lines (C++ address-file format).
	scheddAddr := strings.TrimSpace(strings.SplitN(string(addrBytes), "\n", 2)[0])
	t.Logf("Go schedd at %s", scheddAddr)

	// =====================================================================
	// Part A: stock condor_submit -spool / condor_transfer_data
	// =====================================================================

	// The job's inputs live in a directory we DELETE right after submit; the
	// outputs are retrieved into a separate (surviving) initialdir.
	const inputContent = "hello-from-spool"
	inputsDir := filepath.Join(tmp, "inputs-deleted-after-submit")
	retrieveDir := filepath.Join(tmp, "retrieve")
	for _, d := range []string{inputsDir, retrieveDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
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
	if err := os.WriteFile(filepath.Join(inputsDir, "job.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatal(err)
	}

	submitFile := filepath.Join(tmp, "spool_job.sub")
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
`, filepath.Join(inputsDir, "job.sh"), filepath.Join(inputsDir, "input.dat"), retrieveDir)
	if err := os.WriteFile(submitFile, []byte(subDesc), 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- (A1) condor_submit -spool: submit + spool the input sandbox ----
	out, err := runTool(cfgFile, 120*time.Second, "condor_submit", "-spool", submitFile)
	if err != nil {
		fail("condor_submit -spool failed: %v\n%s", err, out)
	}
	t.Logf("condor_submit -spool:\n%s", out)
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}

	// ---- (A2) delete the submit-side inputs: only the spool copy remains ----
	if err := os.RemoveAll(inputsDir); err != nil {
		t.Fatal(err)
	}
	t.Logf("deleted submit-side input dir %s", inputsDir)

	// ---- (A3) hold/release lifecycle + ad rewrite assertions ----
	// condor_submit -spool returns after the schedd received the sandbox and
	// released the code-16 hold, so the job should promptly show:
	//   JobStatus 1/2 (released, then matched), LastJobStatus=5,
	//   LastHoldReasonCode=16, StageInFinish>0, Cmd rewritten to a basename,
	//   Iwd rewritten into $(SPOOL).
	// Live observation is best-effort (the job can be matched and finish
	// quickly); the authoritative lifecycle assertions run against the history
	// archive at the end of the test.
	sawReleased := false
	emptyPolls := 0
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		row, qerr := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af",
			"JobStatus", "LastJobStatus", "LastHoldReasonCode", "StageInFinish", "Cmd", "Iwd",
			"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
		t.Logf("release-state poll: err=%v row=%q", qerr, strings.TrimSpace(row))
		f := strings.Fields(strings.TrimSpace(row))
		if qerr == nil && len(f) >= 6 && (f[0] == "1" || f[0] == "2") {
			if f[1] != "5" {
				fail("job %d.0: LastJobStatus = %s, want 5 (was Held for spooling)", cluster, f[1])
			}
			if f[2] != "16" {
				fail("job %d.0: LastHoldReasonCode = %s, want 16 (SpoolingInput)", cluster, f[2])
			}
			if fin, err := strconv.Atoi(f[3]); err != nil || fin <= 0 {
				fail("job %d.0: StageInFinish = %s, want a positive timestamp", cluster, f[3])
			}
			if f[4] != "job.sh" {
				fail("job %d.0: Cmd = %q, want rewritten basename \"job.sh\"", cluster, f[4])
			}
			if !strings.HasPrefix(f[5], spoolDir) {
				fail("job %d.0: Iwd = %q, want under spool dir %q", cluster, f[5], spoolDir)
			}
			sawReleased = true
			t.Logf("job %d.0 released from code-16 hold: %s", cluster, row)
			break
		}
		if qerr == nil && len(nonEmptyLines(row)) == 0 {
			emptyPolls++
			if emptyPolls >= 2 {
				// Completed before we caught it in the queue; the history
				// assertions below still verify the lifecycle.
				t.Logf("job %d.0 already left the queue before release-state polling caught it", cluster)
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !sawReleased {
		t.Logf("note: released state not observed live; relying on history assertions")
	}

	// ---- (A4) job runs from the spool copy and completes ----
	gone := false
	deadline = time.Now().Add(150 * time.Second)
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
		fail("job %d.0 never completed (still in queue; its inputs only existed in spool)", cluster)
	}
	t.Logf("job %d.0 completed and left the queue", cluster)

	// The output sandbox must still be sitting in the schedd's spool
	// (leave-in-spool semantics for remote submitters).
	sandbox := filepath.Join(spoolDir, strconv.Itoa(cluster%10000), "0",
		fmt.Sprintf("cluster%d.proc0.subproc0", cluster))
	if data, err := os.ReadFile(filepath.Join(sandbox, "result.txt")); err != nil {
		fail("spooled output result.txt missing from spool sandbox %s: %v", sandbox, err)
	} else if want := "RESULT:" + inputContent + "\n"; string(data) != want {
		fail("spool sandbox result.txt = %q, want %q", data, want)
	}
	t.Logf("output sandbox present in spool at %s", sandbox)

	// ---- (A5) condor_transfer_data retrieves the outputs ----
	out, err = runTool(cfgFile, 120*time.Second, "condor_transfer_data",
		"-addr", scheddAddr, strconv.Itoa(cluster))
	if err != nil {
		fail("condor_transfer_data failed: %v\n%s", err, out)
	}
	t.Logf("condor_transfer_data:\n%s", out)

	// Files land in the job's original initialdir (SUBMIT_Iwd).
	gotResult, err := os.ReadFile(filepath.Join(retrieveDir, "result.txt"))
	if err != nil {
		fail("condor_transfer_data did not return result.txt into %s: %v", retrieveDir, err)
	}
	if want := "RESULT:" + inputContent + "\n"; string(gotResult) != want {
		fail("retrieved result.txt = %q, want %q", gotResult, want)
	}
	gotStdout, err := os.ReadFile(filepath.Join(retrieveDir, "job.out"))
	if err != nil {
		fail("condor_transfer_data did not return job.out into %s: %v", retrieveDir, err)
	}
	if want := "job stdout ok: " + inputContent; !strings.Contains(string(gotStdout), want) {
		fail("retrieved job.out = %q, want it to contain %q", gotStdout, want)
	}
	t.Logf("condor_transfer_data returned outputs with expected content")

	// =====================================================================
	// Part B: the golang-htcondor client (SubmitRemote + SpoolJobFilesFromFS
	// + ReceiveJobSandbox) against the Go schedd
	// =====================================================================

	prevConfig, hadConfig := os.LookupEnv("CONDOR_CONFIG")
	_ = os.Setenv("CONDOR_CONFIG", cfgFile)
	htcondor.ReloadDefaultConfig()
	defer func() {
		if hadConfig {
			_ = os.Setenv("CONDOR_CONFIG", prevConfig)
		} else {
			_ = os.Unsetenv("CONDOR_CONFIG")
		}
		htcondor.ReloadDefaultConfig()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	schedd := htcondor.NewSchedd(h.GetScheddName(), scheddAddr)

	const inputContentB = "hello-from-go-spool"
	scriptB := "#!/bin/sh\n" +
		"got=$(cat input2.dat)\n" +
		"echo \"go job stdout: $got\"\n" +
		"printf 'GO-RESULT:%s\\n' \"$got\" > result2.txt\n" +
		"exit 0\n"
	submitB := `universe = vanilla
executable = /bin/sh
arguments = job2.sh
transfer_executable = false
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = input2.dat,job2.sh
output = job2.out
error = job2.err
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`

	// ---- (B1) SubmitRemote: job arrives Held with HoldReasonCode 16 ----
	clusterB, procAds, err := schedd.SubmitRemote(ctx, submitB)
	if err != nil {
		fail("SubmitRemote failed: %v", err)
	}
	if len(procAds) != 1 {
		fail("SubmitRemote returned %d proc ads, want 1", len(procAds))
	}
	t.Logf("Go client submitted cluster %d", clusterB)

	constraintB := fmt.Sprintf("ClusterId == %d", clusterB)
	ads, _, err := schedd.QueryWithOptions(ctx, constraintB, &htcondor.QueryOptions{Projection: []string{"JobStatus", "HoldReasonCode", "HoldReason"}})
	if err != nil {
		fail("query after SubmitRemote failed: %v", err)
	}
	if len(ads) != 1 {
		fail("query after SubmitRemote returned %d ads, want 1", len(ads))
	}
	if st, _ := ads[0].EvaluateAttrInt("JobStatus"); st != 5 {
		fail("job %d.0 JobStatus = %d before spooling, want 5 (Held)", clusterB, st)
	}
	if code, _ := ads[0].EvaluateAttrInt("HoldReasonCode"); code != 16 {
		fail("job %d.0 HoldReasonCode = %d before spooling, want 16 (SpoolingInput)", clusterB, code)
	}
	t.Logf("job %d.0 is Held with HoldReasonCode 16 (\"Spooling input data files\")", clusterB)

	// ---- (B2) SpoolJobFilesFromFS uploads the input sandbox ----
	inputFS := fstest.MapFS{
		"job2.sh":    &fstest.MapFile{Data: []byte(scriptB), Mode: 0o755},
		"input2.dat": &fstest.MapFile{Data: []byte(inputContentB), Mode: 0o644},
	}
	if err := schedd.SpoolJobFilesFromFS(ctx, procAds, inputFS); err != nil {
		fail("SpoolJobFilesFromFS failed: %v", err)
	}
	t.Logf("input sandbox spooled via the Go client")

	// ---- (B3) the schedd released the code-16 hold ----
	released := false
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ads, _, err = schedd.QueryWithOptions(ctx, constraintB, &htcondor.QueryOptions{Projection: []string{"JobStatus", "StageInFinish", "LastHoldReasonCode"}})
		if err == nil && len(ads) == 1 {
			st, _ := ads[0].EvaluateAttrInt("JobStatus")
			if st == 1 || st == 2 {
				if fin, _ := ads[0].EvaluateAttrInt("StageInFinish"); fin <= 0 {
					fail("job %d.0 released but StageInFinish = %d, want > 0", clusterB, fin)
				}
				if code, _ := ads[0].EvaluateAttrInt("LastHoldReasonCode"); code != 16 {
					fail("job %d.0 released but LastHoldReasonCode = %d, want 16", clusterB, code)
				}
				released = true
				break
			}
			if st == 5 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}
		if err == nil && len(ads) == 0 {
			// Ran to completion before we observed the released state.
			released = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !released {
		fail("job %d.0 was never released after spooling", clusterB)
	}
	t.Logf("job %d.0 released after spool", clusterB)

	// ---- (B4) job runs from the spool sandbox and completes ----
	gone = false
	deadline = time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		ads, _, err = schedd.QueryWithOptions(ctx, constraintB, &htcondor.QueryOptions{Projection: []string{"JobStatus"}})
		if err == nil && len(ads) == 0 {
			gone = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !gone {
		fail("Go-client job %d.0 never completed", clusterB)
	}
	t.Logf("job %d.0 completed and left the queue", clusterB)

	// ---- (B5) ReceiveJobSandbox streams the output sandbox back ----
	var tarBuf bytes.Buffer
	recvCtx, recvCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer recvCancel()
	if err := <-schedd.ReceiveJobSandbox(recvCtx, constraintB, &tarBuf); err != nil {
		fail("ReceiveJobSandbox failed: %v", err)
	}
	files := map[string]string{}
	tr := tar.NewReader(&tarBuf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail("reading sandbox tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			fail("reading %s from sandbox tar: %v", hdr.Name, err)
		}
		files[hdr.Name] = string(data)
	}
	t.Logf("ReceiveJobSandbox returned %d file(s): %v", len(files), keysOf(files))
	if got, want := files["result2.txt"], "GO-RESULT:"+inputContentB+"\n"; got != want {
		fail("sandbox result2.txt = %q, want %q", got, want)
	}
	if got, want := files["job2.out"], "go job stdout: "+inputContentB; !strings.Contains(got, want) {
		fail("sandbox job2.out = %q, want it to contain %q", got, want)
	}
	t.Logf("Go client retrieved the output sandbox with expected content")

	// =====================================================================
	// Lifecycle assertions from the history archive (deterministic): stop the
	// schedd cleanly, then verify the terminal ads carry the full spool story.
	// =====================================================================

	runCondor(t, cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	if !waitGone(binName, 30*time.Second) {
		fail("schedd did not exit after condor_off")
	}
	histDir := filepath.Join(spoolDir, "history")
	arc, err := collections.OpenArchive(collections.ArchiveOptions{Dir: histDir})
	if err != nil {
		fail("opening history archive at %s: %v", histDir, err)
	}
	defer func() { _ = arc.Close() }()

	checkHistory := func(clusterID int, wantCmd, wantSubmitIwd string) {
		t.Helper()
		q, err := vm.Parse(fmt.Sprintf("ClusterId == %d && ProcId == 0", clusterID))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for ad := range arc.Query(q) {
			found = true
			if st, _ := ad.EvaluateAttrInt("JobStatus"); st != 4 {
				fail("history %d.0: JobStatus = %d, want 4 (Completed)", clusterID, st)
			}
			if code, ok := ad.EvaluateAttrInt("ExitCode"); !ok || code != 0 {
				fail("history %d.0: ExitCode = %d (ok=%v), want 0", clusterID, code, ok)
			}
			// The code-16 hold -> release lifecycle.
			if code, _ := ad.EvaluateAttrInt("LastHoldReasonCode"); code != 16 {
				fail("history %d.0: LastHoldReasonCode = %d, want 16 (SpoolingInput)", clusterID, code)
			}
			if fin, _ := ad.EvaluateAttrInt("StageInFinish"); fin <= 0 {
				fail("history %d.0: StageInFinish missing (spool completion not recorded)", clusterID)
			}
			if rr, _ := ad.EvaluateAttrString("ReleaseReason"); rr != "Data files spooled" {
				fail("history %d.0: ReleaseReason = %q, want \"Data files spooled\"", clusterID, rr)
			}
			// rewriteSpooledJobAd semantics.
			if wantCmd != "" {
				if cmd, _ := ad.EvaluateAttrString("Cmd"); cmd != wantCmd {
					fail("history %d.0: Cmd = %q, want rewritten %q", clusterID, cmd, wantCmd)
				}
			}
			if iwd, _ := ad.EvaluateAttrString("Iwd"); !strings.HasPrefix(iwd, spoolDir) {
				fail("history %d.0: Iwd = %q, want under spool dir %q", clusterID, iwd, spoolDir)
			}
			if wantSubmitIwd != "" {
				if siwd, _ := ad.EvaluateAttrString("SUBMIT_Iwd"); siwd != wantSubmitIwd {
					fail("history %d.0: SUBMIT_Iwd = %q, want original submit dir %q", clusterID, siwd, wantSubmitIwd)
				}
			}
			// The output landed in spool and was recorded for retrieval.
			if sof, _ := ad.EvaluateAttrString("SpooledOutputFiles"); !strings.Contains(sof, "result") {
				fail("history %d.0: SpooledOutputFiles = %q, want it to list the result file", clusterID, sof)
			}
		}
		if !found {
			fail("job %d.0 not found in history archive %s", clusterID, histDir)
		}
	}
	checkHistory(cluster, "job.sh", retrieveDir)
	checkHistory(clusterB, "", "")
	t.Logf("history archive confirms the spool lifecycle for clusters %d and %d", cluster, clusterB)

	if t.Failed() {
		dumpAllLogs()
	}
}

// keysOf returns the sorted-ish key list of a small map for logging.
func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
