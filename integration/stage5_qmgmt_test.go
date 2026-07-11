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

// TestStage5QmgmtUnderCondorMaster runs the pure-Go schedd under condor_master
// and drives it with the STOCK C++ command-line tools:
//
//	(1) condor_submit of a 3-proc sleep cluster succeeds;
//	(2) condor_q (both -af and -long) shows 3 idle jobs with correct ids/owner;
//	(3) condor_hold/condor_release/condor_rm perform the status state machine;
//	(4) a schedd restart preserves the queue (durability);
//	(5) the removed job landed in the history Archive.
func TestStage5QmgmtUnderCondorMaster(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q",
		"condor_hold", "condor_release", "condor_rm", "condor_restart", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build the Go schedd with a pid-tagged basename (see stage1 for why).
	binName := fmt.Sprintf("golang-ap-schedd5-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	build := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	extra := fmt.Sprintf(`
# --- Run golang-ap's schedd as the pool's SCHEDD under shared_port ---
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

# --- FS auth + AES encryption everywhere (cedar implements exactly this) ---
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES

# This is a queue/tooling test: jobs must stay Idle. The harness runs a
# negotiator+startd by default, and the schedd can now really match jobs
# (stage 6), which would race the hold/rm/restart assertions below.
START = FALSE
`, scheddBin)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()

	dumpAllLogs := func() {
		for _, name := range []string{"ScheddLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
	}
	fail := func(format string, args ...any) {
		t.Helper()
		dumpAllLogs()
		t.Fatalf(format, args...)
	}

	// Wait for the Go schedd to publish its address (it must be up before
	// condor_submit can locate it).
	if !waitForFile(filepath.Join(logDir, ".schedd_address"), 60*time.Second) {
		fail("Go schedd never wrote its address file")
	}
	me := os.Getenv("USER")
	if me == "" {
		me = "unknown"
	}

	// ---- (1) stock condor_submit of a 3-proc cluster ----
	submitFile := filepath.Join(tmp, "sleep.sub")
	if err := os.WriteFile(submitFile, []byte(`universe = vanilla
executable = /bin/sleep
arguments = 600
should_transfer_files = NO
queue 3
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", submitFile)
	if err != nil {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	t.Logf("condor_submit:\n%s", out)
	if !strings.Contains(out, "3 job(s) submitted to cluster") {
		fail("condor_submit output missing '3 job(s) submitted': %q", out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}

	// ---- (2) stock condor_q sees 3 idle jobs ----
	rows := waitForQRows(t, cfgFile, 3, 30*time.Second)
	if rows == nil {
		out, _ := runTool(cfgFile, 30*time.Second, "condor_q", "-allusers", "-af", "ClusterId", "ProcId", "Owner", "JobStatus")
		fail("condor_q never showed 3 jobs; last output:\n%s", out)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		f := strings.Fields(row)
		if len(f) != 4 {
			fail("condor_q -af row malformed: %q", row)
		}
		if f[0] != fmt.Sprintf("%d", cluster) {
			fail("condor_q row cluster = %s, want %d", f[0], cluster)
		}
		if f[2] != me {
			fail("condor_q row owner = %s, want %s", f[2], me)
		}
		if f[3] != "1" {
			fail("condor_q row status = %s, want 1 (idle)", f[3])
		}
		seen[f[1]] = true
	}
	for _, p := range []string{"0", "1", "2"} {
		if !seen[p] {
			fail("condor_q missing proc %s (saw %v)", p, seen)
		}
	}
	t.Logf("condor_q -af shows 3 idle jobs of cluster %d owned by %s", cluster, me)

	// condor_q -long parses and carries the essentials.
	longOut, err := runTool(cfgFile, 30*time.Second, "condor_q", "-allusers", "-long")
	if err != nil {
		fail("condor_q -long failed: %v\n%s", err, longOut)
	}
	if got := strings.Count(longOut, "GlobalJobId ="); got != 3 {
		fail("condor_q -long shows %d GlobalJobId lines, want 3:\n%s", got, longOut)
	}
	for _, want := range []string{"ClusterId = " + fmt.Sprintf("%d", cluster), "JobStatus = 1", `Owner = "` + me + `"`, "Cmd = "} {
		if !strings.Contains(longOut, want) {
			fail("condor_q -long missing %q:\n%s", want, longOut)
		}
	}
	t.Log("condor_q -long parses with expected attributes")

	// ---- (3) hold / release / rm ----
	holdID := fmt.Sprintf("%d.0", cluster)
	rmID := fmt.Sprintf("%d.1", cluster)

	if out, err := runTool(cfgFile, 30*time.Second, "condor_hold", holdID); err != nil {
		fail("condor_hold %s failed: %v\n%s", holdID, err, out)
	}
	if !waitForJobStatus(cfgFile, cluster, 0, "5", 20*time.Second) {
		fail("job %s never reached held (5)", holdID)
	}
	hr, _ := runTool(cfgFile, 30*time.Second, "condor_q", "-allusers", "-af", "HoldReason",
		"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==0", cluster))
	if strings.TrimSpace(hr) == "" || strings.TrimSpace(hr) == "undefined" {
		fail("held job has no HoldReason (got %q)", hr)
	}
	t.Logf("condor_hold: job %s held with HoldReason %q", holdID, strings.TrimSpace(hr))

	if out, err := runTool(cfgFile, 30*time.Second, "condor_release", holdID); err != nil {
		fail("condor_release %s failed: %v\n%s", holdID, err, out)
	}
	if !waitForJobStatus(cfgFile, cluster, 0, "1", 20*time.Second) {
		fail("job %s never returned to idle (1) after release", holdID)
	}
	t.Logf("condor_release: job %s back to idle", holdID)

	if out, err := runTool(cfgFile, 30*time.Second, "condor_rm", rmID); err != nil {
		fail("condor_rm %s failed: %v\n%s", rmID, err, out)
	}
	if rows := waitForQRows(t, cfgFile, 2, 20*time.Second); rows == nil {
		out, _ := runTool(cfgFile, 30*time.Second, "condor_q", "-allusers", "-af", "ProcId")
		fail("condor_q still does not show 2 jobs after condor_rm; output:\n%s", out)
	}
	left, _ := runTool(cfgFile, 30*time.Second, "condor_q", "-allusers", "-af", "ProcId")
	if strings.Contains(" "+strings.Join(strings.Fields(left), " ")+" ", " 1 ") {
		fail("removed proc %s still visible in condor_q: %q", rmID, left)
	}
	t.Logf("condor_rm: job %s removed from the queue", rmID)

	// ---- (4) durability across a schedd restart ----
	if out, err := runTool(cfgFile, 60*time.Second, "condor_restart", "-daemon", "schedd"); err != nil {
		fail("condor_restart -schedd failed: %v\n%s", err, out)
	}
	// The queue must come back with the same 2 jobs (procs 0 and 2, both idle).
	deadline := time.Now().Add(60 * time.Second)
	restored := false
	for time.Now().Before(deadline) {
		out, err := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId", "ProcId", "JobStatus")
		if err == nil {
			rows := nonEmptyLines(out)
			if len(rows) == 2 {
				ok := true
				procs := map[string]bool{}
				for _, r := range rows {
					f := strings.Fields(r)
					if len(f) != 3 || f[0] != fmt.Sprintf("%d", cluster) || f[2] != "1" {
						ok = false
						break
					}
					procs[f[1]] = true
				}
				if ok && procs["0"] && procs["2"] {
					restored = true
					break
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !restored {
		out, _ := runTool(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId", "ProcId", "JobStatus")
		fail("queue not intact after schedd restart; condor_q:\n%s", out)
	}
	t.Log("queue intact after condor_restart -daemon schedd (durability)")

	// ---- (5) removed job present in the history Archive ----
	// Stop the schedd cleanly first so we open the archive without a live writer.
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
	q, err := vm.Parse(fmt.Sprintf("ClusterId == %d && ProcId == 1", cluster))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for ad := range arc.Query(q) {
		found = true
		if st, _ := ad.EvaluateAttrInt("JobStatus"); st != 3 {
			fail("history record for %s has JobStatus %d, want 3 (Removed)", rmID, st)
		}
		if owner, _ := ad.EvaluateAttrString("Owner"); owner != me {
			fail("history record owner = %q, want %q", owner, me)
		}
	}
	if !found {
		fail("removed job %s not found in history archive %s", rmID, histDir)
	}
	t.Logf("removed job %s present in history archive with JobStatus=3", rmID)
}

// runTool runs an HTCondor tool against the harness config, returning combined
// output and error (unlike runCondor it does not fail the test).
func runTool(configFile string, timeout time.Duration, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
		return string(out), runErr
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return string(out), fmt.Errorf("%s timed out after %s", name, timeout)
	}
}

// waitForQRows polls condor_q until it reports exactly n job rows.
func waitForQRows(t *testing.T, configFile string, n int, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runTool(configFile, 20*time.Second, "condor_q", "-allusers",
			"-af", "ClusterId", "ProcId", "Owner", "JobStatus")
		if err == nil {
			rows := nonEmptyLines(out)
			if len(rows) == n {
				return rows
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// waitForJobStatus polls one job's JobStatus until it equals want.
func waitForJobStatus(configFile string, cluster, proc int, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	constraint := fmt.Sprintf("ClusterId==%d && ProcId==%d", cluster, proc)
	for time.Now().Before(deadline) {
		out, err := runTool(configFile, 20*time.Second, "condor_q", "-allusers",
			"-af", "JobStatus", "-constraint", constraint)
		if err == nil && strings.TrimSpace(out) == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// parseClusterID extracts N from "... submitted to cluster N."
func parseClusterID(out string) int {
	idx := strings.LastIndex(out, "cluster ")
	if idx < 0 {
		return -1
	}
	rest := strings.TrimSpace(out[idx+len("cluster "):])
	rest = strings.TrimSuffix(rest, ".")
	rest = strings.TrimSpace(strings.Split(rest, "\n")[0])
	rest = strings.TrimSuffix(rest, ".")
	n := 0
	if _, err := fmt.Sscanf(rest, "%d", &n); err != nil {
		return -1
	}
	return n
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// waitForFile polls until path exists and is non-empty.
func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(path); err == nil && st.Size() > 0 {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
