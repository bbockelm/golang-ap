// Package integration holds end-to-end tests that run golang-ap's schedd as the
// pool's condor_schedd under a real condor_master, alongside a C++ collector.
// These tests skip unless the HTCondor binaries are on PATH (set PATH to the
// build's sbin+bin to run them).
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage1ScheddUnderCondorMaster runs the pure-Go schedd as the SCHEDD daemon
// under condor_master with a C++ collector. It proves Stage 1 lifecycle:
//
//	(a) the Go schedd advertises and is visible via `condor_status -schedd`;
//	(b) it stays alive (same pid, no master crash-loop) for >= 2 SCHEDD_INTERVALs;
//	(c) `condor_off -daemon schedd` shuts it down cleanly and it does not restart.
func TestStage1ScheddUnderCondorMaster(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_status", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build the Go schedd binary the master will launch as the SCHEDD daemon.
	// condor_master sets the child's argv[0] to the binary's BASENAME, so we make
	// the basename unique to this test run (pid-tagged): pgrep -f then matches
	// exactly this run's process and never an orphan from a prior run.
	binName := fmt.Sprintf("golang-ap-schedd-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	build := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	const interval = 5
	extra := fmt.Sprintf(`
# --- Run golang-ap's schedd as the pool's SCHEDD under shared_port ---
# The schedd is a DaemonCore daemon in DAEMON_LIST, so condor_master pre-creates
# its command socket; under USE_SHARED_PORT (the harness default) we inherit the
# shared-port endpoint (sock=schedd) rather than re-binding a fixed port.
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = %d
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

# --- Authentication: every daemon authenticates (FS) and encrypts (AES-GCM, ---
# --- the only cipher cedar implements) so the Go schedd advertises to the C++ ---
# --- collector exactly like a C++ schedd would. ---
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES
`, scheddBin, interval)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()

	dumpAllLogs := func() {
		for _, name := range []string{"ScheddLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
	}

	ctx := context.Background()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	// (a) The Go schedd must advertise a Scheduler ad the collector serves.
	addr := locateWithRetry(t, ctx, col, "Schedd", 60*time.Second)
	if addr == "" {
		dumpAllLogs()
		t.Fatal("Go schedd never became locatable via the collector")
	}
	t.Logf("Go schedd located via the collector at %s", addr)

	// condor_status -schedd (the C++ query tool) must also see it -- wire-compat
	// with the real client. Retry: the ad may still be propagating.
	if out := waitForCondorStatusSchedd(t, h.GetConfigFile(), 30*time.Second); out == "" {
		dumpAllLogs()
		t.Fatal("condor_status -schedd never listed the Go schedd")
	} else {
		t.Logf("condor_status -schedd:\n%s", out)
	}

	// The schedd process must be running as exactly one process.
	pids := pgrep(t, binName)
	if len(pids) != 1 {
		dumpAllLogs()
		t.Fatalf("expected exactly one schedd process, found %d: %v", len(pids), pids)
	}
	pid := pids[0]
	t.Logf("Go schedd running as pid %s", pid)

	// (b) It must stay alive as the SAME pid for >= 2 SCHEDD_INTERVALs: a master
	// crash-loop (childalive failure, non-zero exit) would restart it under a new
	// pid, or take it out of the collector entirely.
	time.Sleep(time.Duration(2*interval+2) * time.Second)
	pids = pgrep(t, binName)
	if len(pids) != 1 || pids[0] != pid {
		dumpAllLogs()
		t.Fatalf("schedd pid changed or process count wrong after 2 intervals: before=%s now=%v (crash-loop?)", pid, pids)
	}
	if addr := locateWithRetry(t, ctx, col, "Schedd", 15*time.Second); addr == "" {
		dumpAllLogs()
		t.Fatal("Go schedd stopped being locatable after 2 intervals")
	}
	t.Logf("Go schedd still alive as pid %s after 2 intervals", pid)

	// (c) condor_off -daemon schedd must shut it down cleanly (no restart). Ask
	// the master to turn off the schedd; the master signals SIGTERM and does not
	// restart a daemon it was told to turn off.
	runCondor(t, h.GetConfigFile(), 30*time.Second, "condor_off", "-daemon", "schedd")

	if !waitGone(binName, 30*time.Second) {
		dumpAllLogs()
		t.Fatalf("schedd process did not exit after condor_off (pids still: %v)", pgrep(t, binName))
	}
	t.Log("Go schedd exited after condor_off")

	// It must NOT come back (a crash-loop or errant master restart would).
	time.Sleep(time.Duration(2*interval) * time.Second)
	if pids := pgrep(t, binName); len(pids) != 0 {
		dumpAllLogs()
		t.Fatalf("schedd restarted after condor_off (crash-loop?); pids: %v", pids)
	}

	// The master log must show the schedd exited normally, not that it is being
	// restarted after an abnormal exit.
	if data, err := os.ReadFile(filepath.Join(logDir, "MasterLog")); err == nil {
		ml := string(data)
		if strings.Contains(ml, "restarting") && strings.Contains(ml, "abnormal") {
			t.Logf("=== MasterLog ===\n%s", ml)
			t.Fatal("MasterLog indicates an abnormal restart of the schedd")
		}
	}
	t.Log("Stage 1 lifecycle OK: advertise, stable run, clean shutdown, no restart")
}

// waitForCondorStatusSchedd polls `condor_status -schedd -af Name MyAddress`
// until it returns a non-empty listing or the timeout elapses.
func waitForCondorStatusSchedd(t *testing.T, configFile string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runCondorAllowErr(configFile, 15*time.Second, "condor_status", "-schedd", "-af", "Name", "MyAddress")
		if strings.TrimSpace(out) != "" {
			return out
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

// locateWithRetry polls the collector for a daemon of the given type until one
// with a non-empty address appears or the timeout elapses.
func locateWithRetry(t *testing.T, ctx context.Context, col *htcondor.Collector, adType string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if loc, err := col.LocateDaemon(ctx, adType, ""); err == nil && loc != nil && loc.Address != "" {
			return loc.Address
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

// pgrep returns the pids whose full command line contains match.
func pgrep(t *testing.T, match string) []string {
	t.Helper()
	out, _ := exec.Command("pgrep", "-f", match).CombinedOutput()
	var pids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			pids = append(pids, p)
		}
	}
	return pids
}

// waitGone polls until no process matches binPath or the timeout elapses.
func waitGone(binPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("pgrep", "-f", binPath).CombinedOutput()
		if strings.TrimSpace(string(out)) == "" {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// runCondor runs an HTCondor tool against the harness config and returns its
// combined output, failing the test on error.
func runCondor(t *testing.T, configFile string, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not found: %v", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// runCondorAllowErr runs an HTCondor tool and returns its output, ignoring a
// non-zero exit (e.g. condor_status returning nothing yet).
func runCondorAllowErr(configFile string, timeout time.Duration, name string, args ...string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func dumpLog(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err == nil {
		t.Logf("=== %s ===\n%s", filepath.Base(path), data)
	} else {
		t.Logf("(could not read %s: %v)", path, err)
	}
}
