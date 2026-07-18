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
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage16Observability exercises roadmap item #5 end-to-end against the
// pure-Go schedd running as the pool's SCHEDD with a stock C++
// master/collector/negotiator/startd:
//
//	(B) the Prometheus /metrics endpoint (SCHEDD_METRICS_ADDRESS) serves and its
//	    condor_schedd_* counters advance after a job runs;
//	(C) condor_status -schedd -long advertises the enriched ScheddStatistics
//	    attributes (JobsStarted, ShadowsRunning, TotalJobAds, ScheddUptime, ...);
//	(D) condor_reconfig -daemon schedd re-reads a changed SCHEDD_INTERVAL live.
func TestStage16Observability(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_status", "condor_reconfig", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ap-schedd16-%d", os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}

	metricsPort := freePort(t)
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)

	const uidDomain = "golang-ap.test"
	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
SCHEDD_METRICS_ADDRESS = 127.0.0.1:%d
QUEUE_SUPER_USERS = condor

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

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

NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1

SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, scheddBin, metricsPort, uidDomain)

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

	// ---- (B) /metrics serves before any job (baseline) ----
	base := scrapeMetricsWithRetry(t, metricsURL, 30*time.Second)
	if base == "" {
		fail("metrics endpoint never served at %s", metricsURL)
	}
	for _, name := range []string{
		"condor_schedd_jobs_started_total",
		"condor_schedd_jobs_completed_total",
		"condor_schedd_matches_received_total",
		"condor_schedd_negotiation_cycles_total",
		"condor_schedd_shadows_running",
		"condor_schedd_job_ads",
		"condor_schedd_uptime_seconds",
		"go_goroutines", // standard Go collector
	} {
		if !strings.Contains(base, name) {
			fail("baseline /metrics missing metric %q:\n%s", name, base)
		}
	}
	t.Logf("baseline /metrics served with condor_schedd_* metrics present")

	// ---- submit a short vanilla job ----
	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nsleep 5\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	submitFile := filepath.Join(tmp, "job.sub")
	subDesc := fmt.Sprintf(`universe = vanilla
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
		fail("could not parse cluster id from: %q", out)
	}
	t.Logf("submitted cluster %d", cluster)

	// ---- (C) condor_status -schedd -long advertises the stat attrs while jobs exist ----
	// Wait until the schedd ad shows the job (TotalJobAds >= 1), then check the
	// enriched stat attributes are present.
	statAttrs := []string{"JobsStarted", "JobsExited", "JobsCompleted", "ShadowExceptions",
		"ShadowsRunning", "JobsMaterialized", "TotalJobAds", "NumUsers", "ScheddUptime"}
	if !waitForScheddAdAttr(t, cfgFile, "TotalJobAds", 60*time.Second) {
		fail("schedd ad never showed TotalJobAds")
	}
	adLong, _ := runTool(cfgFile, 20*time.Second, "condor_status", "-schedd", "-long")
	for _, a := range statAttrs {
		if !regexp.MustCompile(`(?m)^` + a + `\s*=`).MatchString(adLong) {
			fail("condor_status -schedd -long missing stat attr %q:\n%s", a, adLong)
		}
	}
	t.Logf("condor_status -schedd -long advertises the enriched stat attributes")

	// ---- wait for the job to run and leave the queue ----
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
		fail("job %d.0 never left the queue", cluster)
	}
	t.Logf("job %d.0 completed and left the queue", cluster)

	// ---- (B) after the job: counters advanced ----
	after := scrapeMetricsWithRetry(t, metricsURL, 30*time.Second)
	assertCounterAtLeast(t, after, "condor_schedd_matches_received_total", 1)
	assertCounterAtLeast(t, after, "condor_schedd_negotiation_cycles_total", 1)
	assertCounterAtLeast(t, after, "condor_schedd_jobs_started_total", 1)
	assertCounterAtLeast(t, after, "condor_schedd_jobs_exited_total", 1)
	assertCounterAtLeast(t, after, "condor_schedd_jobs_completed_total", 1)
	t.Logf("/metrics counters advanced after the job ran")

	// The schedd ad also reflects the run (JobsStarted >= 1).
	jsStr, _ := runTool(cfgFile, 20*time.Second, "condor_status", "-schedd", "-af", "JobsStarted")
	if v, err := strconv.Atoi(strings.TrimSpace(firstField(jsStr))); err != nil || v < 1 {
		fail("schedd ad JobsStarted = %q, want >= 1", jsStr)
	}
	t.Logf("schedd ad JobsStarted reflects the completed run")

	// ---- (D) live reconfig of SCHEDD_INTERVAL ----
	f, err := os.OpenFile(cfgFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fail("opening config for reconfig: %v", err)
	}
	if _, err := f.WriteString("\nSCHEDD_INTERVAL = 17\n"); err != nil {
		_ = f.Close()
		fail("appending to config: %v", err)
	}
	_ = f.Close()

	if out, err := runTool(cfgFile, 30*time.Second, "condor_reconfig", "-daemon", "schedd"); err != nil {
		fail("condor_reconfig failed: %v\n%s", err, out)
	}

	// The scheduler logs the newly-adopted interval; poll ScheddLog for it.
	if !waitForLogContains(filepath.Join(logDir, "ScheddLog"),
		[]string{"reconfig applied", "17s"}, 30*time.Second) {
		fail("ScheddLog never showed the reconfigured SCHEDD_INTERVAL=17s")
	}
	t.Logf("condor_reconfig re-read SCHEDD_INTERVAL live (17s adopted)")

	runCondor(t, cfgFile, 30*time.Second, "condor_off", "-daemon", "schedd")
	_ = waitGone(binName, 30*time.Second)

	if t.Failed() {
		dumpAllLogs()
	}
}

// freePort returns an available localhost TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocating free port: %v", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// scrapeMetricsWithRetry GETs the /metrics URL until it returns 200 or timeout.
func scrapeMetricsWithRetry(t *testing.T, url string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return string(body)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

// metricValue extracts the float value of a no-label metric sample line.
func metricValue(body, name string) (float64, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\s+([0-9.e+-]+)\s*$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func assertCounterAtLeast(t *testing.T, body, name string, want float64) {
	t.Helper()
	v, ok := metricValue(body, name)
	if !ok {
		t.Errorf("metric %q not found in /metrics output", name)
		return
	}
	if v < want {
		t.Errorf("metric %q = %v, want >= %v", name, v, want)
	}
}

// waitForScheddAdAttr polls condor_status -schedd -long until it contains attr.
func waitForScheddAdAttr(t *testing.T, cfgFile, attr string, timeout time.Duration) bool {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + attr + `\s*=`)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := runTool(cfgFile, 15*time.Second, "condor_status", "-schedd", "-long")
		if re.MatchString(out) {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// waitForLogContains polls a log file until it contains every needle on one line
// (all needles present anywhere in the file), or timeout elapses.
func waitForLogContains(path string, needles []string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			s := string(data)
			all := true
			for _, n := range needles {
				if !strings.Contains(s, n) {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func firstField(s string) string {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
