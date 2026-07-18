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
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/internal/match"
	"github.com/bbockelm/golang-ap/shadow"
)

// TestStage4TransferJob extends the stage-3 claim/activate/run flow with real
// file transfer: the Go shadow acts as the file-transfer server for the stock
// C++ starter. A vanilla job with ShouldTransferFiles=YES,
// WhenToTransferOutput=ON_EXIT transfers a fresh shell-script executable
// (TransferExecutable=true) plus a TransferInput data file; the job verifies the
// input's content, writes its stdout and one explicit output file, and exits 0.
//
// It asserts:
//
//	(1) the job exits 0;
//	(2) the two output files (the explicit result file and the captured stdout)
//	    arrive back in the job Iwd with the expected content;
//	(3) the StarterLog shows the filetrans session resumption and both transfer
//	    directions (the starter's DoDownload of input and DoUpload of output).
func TestStage4TransferJob(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	const aliveInterval = 10
	extra := fmt.Sprintf(`
# --- Stage 4: a C++ startd whose slot we claim, activate, and serve file
#     transfer for from Go. ---
DAEMON_LIST = MASTER, COLLECTOR, STARTD

NUM_CPUS = 1
MEMORY = 512
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = %d

NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = FALSE

SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION_METHODS = FS

STARTD_DEBUG = D_SECURITY:2 D_COMMAND:2 D_FULLDEBUG
# D_SECURITY:2 shows the filetrans session resumption; D_FULLDEBUG logs every
# FileTransfer protocol step (DoDownload/DoUpload).
STARTER_DEBUG = D_SECURITY:2 D_SYSCALLS:2 D_FULLDEBUG
`, aliveInterval)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()

	prevConfig, hadConfig := os.LookupEnv("CONDOR_CONFIG")
	_ = os.Setenv("CONDOR_CONFIG", h.GetConfigFile())
	htcondor.ReloadDefaultConfig()
	t.Cleanup(func() {
		if hadConfig {
			_ = os.Setenv("CONDOR_CONFIG", prevConfig)
		} else {
			_ = os.Unsetenv("CONDOR_CONFIG")
		}
		htcondor.ReloadDefaultConfig()
	})

	var starterLogs func() []string
	dumpLogs := func() {
		for _, name := range []string{"StartLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		for _, m := range starterLogs() {
			dumpLog(t, m)
		}
	}
	starterLogs = func() []string {
		matches, _ := filepath.Glob(filepath.Join(logDir, "StarterLog*"))
		return matches
	}

	if err := h.WaitForStartd(60 * time.Second); err != nil {
		dumpLogs()
		t.Fatalf("startd never advertised: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// (1) Claim id from the startd private ads.
	claimID, slotName, slotAd := "", "", (*classad.ClassAd)(nil)
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		pvtAds, err := queryStartdPrivateAds(ctx, h.GetCollectorAddr())
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		for _, ad := range pvtAds {
			cid := firstNonEmpty(adStr(ad, "Capability"), adStr(ad, "ClaimId"))
			if cid != "" {
				claimID, slotName, slotAd = cid, adStr(ad, "Name"), ad
				break
			}
		}
		if claimID != "" {
			break
		}
		time.Sleep(time.Second)
	}
	if claimID == "" {
		dumpLogs()
		t.Fatal("could not obtain a claim id from the startd private ads")
	}
	t.Logf("got claim id for slot %q", slotName)

	// (2) Go "schedd" ALIVE server over the imported claim session.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	schedulerAddr := fmt.Sprintf("<%s>", ln.Addr().String())

	table := match.NewTable(nil)
	if _, err := table.CreateFromClaim(claimID, slotAd, aliveInterval); err != nil {
		dumpLogs()
		t.Fatalf("importing claim session into match table: %v", err)
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   table.Cache(),
	})
	match.RegisterALIVE(srv, table, func(e match.AliveEvent) {
		t.Logf("ALIVE received: found=%v interval=%d", e.Found, e.AliveInterval)
	})
	go func() { _ = srv.Serve(ctx, ln) }()

	// (3) The file-transfer endpoint: the server the starter connects back to
	// (FILETRANS_UPLOAD/DOWNLOAD). Test-owned here; stage 6 shares the schedd's.
	ftLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen (ft endpoint): %v", err)
	}
	defer func() { _ = ftLn.Close() }()
	endpoint := shadow.NewEndpoint(security.NewSessionCache(), nil, t.Logf)
	go func() { _ = endpoint.Serve(ctx, ftLn) }()
	for i := 0; i < 100 && endpoint.Sinful() == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if endpoint.Sinful() == "" {
		t.Fatal("file-transfer endpoint never reported its sinful address")
	}
	t.Logf("file-transfer endpoint at %s", endpoint.Sinful())

	// (4) Build the transfer job: a script executable + one input file, checking
	// the input and producing two outputs.
	whoami := "test"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}
	uidDomain := condorConfigVal(h.GetConfigFile(), "UID_DOMAIN")
	const inputContent = "hello-from-shadow"
	iwd, jobAd := buildTransferJobAd(t, whoami, uidDomain, inputContent)

	sc, err := startd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	res, err := sc.RequestClaim(ctx, &startd.ClaimRequest{
		RequestAd:     jobAd,
		SchedulerAddr: schedulerAddr,
		AliveInterval: aliveInterval,
		ScheddName:    "golang-ap-stage4@127.0.0.1",
	})
	if err != nil || !res.OK {
		dumpLogs()
		t.Fatalf("REQUEST_CLAIM failed: err=%v res=%+v", err, res)
	}
	if !waitForSlotState(t, h.GetConfigFile(), slotName, "Claimed", 30*time.Second) {
		dumpLogs()
		t.Fatalf("slot %q never went Claimed", slotName)
	}

	ac, err := sc.ActivateClaim(ctx, jobAd, &startd.ActivateOptions{WantFailureAd: true})
	if err != nil {
		dumpLogs()
		t.Fatalf("ACTIVATE_CLAIM: %v", err)
	}
	t.Logf("claim activated; serving starter with file transfer")

	// (5) Serve the starter's syscalls AND file transfer from the Go shadow.
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
		JobAd:            jobAd,
		ClaimID:          claimID,
		TransferEndpoint: endpoint,
		ShadowAddr:       schedulerAddr,
		ShadowVersion:    localCondorVersion(t),
		UIDDomain:        uidDomain,
		Startd:           sc,
		OnEvent: func(e shadow.Event) {
			t.Logf("shadow event: %s", e.Type)
			if e.Type == shadow.EventGetJobInfo && e.Ad != nil {
				tk, _ := e.Ad.EvaluateAttrString("TransferKey")
				ts, _ := e.Ad.EvaluateAttrString("TransferSocket")
				t.Logf("get_job_info ad: TransferKey=%q TransferSocket=%q", tk, ts)
			}
		},
		Logf: t.Logf,
	})
	if err != nil {
		dumpLogs()
		t.Fatalf("shadow.New: %v", err)
	}

	type runOut struct {
		res *shadow.Result
		err error
	}
	runCh := make(chan runOut, 1)
	go func() {
		r, err := sh.Run(ctx)
		runCh <- runOut{r, err}
	}()

	var out runOut
	select {
	case out = <-runCh:
	case <-ctx.Done():
		dumpLogs()
		t.Fatal("shadow.Run did not finish before the test deadline")
	}
	if out.err != nil {
		dumpLogs()
		t.Fatalf("shadow.Run: %v (result: %+v)", out.err, out.res)
	}
	result := out.res

	// (6) The job must have exited 0.
	t.Logf("job finished: status=%d reason=%d", result.ExitStatus, result.Reason)
	if code, ok := result.ExitCode(); !ok || code != 0 {
		dumpLogs()
		t.Fatalf("job exit code = %d (ok=%v), want 0 (job likely failed its input check)", code, ok)
	}
	if !result.ExitedNormally() {
		dumpLogs()
		t.Errorf("job exit reason = %d, want normal", result.Reason)
	}

	// (7) The two output files must be back in Iwd with the expected content.
	resultFile := filepath.Join(iwd, "result.txt")
	gotResult, err := os.ReadFile(resultFile)
	if err != nil {
		dumpLogs()
		t.Fatalf("explicit output file %s not returned: %v", resultFile, err)
	}
	if wantResult := "RESULT:" + inputContent + "\n"; string(gotResult) != wantResult {
		t.Errorf("result.txt = %q, want %q", string(gotResult), wantResult)
	}

	stdoutFile := filepath.Join(iwd, "job.out")
	gotStdout, err := os.ReadFile(stdoutFile)
	if err != nil {
		dumpLogs()
		t.Fatalf("captured stdout file %s not returned: %v", stdoutFile, err)
	}
	if want := "job stdout ok: " + inputContent; !strings.Contains(string(gotStdout), want) {
		t.Errorf("job.out = %q, want it to contain %q", string(gotStdout), want)
	}

	// (8) The StarterLog must show the filetrans session resumption and both
	// transfer directions (starter DoDownload of input, DoUpload of output).
	assertStarterLog(t, starterLogs())

	if t.Failed() {
		dumpLogs()
	}
}

// buildTransferJobAd writes a fresh shell-script executable and an input data
// file into a temp Iwd and returns (iwd, jobAd) for a job that verifies the
// input and writes two outputs. The script is written fresh (never a signed
// system binary) so transferring it does not break code signing on macOS.
func buildTransferJobAd(t *testing.T, owner, uidDomain, inputContent string) (string, *classad.ClassAd) {
	t.Helper()
	iwd := t.TempDir()

	// A fresh, self-contained script: verify the transferred input, emit stdout,
	// and write one explicit output file. Non-zero exit if the input is wrong,
	// which surfaces as a non-zero job exit code the test asserts on.
	script := "#!/bin/sh\n" +
		"expected='" + inputContent + "'\n" +
		"got=$(cat input.dat)\n" +
		"if [ \"$got\" != \"$expected\" ]; then\n" +
		"  echo \"MISMATCH: got [$got] want [$expected]\" 1>&2\n" +
		"  exit 17\n" +
		"fi\n" +
		"echo \"job stdout ok: $got\"\n" +
		"printf 'RESULT:%s\\n' \"$got\" > result.txt\n" +
		"exit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	ad := classad.New()
	_ = ad.Set("MyType", "Job")
	_ = ad.Set("ClusterId", int64(1))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("GlobalJobId", fmt.Sprintf("golang-ap-stage4#1.0#%d", time.Now().Unix()))
	_ = ad.Set("JobUniverse", int64(5)) // vanilla
	_ = ad.Set("Owner", owner)
	if uidDomain != "" {
		_ = ad.Set("User", owner+"@"+uidDomain)
	}
	_ = ad.Set("Cmd", scriptPath)
	_ = ad.Set("Iwd", iwd)
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Err", "job.err")
	_ = ad.Set("ShouldTransferFiles", "YES")
	_ = ad.Set("WhenToTransferOutput", "ON_EXIT")
	_ = ad.Set("TransferExecutable", true)
	_ = ad.Set("TransferInput", "input.dat")
	_ = ad.Set("JobStatus", int64(2)) // Running
	_ = ad.Set("JobLeaseDuration", int64(1200))
	_ = ad.Set("RequestCpus", int64(1))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	_ = ad.Set("Requirements", true)
	_ = ad.Set("NiceUser", false)
	return iwd, ad
}

// assertStarterLog checks the starter log(s) for evidence of the filetrans
// session resumption and both file-transfer directions.
func assertStarterLog(t *testing.T, logs []string) {
	t.Helper()
	var combined strings.Builder
	for _, p := range logs {
		if b, err := os.ReadFile(p); err == nil {
			combined.Write(b)
			combined.WriteByte('\n')
		}
	}
	text := combined.String()
	if text == "" {
		t.Errorf("no StarterLog content found for transfer assertions")
		return
	}
	checks := map[string]bool{
		"filetrans session resumption": strings.Contains(text, "filetrans."),
		"input transfer (DoDownload)":  strings.Contains(text, "DoDownload"),
		"output transfer (DoUpload)":   strings.Contains(text, "DoUpload"),
	}
	for what, ok := range checks {
		if !ok {
			t.Errorf("StarterLog missing evidence of %s", what)
		} else {
			t.Logf("StarterLog shows %s", what)
		}
	}
}
