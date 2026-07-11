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

// TestStage3ActivateAndRunJob extends the stage-2 direct-claim flow through a
// full job run: after REQUEST_CLAIM succeeds it ACTIVATE_CLAIMs the slot with
// a minimal vanilla job ad, keeps the activation socket as the remote-syscall
// channel, and serves a stock C++ condor_starter's pseudo-syscalls from a Go
// "shadow" until the job (a short /bin/sh sleep) runs to completion. It then
// asserts:
//
//	(1) the slot went Claimed/Busy while the job ran;
//	(2) the shadow's Result reports a normal exit with status 0;
//	(3) the claim wind-down (DEACTIVATE_CLAIM_JOB_DONE + RELEASE_CLAIM)
//	    returned the slot to Unclaimed.
func TestStage3ActivateAndRunJob(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	const aliveInterval = 10
	extra := fmt.Sprintf(`
# --- Stage 3: a C++ startd whose slot we claim AND activate from Go. ---
DAEMON_LIST = MASTER, COLLECTOR, STARTD

NUM_CPUS = 1
MEMORY = 512
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
ALIVE_INTERVAL = %d

# One STATIC slot (a pslot would carve a dslot instead of going Claimed).
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = FALSE

# Claim sessions require match-password auth + AES (cedar's only cipher).
SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION_METHODS = FS

STARTD_DEBUG = D_SECURITY:2 D_COMMAND:2 D_FULLDEBUG
# D_SYSCALLS:2 names every remote syscall the starter attempts.
STARTER_DEBUG = D_SYSCALLS:2 D_FULLDEBUG
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

	dumpLogs := func() {
		for _, name := range []string{"StartLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		// The starter log name carries the slot id (StarterLog.slot1, ...).
		matches, _ := filepath.Glob(filepath.Join(logDir, "StarterLog*"))
		for _, m := range matches {
			dumpLog(t, m)
		}
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
			t.Logf("pvt-ad query error (will retry): %v", err)
			time.Sleep(time.Second)
			continue
		}
		for _, ad := range pvtAds {
			cid := firstNonEmpty(adStr(ad, "Capability"), adStr(ad, "ClaimId"))
			if cid != "" {
				claimID = cid
				slotName = adStr(ad, "Name")
				slotAd = ad
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

	// (2) Go "schedd" server: answers the startd's ALIVE keepalives over the
	// imported claim session while the job runs.
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

	// (3) REQUEST_CLAIM.
	whoami := "test"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}
	uidDomain := condorConfigVal(h.GetConfigFile(), "UID_DOMAIN")

	jobAd := buildVanillaJobAd(t, whoami, uidDomain)

	sc, err := startd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	res, err := sc.RequestClaim(ctx, &startd.ClaimRequest{
		RequestAd:     jobAd,
		SchedulerAddr: schedulerAddr,
		AliveInterval: aliveInterval,
		ScheddName:    "golang-ap-stage3@127.0.0.1",
	})
	if err != nil || !res.OK {
		dumpLogs()
		t.Fatalf("REQUEST_CLAIM failed: err=%v res=%+v", err, res)
	}
	if !waitForSlotState(t, h.GetConfigFile(), slotName, "Claimed", 30*time.Second) {
		dumpLogs()
		t.Fatalf("slot %q never went Claimed", slotName)
	}
	t.Logf("slot %q is Claimed; activating", slotName)

	// (4) ACTIVATE_CLAIM: the same socket becomes the remote-syscall channel.
	ac, err := sc.ActivateClaim(ctx, jobAd, &startd.ActivateOptions{WantFailureAd: true})
	if err != nil {
		dumpLogs()
		t.Fatalf("ACTIVATE_CLAIM: %v", err)
	}
	t.Logf("claim activated (reply ad: %v)", ac.ReplyAd)

	// (5) Serve the starter's remote syscalls from the Go shadow.
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
		JobAd:         jobAd,
		ShadowAddr:    schedulerAddr,
		ShadowVersion: localCondorVersion(t),
		UIDDomain:     uidDomain,
		Startd:        sc,
		OnEvent: func(e shadow.Event) {
			t.Logf("shadow event: %s", e.Type)
		},
		Logf: t.Logf,
	})
	if err != nil {
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

	// (6) While the job (an 8s sleep) runs, the slot must show Claimed/Busy.
	sawBusy := waitForSlotStateActivity(t, h.GetConfigFile(), slotName, "Claimed", "Busy", 60*time.Second)
	if !sawBusy {
		t.Errorf("slot %q never showed Claimed/Busy while the job ran", slotName)
	} else {
		t.Logf("slot %q observed Claimed/Busy", slotName)
	}

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

	// (7) The job must have exited normally with status 0.
	t.Logf("job finished: status=%d reason=%d", result.ExitStatus, result.Reason)
	if code, ok := result.ExitCode(); !ok || code != 0 {
		dumpLogs()
		t.Errorf("job exit code = %d (ok=%v), want 0", code, ok)
	}
	if !result.ExitedNormally() {
		dumpLogs()
		t.Errorf("job exit reason = %d, want JOB_EXITED (%d) or JOB_EXITED_AND_CLAIM_CLOSING (%d)",
			result.Reason, shadow.JobExited, shadow.JobExitedAndClaimClosing)
	}
	if result.ExitAd == nil {
		t.Errorf("no final update ad captured from job_exit")
	}
	if result.UpdateAd == nil {
		t.Errorf("no register_job_info update ad captured")
	}

	// (8) Run() already deactivated (JOB_DONE) and released; the slot must
	// return to Unclaimed.
	if !waitForSlotState(t, h.GetConfigFile(), slotName, "Unclaimed", 60*time.Second) {
		dumpLogs()
		t.Fatalf("slot %q did not return to Unclaimed after the job", slotName)
	}
	t.Logf("slot %q returned to Unclaimed after deactivate+release", slotName)

	if t.Failed() {
		dumpLogs()
	}
}

// buildVanillaJobAd constructs the minimal vanilla-universe job ad a stock
// starter needs for a no-file-transfer run of /bin/sh. Arguments uses the V2
// ("Arguments" attribute) raw syntax: whitespace-separated tokens with single
// quotes protecting embedded spaces, parsed by ArgList::AppendArgsV2Raw.
func buildVanillaJobAd(t *testing.T, owner, uidDomain string) *classad.ClassAd {
	t.Helper()
	iwd := t.TempDir()

	ad := classad.New()
	_ = ad.Set("MyType", "Job")
	_ = ad.Set("ClusterId", int64(1))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("GlobalJobId", fmt.Sprintf("golang-ap-stage3#1.0#%d", time.Now().Unix()))
	_ = ad.Set("JobUniverse", int64(5)) // vanilla
	_ = ad.Set("Owner", owner)
	if uidDomain != "" {
		_ = ad.Set("User", owner+"@"+uidDomain)
	}
	// NOTE (macOS): exec /bin/sh directly; copying a signed system binary
	// into the sandbox breaks code signing.
	_ = ad.Set("Cmd", "/bin/sh")
	_ = ad.Set("Arguments", "-c 'sleep 8; exit 0'")
	_ = ad.Set("Iwd", iwd)
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "/dev/null")
	_ = ad.Set("Err", "/dev/null")
	_ = ad.Set("ShouldTransferFiles", "NO")
	_ = ad.Set("WhenToTransferOutput", "ON_EXIT")
	_ = ad.Set("TransferExecutable", false)
	_ = ad.Set("JobStatus", int64(2)) // Running (the schedd sets this before activation)
	_ = ad.Set("JobLeaseDuration", int64(1200))
	_ = ad.Set("RequestCpus", int64(1))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	_ = ad.Set("Requirements", true)
	_ = ad.Set("NiceUser", false)
	return ad
}

// waitForSlotStateActivity polls condor_status until the named slot reports
// both the wanted State and Activity.
func waitForSlotStateActivity(t *testing.T, configFile, slotName, wantState, wantActivity string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runCondorAllowErr(configFile, 15*time.Second, "condor_status", "-af", "Name", "State", "Activity")
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && (slotName == "" || f[0] == slotName) && f[1] == wantState && f[2] == wantActivity {
				return true
			}
		}
		time.Sleep(time.Second)
	}
	t.Logf("last condor_status: %s", runCondorAllowErr(configFile, 15*time.Second, "condor_status", "-af", "Name", "State", "Activity"))
	return false
}

// localCondorVersion returns the local "$CondorVersion: ...$" string so the
// starter treats the Go shadow as a modern peer (enabling job_termination,
// event_notification, request_guidance, dprintf_stats). Falls back to a
// plausible modern string if condor_version is unavailable.
func localCondorVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("condor_version").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "$CondorVersion:") {
				return line
			}
		}
	}
	return "$CondorVersion: 25.0.0 2025-01-01 BuildID: 0 $"
}

// condorConfigVal fetches one param from the harness config (empty on error).
func condorConfigVal(configFile, name string) string {
	out := runCondorAllowErr(configFile, 15*time.Second, "condor_config_val", name)
	return strings.TrimSpace(out)
}
