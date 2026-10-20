package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage18NegotiateAfterUDPFamilyResume runs a job through the pure-Go
// schedd after a C++ daemon has used the master's family session over UDP
// with the C++ negotiator, with encryption required and BLOWFISH among the
// crypto methods.
//
// A UDP command resumes the family session with BLOWFISH (UDP has no AES),
// and the receiving negotiator then prefers BLOWFISH for the session over TCP
// too, so its NEGOTIATE to the Go schedd names BLOWFISH. The Go schedd holds
// only the session's AES key: it refuses that resumption, the negotiator
// negotiates a new session, which uses AES, and the job is matched and runs.
//
// The UDP sender is a second, C++ schedd under the same master: its RESCHEDULE
// reaches the negotiator over UDP, which needs the negotiator off shared port.
func TestStage18NegotiateAfterUDPFamilyResume(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_reschedule"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	scheddBin := buildScheddBin(t, tmp, "18")
	cxxSpool := filepath.Join(tmp, "cxx-spool")
	if err := os.MkdirAll(cxxSpool, 0o755); err != nil {
		t.Fatal(err)
	}

	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

# A C++ schedd beside the Go one, under the same master and family session.
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD, CXX_SCHEDD
DC_DAEMON_LIST = + CXX_SCHEDD
CXX_SCHEDD = $(SBIN)/condor_schedd
CXX_SCHEDD_ARGS = -local-name cxxschedd
CXXSCHEDD.SCHEDD_NAME = cxxschedd
CXXSCHEDD.SCHEDD_LOG = $(LOG)/CxxScheddLog
CXXSCHEDD.SPOOL = %s
CXXSCHEDD.SCHEDD_ADDRESS_FILE = $(LOG)/.cxxschedd_address
CXXSCHEDD.SCHEDD_DAEMON_AD_FILE = $(LOG)/.cxxschedd_classad

# The negotiator keeps its own UDP command socket, so schedds send it
# RESCHEDULE over UDP.
NEGOTIATOR.USE_SHARED_PORT = False
NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1
NEGOTIATOR_DEBUG = D_FULLDEBUG D_SECURITY

UID_DOMAIN = golang-ap.test
TRUST_UID_DOMAIN = True

NUM_CPUS = 1
MEMORY = 512
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
NUM_SLOTS_TYPE_1 = 1
SLOT_TYPE_1 = 100%%
SLOT_TYPE_1_PARTITIONABLE = FALSE

SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_CRYPTO_METHODS = AES, BLOWFISH, 3DES
`, scheddBin, cxxSpool)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()

	dumpAllLogs := func() {
		for _, name := range []string{"ScheddLog", "CxxScheddLog", "NegotiatorLog", "StartLog", "MasterLog"} {
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
	cxxAddrFile := filepath.Join(logDir, ".cxxschedd_address")
	if !waitForFile(cxxAddrFile, 60*time.Second) {
		fail("C++ schedd never wrote its address file")
	}
	data, err := os.ReadFile(cxxAddrFile)
	if err != nil {
		t.Fatal(err)
	}
	cxxAddr := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])

	// The C++ schedd's RESCHEDULE resumes the family session in the negotiator
	// over UDP before the negotiator first contacts the Go schedd.
	if out, err := runTool(cfgFile, 30*time.Second, "condor_reschedule", "-addr", cxxAddr); err != nil {
		fail("condor_reschedule of the C++ schedd: %v\n%s", err, out)
	}
	negLog := filepath.Join(logDir, "NegotiatorLog")
	if !waitForLogContains(negLog, []string{"DC_AUTHENTICATE: packet from", "uses crypto session family:"}, 60*time.Second) {
		fail("negotiator never received a UDP command over the family session")
	}

	sub := writeSleepJob(t, tmp, 1, 0, "")
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", sub)
	if err != nil {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}
	if id := afField(cfgFile, cluster, 0, "GlobalJobId"); !strings.HasPrefix(id, h.GetScheddName()+"#") {
		fail("job %d.0 is not in the Go schedd's queue (GlobalJobId %q)", cluster, id)
	}
	if !waitClusterEmpty(cfgFile, cluster, 120*time.Second) {
		fail("job %d.0 never completed: the negotiator could not NEGOTIATE with the Go schedd", cluster)
	}
	t.Logf("job %d.0 completed", cluster)

	// The Go schedd refused at most one resumption: the negotiator
	// renegotiates once, then holds an AES session with it.
	logData, err := os.ReadFile(filepath.Join(logDir, "ScheddLog"))
	if err != nil {
		t.Fatal(err)
	}
	refused := strings.Count(string(logData), "refusing the session")
	t.Logf("Go schedd refused %d non-AES family-session resumption(s)", refused)
	if refused > 1 {
		fail("Go schedd refused %d non-AES resumptions, want at most 1", refused)
	}
}
