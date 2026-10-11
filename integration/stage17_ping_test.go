package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStage17PingLevels runs the STOCK condor_ping -table ALL against the
// pure-Go schedd and checks each authorization level's row: the decision
// follows the schedd's ALLOW_<level> lists and SEC_<level>_* policy, and each
// level negotiates under its own policy, as the C++ schedd answers the same
// configuration:
//
//   - NEGOTIATOR and ADVERTISE_STARTD are refused by ALLOW_<level>;
//   - CONFIG (ALLOW_CONFIG = *) and ADVERTISE_MASTER are refused by their
//     SEC_<level>_AUTHENTICATION = NEVER, which the tool's required
//     authentication cannot meet;
//   - DAEMON and ADVERTISE_SCHEDD, whose SEC_ADVERTISE_SCHEDD_* is unset, are
//     encrypted under SEC_DAEMON_ENCRYPTION = REQUIRED;
//   - every other level is allowed for the test's FS identity.
func TestStage17PingLevels(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_ping"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	scheddBin := buildScheddBin(t, tmp, "17")
	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES

SCHEDD.SEC_DAEMON_ENCRYPTION = REQUIRED
SCHEDD.SEC_CONFIG_AUTHENTICATION = NEVER
SCHEDD.SEC_ADVERTISE_MASTER_AUTHENTICATION = NEVER
SCHEDD.ALLOW_CONFIG = *
SCHEDD.ALLOW_NEGOTIATOR = nobody@nowhere.example
SCHEDD.ALLOW_ADVERTISE_STARTD = nobody@nowhere.example

START = FALSE
`, scheddBin)

	h, cfgFile, logDir := startGoSchedd(t, extra)
	defer h.Shutdown()
	fail := func(format string, args ...any) {
		t.Helper()
		dumpLog(t, filepath.Join(logDir, "ScheddLog"))
		t.Fatalf(format, args...)
	}

	b, err := os.ReadFile(filepath.Join(logDir, ".schedd_address"))
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])

	// condor_ping exits non-zero when any level fails; the rows decide.
	out, _ := runTool(cfgFile, 60*time.Second, "condor_ping", "-addr", addr, "-table", "ALL")
	t.Logf("condor_ping -table ALL:\n%s", out)
	type row struct{ auth, encryption, decision string }
	rows := map[string]row{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && f[0] != "Instruction" {
			rows[f[0]] = row{auth: f[1], encryption: f[2], decision: f[4]}
		}
	}
	for _, want := range []struct {
		level, decision, encryption string
	}{
		{"ALLOW", "ALLOW", ""},
		{"READ", "ALLOW", ""},
		{"WRITE", "ALLOW", ""},
		{"NEGOTIATOR", "FAIL", ""},
		{"ADMINISTRATOR", "ALLOW", ""},
		{"OWNER", "ALLOW", ""},
		{"CONFIG", "FAIL", ""},
		{"DAEMON", "ALLOW", "AES"},
		{"ADVERTISE_STARTD", "FAIL", ""},
		{"ADVERTISE_SCHEDD", "ALLOW", "AES"},
		{"ADVERTISE_MASTER", "FAIL", ""},
	} {
		got, ok := rows[want.level]
		if !ok {
			fail("condor_ping printed no row for %s", want.level)
		}
		if got.decision != want.decision {
			fail("condor_ping %s decision = %s, want %s", want.level, got.decision, want.decision)
		}
		if want.decision == "ALLOW" && got.auth != "FS" {
			fail("condor_ping %s authenticated with %s, want FS", want.level, got.auth)
		}
		if want.encryption != "" && got.encryption != want.encryption {
			fail("condor_ping %s encryption = %s, want %s", want.level, got.encryption, want.encryption)
		}
	}
	if strings.Contains(out, "CMD_NOT_FOUND") || strings.Contains(out, "not found") {
		fail("condor_ping reported a command not found:\n%s", out)
	}
}
