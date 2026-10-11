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
// pure-Go schedd and against the C++ schedd under the same configuration and
// checks every authorization level's row matches: authentication method,
// encryption, integrity, decision and identity. Each level negotiates under
// its own SEC_<level>_* policy and is decided by its ALLOW_<level> list:
//
//   - NEGOTIATOR and ADVERTISE_STARTD are refused by ALLOW_<level>;
//   - CONFIG (ALLOW_CONFIG = *) and ADVERTISE_MASTER are refused by their
//     SEC_<level>_AUTHENTICATION = NEVER, which the tool's required
//     authentication cannot meet;
//   - every other level is allowed for the test's FS identity.
func TestStage17PingLevels(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_ping"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	scheddBin := buildScheddBin(t, t.TempDir(), "17")
	goRows := pingLevels(t, "SCHEDD = "+scheddBin)
	cxxRows := pingLevels(t, "")

	for _, want := range []struct{ level, decision string }{
		{"ALLOW", "ALLOW"},
		{"READ", "ALLOW"},
		{"WRITE", "ALLOW"},
		{"NEGOTIATOR", "FAIL"},
		{"ADMINISTRATOR", "ALLOW"},
		{"OWNER", "ALLOW"},
		{"CONFIG", "FAIL"},
		{"DAEMON", "ALLOW"},
		{"ADVERTISE_STARTD", "FAIL"},
		{"ADVERTISE_SCHEDD", "ALLOW"},
		{"ADVERTISE_MASTER", "FAIL"},
	} {
		got, ok := goRows[want.level]
		if !ok {
			t.Errorf("condor_ping printed no row for %s against the Go schedd", want.level)
			continue
		}
		if got.decision != want.decision {
			t.Errorf("condor_ping %s decision = %s, want %s", want.level, got.decision, want.decision)
		}
		if cxx := cxxRows[want.level]; got != cxx {
			t.Errorf("condor_ping %s: Go schedd %+v, C++ schedd %+v", want.level, got, cxx)
		}
	}
}

// pingRow is one level's row of condor_ping -table.
type pingRow struct{ auth, encryption, integrity, decision, identity string }

// pingLevels boots a pool whose SCHEDD is set by scheddLine ("" keeps the
// C++ schedd) with stage 17's security configuration and returns condor_ping
// -table ALL's rows against that schedd, keyed by level.
func pingLevels(t *testing.T, scheddLine string) map[string]pingRow {
	t.Helper()
	extra := fmt.Sprintf(`
%s
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
`, scheddLine)

	h, cfgFile, logDir := startGoSchedd(t, extra)
	defer h.Shutdown()

	b, err := os.ReadFile(filepath.Join(logDir, ".schedd_address"))
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])

	// condor_ping exits non-zero when any level fails; the rows decide.
	out, _ := runTool(cfgFile, 60*time.Second, "condor_ping", "-addr", addr, "-table", "ALL")
	t.Logf("condor_ping -table ALL against %q:\n%s", scheddLine, out)
	if strings.Contains(out, "CMD_NOT_FOUND") || strings.Contains(out, "not found") {
		dumpLog(t, filepath.Join(logDir, "ScheddLog"))
		t.Fatalf("condor_ping reported a command not found:\n%s", out)
	}
	rows := map[string]pingRow{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && f[0] != "Instruction" {
			rows[f[0]] = pingRow{auth: f[1], encryption: f[2], integrity: f[3], decision: f[4], identity: f[5]}
		}
	}
	return rows
}
