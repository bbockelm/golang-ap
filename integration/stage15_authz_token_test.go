package integration

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"golang.org/x/crypto/hkdf"
)

// TestStage15QeditAuthz drives the pure-Go schedd with the STOCK condor_qedit
// tool to exercise per-attribute QMGMT authorization on the real wire:
//
//	(1) condor_qedit of a free attribute on the owner's own job succeeds;
//	(2) condor_qedit of an IMMUTABLE attribute (Owner, ClusterId) is rejected and
//	    the committed value is left unchanged.
//
// Cross-owner and protected-attr rejection are covered deterministically by the
// internal/queue authz unit tests (a single OS user drives every stock tool here,
// so multi-user identities can only be produced over the token path below).
func TestStage15QeditAuthz(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_qedit"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	scheddBin := buildScheddBin(t, tmp, "15a")
	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES

# Enforce per-attribute authorization (the base harness config sets this True,
# which would bypass ownership + protected checks).
QUEUE_ALL_USERS_TRUSTED = False

# Queue/tooling test: keep jobs Idle.
START = FALSE
`, scheddBin)

	h, cfgFile, logDir := startGoSchedd(t, extra)
	defer h.Shutdown()
	fail := func(format string, args ...any) {
		t.Helper()
		for _, n := range []string{"ScheddLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, n))
		}
		t.Fatalf(format, args...)
	}

	// Submit a 1-proc job (FS auth, as the test's OS user).
	subFile := filepath.Join(tmp, "sleep.sub")
	if err := os.WriteFile(subFile, []byte("universe = vanilla\nexecutable = /bin/sleep\narguments = 600\nshould_transfer_files = NO\nMyCustomAttr = 1\nqueue 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runTool(cfgFile, 60*time.Second, "condor_submit", subFile)
	if err != nil || !strings.Contains(out, "submitted to cluster") {
		fail("condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id: %q", out)
	}
	if waitForQRows(t, cfgFile, 1, 30*time.Second) == nil {
		fail("job never appeared in condor_q")
	}
	jobID := fmt.Sprintf("%d.0", cluster)

	// (1) qedit a FREE attribute -> succeeds and takes effect.
	if _, err := runTool(cfgFile, 30*time.Second, "condor_qedit", jobID, "MyCustomAttr", "42"); err != nil {
		fail("condor_qedit of a free attribute failed: %v", err)
	}
	if !waitForAttr(cfgFile, cluster, 0, "MyCustomAttr", "42", 15*time.Second) {
		fail("free attribute was not updated by condor_qedit")
	}
	t.Log("condor_qedit of a free attribute succeeded")

	// (2) qedit an IMMUTABLE attribute -> rejected; Owner unchanged.
	me := os.Getenv("USER")
	if me == "" {
		me = "unknown"
	}
	qedOut, qedErr := runTool(cfgFile, 30*time.Second, "condor_qedit", jobID, "Owner", `"hacker"`)
	t.Logf("condor_qedit Owner (expected to fail): err=%v\n%s", qedErr, qedOut)
	// Regardless of the tool's exit reporting, the committed Owner must be unchanged.
	gotOwner := afValue(cfgFile, cluster, 0, "Owner")
	if gotOwner != me {
		fail("immutable Owner was changed to %q (want %q) -- authz not enforced", gotOwner, me)
	}
	// A well-behaved condor_qedit reports the failure.
	if qedErr == nil && !strings.Contains(qedOut, "Failed") && !strings.Contains(qedOut, "failed") {
		t.Logf("note: condor_qedit did not surface an error, but Owner correctly unchanged")
	}
	t.Log("condor_qedit of an immutable attribute was rejected; Owner unchanged")

	// (3) qedit ClusterId (immutable) -> rejected; value unchanged.
	_, _ = runTool(cfgFile, 30*time.Second, "condor_qedit", jobID, "ClusterId", fmt.Sprintf("%d", cluster+999))
	if got := afValue(cfgFile, cluster, 0, "ClusterId"); got != fmt.Sprintf("%d", cluster) {
		fail("immutable ClusterId was changed to %q -- authz not enforced", got)
	}
	t.Log("condor_qedit of immutable ClusterId was rejected")
}

// TestStage15TokenSubmit provisions an IDTOKEN signed by a pool key the Go schedd
// trusts, then runs STOCK condor_submit authenticating with that token (IDTOKENS,
// not FS). It asserts the committed job's Owner is the token SUBJECT (which
// differs from the test's OS user), proving the token identity -> Owner mapping.
func TestStage15TokenSubmit(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	scheddBin := buildScheddBin(t, tmp, "15b")

	const trustDomain = "example.net"
	const tokenSubject = "tokenuser@example.net"
	const tokenOwner = "tokenuser" // schedd maps subject local-part -> Owner

	// Pool signing key the schedd will trust and we sign the token with.
	poolKeyPath := filepath.Join(tmp, "POOL")
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolKeyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	extra := fmt.Sprintf(`
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

# Accept IDTOKENS (the token submit) and FS (harness daemons) at the schedd,
# preferring IDTOKENS so a client offering both authenticates by token. FS-only
# daemons still match FS (the only shared method).
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = IDTOKENS, FS
SEC_DEFAULT_CRYPTO_METHODS = AES

# Token trust: the pool signing key + issuer domain the schedd verifies against.
UID_DOMAIN = %s
TRUST_DOMAIN = %s
SEC_TOKEN_POOL_SIGNING_KEY_FILE = %s

START = FALSE
`, scheddBin, trustDomain, trustDomain, poolKeyPath)

	h, cfgFile, logDir := startGoSchedd(t, extra)
	defer h.Shutdown()
	fail := func(format string, args ...any) {
		t.Helper()
		for _, n := range []string{"ScheddLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, n))
		}
		t.Fatalf(format, args...)
	}

	// Mint an IDTOKEN for tokenSubject and drop it in a token directory.
	token, err := mintIDToken(poolKeyPath, "POOL", tokenSubject, trustDomain)
	if err != nil {
		t.Fatalf("minting IDTOKEN: %v", err)
	}
	tokenDir := filepath.Join(tmp, "tokens.d")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenDir, "submit_token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// condor_submit authenticating via IDTOKENS only, using the token directory.
	// The overrides apply only to this invocation, so the harness's own daemons
	// keep using FS.
	// Restrict the CLIENT's offered methods entirely to IDTOKENS (both the DEFAULT
	// and CLIENT lists -- the tool builds its offer from DEFAULT), so the schedd's
	// handshake must select TOKEN rather than falling back to its FS preference.
	submitEnv := []string{
		"_CONDOR_SEC_DEFAULT_AUTHENTICATION_METHODS=IDTOKENS",
		"_CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS=IDTOKENS",
		"_CONDOR_SEC_TOKEN_DIRECTORY=" + tokenDir,
	}
	subFile := filepath.Join(tmp, "token.sub")
	if err := os.WriteFile(subFile, []byte("universe = vanilla\nexecutable = /bin/sleep\narguments = 600\nshould_transfer_files = NO\nqueue 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runToolEnv(cfgFile, submitEnv, 60*time.Second, "condor_submit", subFile)
	t.Logf("condor_submit (IDTOKENS):\n%s", out)
	if err != nil || !strings.Contains(out, "submitted to cluster") {
		fail("token-authenticated condor_submit failed: %v\n%s", err, out)
	}
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from token submit: %q", out)
	}

	// The job must exist and be owned by the TOKEN subject (not the OS user).
	deadline := time.Now().Add(30 * time.Second)
	var gotOwner string
	for time.Now().Before(deadline) {
		gotOwner = afValue(cfgFile, cluster, 0, "Owner")
		if gotOwner != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if gotOwner != tokenOwner {
		fail("token-submitted job Owner = %q, want %q (token subject local-part)", gotOwner, tokenOwner)
	}
	me := os.Getenv("USER")
	if gotOwner == me {
		fail("Owner matched the OS user %q; the token identity did not drive the Owner", me)
	}
	t.Logf("token-authenticated submit created a job owned by the token identity %q", gotOwner)
}

// ----- shared helpers -----

// buildScheddBin compiles the golang-ap schedd into tmp with a pid+tag-unique name.
func buildScheddBin(t *testing.T, tmp, tag string) string {
	t.Helper()
	binName := fmt.Sprintf("golang-ap-schedd%s-%d", tag, os.Getpid())
	scheddBin := filepath.Join(tmp, binName)
	build := exec.Command("go", "build", "-buildvcs=false", "-o", scheddBin, "../cmd/schedd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ap schedd: %v\n%s", err, out)
	}
	return scheddBin
}

// startGoSchedd boots the harness with the Go schedd config and waits for its
// address file. Returns the harness plus the config-file path and log dir.
func startGoSchedd(t *testing.T, extra string) (*htcondor.CondorTestHarness, string, string) {
	t.Helper()
	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()
	if !waitForFile(filepath.Join(logDir, ".schedd_address"), 60*time.Second) {
		dumpLog(t, filepath.Join(logDir, "ScheddLog"))
		dumpLog(t, filepath.Join(logDir, "MasterLog"))
		t.Fatal("Go schedd never wrote its address file")
	}
	return h, cfgFile, logDir
}

// runToolEnv is runTool with extra environment variables (e.g. _CONDOR_* knob
// overrides) layered on top of the process environment + CONDOR_CONFIG.
func runToolEnv(configFile string, extraEnv []string, timeout time.Duration, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	cmd.Env = append(cmd.Env, extraEnv...)
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

// afValue returns condor_q -af <attr> for one job (trimmed), or "".
func afValue(configFile string, cluster, proc int, attr string) string {
	out, err := runTool(configFile, 20*time.Second, "condor_q", "-allusers", "-af", attr,
		"-constraint", fmt.Sprintf("ClusterId==%d && ProcId==%d", cluster, proc))
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(out)
	if v == "undefined" {
		return ""
	}
	return v
}

// waitForAttr polls condor_q until one job's attr equals want.
func waitForAttr(configFile string, cluster, proc int, attr, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if afValue(configFile, cluster, proc, attr) == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// mintIDToken produces an HTCondor IDTOKEN (HS256 JWT) signed with the pool key,
// byte-identical to cedar's verify path: read key file, XOR-unscramble 0xdeadbeef,
// double for the POOL key, HKDF(input,"htcondor","master jwt") -> 32-byte HMAC key.
func mintIDToken(keyPath, keyID, subject, issuer string) (string, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	key := make([]byte, len(raw))
	for i := range raw {
		key[i] = raw[i] ^ deadbeef[i%len(deadbeef)]
	}
	hkdfInput := key
	if keyID == "POOL" {
		hkdfInput = append(append([]byte{}, key...), key...)
	}

	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	header := map[string]string{"alg": "HS256", "typ": "JWT", "kid": keyID}
	hj, _ := json.Marshal(header)
	now := time.Now().Unix()
	payload := map[string]any{
		"sub": subject,
		"iss": issuer,
		"jti": hex.EncodeToString(jti),
		"iat": now,
		"nbf": now - 30,
		"exp": now + 3600,
	}
	pj, _ := json.Marshal(payload)
	signData := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(pj)

	jwtKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, hkdfInput, []byte("htcondor"), []byte("master jwt")), jwtKey); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(signData))
	return signData + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
