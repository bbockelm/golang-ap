package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"
	hqmgmt "github.com/bbockelm/golang-htcondor/qmgmt"

	"github.com/bbockelm/golang-ap/internal/factory"
	"github.com/bbockelm/golang-ap/internal/match"
	"github.com/bbockelm/golang-ap/internal/negotiate"
	"github.com/bbockelm/golang-ap/internal/queue"
	"github.com/bbockelm/golang-ap/internal/sched"
	"github.com/bbockelm/golang-ap/internal/spool"
	"github.com/bbockelm/golang-ap/internal/stats"
	"github.com/bbockelm/golang-ap/shadow"
)

// These tests drive the schedd's command server as run() builds it (the
// daemon's Authz with authzOptions, installAuthz, the DaemonCore defaults,
// the real command registrations, Authz.Serve) over loopback, and check that
// the ALLOW_/DENY_ policy decides which identities may run which command.
//
// Identities are HTCondor's full user@domain names. A peer is given one by a
// pre-shared session the schedd attributes to that identity (the way a claim
// or family session carries its identity), so the policy sees exactly the
// name under test whatever an authentication method reports.

const testTrustDomain = "pool"

// authzSchedd is a running schedd command server plus the means to reach it
// as any identity.
type authzSchedd struct {
	addr      string
	cfgFile   string
	keyDir    string
	cache     *security.SessionCache
	az        *daemon.Authz
	q         *queue.Queue
	log       *logging.Logger
	stats     *stats.Collector
	records   chan slog.Record
	reconfigs atomic.Int32
}

// startAuthzSchedd serves the schedd's commands with the ALLOW_/DENY_
// policy knobs, read from a configuration file as a daemon reads its own, so
// DC_RECONFIG reloads it. SEC_DEFAULT_AUTHENTICATION is OPTIONAL, so an
// anonymous peer can negotiate every level that does not force
// authentication and only the authorization policy keeps it out.
func startAuthzSchedd(t *testing.T, knobs map[string]string) *authzSchedd {
	t.Helper()
	as := &authzSchedd{
		cfgFile: filepath.Join(t.TempDir(), "condor_config"),
		keyDir:  t.TempDir(),
		records: make(chan slog.Record, 64),
	}
	if err := security.GeneratePoolSigningKey(filepath.Join(as.keyDir, "POOL")); err != nil {
		t.Fatal(err)
	}
	as.writeConfig(t, knobs)
	t.Setenv("CONDOR_CONFIG", as.cfgFile)
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "SCHEDD"})
	if err != nil {
		t.Fatal(err)
	}
	as.log, err = logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(daemon.Options{Subsys: "SCHEDD", Config: cfg, Logger: as.log})
	if err != nil {
		t.Fatal(err)
	}

	// As run() builds it.
	sec, err := d.ServerSecurityConfig(commands.QUERY_SCHEDD_ADS, "DAEMON")
	if err != nil {
		t.Fatal(err)
	}
	as.cache = security.NewSessionCache()
	sec.SessionCache = as.cache
	srv := cedarserver.New(sec)
	as.az, err = d.NewAuthz(authzOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := installAuthz(d, srv, as.az); err != nil {
		t.Fatal(err)
	}
	d.RegisterDefaultCommands(srv)

	spoolDir := t.TempDir()
	as.q, err = queue.Open(queue.Options{Dir: spoolDir, ScheddName: "schedd", UIDDomain: testTrustDomain})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.q.Close() })
	registerQueueCommands(srv, as.q, as.log, spoolDir)
	as.stats = stats.New()
	neg := negotiate.New(as.q, as.log, func(negotiate.Match) {})
	neg.SetStats(as.stats)
	neg.Register(srv)
	scheduler := sched.New(sched.Options{})
	matEngine := factory.NewEngine(as.q, as.log, 0)
	d.OnReconfig(func(newCfg *config.Config) {
		reconfigure(newCfg, as.log, scheduler, matEngine, as.q)
		as.reconfigs.Add(1)
	})

	logger := slog.New(&recordHandler{ch: as.records})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = as.az.Serve(srv, logger)(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	as.addr = ln.Addr().String()
	return as
}

// writeConfig writes the schedd's configuration file: the test pool's
// security settings plus knobs.
func (as *authzSchedd) writeConfig(t *testing.T, knobs map[string]string) {
	t.Helper()
	var b strings.Builder
	for k, v := range map[string]string{
		"SEC_DEFAULT_AUTHENTICATION":         "OPTIONAL",
		"SEC_DEFAULT_ENCRYPTION":             "OPTIONAL",
		"SEC_DEFAULT_INTEGRITY":              "OPTIONAL",
		"SEC_DEFAULT_AUTHENTICATION_METHODS": "IDTOKENS",
		"SEC_DEFAULT_CRYPTO_METHODS":         "AES",
		"SEC_TOKEN_POOL_SIGNING_KEY_FILE":    filepath.Join(as.keyDir, "POOL"),
		"SEC_PASSWORD_DIRECTORY":             as.keyDir,
		"TRUST_DOMAIN":                       testTrustDomain,
	} {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	for k, v := range knobs {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	if err := os.WriteFile(as.cfgFile, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// as returns a client security config for a peer the schedd knows as
// identity: a session pre-shared with the schedd and attributed to identity
// there. "" returns an anonymous config. Each config carries its own session
// cache, so no session (and so no identity) is reused across clients.
func (as *authzSchedd) as(t *testing.T, identity string) *security.SecurityConfig {
	t.Helper()
	if identity == "" {
		return &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{},
			Authentication: security.SecurityNever,
			Encryption:     security.SecurityNever,
			Integrity:      security.SecurityNever,
			SessionCache:   security.NewSessionCache(),
		}
	}
	claim, err := security.MintClaimSession(as.cache, security.MintClaimOptions{
		Sinful:  "<127.0.0.1:1>",
		PeerFQU: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	cc := security.NewSessionCache()
	sid, err := security.ImportClaimSession(cc, claim.ClaimID(), security.ClaimSessionOptions{PeerFQU: "schedd@" + testTrustDomain})
	if err != nil {
		t.Fatal(err)
	}
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionID:      sid,
		SessionCache:   cc,
	}
}

// token returns a client security config that authenticates with an IDTOKEN
// for subject, signed by the schedd's pool key.
func (as *authzSchedd) token(t *testing.T, subject string) *security.SecurityConfig {
	t.Helper()
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(as.keyDir, "POOL", subject, testTrustDomain, now, now+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          tok,
		TrustDomain:    testTrustDomain,
		SessionCache:   security.NewSessionCache(),
	}
}

// dial connects as sec's identity to run cmd.
func (as *authzSchedd) dial(t *testing.T, sec *security.SecurityConfig, cmd int) (*client.HTCondorClient, context.Context, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cs := *sec
	cs.Command = cmd
	cl, err := client.ConnectAndAuthenticate(ctx, as.addr, &cs)
	if err != nil {
		return nil, ctx, err
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl, ctx, nil
}

// command sends cmd, which carries no payload and no reply, as sec's
// identity. Over a resumed session the schedd refuses a command by closing
// the connection, which the client cannot tell from success; the denial log
// and the command's effect tell them apart.
func (as *authzSchedd) command(t *testing.T, sec *security.SecurityConfig, cmd int) {
	t.Helper()
	if _, _, err := as.dial(t, sec, cmd); err != nil {
		t.Fatalf("sending command %d: %v", cmd, err)
	}
}

// reconfig sends DC_RECONFIG as sec's identity and waits for the schedd to
// finish reloading its configuration.
func (as *authzSchedd) reconfig(t *testing.T, sec *security.SecurityConfig) {
	t.Helper()
	before := as.reconfigs.Load()
	as.command(t, sec, commands.DC_RECONFIG)
	deadline := time.Now().Add(10 * time.Second)
	for as.reconfigs.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("DC_RECONFIG was accepted but the schedd did not reconfigure")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// negotiate opens NEGOTIATE as sec's identity, asks for the first job of
// submitter alice, and returns the schedd's reply opcode, or an error if the
// schedd refused the command.
func (as *authzSchedd) negotiate(t *testing.T, sec *security.SecurityConfig) (int, error) {
	t.Helper()
	cl, ctx, err := as.dial(t, sec, commands.NEGOTIATE)
	if err != nil {
		return 0, err
	}
	m := message.NewMessageForStream(cl.GetStream())
	if err := m.PutClassAd(ctx, mustParse(t, `[Owner="alice@pool"]`)); err != nil {
		return 0, err
	}
	if err := m.FinishMessage(ctx); err != nil {
		return 0, err
	}
	m = message.NewMessageForStream(cl.GetStream())
	if err := m.PutInt(ctx, commands.SEND_JOB_INFO); err != nil {
		return 0, err
	}
	if err := m.FinishMessage(ctx); err != nil {
		return 0, err
	}
	return message.NewMessageFromStream(cl.GetStream()).GetInt(ctx)
}

// newCluster opens QMGMT_WRITE_CMD as sec's identity and allocates a cluster,
// returning its id, or an error if the schedd refused the command.
func (as *authzSchedd) newCluster(t *testing.T, sec *security.SecurityConfig) (int, error) {
	t.Helper()
	cl, ctx, err := as.dial(t, sec, commands.QMGMT_WRITE_CMD)
	if err != nil {
		return 0, err
	}
	m := message.NewMessageForStream(cl.GetStream())
	if err := m.PutInt(ctx, hqmgmt.OpNewCluster); err != nil {
		return 0, err
	}
	if err := m.FinishMessage(ctx); err != nil {
		return 0, err
	}
	rval, _, err := hqmgmt.ReadReply(ctx, message.NewMessageFromStream(cl.GetStream()))
	return rval, err
}

// queryJobs runs QUERY_JOB_ADS as sec's identity and returns the job ads, or
// an error if the schedd refused the command.
func (as *authzSchedd) queryJobs(t *testing.T, sec *security.SecurityConfig) ([]*classad.ClassAd, error) {
	t.Helper()
	cl, ctx, err := as.dial(t, sec, commands.QUERY_JOB_ADS)
	if err != nil {
		return nil, err
	}
	m := message.NewMessageForStream(cl.GetStream())
	if err := m.PutClassAd(ctx, mustParse(t, `[Requirements=true]`)); err != nil {
		return nil, err
	}
	if err := m.FinishMessage(ctx); err != nil {
		return nil, err
	}
	var out []*classad.ClassAd
	for {
		ad, err := message.NewMessageFromStream(cl.GetStream()).GetClassAd(ctx)
		if err != nil {
			return nil, err
		}
		if mt, _ := ad.EvaluateAttrString("MyType"); mt == "Summary" {
			return out, nil
		}
		out = append(out, ad)
	}
}

// submitJob commits a one-proc cluster owned by owner straight into the queue.
func (as *authzSchedd) submitJob(t *testing.T, owner string) int {
	t.Helper()
	txn := as.q.Begin(owner)
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txn.NewProc(c); err != nil {
		t.Fatal(err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatal(err)
	}
	return c
}

// waitDenial returns the attributes of the next PERMISSION DENIED record.
func (as *authzSchedd) waitDenial(t *testing.T) map[string]string {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case r := <-as.records:
			if r.Message != "PERMISSION DENIED" {
				continue
			}
			attrs := map[string]string{}
			r.Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = a.Value.String()
				return true
			})
			return attrs
		case <-timeout:
			t.Fatal("no PERMISSION DENIED was logged")
			return nil
		}
	}
}

// expectDenial checks the next denial names the command, level, user and
// deciding knobs.
func (as *authzSchedd) expectDenial(t *testing.T, command, level, user, allowKnob, denyKnob string) {
	t.Helper()
	got := as.waitDenial(t)
	want := map[string]string{
		"command":    command,
		"level":      level,
		"user":       user,
		"allow_knob": allowKnob,
		"deny_knob":  denyKnob,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("denial %s = %q, want %q (record %v)", k, got[k], v, got)
		}
	}
	if got["peer"] == "" {
		t.Errorf("denial names no peer (record %v)", got)
	}
}

// TestAuthzNegotiateNeedsNegotiator: NEGOTIATE is authorized at NEGOTIATOR
// only. An identity that holds WRITE but is outside ALLOW_NEGOTIATOR, or an
// IDTOKENS peer outside it, cannot negotiate (the handler never runs); the
// negotiator's identity can.
func TestAuthzNegotiateNeedsNegotiator(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_NEGOTIATOR": "negotiator@pool",
		"ALLOW_WRITE":      "*",
		"ALLOW_READ":       "*",
	})

	if op, err := as.negotiate(t, as.as(t, "alice@pool")); err == nil {
		t.Fatalf("NEGOTIATE as alice@pool (outside ALLOW_NEGOTIATOR) answered %d, want refused", op)
	}
	as.expectDenial(t, "NEGOTIATE", "NEGOTIATOR", "alice@pool", "ALLOW_NEGOTIATOR", "")

	if op, err := as.negotiate(t, as.token(t, "mallory@pool")); err == nil {
		t.Fatalf("NEGOTIATE with an IDTOKEN outside ALLOW_NEGOTIATOR answered %d, want refused", op)
	}
	as.waitDenial(t)
	if n := as.stats.Snapshot().NegotiationCycles; n != 0 {
		t.Fatalf("NegotiationCycles = %d after refused NEGOTIATEs, want 0 (handler ran)", n)
	}

	op, err := as.negotiate(t, as.as(t, "negotiator@pool"))
	if err != nil {
		t.Fatalf("NEGOTIATE as negotiator@pool: %v", err)
	}
	if op != commands.NO_MORE_JOBS {
		t.Fatalf("NEGOTIATE as negotiator@pool answered %d, want NO_MORE_JOBS", op)
	}
	if n := as.stats.Snapshot().NegotiationCycles; n != 1 {
		t.Fatalf("NegotiationCycles = %d, want 1", n)
	}
}

// TestAuthzQmgmtWriteNeedsWrite: an identity outside ALLOW_WRITE cannot open
// a QMGMT write connection; one inside it can, and the outsider can still
// read the queue under ALLOW_READ = *.
func TestAuthzQmgmtWriteNeedsWrite(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_WRITE": "alice@pool",
		"ALLOW_READ":  "*",
	})
	before := as.q.Counts().Total

	if id, err := as.newCluster(t, as.as(t, "bob@pool")); err == nil {
		t.Fatalf("QMGMT NewCluster as bob@pool (outside ALLOW_WRITE) returned %d, want refused", id)
	}
	as.expectDenial(t, "QMGMT_WRITE_CMD", "WRITE", "bob@pool", "ALLOW_WRITE", "")

	id, err := as.newCluster(t, as.as(t, "alice@pool"))
	if err != nil {
		t.Fatalf("QMGMT NewCluster as alice@pool: %v", err)
	}
	if id <= 0 {
		t.Fatalf("QMGMT NewCluster as alice@pool returned %d, want a cluster id", id)
	}
	if got := as.q.Counts().Total; got != before {
		t.Fatalf("queue holds %d jobs, want %d (nothing committed)", got, before)
	}
}

// TestAuthzDenyOverridesAllow: DENY_WRITE refuses an identity ALLOW_WRITE
// admits, and leaves the others admitted.
func TestAuthzDenyOverridesAllow(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_WRITE": "*@pool",
		"DENY_WRITE":  "bob@pool",
		"ALLOW_READ":  "*",
	})

	if id, err := as.newCluster(t, as.as(t, "bob@pool")); err == nil {
		t.Fatalf("QMGMT NewCluster as bob@pool (in DENY_WRITE) returned %d, want refused", id)
	}
	as.expectDenial(t, "QMGMT_WRITE_CMD", "WRITE", "bob@pool", "ALLOW_WRITE", "DENY_WRITE")

	if id, err := as.newCluster(t, as.as(t, "alice@pool")); err != nil || id <= 0 {
		t.Fatalf("QMGMT NewCluster as alice@pool = %d, %v; want a cluster id", id, err)
	}
}

// TestAuthzReadUnderAllowReadStar: with ALLOW_READ = *, condor_q's
// QUERY_JOB_ADS works for an identity with no other rights and for an
// anonymous peer, and returns the queue.
func TestAuthzReadUnderAllowReadStar(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_READ":       "*",
		"ALLOW_WRITE":      "alice@pool",
		"ALLOW_NEGOTIATOR": "negotiator@pool",
	})
	cluster := as.submitJob(t, "alice")

	for _, who := range []string{"bob@pool", ""} {
		ads, err := as.queryJobs(t, as.as(t, who))
		if err != nil {
			t.Fatalf("QUERY_JOB_ADS as %q: %v", who, err)
		}
		if len(ads) != 1 {
			t.Fatalf("QUERY_JOB_ADS as %q returned %d ads, want 1", who, len(ads))
		}
		if c, _ := ads[0].EvaluateAttrInt("ClusterId"); int(c) != cluster {
			t.Fatalf("QUERY_JOB_ADS as %q returned cluster %d, want %d", who, c, cluster)
		}
	}
}

// TestAuthzQmgmtWriteForcesAuthentication: QMGMT_WRITE_CMD is negotiated with
// authentication required, as the C++ schedd registers it, so an anonymous
// peer cannot open it even under ALLOW_WRITE = *, while it can read.
func TestAuthzQmgmtWriteForcesAuthentication(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_WRITE": "*",
		"ALLOW_READ":  "*",
	})
	if id, err := as.newCluster(t, as.as(t, "")); err == nil {
		t.Fatalf("anonymous QMGMT NewCluster returned %d, want refused", id)
	}
	if _, err := as.queryJobs(t, as.as(t, "")); err != nil {
		t.Fatalf("anonymous QUERY_JOB_ADS: %v", err)
	}
	if id, err := as.newCluster(t, as.token(t, "alice@pool")); err != nil || id <= 0 {
		t.Fatalf("authenticated QMGMT NewCluster = %d, %v; want a cluster id", id, err)
	}
}

// TestAuthzReconfigReloads: DC_RECONFIG rebuilds the policy, so a changed
// ALLOW_WRITE (here its _SCHEDD variant) decides the next command.
func TestAuthzReconfigReloads(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_WRITE":         "alice@pool",
		"ALLOW_READ":          "*",
		"ALLOW_ADMINISTRATOR": "admin@pool",
	})
	if _, err := as.newCluster(t, as.as(t, "bob@pool")); err == nil {
		t.Fatal("QMGMT NewCluster as bob@pool succeeded before reconfig, want refused")
	}
	as.waitDenial(t)

	as.writeConfig(t, map[string]string{
		"ALLOW_WRITE":         "alice@pool",
		"ALLOW_WRITE_SCHEDD":  "bob@pool",
		"ALLOW_READ":          "*",
		"ALLOW_ADMINISTRATOR": "admin@pool",
	})
	as.reconfig(t, as.as(t, "admin@pool"))

	if id, err := as.newCluster(t, as.as(t, "bob@pool")); err != nil || id <= 0 {
		t.Fatalf("QMGMT NewCluster as bob@pool after reconfig = %d, %v; want a cluster id", id, err)
	}
	if _, err := as.newCluster(t, as.as(t, "alice@pool")); err == nil {
		t.Fatal("QMGMT NewCluster as alice@pool succeeded after reconfig dropped her, want refused")
	}
	as.expectDenial(t, "QMGMT_WRITE_CMD", "WRITE", "alice@pool", "ALLOW_WRITE_SCHEDD", "")
}

// TestAuthzFamilySessionReconfigures: condor_master's family session may
// reconfigure the schedd (condor_reconfig) whatever ALLOW_ADMINISTRATOR and
// DENY_ADMINISTRATOR say, as DaemonCore punches ADMINISTRATOR for it; any
// other identity is decided by the lists.
func TestAuthzFamilySessionReconfigures(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"DENY_ADMINISTRATOR":  "condor@*",
		"ALLOW_READ":          "*",
	})
	for _, who := range []string{"alice@pool", "condor@pool"} {
		as.command(t, as.as(t, who), commands.DC_RECONFIG)
		as.expectDenial(t, "DC_RECONFIG", "ADMINISTRATOR", who, "ALLOW_ADMINISTRATOR", "DENY_ADMINISTRATOR")
	}
	if n := as.reconfigs.Load(); n != 0 {
		t.Fatalf("schedd reconfigured %d time(s) on refused DC_RECONFIGs, want 0", n)
	}
	as.reconfig(t, as.as(t, "condor@family"))
}

// TestAuthzFamilySession: condor_master's family session holds the levels
// DaemonCore grants it whatever ALLOW_/DENY_ say, so the negotiator can
// negotiate over it; another condor identity is still decided by the lists.
func TestAuthzFamilySession(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_NEGOTIATOR": "negotiator@pool",
		"DENY_NEGOTIATOR":  "condor@*",
		"ALLOW_READ":       "*",
	})
	if op, err := as.negotiate(t, as.as(t, "condor@family")); err != nil || op != commands.NO_MORE_JOBS {
		t.Fatalf("NEGOTIATE as condor@family = %d, %v; want NO_MORE_JOBS", op, err)
	}
	if op, err := as.negotiate(t, as.as(t, "condor@pool")); err == nil {
		t.Fatalf("NEGOTIATE as condor@pool (in DENY_NEGOTIATOR) answered %d, want refused", op)
	}
	as.expectDenial(t, "NEGOTIATE", "NEGOTIATOR", "condor@pool", "ALLOW_NEGOTIATOR", "DENY_NEGOTIATOR")

	for _, perm := range []string{"ADMINISTRATOR", "DAEMON", "NEGOTIATOR", "WRITE", "READ"} {
		for _, who := range []string{"condor@family", "condor@parent"} {
			if perm == "NEGOTIATOR" && who == "condor@parent" {
				continue
			}
			if !as.az.Authorize(perm, "127.0.0.1:1", who) {
				t.Errorf("%s not authorized at %s", who, perm)
			}
		}
		if perm != "READ" && as.az.Authorize(perm, "127.0.0.1:1", "condor@pool") {
			t.Errorf("condor@pool authorized at %s with no ALLOW_%s", perm, perm)
		}
	}
	if as.az.Authorize("NEGOTIATOR", "127.0.0.1:1", "condor@parent") {
		t.Error("condor@parent authorized at NEGOTIATOR; DaemonCore grants it ADMINISTRATOR and DAEMON only")
	}
}

// TestAuthzNegotiatorMatchSession: the negotiator's match session holds
// NEGOTIATOR whatever ALLOW_NEGOTIATOR says while
// SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION is on (its default), as the C++
// schedd punches it, and is decided by the lists when it is off.
func TestAuthzNegotiatorMatchSession(t *testing.T) {
	for _, tc := range []struct {
		knob string
		want bool
	}{{"", true}, {"true", true}, {"false", false}} {
		t.Run("SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION="+tc.knob, func(t *testing.T) {
			knobs := map[string]string{
				"ALLOW_NEGOTIATOR": "negotiator@pool",
				"ALLOW_READ":       "*",
			}
			if tc.knob != "" {
				knobs["SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION"] = tc.knob
			}
			as := startAuthzSchedd(t, knobs)
			op, err := as.negotiate(t, as.as(t, authz.NegotiatorSideMatchSessionFQU))
			if !tc.want {
				if err == nil {
					t.Fatalf("NEGOTIATE over the match session answered %d, want refused", op)
				}
				as.expectDenial(t, "NEGOTIATE", "NEGOTIATOR", authz.NegotiatorSideMatchSessionFQU, "ALLOW_NEGOTIATOR", "")
				return
			}
			if err != nil || op != commands.NO_MORE_JOBS {
				t.Fatalf("NEGOTIATE over the match session = %d, %v; want NO_MORE_JOBS", op, err)
			}
			if as.az.Authorize("WRITE", "127.0.0.1:1", authz.NegotiatorSideMatchSessionFQU) {
				t.Error("match session authorized at WRITE; the schedd grants it NEGOTIATOR only")
			}
		})
	}
}

// TestCommandLevelsMatchCxx pins the level every schedd command is
// registered at, and whether it is negotiated with authentication forced, to
// the C++ schedd's registration (Scheduler::Register, schedd.cpp; FileTransfer
// for FILETRANS_*; DaemonCore for DC_*), and checks every command's policy
// advertises the schedd's version.
func TestCommandLevelsMatchCxx(t *testing.T) {
	as := startAuthzSchedd(t, nil) // for its queue and logger
	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION", "OPTIONAL")
	d, err := daemon.New(daemon.Options{Subsys: "SCHEDD", Config: cfg, Logger: as.log})
	if err != nil {
		t.Fatal(err)
	}
	const version = "$CondorVersion: 25.8.0 2026-03-11 $"
	sec := &security.SecurityConfig{SessionCache: security.NewSessionCache(), RemoteVersion: version}
	srv := cedarserver.New(sec)
	az, err := daemon.NewAuthz(cfg, authzOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := installAuthz(d, srv, az); err != nil {
		t.Fatal(err)
	}
	d.RegisterDefaultCommands(srv)
	registerQueueCommands(srv, as.q, as.log, t.TempDir())
	negotiate.New(as.q, as.log, nil).Register(srv)
	spool.New(spool.Options{Queue: as.q, SpoolDir: t.TempDir()}).Register(srv)
	match.RegisterALIVE(srv, match.NewTable(sec.SessionCache), nil)
	shadow.NewSharedEndpoint(srv, sec.SessionCache, "<127.0.0.1:1>", nil)

	for _, tc := range []struct {
		cmd       int
		level     string
		forceAuth bool
	}{
		{commands.NEGOTIATE, "NEGOTIATOR", false},
		{commands.QMGMT_READ_CMD, "READ", false},
		{commands.QMGMT_WRITE_CMD, "WRITE", true},
		{commands.QUERY_JOB_ADS, "READ", false},
		{commands.QUERY_JOB_ADS_WITH_AUTH, "READ", true},
		{commands.ACT_ON_JOBS, "WRITE", true},
		{commands.SPOOL_JOB_FILES, "WRITE", true},
		{commands.SPOOL_JOB_FILES_WITH_PERMS, "WRITE", true},
		{commands.TRANSFER_DATA, "WRITE", true},
		{commands.TRANSFER_DATA_WITH_PERMS, "WRITE", true},
		{match.ALIVE, "READ", false},
		{commands.FILETRANS_UPLOAD, "WRITE", false},
		{commands.FILETRANS_DOWNLOAD, "WRITE", false},
		{commands.DC_NOP_CONFIG, "CONFIG", false},
		{commands.DC_NOP_ADVERTISE_SCHEDD, "ADVERTISE_SCHEDD", false},
		{commands.DC_NOP_ADVERTISE_STARTD, "ADVERTISE_STARTD", false},
		{commands.DC_NOP_ADVERTISE_MASTER, "ADVERTISE_MASTER", false},
	} {
		name := commandName(tc.cmd)
		perms := srv.CommandPerms(tc.cmd)
		if len(perms) != 1 || perms[0] != tc.level {
			t.Errorf("%s registered at %v, want [%s]", name, perms, tc.level)
		}
		got := srv.SecurityConfigForCommand(tc.cmd)
		if got == nil {
			t.Errorf("%s has no per-level security policy", name)
			continue
		}
		if forced := got.Authentication == security.SecurityRequired; forced != tc.forceAuth {
			t.Errorf("%s negotiated with authentication required = %v, want %v", name, forced, tc.forceAuth)
		}
		if got.RemoteVersion != version {
			t.Errorf("%s policy advertises version %q, want %q", name, got.RemoteVersion, version)
		}
	}
}

// TestCommandsNegotiateAtTheirLevel runs handshakes against the schedd as
// run() builds it: each command negotiates under the SEC_<level>_* policy of
// the level it is registered at, an ADVERTISE_* level falling back to
// SEC_DAEMON_* while its own is unset and following SEC_ADVERTISE_<x>_* once
// a reconfig sets it, a CONFIG command under SEC_DEFAULT_* rather than
// SEC_DAEMON_*, and a forceAuthCommands command requires authentication
// whatever its level's policy says. Every ALLOW_<level> admits anyone, so a
// refused handshake is the security policy's doing, not authorization's.
func TestCommandsNegotiateAtTheirLevel(t *testing.T) {
	knobs := map[string]string{"SEC_DAEMON_AUTHENTICATION": "REQUIRED"}
	for _, lvl := range []string{"READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "CONFIG", "DAEMON",
		"ADVERTISE_SCHEDD", "ADVERTISE_STARTD", "ADVERTISE_MASTER"} {
		knobs["ALLOW_"+lvl] = "*"
	}
	as := startAuthzSchedd(t, knobs)

	expect := func(phase string, cmd int, wantAnonymous bool) {
		t.Helper()
		name := commandName(cmd)
		_, _, err := as.dial(t, as.as(t, ""), cmd)
		var denied *security.AuthorizationError
		if errors.As(err, &denied) {
			t.Errorf("%s: anonymous %s refused by authorization (%v), want only the security policy to decide", phase, name, err)
		} else if accepted := err == nil; accepted != wantAnonymous {
			t.Errorf("%s: anonymous %s negotiated = %v (err %v), want %v", phase, name, accepted, err, wantAnonymous)
		}
		if _, _, err := as.dial(t, as.token(t, "alice@pool"), cmd); err != nil {
			t.Errorf("%s: authenticated %s refused: %v", phase, name, err)
		}
	}

	for _, tc := range []struct {
		cmd           int
		wantAnonymous bool
	}{
		{commands.DC_NOP_READ, true},
		{commands.DC_NOP_WRITE, true},
		{commands.DC_NOP_CONFIG, true},
		{commands.DC_NOP_DAEMON, false},
		{commands.DC_NOP_ADVERTISE_SCHEDD, false},
		{commands.DC_NOP_ADVERTISE_STARTD, false},
		{commands.DC_NOP_ADVERTISE_MASTER, false},
		{commands.QUERY_JOB_ADS, true},
		{commands.QUERY_JOB_ADS_WITH_AUTH, false},
		{commands.QMGMT_WRITE_CMD, false},
		{commands.ACT_ON_JOBS, false},
	} {
		expect("SEC_ADVERTISE_SCHEDD_AUTHENTICATION unset", tc.cmd, tc.wantAnonymous)
	}

	knobs["SEC_ADVERTISE_SCHEDD_AUTHENTICATION"] = "OPTIONAL"
	as.writeConfig(t, knobs)
	as.reconfig(t, as.token(t, "alice@pool"))
	expect("SEC_ADVERTISE_SCHEDD_AUTHENTICATION=OPTIONAL", commands.DC_NOP_ADVERTISE_SCHEDD, true)
	expect("SEC_ADVERTISE_SCHEDD_AUTHENTICATION=OPTIONAL", commands.DC_NOP_ADVERTISE_STARTD, false)
	expect("SEC_ADVERTISE_SCHEDD_AUTHENTICATION=OPTIONAL", commands.DC_NOP_DAEMON, false)
}

// TestLogDenialIgnoresOtherErrors: only authorization refusals are logged as
// PERMISSION DENIED.
func TestLogDenialIgnoresOtherErrors(t *testing.T) {
	records := make(chan slog.Record, 4)
	az, err := daemon.NewAuthz(config.NewEmpty(), authzOptions())
	if err != nil {
		t.Fatal(err)
	}
	if az.LogDenial(slog.New(&recordHandler{ch: records}), nil, "127.0.0.1:1",
		errors.New("cedar/server: command 1112 (QMGMT_WRITE_CMD) refused: session (authenticated=false encrypted=false) does not meet the command's security level")) {
		t.Error("LogDenial reported a security-level refusal as an authorization denial")
	}
	if len(records) != 0 {
		t.Errorf("logged %d records for a security-level refusal, want 0", len(records))
	}
}

// commandName names cmd in a failure message, by number where cedar's
// command table has no name for it (the DC_NOP_* levels).
func commandName(cmd int) string {
	return fmt.Sprintf("%s (%d)", commands.GetCommandName(cmd), cmd)
}

func mustParse(t *testing.T, s string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ad
}

// recordHandler is a slog.Handler that hands every record to a channel.
type recordHandler struct{ ch chan slog.Record }

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.ch <- r.Clone():
	default:
	}
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }
