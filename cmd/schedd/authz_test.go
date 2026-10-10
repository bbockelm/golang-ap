package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
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

// These tests drive the schedd's command server as run() builds it
// (installAuthz, the real command registrations, serveCommands) over
// loopback, and check that the ALLOW_/DENY_ policy decides which identities
// may run which command.
//
// Identities are HTCondor's full user@domain names. A peer is given one by a
// pre-shared session the schedd attributes to that identity (the way a claim
// or family session carries its identity), so the policy sees exactly the
// name under test whatever an authentication method reports.

const testTrustDomain = "pool"

// authzSchedd is a running schedd command server plus the means to reach it
// as any identity.
type authzSchedd struct {
	addr    string
	cfg     *config.Config
	keyDir  string
	cache   *security.SessionCache
	az      *scheddAuthz
	q       *queue.Queue
	log     *logging.Logger
	stats   *stats.Collector
	records chan slog.Record
}

// startAuthzSchedd serves the schedd's commands with the ALLOW_/DENY_
// policy knobs. SEC_DEFAULT_AUTHENTICATION is OPTIONAL, so an anonymous peer
// can negotiate every level that does not force authentication and only the
// authorization policy keeps it out.
func startAuthzSchedd(t *testing.T, knobs map[string]string) *authzSchedd {
	t.Helper()
	keyDir := t.TempDir()
	if err := security.GeneratePoolSigningKey(filepath.Join(keyDir, "POOL")); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewEmpty()
	for k, v := range map[string]string{
		"SEC_DEFAULT_AUTHENTICATION":         "OPTIONAL",
		"SEC_DEFAULT_ENCRYPTION":             "OPTIONAL",
		"SEC_DEFAULT_INTEGRITY":              "OPTIONAL",
		"SEC_DEFAULT_AUTHENTICATION_METHODS": "IDTOKENS",
		"SEC_DEFAULT_CRYPTO_METHODS":         "AES",
		"SEC_TOKEN_POOL_SIGNING_KEY_FILE":    filepath.Join(keyDir, "POOL"),
		"SEC_PASSWORD_DIRECTORY":             keyDir,
		"TRUST_DOMAIN":                       testTrustDomain,
	} {
		cfg.Set(k, v)
	}
	for k, v := range knobs {
		cfg.Set(k, v)
	}

	// As run() builds it.
	sec, err := htcondor.GetServerSecurityConfig(cfg, commands.QUERY_SCHEDD_ADS, "DAEMON")
	if err != nil {
		t.Fatal(err)
	}
	cache := security.NewSessionCache()
	sec.SessionCache = cache
	srv := cedarserver.New(sec)
	az, err := newScheddAuthz(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := installAuthz(srv, az, cfg, sec); err != nil {
		t.Fatal(err)
	}

	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	spoolDir := t.TempDir()
	q, err := queue.Open(queue.Options{Dir: spoolDir, ScheddName: "schedd", UIDDomain: testTrustDomain})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	registerQueueCommands(srv, q, log, spoolDir)
	st := stats.New()
	neg := negotiate.New(q, log, func(negotiate.Match) {})
	neg.SetStats(st)
	neg.Register(srv)

	records := make(chan slog.Record, 64)
	logger := slog.New(&recordHandler{ch: records})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serveCommands(srv, az, logger)(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &authzSchedd{
		addr: ln.Addr().String(), cfg: cfg, keyDir: keyDir, cache: cache,
		az: az, q: q, log: log, stats: st, records: records,
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

// TestAuthzReconfigReloads: reconfigure rebuilds the policy, so a changed
// ALLOW_WRITE (here its _SCHEDD variant) decides the next command.
func TestAuthzReconfigReloads(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_WRITE": "alice@pool",
		"ALLOW_READ":  "*",
	})
	if _, err := as.newCluster(t, as.as(t, "bob@pool")); err == nil {
		t.Fatal("QMGMT NewCluster as bob@pool succeeded before reconfig, want refused")
	}
	as.waitDenial(t)

	next := config.NewEmpty()
	next.Set("ALLOW_WRITE", "alice@pool")
	next.Set("ALLOW_WRITE_SCHEDD", "bob@pool")
	next.Set("ALLOW_READ", "*")
	reconfigure(next, as.log, sched.New(sched.Options{}), factory.NewEngine(as.q, as.log, 0), as.q, as.az)

	if id, err := as.newCluster(t, as.as(t, "bob@pool")); err != nil || id <= 0 {
		t.Fatalf("QMGMT NewCluster as bob@pool after reconfig = %d, %v; want a cluster id", id, err)
	}
	if _, err := as.newCluster(t, as.as(t, "alice@pool")); err == nil {
		t.Fatal("QMGMT NewCluster as alice@pool succeeded after reconfig dropped her, want refused")
	}
	as.expectDenial(t, "QMGMT_WRITE_CMD", "WRITE", "alice@pool", "ALLOW_WRITE_SCHEDD", "")
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

// TestAuthzAdvertisesNegotiatedCommandOnly: the post-auth reply lists only
// the negotiated command, so a C++ client negotiates a new session for each
// other command instead of resuming one it would then re-authenticate on.
func TestAuthzAdvertisesNegotiatedCommandOnly(t *testing.T) {
	as := startAuthzSchedd(t, map[string]string{
		"ALLOW_WRITE": "*",
		"ALLOW_READ":  "*",
	})
	cl, _, err := as.dial(t, as.token(t, "alice@pool"), commands.QMGMT_WRITE_CMD)
	if err != nil {
		t.Fatal(err)
	}
	if got := cl.GetSecurityNegotiation().ValidCommands; got != "1112" {
		t.Fatalf("post-auth ValidCommands = %q, want only QMGMT_WRITE_CMD (1112)", got)
	}
}

// TestCommandLevelsMatchCxx pins the level every schedd command is
// registered at, and whether it is negotiated with authentication forced, to
// the C++ schedd's registration (Scheduler::Register, schedd.cpp; FileTransfer
// for FILETRANS_*; DaemonCore for DC_*).
func TestCommandLevelsMatchCxx(t *testing.T) {
	as := startAuthzSchedd(t, nil) // for its queue and logger
	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION", "OPTIONAL")
	sec := &security.SecurityConfig{SessionCache: security.NewSessionCache()}
	srv := cedarserver.New(sec)
	az, err := newScheddAuthz(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := installAuthz(srv, az, cfg, sec); err != nil {
		t.Fatal(err)
	}
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
	} {
		name := commands.GetCommandName(tc.cmd)
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
	}
}

// TestLogDenialIgnoresOtherErrors: only authorization refusals are logged as
// PERMISSION DENIED.
func TestLogDenialIgnoresOtherErrors(t *testing.T) {
	records := make(chan slog.Record, 4)
	az, err := newScheddAuthz(config.NewEmpty())
	if err != nil {
		t.Fatal(err)
	}
	az.logDenial(slog.New(&recordHandler{ch: records}), nil, "127.0.0.1:1",
		errors.New("cedar/server: command 1112 (QMGMT_WRITE_CMD) refused: session (authenticated=false encrypted=false) does not meet the command's security level"))
	if len(records) != 0 {
		t.Errorf("logged %d records for a security-level refusal, want 0", len(records))
	}
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
