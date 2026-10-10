package shadow

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// These tests cover a job without file transfer (no TransferEndpoint): the
// shadow must still hand the starter the claim-derived reconnect session, and
// a later reconnecting shadow must be able to resume it to reach the starter.

// caServer serves CA_CMD on loopback over cache, answering each request with
// handle's reply ad.
func caServer(t *testing.T, ln net.Listener, cache *security.SessionCache, handle func(c *cedarserver.Conn, req *classad.ClassAd) *classad.ClassAd) {
	t.Helper()
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})
	srv.Handle(caCmd, func(ctx context.Context, c *cedarserver.Conn) error {
		req, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx)
		if err != nil {
			return err
		}
		out := message.NewMessageForStream(c.Stream)
		if err := out.PutClassAd(ctx, handle(c, req)); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}, "WRITE")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func noTransferJobAd() *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("ClusterId", int64(3))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("Cmd", "/bin/sh")
	_ = ad.Set("Iwd", "/tmp")
	_ = ad.Set("ShouldTransferFiles", "NO")
	_ = ad.Set("GlobalJobId", "schedd#3.0#1")
	return ad
}

// getSecSessionInfo runs a shadow for a job without file transfer on claimID
// and returns the six strings its get_sec_session_info reply carries.
func getSecSessionInfo(t *testing.T, claimID string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	starterSt, shadowSt := loopbackStreams(t)
	sh, err := New(shadowSt, nil, Config{
		JobAd:      noTransferJobAd(),
		ClaimID:    claimID,
		ShadowAddr: "<127.0.0.1:12345>",
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	runDone := make(chan struct{})
	runCtx, stop := context.WithCancel(ctx)
	go func() {
		defer close(runDone)
		_, _ = sh.Run(runCtx)
	}()
	defer func() {
		stop()
		_ = shadowSt.Close()
		<-runDone
	}()

	fs := &fakeStarter{t: t, st: starterSt}
	in := fs.call(ctx, opGetSecSessionInfo, func(m *message.Message) error {
		if err := m.PutString(ctx, ""); err != nil {
			return err
		}
		return m.PutString(ctx, "")
	})
	rval, err := in.GetInt(ctx)
	if err != nil {
		t.Fatalf("get_sec_session_info rval: %v", err)
	}
	if rval < 0 {
		t.Fatalf("get_sec_session_info declined (rval=%d) for a job without file transfer", rval)
	}
	var out []string
	for i := 0; i < 6; i++ {
		v, err := in.GetString(ctx)
		if err != nil {
			t.Fatalf("get_sec_session_info string %d: %v", i, err)
		}
		out = append(out, v)
	}
	return out
}

// TestGetSecSessionInfoWithoutTransfer: a shadow with no file transfer hands
// the starter the claim session as the reconnect session, as
// RemoteResource::getSecSessionInfo does.
func TestGetSecSessionInfoWithoutTransfer(t *testing.T) {
	claim, err := security.MintClaimSession(security.NewSessionCache(), security.MintClaimOptions{Sinful: "<127.0.0.1:1>"})
	if err != nil {
		t.Fatal(err)
	}
	got := getSecSessionInfo(t, claim.ClaimID())
	cid := security.ParseClaimIDStrict(claim.ClaimID())
	if got[0] != claim.SessionID() || got[1] != cid.SecSessionInfo() || got[2] != cid.SecSessionKey() {
		t.Fatalf("reconnect session = {%q, %q, <key>}, want the claim session %q", got[0], got[1], claim.SessionID())
	}
	if got[3] != "filetrans."+claim.SessionID() || got[5] != cid.SecSessionKey() {
		t.Fatalf("filetrans session id = %q, want the claim's derived filetrans session", got[3])
	}
}

// TestReconnectWithoutTransfer: the starter registers the reconnect session a
// shadow without file transfer handed it, and only accepts CA_RECONNECT_JOB
// over that session (as golang-ep's starter does); a reconnecting shadow for
// the same job locates the starter through the startd and is accepted.
func TestReconnectWithoutTransfer(t *testing.T) {
	startdLn := listen(t)
	starterLn := listen(t)
	startdCache := security.NewSessionCache()
	claim, err := security.MintClaimSession(startdCache, security.MintClaimOptions{
		Sinful: "<" + startdLn.Addr().String() + ">",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Original activation: the starter asks for the session material and
	// registers the reconnect session on its command port.
	info := getSecSessionInfo(t, claim.ClaimID())
	starterCache := security.NewSessionCache()
	entry, err := security.CreateNonNegotiatedSession(&security.InheritedSession{
		Type:        security.SessionTypeNormal,
		SessionID:   info[0],
		SessionInfo: info[1],
		SessionKey:  info[2],
	}, "")
	if err != nil {
		t.Fatalf("registering reconnect session: %v", err)
	}
	entry.SetInherited(true)
	starterCache.Store(entry)

	caServer(t, startdLn, startdCache, func(_ *cedarserver.Conn, req *classad.ClassAd) *classad.ClassAd {
		reply := classad.New()
		if cmd, _ := req.EvaluateAttrString("Command"); cmd != caLocateStarterCmd {
			reply.InsertAttrString("Result", "Failure")
			return reply
		}
		reply.InsertAttrString("Result", caResultSuccess)
		reply.InsertAttrString("StarterIpAddr", "<"+starterLn.Addr().String()+">")
		return reply
	})
	var accepted atomic.Bool
	caServer(t, starterLn, starterCache, func(c *cedarserver.Conn, req *classad.ClassAd) *classad.ClassAd {
		reply := classad.New()
		cmd, _ := req.EvaluateAttrString("Command")
		if cmd != caReconnectJobCmd || c.Negotiation == nil || c.Negotiation.SessionId != info[0] {
			reply.InsertAttrString("Result", "NotAuthorized")
			return reply
		}
		accepted.Store(true)
		reply.InsertAttrString("Result", caResultSuccess)
		return reply
	})

	sh, err := NewReconnect(Config{
		JobAd:      noTransferJobAd(),
		ClaimID:    claim.ClaimID(),
		ShadowAddr: "<127.0.0.1:12345>",
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatalf("NewReconnect without a transfer endpoint: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sh.establishReconnect(ctx); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if !accepted.Load() {
		t.Fatal("starter did not accept CA_RECONNECT_JOB over the reconnect session")
	}
	if sh.st == nil {
		t.Fatal("reconnect installed no syscall stream")
	}
	if sh.closer != nil {
		_ = sh.closer.Close()
	}
}
