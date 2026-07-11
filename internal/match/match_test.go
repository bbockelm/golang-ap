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

package match

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

const (
	sessionInfo = `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`
	secretKey   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestCreateRenewExpire(t *testing.T) {
	table := NewTable(nil)
	table.SetAlivesMissed(2)
	claimID := "<127.0.0.1:9618>#1700000000#7#" + sessionInfo + secretKey

	rec, err := table.CreateFromClaim(claimID, nil, 10)
	if err != nil {
		t.Fatalf("CreateFromClaim: %v", err)
	}
	if rec.State != StateClaimed {
		t.Errorf("state = %v, want Claimed", rec.State)
	}
	if table.Len() != 1 {
		t.Fatalf("table len = %d, want 1", table.Len())
	}

	// Found by the secret claim id.
	if _, ok := table.FindByClaimID(claimID); !ok {
		t.Fatal("FindByClaimID did not find the record")
	}

	// Lease ~ 2*10 = 20s out; not expired now, expired far in the future.
	if got := table.ExpireSweep(time.Now()); len(got) != 0 {
		t.Errorf("premature expiry: %d", len(got))
	}

	// Force the deadline into the past, renew, then confirm it survives a sweep.
	rec.LeaseDeadline = time.Now().Add(-time.Second)
	if !table.RenewLease(claimID) {
		t.Fatal("RenewLease returned false for a known claim")
	}
	if got := table.ExpireSweep(time.Now()); len(got) != 0 {
		t.Errorf("record expired after renew: %d", len(got))
	}

	// Now let it truly expire.
	rec.LeaseDeadline = time.Now().Add(-time.Second)
	expired := table.ExpireSweep(time.Now())
	if len(expired) != 1 {
		t.Fatalf("expired = %d, want 1", len(expired))
	}
	if table.Len() != 0 {
		t.Errorf("table len = %d after expiry, want 0", table.Len())
	}
}

// TestALIVEHandlerLoopback proves the ALIVE keepalive path end to end: a
// "startd" resumes the claim session and sends ALIVE; the schedd's handler finds
// the match, replies the alive interval, and renews the lease -- with no fresh
// authentication.
func TestALIVEHandlerLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr := fmt.Sprintf("<%s>", ln.Addr().String())
	claimID := addr + "#1700000000#7#" + sessionInfo + secretKey

	// Schedd side: match table + server sharing the table's session cache.
	table := NewTable(nil)
	rec, err := table.CreateFromClaim(claimID, nil, 42)
	if err != nil {
		t.Fatalf("CreateFromClaim: %v", err)
	}
	before := rec.LeaseDeadline

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   table.Cache(),
	})
	events := make(chan AliveEvent, 1)
	RegisterALIVE(srv, table, func(e AliveEvent) { events <- e })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	// Startd side: import the claim session (execute-side identity) and send ALIVE.
	time.Sleep(5 * time.Millisecond) // let the lease clock advance past `before`
	startdCache := security.NewSessionCache()
	sesid, err := security.ImportClaimSession(startdCache, claimID, security.ClaimSessionOptions{
		PeerAddr:           addr,
		PeerFQU:            security.ExecuteSideMatchSessionFQU,
		ExtraValidCommands: []int{ALIVE},
	})
	if err != nil {
		t.Fatalf("startd ImportClaimSession: %v", err)
	}

	hc, err := client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
		Command:      ALIVE,
		PeerName:     addr,
		SessionCache: startdCache,
		SessionID:    sesid,
	})
	if err != nil {
		t.Fatalf("startd connect/resume: %v", err)
	}
	defer func() { _ = hc.Close() }()
	if !hc.GetStream().IsEncrypted() {
		t.Fatal("startd stream not encrypted")
	}

	out := message.NewMessageForStream(hc.GetStream())
	if err := out.PutString(ctx, claimID); err != nil {
		t.Fatalf("send claim id: %v", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		t.Fatalf("finish: %v", err)
	}
	in := message.NewMessageFromStream(hc.GetStream())
	reply, err := in.GetInt(ctx)
	if err != nil {
		t.Fatalf("read ALIVE reply: %v", err)
	}
	if reply != 42 {
		t.Errorf("ALIVE reply = %d, want 42 (alive interval)", reply)
	}

	select {
	case e := <-events:
		if !e.Found {
			t.Error("ALIVE handler did not find the match")
		}
		if e.AliveInterval != 42 {
			t.Errorf("event alive interval = %d, want 42", e.AliveInterval)
		}
	case <-ctx.Done():
		t.Fatal("ALIVE event never delivered")
	}

	// Lease must have moved forward.
	if r, ok := table.FindByClaimID(claimID); !ok || !r.LeaseDeadline.After(before) {
		t.Errorf("lease not renewed: before=%v after=%v ok=%v", before, r.LeaseDeadline, ok)
	}
}

func TestALIVEUnknownClaim(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr := fmt.Sprintf("<%s>", ln.Addr().String())
	claimID := addr + "#1700000000#7#" + sessionInfo + secretKey

	// Import the session into a cache but DO NOT create a match record, so the
	// handler resumes the session yet finds no match -> replies -1.
	table := NewTable(nil)
	if _, err := security.ImportClaimSession(table.Cache(), claimID, security.ClaimSessionOptions{
		PeerAddr: addr,
		PeerFQU:  security.SubmitSideMatchSessionFQU,
	}); err != nil {
		t.Fatalf("ImportClaimSession: %v", err)
	}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   table.Cache(),
	})
	RegisterALIVE(srv, table, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	startdCache := security.NewSessionCache()
	sesid, _ := security.ImportClaimSession(startdCache, claimID, security.ClaimSessionOptions{
		PeerAddr: addr, PeerFQU: security.ExecuteSideMatchSessionFQU, ExtraValidCommands: []int{ALIVE},
	})
	hc, err := client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
		Command: ALIVE, PeerName: addr, SessionCache: startdCache, SessionID: sesid,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = hc.Close() }()

	out := message.NewMessageForStream(hc.GetStream())
	_ = out.PutString(ctx, claimID)
	_ = out.FinishMessage(ctx)
	in := message.NewMessageFromStream(hc.GetStream())
	reply, err := in.GetInt(ctx)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply != -1 {
		t.Errorf("reply = %d, want -1 for unknown claim", reply)
	}
}
