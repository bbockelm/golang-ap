package spool

import (
	"context"
	"testing"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/golang-ap/internal/conntest"
	"github.com/bbockelm/golang-ap/internal/queue"
)

func openIdentityQueue(t *testing.T) (*queue.Queue, int) {
	t.Helper()
	q, err := queue.Open(queue.Options{
		Dir:        t.TempDir(),
		ScheddName: "testschedd",
		UIDDomain:  "pool",
		SuperUsers: []string{"condor"},
	})
	if err != nil {
		t.Fatalf("queue.Open: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	txn := q.Begin("alice")
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatalf("NewCluster: %v", err)
	}
	if _, err := txn.NewProc(c); err != nil {
		t.Fatalf("NewProc: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return q, c
}

// spoolFor sends the SPOOL_JOB_FILES job list for c.0 and hangs up, returning
// whether the schedd accepted the caller as entitled to spool for the job (it
// stamps StageInStart only after the ownership check passes).
func spoolFor(t *testing.T, q *queue.Queue, neg *security.SecurityNegotiation, c int) bool {
	t.Helper()
	ctx := context.Background()
	h := New(Options{Queue: q, SpoolDir: t.TempDir()})
	s, done := conntest.Serve(t, commands.SPOOL_JOB_FILES, neg, h.handleSpool)
	m1 := message.NewMessageForStream(s)
	if err := m1.PutInt32(ctx, 1); err != nil {
		t.Fatalf("send count: %v", err)
	}
	if err := m1.FinishMessage(ctx); err != nil {
		t.Fatalf("finish count: %v", err)
	}
	m2 := message.NewMessageForStream(s)
	if err := m2.PutInt32(ctx, int32(c)); err != nil {
		t.Fatalf("send cluster: %v", err)
	}
	if err := m2.PutInt32(ctx, 0); err != nil {
		t.Fatalf("send proc: %v", err)
	}
	if err := m2.FinishMessage(ctx); err != nil {
		t.Fatalf("finish ids: %v", err)
	}
	_ = s.Close() // no sandbox follows; the handler fails either way
	<-done
	ad, ok := q.Get(c, 0)
	if !ok {
		t.Fatalf("job %d.0 missing", c)
	}
	_, started := ad.EvaluateAttrInt("StageInStart")
	return started
}

// transferCount sends a TRANSFER_DATA request for every job and returns how
// many jobs the schedd agrees to send back.
func transferCount(t *testing.T, q *queue.Queue, neg *security.SecurityNegotiation) int32 {
	t.Helper()
	ctx := context.Background()
	h := New(Options{Queue: q, SpoolDir: t.TempDir()})
	s, done := conntest.Serve(t, commands.TRANSFER_DATA, neg, h.handleTransfer)
	m1 := message.NewMessageForStream(s)
	if err := m1.PutString(ctx, "true"); err != nil {
		t.Fatalf("send constraint: %v", err)
	}
	if err := m1.FinishMessage(ctx); err != nil {
		t.Fatalf("finish constraint: %v", err)
	}
	n, err := message.NewMessageFromStream(s).GetInt32(ctx)
	if err != nil {
		t.Fatalf("read job count: %v", err)
	}
	_ = s.Close()
	<-done
	return n
}

// A connection that did not authenticate cannot spool input for, or retrieve
// output of, a job owned by the user its negotiation names, nor act as the
// superuser; the authenticated owner can.
func TestSpoolRequiresAuthenticatedOwner(t *testing.T) {
	for _, user := range []string{"condor@pool", "alice@pool"} {
		q, c := openIdentityQueue(t)
		neg := conntest.Negotiation(user, false)
		if spoolFor(t, q, neg, c) {
			t.Errorf("unauthenticated %s passed the spool ownership check", user)
		}
		if n := transferCount(t, q, neg); n != 0 {
			t.Errorf("unauthenticated %s: TRANSFER_DATA offered %d job(s), want 0", user, n)
		}
	}

	q, c := openIdentityQueue(t)
	if n := transferCount(t, q, conntest.Negotiation("bob@pool", true)); n != 0 {
		t.Errorf("bob: TRANSFER_DATA offered %d of alice's job(s), want 0", n)
	}
	if n := transferCount(t, q, conntest.Negotiation("alice@pool", true)); n != 1 {
		t.Errorf("alice: TRANSFER_DATA offered %d job(s), want 1", n)
	}
	if !spoolFor(t, q, conntest.Negotiation("alice@pool", true), c) {
		t.Errorf("authenticated owner failed the spool ownership check")
	}
}
