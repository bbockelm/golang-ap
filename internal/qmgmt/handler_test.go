package qmgmt

import (
	"context"
	"testing"

	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
	hqmgmt "github.com/bbockelm/golang-htcondor/qmgmt"

	"github.com/bbockelm/golang-ap/internal/conntest"
	"github.com/bbockelm/golang-ap/internal/queue"
)

func openQueue(t *testing.T) *queue.Queue {
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
	return q
}

// seedJob commits a one-proc cluster owned by owner through the queue API.
func seedJob(t *testing.T, q *queue.Queue, owner string) int {
	t.Helper()
	txn := q.Begin(owner)
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatalf("NewCluster: %v", err)
	}
	if _, err := txn.NewProc(c); err != nil {
		t.Fatalf("NewProc: %v", err)
	}
	if err := txn.SetAttribute(c, 0, "Cmd", `"/bin/true"`); err != nil {
		t.Fatalf("SetAttribute: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return c
}

// client speaks the QMGMT client side over a conntest connection.
type client struct {
	t    *testing.T
	s    *stream.Stream
	done <-chan error
}

func dial(t *testing.T, q *queue.Queue, neg *security.SecurityNegotiation) *client {
	t.Helper()
	srv := New(q, conntest.Logger(t), t.TempDir())
	s, done := conntest.Serve(t, hqmgmt.WriteCmd, neg, srv.Handle)
	return &client{t: t, s: s, done: done}
}

// call sends op with its int/string args and reads the rval [+terrno] reply.
func (c *client) call(op int, args ...any) (rval, terrno int) {
	c.t.Helper()
	ctx := context.Background()
	wm := message.NewMessageForStream(c.s)
	if err := wm.PutInt(ctx, op); err != nil {
		c.t.Fatalf("op %d: %v", op, err)
	}
	for _, a := range args {
		var err error
		switch v := a.(type) {
		case int:
			err = wm.PutInt(ctx, v)
		case string:
			err = wm.PutString(ctx, v)
		}
		if err != nil {
			c.t.Fatalf("op %d arg: %v", op, err)
		}
	}
	if err := wm.FinishMessage(ctx); err != nil {
		c.t.Fatalf("op %d finish: %v", op, err)
	}
	rm := message.NewMessageFromStream(c.s)
	rval, terrno, err := hqmgmt.ReadReply(ctx, rm)
	if err != nil {
		c.t.Fatalf("op %d reply: %v", op, err)
	}
	// NewCluster failures and every commit reply carry a trailing ad.
	if (op == hqmgmt.OpNewCluster && rval < 0) || op == hqmgmt.OpCommitTransactionNoFlags {
		if _, err := rm.GetClassAd(ctx); err != nil {
			c.t.Fatalf("op %d reply ad: %v", op, err)
		}
	}
	return rval, terrno
}

func (c *client) close() {
	c.t.Helper()
	ctx := context.Background()
	wm := message.NewMessageForStream(c.s)
	if err := wm.PutInt(ctx, hqmgmt.OpCloseSocket); err != nil {
		c.t.Fatalf("close: %v", err)
	}
	if err := wm.FinishMessage(ctx); err != nil {
		c.t.Fatalf("close finish: %v", err)
	}
	if err := <-c.done; err != nil {
		c.t.Fatalf("handler: %v", err)
	}
}

func wantDenied(t *testing.T, what string, rval, terrno int) {
	t.Helper()
	if rval >= 0 || terrno != eACCES {
		t.Errorf("%s: got rval=%d terrno=%d, want rval<0 terrno=EACCES", what, rval, terrno)
	}
}

func wantOK(t *testing.T, what string, rval, terrno int) {
	t.Helper()
	if rval < 0 {
		t.Errorf("%s: got rval=%d terrno=%d, want success", what, rval, terrno)
	}
}

// A QMGMT connection whose negotiation names a user but did not authenticate
// has no identity: it cannot submit, edit, or remove jobs, and the name it
// carries -- even the queue superuser's -- grants nothing.
func TestQmgmtUnauthenticatedHasNoIdentity(t *testing.T) {
	for _, user := range []string{"condor@pool", "alice@pool"} {
		t.Run(user, func(t *testing.T) {
			q := openQueue(t)
			c := seedJob(t, q, "alice")
			before := q.Counts().Total

			cl := dial(t, q, conntest.Negotiation(user, false))
			r, e := cl.call(hqmgmt.OpNewCluster)
			wantDenied(t, "NewCluster", r, e)
			r, e = cl.call(hqmgmt.OpSetAttribute, c, 0, `"edited"`, "Cmd")
			wantDenied(t, "SetAttribute on alice's job", r, e)
			r, e = cl.call(hqmgmt.OpDeleteAttribute, c, 0, "Cmd")
			wantDenied(t, "DeleteAttribute on alice's job", r, e)
			r, e = cl.call(hqmgmt.OpDestroyProc, c, 0)
			wantDenied(t, "DestroyProc on alice's job", r, e)
			r, e = cl.call(hqmgmt.OpDestroyCluster, c)
			wantDenied(t, "DestroyCluster on alice's job", r, e)
			// SetEffectiveOwner is a superuser-only op.
			r, e = cl.call(hqmgmt.OpSetEffectiveOwner, "alice")
			wantDenied(t, "SetEffectiveOwner", r, e)
			r, e = cl.call(hqmgmt.OpCommitTransactionNoFlags)
			wantOK(t, "empty commit", r, e)
			cl.close()

			ad, ok := q.Get(c, 0)
			if !ok {
				t.Fatalf("alice's job %d.0 was removed", c)
			}
			if cmd, _ := ad.EvaluateAttrString("Cmd"); cmd != "/bin/true" {
				t.Errorf("alice's job Cmd = %q, want unchanged /bin/true", cmd)
			}
			if got := q.Counts().Total; got != before {
				t.Errorf("queue has %d jobs, want %d", got, before)
			}
		})
	}
}

// The same operations on an authenticated connection still work: the owner
// submits, edits, and removes; a non-owner cannot remove; the superuser can.
func TestQmgmtAuthenticatedOwner(t *testing.T) {
	q := openQueue(t)
	c := seedJob(t, q, "alice")
	other := seedJob(t, q, "alice")

	alice := dial(t, q, conntest.Negotiation("alice@pool", true))
	nc, e := alice.call(hqmgmt.OpNewCluster)
	wantOK(t, "NewCluster", nc, e)
	r, e := alice.call(hqmgmt.OpNewProc, nc)
	wantOK(t, "NewProc", r, e)
	r, e = alice.call(hqmgmt.OpSetAttribute, nc, 0, `"/bin/sleep"`, "Cmd")
	wantOK(t, "SetAttribute on new job", r, e)
	r, e = alice.call(hqmgmt.OpSetAttribute, c, 0, `"edited"`, "Cmd")
	wantOK(t, "SetAttribute on own job", r, e)
	r, e = alice.call(hqmgmt.OpCommitTransactionNoFlags)
	wantOK(t, "commit", r, e)
	alice.close()

	ad, ok := q.Get(nc, 0)
	if !ok {
		t.Fatalf("submitted job %d.0 missing", nc)
	}
	if o, _ := ad.EvaluateAttrString("Owner"); o != "alice" {
		t.Errorf("submitted job Owner = %q, want alice", o)
	}
	if ad, _ := q.Get(c, 0); ad != nil {
		if cmd, _ := ad.EvaluateAttrString("Cmd"); cmd != "edited" {
			t.Errorf("own-job edit: Cmd = %q, want edited", cmd)
		}
	}

	bob := dial(t, q, conntest.Negotiation("bob@pool", true))
	r, e = bob.call(hqmgmt.OpDestroyProc, other, 0)
	wantDenied(t, "bob DestroyProc on alice's job", r, e)
	r, e = bob.call(hqmgmt.OpDestroyCluster, other)
	wantDenied(t, "bob DestroyCluster on alice's job", r, e)
	bob.close()
	if _, ok := q.Get(other, 0); !ok {
		t.Fatalf("bob removed alice's job %d.0", other)
	}

	condor := dial(t, q, conntest.Negotiation("condor@pool", true))
	r, e = condor.call(hqmgmt.OpSetEffectiveOwner, "alice")
	wantOK(t, "superuser SetEffectiveOwner", r, e)
	r, e = condor.call(hqmgmt.OpDestroyProc, other, 0)
	wantOK(t, "superuser DestroyProc", r, e)
	r, e = condor.call(hqmgmt.OpCommitTransactionNoFlags)
	wantOK(t, "superuser commit", r, e)
	condor.close()
	if _, ok := q.Get(other, 0); ok {
		t.Errorf("superuser DestroyProc did not remove %d.0", other)
	}

	alice = dial(t, q, conntest.Negotiation("alice@pool", true))
	r, e = alice.call(hqmgmt.OpDestroyProc, c, 0)
	wantOK(t, "owner DestroyProc", r, e)
	r, e = alice.call(hqmgmt.OpCommitTransactionNoFlags)
	wantOK(t, "owner commit", r, e)
	alice.close()
	if _, ok := q.Get(c, 0); ok {
		t.Errorf("owner DestroyProc did not remove %d.0", c)
	}
}
