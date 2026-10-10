package actions

import (
	"context"
	"fmt"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"

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
	if err := txn.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return c
}

// actOnJob runs one ACT_ON_JOBS request for job c.0 through the real handler
// (acking phase 2 when the schedd offers it) and returns the per-job result code
// and the IsQueueSuperUser flag from the result ad.
func actOnJob(t *testing.T, q *queue.Queue, neg *security.SecurityNegotiation, action, c int) (code int64, super bool) {
	t.Helper()
	ctx := context.Background()
	s, done := conntest.Serve(t, int(commands.ACT_ON_JOBS), neg, New(q, conntest.Logger(t)).Handle)

	cmd := classad.New()
	_ = cmd.Set("JobAction", int64(action))
	_ = cmd.Set("ActionResultType", int64(1)) // AR_LONG: per-job codes
	cmd.InsertAttrString("ActionIds", fmt.Sprintf("%d.0", c))
	cmd.InsertAttrString("RemoveReason", "test")
	cmd.InsertAttrString("HoldReason", "test")
	wm := message.NewMessageForStream(s)
	if err := wm.PutClassAd(ctx, cmd); err != nil {
		t.Fatalf("send command ad: %v", err)
	}
	if err := wm.FinishMessage(ctx); err != nil {
		t.Fatalf("finish command ad: %v", err)
	}
	res, err := message.NewMessageFromStream(s).GetClassAd(ctx)
	if err != nil {
		t.Fatalf("read result ad: %v", err)
	}
	code, _ = res.EvaluateAttrInt(fmt.Sprintf("job_%d_0", c))
	super, _ = res.EvaluateAttrBool("IsQueueSuperUser")
	if code == queue.ArSuccess {
		ack := message.NewMessageForStream(s)
		if err := ack.PutInt(ctx, wireOK); err != nil {
			t.Fatalf("send ack: %v", err)
		}
		if err := ack.FinishMessage(ctx); err != nil {
			t.Fatalf("finish ack: %v", err)
		}
		if _, err := message.NewMessageFromStream(s).GetInt(ctx); err != nil {
			t.Fatalf("read final OK: %v", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("handler: %v", err)
	}
	return code, super
}

// condor_rm / condor_hold on a connection that did not authenticate may not act
// on anyone's job, whatever user name its negotiation carries, and is not a
// queue superuser.
func TestActOnJobsUnauthenticatedDenied(t *testing.T) {
	for _, user := range []string{"condor@pool", "alice@pool"} {
		for _, action := range []int{jaRemoveJobs, jaHoldJobs} {
			t.Run(fmt.Sprintf("%s/action%d", user, action), func(t *testing.T) {
				q := openQueue(t)
				c := seedJob(t, q, "alice")
				code, super := actOnJob(t, q, conntest.Negotiation(user, false), action, c)
				if code != queue.ArPermissionDenied {
					t.Errorf("result code = %d, want ArPermissionDenied(%d)", code, queue.ArPermissionDenied)
				}
				if super {
					t.Errorf("IsQueueSuperUser = true for an unauthenticated connection")
				}
				ad, ok := q.Get(c, 0)
				if !ok {
					t.Fatalf("job %d.0 was removed", c)
				}
				if st, _ := ad.EvaluateAttrInt("JobStatus"); st != queue.StatusIdle {
					t.Errorf("JobStatus = %d, want Idle", st)
				}
			})
		}
	}
}

// Authenticated: the owner removes their job, a non-owner cannot, and the
// superuser is reported as one.
func TestActOnJobsAuthenticated(t *testing.T) {
	q := openQueue(t)
	c := seedJob(t, q, "alice")

	if code, super := actOnJob(t, q, conntest.Negotiation("bob@pool", true), jaRemoveJobs, c); code != queue.ArPermissionDenied || super {
		t.Errorf("bob: code=%d super=%v, want ArPermissionDenied, false", code, super)
	}
	if _, ok := q.Get(c, 0); !ok {
		t.Fatalf("bob removed alice's job")
	}
	if code, super := actOnJob(t, q, conntest.Negotiation("condor@pool", true), jaHoldJobs, c); code != queue.ArSuccess || !super {
		t.Errorf("superuser hold: code=%d super=%v, want ArSuccess, true", code, super)
	}
	if code, _ := actOnJob(t, q, conntest.Negotiation("alice@pool", true), jaRemoveJobs, c); code != queue.ArSuccess {
		t.Errorf("alice: code=%d, want ArSuccess", code)
	}
	if _, ok := q.Get(c, 0); ok {
		t.Errorf("alice's remove left job %d.0 in the queue", c)
	}
}

// condor_rm compares the caller's whole user@domain with the job's User:
// alice@otherpool may not remove alice@pool's job, condor@otherdomain is not a
// queue superuser, and condor@family is.
func TestActOnJobsFullName(t *testing.T) {
	q := openQueue(t)
	c := seedJob(t, q, "alice@pool")

	for _, user := range []string{"alice@otherpool", "condor@otherdomain"} {
		if code, super := actOnJob(t, q, conntest.Negotiation(user, true), jaRemoveJobs, c); code != queue.ArPermissionDenied || super {
			t.Errorf("%s: code=%d super=%v, want ArPermissionDenied, false", user, code, super)
		}
	}
	if _, ok := q.Get(c, 0); !ok {
		t.Fatalf("a non-owner removed alice@pool's job")
	}
	if code, super := actOnJob(t, q, conntest.Negotiation("condor@family", true), jaHoldJobs, c); code != queue.ArSuccess || !super {
		t.Errorf("condor@family hold: code=%d super=%v, want ArSuccess, true", code, super)
	}
	if code, _ := actOnJob(t, q, conntest.Negotiation("alice@pool", true), jaRemoveJobs, c); code != queue.ArSuccess {
		t.Errorf("alice@pool: code=%d, want ArSuccess", code)
	}
	if _, ok := q.Get(c, 0); ok {
		t.Errorf("alice@pool's remove left job %d.0 in the queue", c)
	}
}
