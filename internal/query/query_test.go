package query

import (
	"context"
	"slices"
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

func seedJob(t *testing.T, q *queue.Queue, owner string) {
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
}

// myJobsOwners runs a condor_q-style "only my jobs" QUERY_JOB_ADS through the
// real handler and returns the sorted Owner of every job ad returned.
func myJobsOwners(t *testing.T, q *queue.Queue, neg *security.SecurityNegotiation) []string {
	t.Helper()
	ctx := context.Background()
	s, done := conntest.Serve(t, int(commands.QUERY_JOB_ADS), neg, New(q, conntest.Logger(t)).Handle)

	req := classad.New()
	_ = req.Set("MyJobs", true)
	_ = req.Set("Requirements", true)
	wm := message.NewMessageForStream(s)
	if err := wm.PutClassAd(ctx, req); err != nil {
		t.Fatalf("send query ad: %v", err)
	}
	if err := wm.FinishMessage(ctx); err != nil {
		t.Fatalf("finish query ad: %v", err)
	}
	var owners []string
	for {
		ad, err := message.NewMessageFromStream(s).GetClassAd(ctx)
		if err != nil {
			t.Fatalf("read ad: %v", err)
		}
		if mt, _ := ad.EvaluateAttrString("MyType"); mt == "Summary" {
			break
		}
		o, _ := ad.EvaluateAttrString("Owner")
		owners = append(owners, o)
	}
	if err := <-done; err != nil {
		t.Fatalf("handler: %v", err)
	}
	slices.Sort(owners)
	return owners
}

// An unauthenticated MyJobs query is answered as for an anonymous caller (the
// C++ schedd: no mapped owner -> no only-my-jobs clause), never as the user its
// negotiation names; an authenticated one is scoped to the caller's own jobs.
func TestQueryMyJobsIdentity(t *testing.T) {
	q := openQueue(t)
	seedJob(t, q, "alice")
	seedJob(t, q, "bob")

	anon := myJobsOwners(t, q, nil)
	if want := []string{"alice", "bob"}; !slices.Equal(anon, want) {
		t.Fatalf("anonymous MyJobs query: owners %v, want %v", anon, want)
	}
	for _, user := range []string{"alice@pool", "condor@pool"} {
		if got := myJobsOwners(t, q, conntest.Negotiation(user, false)); !slices.Equal(got, anon) {
			t.Errorf("unauthenticated %s: owners %v, want the anonymous result %v", user, got, anon)
		}
	}
	if got, want := myJobsOwners(t, q, conntest.Negotiation("alice@pool", true)), []string{"alice"}; !slices.Equal(got, want) {
		t.Errorf("authenticated alice: owners %v, want %v", got, want)
	}
	if got, want := myJobsOwners(t, q, conntest.Negotiation("bob@pool", true)), []string{"bob"}; !slices.Equal(got, want) {
		t.Errorf("authenticated bob: owners %v, want %v", got, want)
	}
}
