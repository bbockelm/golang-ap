package queue

import (
	"fmt"
	"testing"

	"github.com/PelicanPlatform/classad/collections/vm"
)

func openTestQueue(t *testing.T, dir string) *Queue {
	t.Helper()
	q, err := Open(Options{
		Dir:        dir,
		ScheddName: "testschedd",
		UIDDomain:  "example.net",
		SuperUsers: []string{"condor", "root"},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return q
}

// submitCluster commits a cluster with n procs owned by owner and returns the
// cluster id.
func submitCluster(t *testing.T, q *Queue, owner string, n int) int {
	t.Helper()
	txn := q.Begin(owner)
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatalf("NewCluster: %v", err)
	}
	if err := txn.SetAttribute(c, -1, "Cmd", `"/bin/sleep"`); err != nil {
		t.Fatalf("SetAttribute cluster: %v", err)
	}
	for i := 0; i < n; i++ {
		p, err := txn.NewProc(c)
		if err != nil {
			t.Fatalf("NewProc: %v", err)
		}
		if p != i {
			t.Fatalf("NewProc returned %d, want %d", p, i)
		}
		if err := txn.SetAttribute(c, p, "Args", fmt.Sprintf("%q", fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("SetAttribute proc: %v", err)
		}
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return c
}

// TestReadYourWritesInTxn: reads inside a transaction see staged state layered
// over committed state; committed state is untouched until commit.
func TestReadYourWritesInTxn(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	txn := q.Begin("alice")
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatal(err)
	}
	p, err := txn.NewProc(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := txn.SetAttribute(c, p, "Foo", `"bar"`); err != nil {
		t.Fatal(err)
	}
	if err := txn.SetAttribute(c, -1, "ClusterAttr", "42"); err != nil {
		t.Fatal(err)
	}

	// Read-your-writes on the proc attr.
	if v, ok := txn.GetAttribute(c, p, "Foo"); !ok || v != `"bar"` {
		t.Errorf("GetAttribute(Foo) = %q, %v; want \"bar\"", v, ok)
	}
	// Proc reads fall through to the staged cluster ad.
	if v, ok := txn.GetAttribute(c, p, "ClusterAttr"); !ok || v != "42" {
		t.Errorf("GetAttribute(ClusterAttr via proc) = %q, %v; want 42", v, ok)
	}
	// Deleted staged attrs disappear.
	txn.DeleteAttribute(c, p, "Foo")
	if _, ok := txn.GetAttribute(c, p, "Foo"); ok {
		t.Error("GetAttribute(Foo) after DeleteAttribute still present")
	}
	// Nothing visible outside the txn before commit.
	if _, ok := q.Get(c, p); ok {
		t.Error("uncommitted job visible in committed store")
	}
}

// TestAbortDiscards: an aborted transaction leaves no trace.
func TestAbortDiscards(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	txn := q.Begin("alice")
	c, _ := txn.NewCluster()
	p, _ := txn.NewProc(c)
	_ = txn.SetAttribute(c, p, "Foo", `"bar"`)
	txn.Abort()

	if _, ok := q.Get(c, p); ok {
		t.Error("aborted job present in store")
	}
	if got := q.Counts().Total; got != 0 {
		t.Errorf("Counts.Total = %d after abort, want 0", got)
	}
}

// TestAtomicMultiProcCommit: a 3-proc commit lands all procs with materialized
// forced attributes (ClusterId/ProcId/JobStatus/QDate/GlobalJobId/Owner/User).
func TestAtomicMultiProcCommit(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	c := submitCluster(t, q, "alice", 3)

	if got := q.Counts().Total; got != 3 {
		t.Fatalf("Counts.Total = %d, want 3", got)
	}
	for p := 0; p < 3; p++ {
		ad, ok := q.Get(c, p)
		if !ok {
			t.Fatalf("job %d.%d missing after commit", c, p)
		}
		if v, _ := ad.EvaluateAttrInt("ClusterId"); int(v) != c {
			t.Errorf("job %d.%d ClusterId = %d", c, p, v)
		}
		if v, _ := ad.EvaluateAttrInt("ProcId"); int(v) != p {
			t.Errorf("job %d.%d ProcId = %d", c, p, v)
		}
		if v, _ := ad.EvaluateAttrInt("JobStatus"); v != StatusIdle {
			t.Errorf("job %d.%d JobStatus = %d, want 1", c, p, v)
		}
		if v, _ := ad.EvaluateAttrString("Owner"); v != "alice" {
			t.Errorf("job %d.%d Owner = %q", c, p, v)
		}
		if v, _ := ad.EvaluateAttrString("User"); v != "alice@example.net" {
			t.Errorf("job %d.%d User = %q", c, p, v)
		}
		if v, ok := ad.EvaluateAttrInt("QDate"); !ok || v <= 0 {
			t.Errorf("job %d.%d QDate = %d, %v", c, p, v, ok)
		}
		gjid, _ := ad.EvaluateAttrString("GlobalJobId")
		want := fmt.Sprintf("testschedd#%d.%d#", c, p)
		if len(gjid) < len(want) || gjid[:len(want)] != want {
			t.Errorf("job %d.%d GlobalJobId = %q, want prefix %q", c, p, gjid, want)
		}
		// Inherited cluster attr appears on the flattened proc ad.
		if v, _ := ad.EvaluateAttrString("Cmd"); v != "/bin/sleep" {
			t.Errorf("job %d.%d Cmd = %q (cluster attr not inherited)", c, p, v)
		}
	}
}

// TestOwnerEnforcement: a non-superuser cannot claim another owner; superusers
// can.
func TestOwnerEnforcement(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	txn := q.Begin("alice")
	if err := txn.SetEffectiveOwner("bob"); err == nil {
		t.Error("non-superuser SetEffectiveOwner(bob) succeeded, want error")
	}
	if err := txn.SetEffectiveOwner("alice"); err != nil {
		t.Errorf("SetEffectiveOwner(self) failed: %v", err)
	}
	sup := q.Begin("condor")
	if err := sup.SetEffectiveOwner("bob"); err != nil {
		t.Errorf("superuser SetEffectiveOwner(bob) failed: %v", err)
	}
	c, _ := sup.NewCluster()
	p, _ := sup.NewProc(c)
	_ = sup.SetAttribute(c, p, "Cmd", `"/bin/true"`)
	if err := sup.Commit(); err != nil {
		t.Fatal(err)
	}
	ad, _ := q.Get(c, p)
	if v, _ := ad.EvaluateAttrString("Owner"); v != "bob" {
		t.Errorf("Owner = %q, want bob", v)
	}
}

// TestCrashRecovery: state committed before a "kill" (Close-less reopen is not
// possible with mmap, so we Close without any graceful queue-level flush beyond
// what Commit itself guarantees) survives a reopen; uncommitted staged state does
// not.
func TestCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	q := openTestQueue(t, dir)

	c1 := submitCluster(t, q, "alice", 2)

	// Stage but do NOT commit a second cluster (simulates dying mid-txn).
	txn := q.Begin("alice")
	c2, _ := txn.NewCluster()
	p2, _ := txn.NewProc(c2)
	_ = txn.SetAttribute(c2, p2, "Cmd", `"/bin/false"`)
	// no Commit, no Abort — the "process" dies here.
	_ = q.Close()

	q2 := openTestQueue(t, dir)
	defer q2.Close()

	if got := q2.Counts().Total; got != 2 {
		t.Fatalf("recovered Counts.Total = %d, want 2 (committed procs only)", got)
	}
	if _, ok := q2.Get(c1, 0); !ok {
		t.Error("committed job lost across reopen")
	}
	if _, ok := q2.Get(c2, 0); ok {
		t.Error("uncommitted staged job survived reopen")
	}
	// Cluster ids keep advancing (never reused) after recovery.
	txn2 := q2.Begin("alice")
	c3, err := txn2.NewCluster()
	if err != nil {
		t.Fatal(err)
	}
	if c3 <= c2 {
		t.Errorf("cluster id after recovery = %d, want > %d", c3, c2)
	}
	txn2.Abort()
}

// TestCounterMonotonicity: cluster ids strictly increase, across transactions,
// aborts, and reopens.
func TestCounterMonotonicity(t *testing.T) {
	dir := t.TempDir()
	q := openTestQueue(t, dir)

	var last int
	for i := 0; i < 5; i++ {
		txn := q.Begin("alice")
		c, err := txn.NewCluster()
		if err != nil {
			t.Fatal(err)
		}
		if c <= last {
			t.Fatalf("cluster id %d not > previous %d", c, last)
		}
		last = c
		if i%2 == 0 {
			txn.Abort() // aborts must not release the id
		} else {
			p, _ := txn.NewProc(c)
			_ = txn.SetAttribute(c, p, "Cmd", `"/bin/true"`)
			if err := txn.Commit(); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = q.Close()

	q2 := openTestQueue(t, dir)
	defer q2.Close()
	txn := q2.Begin("alice")
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatal(err)
	}
	if c <= last {
		t.Errorf("cluster id %d after reopen not > %d", c, last)
	}
	txn.Abort()
}

// TestHoldReleaseRemove: the JobStatus state machine plus history archiving.
func TestHoldReleaseRemove(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	c := submitCluster(t, q, "alice", 3)

	hold := ActionRequest{Kind: ActHold, Actor: "alice", Reason: "test hold"}
	if code := q.CheckAction(c, 0, hold); code != ArSuccess {
		t.Fatalf("CheckAction(hold) = %d", code)
	}
	if code := q.ApplyAction(c, 0, hold); code != ArSuccess {
		t.Fatalf("ApplyAction(hold) = %d", code)
	}
	ad, _ := q.Get(c, 0)
	if v, _ := ad.EvaluateAttrInt("JobStatus"); v != StatusHeld {
		t.Errorf("JobStatus after hold = %d, want 5", v)
	}
	if v, _ := ad.EvaluateAttrString("HoldReason"); v != "test hold" {
		t.Errorf("HoldReason = %q", v)
	}
	if v, _ := ad.EvaluateAttrInt("HoldReasonCode"); v != 1 {
		t.Errorf("HoldReasonCode = %d, want 1", v)
	}

	// Wrong-state release on an idle job.
	if code := q.ApplyAction(c, 1, ActionRequest{Kind: ActRelease, Actor: "alice"}); code != ArBadStatus {
		t.Errorf("release of idle job = %d, want ArBadStatus", code)
	}
	// Permission denied for another non-super user.
	if code := q.ApplyAction(c, 0, ActionRequest{Kind: ActRelease, Actor: "mallory"}); code != ArPermissionDenied {
		t.Errorf("release by mallory = %d, want ArPermissionDenied", code)
	}
	// Release the held job.
	if code := q.ApplyAction(c, 0, ActionRequest{Kind: ActRelease, Actor: "alice"}); code != ArSuccess {
		t.Errorf("release = %d, want success", code)
	}
	ad, _ = q.Get(c, 0)
	if v, _ := ad.EvaluateAttrInt("JobStatus"); v != StatusIdle {
		t.Errorf("JobStatus after release = %d, want 1", v)
	}
	if _, ok := ad.Lookup("HoldReason"); ok {
		t.Error("HoldReason survived release")
	}

	// Remove job 2: gone from live queue, present in history as Removed.
	if code := q.ApplyAction(c, 2, ActionRequest{Kind: ActRemove, Actor: "alice", Reason: "bye"}); code != ArSuccess {
		t.Fatalf("remove = %d, want success", code)
	}
	if _, ok := q.Get(c, 2); ok {
		t.Error("removed job still in live queue")
	}
	if got := q.Counts().Total; got != 2 {
		t.Errorf("Counts.Total after remove = %d, want 2", got)
	}
	vq, err := vm.Parse(fmt.Sprintf("ClusterId == %d && ProcId == 2", c))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for had := range q.hist.Query(vq) {
		found = true
		if v, _ := had.EvaluateAttrInt("JobStatus"); v != StatusRemoved {
			t.Errorf("history JobStatus = %d, want 3", v)
		}
		if v, _ := had.EvaluateAttrString("Cmd"); v != "/bin/sleep" {
			t.Errorf("history record not flattened: Cmd = %q", v)
		}
	}
	if !found {
		t.Error("removed job not found in history archive")
	}
}
