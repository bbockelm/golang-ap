package queue

import (
	"errors"
	"testing"
)

// openAuthzQueue opens a queue with custom authorization options for the
// protected/secure/all-trusted tests.
func openAuthzQueue(t *testing.T, opts Options) *Queue {
	t.Helper()
	opts.Dir = t.TempDir()
	opts.ScheddName = "testschedd"
	opts.UIDDomain = "example.net"
	if opts.SuperUsers == nil {
		opts.SuperUsers = []string{"condor", "root"}
	}
	q, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return q
}

func isAuthzErr(err error) bool {
	return errors.As(err, new(*AuthzError))
}

// A non-owner may not change attributes on a committed job they do not own.
func TestAuthzCrossOwnerSetDenied(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	bob := q.Begin("bob")
	err := bob.SetAttribute(c, 0, "Foo", `"bar"`)
	if !isAuthzErr(err) {
		t.Fatalf("bob editing alice's job: want AuthzError, got %v", err)
	}
	// Cluster-level edit is likewise denied.
	if err := bob.SetAttribute(c, -1, "Foo", `"bar"`); !isAuthzErr(err) {
		t.Fatalf("bob editing alice's cluster ad: want AuthzError, got %v", err)
	}
	// Delete is denied too.
	if err := bob.DeleteAttribute(c, 0, "Args"); !isAuthzErr(err) {
		t.Fatalf("bob deleting attr on alice's job: want AuthzError, got %v", err)
	}
}

// The owner may freely edit a non-protected, non-immutable attr on their own
// committed job (the condor_qedit happy path).
func TestAuthzOwnerEditOwnJobAllowed(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	txn := q.Begin("alice")
	if err := txn.SetAttribute(c, 0, "Foo", `"bar"`); err != nil {
		t.Fatalf("alice editing her own job: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	ad, ok := q.Get(c, 0)
	if !ok {
		t.Fatal("job vanished")
	}
	if v, _ := ad.EvaluateAttrString("Foo"); v != "bar" {
		t.Fatalf("Foo = %q, want bar", v)
	}
}

// Immutable attributes may not be changed on a committed job -- not by the owner,
// nor by a superuser.
func TestAuthzImmutableDenied(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	for _, attr := range []string{"Owner", "ClusterId", "ProcId", "User", "MyType", "AccountingGroup"} {
		if err := q.Begin("alice").SetAttribute(c, 0, attr, `"x"`); !isAuthzErr(err) {
			t.Fatalf("owner setting immutable %s: want AuthzError, got %v", attr, err)
		}
		// Even a superuser cannot edit an immutable attr on a committed job.
		if err := q.Begin("condor").SetAttribute(c, 0, attr, `"x"`); !isAuthzErr(err) {
			t.Fatalf("superuser setting immutable %s: want AuthzError, got %v", attr, err)
		}
		// Nor delete it.
		if err := q.Begin("alice").DeleteAttribute(c, 0, attr); !isAuthzErr(err) {
			t.Fatalf("owner deleting immutable %s: want AuthzError, got %v", attr, err)
		}
	}
}

// A superuser may edit another user's (non-immutable) job attribute.
func TestAuthzSuperuserCrossOwnerAllowed(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	txn := q.Begin("condor") // a QUEUE_SUPER_USER
	if err := txn.SetAttribute(c, 0, "Foo", `"bar"`); err != nil {
		t.Fatalf("superuser editing alice's job: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// Protected attributes are settable on a committed job only by a superuser (or
// all-trusted) that has enabled SetAllowProtectedAttrChanges.
func TestAuthzProtected(t *testing.T) {
	q := openAuthzQueue(t, Options{ProtectedAttrs: []string{"ProtMe"}})
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	// Owner (non-super) is always denied a protected attr.
	if err := q.Begin("alice").SetAttribute(c, 0, "ProtMe", `"x"`); !isAuthzErr(err) {
		t.Fatalf("owner setting protected attr: want AuthzError, got %v", err)
	}
	// Superuser WITHOUT the allow flag is denied.
	if err := q.Begin("condor").SetAttribute(c, 0, "ProtMe", `"x"`); !isAuthzErr(err) {
		t.Fatalf("superuser (no allow flag) setting protected attr: want AuthzError, got %v", err)
	}
	// Superuser WITH the allow flag is permitted.
	txn := q.Begin("condor")
	txn.SetAllowProtectedChanges(true)
	if err := txn.SetAttribute(c, 0, "ProtMe", `"x"`); err != nil {
		t.Fatalf("superuser (allow flag) setting protected attr: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// Secure attributes from a client are silently ignored by default, or rejected
// when IGNORE_ATTEMPTS_TO_SET_SECURE_JOB_ATTRS is false.
func TestAuthzSecure(t *testing.T) {
	// Default: ignore quietly. SetAttribute returns nil but does not stage.
	q := openAuthzQueue(t, Options{IgnoreSecureAttrs: true})
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)
	txn := q.Begin("alice")
	if err := txn.SetAttribute(c, 0, "AuthTokenSubject", `"attacker@evil"`); err != nil {
		t.Fatalf("secure-attr set (ignore mode) should return nil, got %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if ad, ok := q.Get(c, 0); ok {
		if _, present := ad.Lookup("AuthTokenSubject"); present {
			t.Fatal("secure attr was staged despite ignore mode")
		}
	}

	// Reject mode.
	q2 := openAuthzQueue(t, Options{IgnoreSecureAttrs: false})
	defer q2.Close()
	c2 := submitCluster(t, q2, "alice", 1)
	if err := q2.Begin("alice").SetAttribute(c2, 0, "AuthTokenSubject", `"x"`); !isAuthzErr(err) {
		t.Fatalf("secure-attr set (reject mode): want AuthzError, got %v", err)
	}
}

// Ads still being built in the transaction are exempt from the ownership /
// immutable checks (they are pinned by materialize at commit) -- otherwise normal
// submit could not set Owner-adjacent attrs on new jobs.
func TestAuthzNewInTxnExempt(t *testing.T) {
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
	// Setting what would be an immutable attr on a not-yet-committed job is
	// allowed at stage time; materialize forces the real identity at commit.
	if err := txn.SetAttribute(c, p, "Owner", `"someoneelse"`); err != nil {
		t.Fatalf("staging Owner on a new job should be allowed, got %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	ad, ok := q.Get(c, p)
	if !ok {
		t.Fatal("job vanished")
	}
	if o, _ := ad.EvaluateAttrString("Owner"); o != "alice" {
		t.Fatalf("committed Owner = %q, want alice (materialize must force it)", o)
	}
}

// condor_rm/hold/release (ACT_ON_JOBS) may not touch another user's job, but a
// superuser and the schedd's own System-initiated actions may.
func TestAuthzActionOwnership(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	// Bob cannot hold alice's job.
	if got := q.CheckAction(c, 0, ActionRequest{Kind: ActHold, Actor: "bob"}); got != ArPermissionDenied {
		t.Fatalf("bob holding alice's job: got %d, want ArPermissionDenied(%d)", got, ArPermissionDenied)
	}
	// Bob cannot rm alice's job.
	if got := q.CheckAction(c, 0, ActionRequest{Kind: ActRemove, Actor: "bob"}); got != ArPermissionDenied {
		t.Fatalf("bob removing alice's job: got %d, want ArPermissionDenied", got)
	}
	// Alice can hold her own job.
	if got := q.CheckAction(c, 0, ActionRequest{Kind: ActHold, Actor: "alice"}); got != ArSuccess {
		t.Fatalf("alice holding her own job: got %d, want ArSuccess", got)
	}
	// A superuser can act on it.
	if got := q.CheckAction(c, 0, ActionRequest{Kind: ActHold, Actor: "condor"}); got != ArSuccess {
		t.Fatalf("superuser holding alice's job: got %d, want ArSuccess", got)
	}
	// A schedd System action (policy firing) bypasses the owner check.
	if got := q.CheckAction(c, 0, ActionRequest{Kind: ActHold, Actor: "", System: true}); got != ArSuccess {
		t.Fatalf("system hold: got %d, want ArSuccess", got)
	}
}

// QUEUE_ALL_USERS_TRUSTED bypasses the ownership + protected checks, but immutable
// attrs stay immutable.
func TestAuthzAllUsersTrusted(t *testing.T) {
	q := openAuthzQueue(t, Options{AllUsersTrusted: true, ProtectedAttrs: []string{"ProtMe"}})
	defer q.Close()
	c := submitCluster(t, q, "alice", 1)

	// Cross-owner edit now allowed.
	if err := q.Begin("bob").SetAttribute(c, 0, "Foo", `"bar"`); err != nil {
		t.Fatalf("all-trusted cross-owner edit: %v", err)
	}
	// Immutable still denied.
	if err := q.Begin("bob").SetAttribute(c, 0, "Owner", `"bob"`); !isAuthzErr(err) {
		t.Fatalf("all-trusted immutable edit: want AuthzError, got %v", err)
	}
}
