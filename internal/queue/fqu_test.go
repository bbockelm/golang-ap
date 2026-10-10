package queue

import (
	"regexp"
	"slices"
	"testing"
)

// Identities are compared as the whole user@domain (UID_DOMAIN example.net in
// these tests): QUEUE_SUPER_USERS entries, job ownership, the effective owner
// and the submitter name.

func TestFQUSuperUsers(t *testing.T) {
	q := openAuthzQueue(t, Options{SuperUsers: []string{"condor", "root", "admin@site.org"}})
	defer func() { _ = q.Close() }()
	cases := []struct {
		user  string
		super bool
	}{
		{"condor@example.net", true},
		{"condor@EXAMPLE.NET", true},
		{"condor", true}, // a name without a domain is in UID_DOMAIN
		{"condor@family", true},
		{"condor@parent", true},
		{"condor@child", true},
		{"root@example.net", true},
		{"admin@site.org", true},
		{"condor@otherdomain", false}, // e.g. an IDTOKEN from another trust domain
		{"condor@example.net.evil", false},
		{"condor@unmapped", false},
		{"Condor@example.net", false},
		{"root@family", false},
		{"admin@example.net", false},
		{"admin", false},
		{"alice@example.net", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := q.IsSuperUser(tc.user); got != tc.super {
			t.Errorf("IsSuperUser(%q) = %v, want %v", tc.user, got, tc.super)
		}
	}

	// condor_reconfig rebuilds the set the same way.
	q.SetAuthz(Options{SuperUsers: []string{"carol"}})
	if !q.IsSuperUser("carol@example.net") || q.IsSuperUser("carol@otherdomain") || q.IsSuperUser("condor@family") {
		t.Errorf("after SetAuthz: carol@example.net=%v carol@otherdomain=%v condor@family=%v, want true/false/false",
			q.IsSuperUser("carol@example.net"), q.IsSuperUser("carol@otherdomain"), q.IsSuperUser("condor@family"))
	}
}

// A non-super condor@<other domain> may not edit, destroy or act on another
// user's job; condor@UID_DOMAIN and condor@family may.
func TestFQUSuperUserWrites(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer func() { _ = q.Close() }()
	c := submitCluster(t, q, "alice@example.net", 1)

	impostor := q.Begin("condor@otherdomain")
	if err := impostor.SetAttribute(c, 0, "Foo", `"x"`); !isAuthzErr(err) {
		t.Errorf("condor@otherdomain SetAttribute: want AuthzError, got %v", err)
	}
	if err := impostor.DestroyProc(c, 0); !isAuthzErr(err) {
		t.Errorf("condor@otherdomain DestroyProc: want AuthzError, got %v", err)
	}
	if err := impostor.SetEffectiveOwner("bob"); err == nil {
		t.Error("condor@otherdomain SetEffectiveOwner(bob) succeeded, want error")
	}
	if got := q.CheckAction(c, 0, ActionRequest{Kind: ActHold, Actor: "condor@otherdomain"}); got != ArPermissionDenied {
		t.Errorf("condor@otherdomain hold: code %d, want ArPermissionDenied", got)
	}
	for _, user := range []string{"condor@example.net", "condor@family"} {
		if err := q.Begin(user).SetAttribute(c, 0, "Foo", `"x"`); err != nil {
			t.Errorf("%s SetAttribute: %v", user, err)
		}
		if got := q.CheckAction(c, 0, ActionRequest{Kind: ActHold, Actor: user}); got != ArSuccess {
			t.Errorf("%s hold: code %d, want ArSuccess", user, got)
		}
	}
}

// alice@example.net owns her jobs; alice@otherpool, whose jobs carry the same
// Owner, does not, and vice versa.
func TestFQUOwnership(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer func() { _ = q.Close() }()
	mine := submitCluster(t, q, "alice@example.net", 1)
	theirs := submitCluster(t, q, "alice@otherpool", 1)

	for c, want := range map[int][2]string{mine: {"alice", "alice@example.net"}, theirs: {"alice", "alice@otherpool"}} {
		ad, _ := q.Get(c, 0)
		owner, _ := ad.EvaluateAttrString("Owner")
		user, _ := ad.EvaluateAttrString("User")
		if owner != want[0] || user != want[1] {
			t.Errorf("job %d.0: Owner=%q User=%q, want %q %q", c, owner, user, want[0], want[1])
		}
	}

	for _, tc := range []struct {
		actor string
		c     int
		owns  bool
	}{
		{"alice@example.net", mine, true},
		{"alice@EXAMPLE.net", mine, true},
		{"alice", mine, true},
		{"alice@otherpool", mine, false},
		{"alice@otherpool", theirs, true},
		{"alice@example.net", theirs, false},
		{"alice", theirs, false},
	} {
		ad, _ := q.Get(tc.c, 0)
		if got := q.OwnsJobAd(tc.actor, ad); got != tc.owns {
			t.Errorf("OwnsJobAd(%s, %d.0) = %v, want %v", tc.actor, tc.c, got, tc.owns)
		}
		wantCode := ArPermissionDenied
		if tc.owns {
			wantCode = ArSuccess
		}
		if got := q.CheckAction(tc.c, 0, ActionRequest{Kind: ActHold, Actor: tc.actor}); got != wantCode {
			t.Errorf("CheckAction hold by %s on %d.0: code %d, want %d", tc.actor, tc.c, got, wantCode)
		}
		err := q.Begin(tc.actor).SetAttribute(tc.c, 0, "Foo", `"x"`)
		if tc.owns && err != nil {
			t.Errorf("%s SetAttribute on %d.0: %v", tc.actor, tc.c, err)
		}
		if !tc.owns && !isAuthzErr(err) {
			t.Errorf("%s SetAttribute on %d.0: want AuthzError, got %v", tc.actor, tc.c, err)
		}
	}
}

// An identity in the unmapped domain is not an account: its transaction is
// anonymous and cannot submit.
func TestFQUUnmappedIsAnonymous(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer func() { _ = q.Close() }()
	for _, user := range []string{"ssl@unmapped", "scitokens@unmapped", "alice@Unmapped"} {
		txn := q.Begin(user)
		if _, err := txn.NewCluster(); !isAuthzErr(err) {
			t.Errorf("%s NewCluster: want AuthzError, got %v", user, err)
		}
	}
	sup := q.Begin("condor@example.net")
	if err := sup.SetEffectiveOwner("ssl@unmapped"); err == nil {
		t.Error("superuser SetEffectiveOwner(ssl@unmapped) succeeded, want error")
	}
	if q.Counts().Total != 0 {
		t.Errorf("queue has %d jobs, want 0", q.Counts().Total)
	}
}

// SetEffectiveOwner naming the caller itself keeps the caller's full
// identity; a superuser's other owner without a domain is in UID_DOMAIN.
func TestFQUEffectiveOwner(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer func() { _ = q.Close() }()
	submitAs := func(txn *Txn) (owner, user string) {
		t.Helper()
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
		ad, _ := q.Get(c, 0)
		owner, _ = ad.EvaluateAttrString("Owner")
		user, _ = ad.EvaluateAttrString("User")
		return owner, user
	}

	txn := q.Begin("alice@otherpool")
	if err := txn.SetEffectiveOwner("alice@otherpool"); err != nil {
		t.Fatalf("self SetEffectiveOwner: %v", err)
	}
	if o, u := submitAs(txn); o != "alice" || u != "alice@otherpool" {
		t.Errorf("self-set alice@otherpool: Owner=%q User=%q, want alice alice@otherpool", o, u)
	}
	if err := q.Begin("alice@otherpool").SetEffectiveOwner("alice"); err == nil {
		t.Error("alice@otherpool SetEffectiveOwner(alice) succeeded; alice is alice@example.net")
	}

	txn = q.Begin("alice@example.net")
	if err := txn.SetEffectiveOwner("alice"); err != nil {
		t.Fatalf("bare self SetEffectiveOwner: %v", err)
	}
	if o, u := submitAs(txn); o != "alice" || u != "alice@example.net" {
		t.Errorf("self-set alice: Owner=%q User=%q, want alice alice@example.net", o, u)
	}

	submitJobs(t, q, "bob@example.net", 1, nil, nil)
	txn = q.Begin("condor@family")
	if err := txn.SetEffectiveOwner("bob"); err != nil {
		t.Fatalf("superuser SetEffectiveOwner(bob): %v", err)
	}
	if o, u := submitAs(txn); o != "bob" || u != "bob@example.net" {
		t.Errorf("superuser as bob: Owner=%q User=%q, want bob bob@example.net", o, u)
	}
}

// The submitter is the owner at ACCOUNTING_DOMAIN, whatever domain the job's
// User has, and negotiation finds a submitter's idle jobs by that name.
func TestFQUSubmitterName(t *testing.T) {
	q := openAuthzQueue(t, Options{AccountingDomain: "acct.example"})
	defer func() { _ = q.Close() }()
	submitJobs(t, q, "alice@example.net", 1, nil, nil)
	submitJobs(t, q, "alice@otherpool", 1, nil, nil)
	submitJobs(t, q, "bob@example.net", 2, nil, nil)

	got := map[string]SubmitterCount{}
	for _, sc := range q.SubmitterCounts() {
		got[sc.Name] = sc
	}
	if len(got) != 2 || got["alice@acct.example"].Idle != 2 || got["bob@acct.example"].Idle != 2 ||
		got["alice@acct.example"].Owner != "alice" {
		t.Fatalf("SubmitterCounts = %+v, want alice@acct.example and bob@acct.example with 2 idle each", got)
	}
	var users []string
	for g := range q.IdleRequestGroups("alice@acct.example", []string{"RequestMemory"}) {
		for _, id := range g.JobIDs {
			ad, _ := q.Get(id.Cluster, id.Proc)
			u, _ := ad.EvaluateAttrString("User")
			users = append(users, u)
		}
	}
	slices.Sort(users)
	if want := []string{"alice@example.net", "alice@otherpool"}; !slices.Equal(users, want) {
		t.Errorf("IdleRequestGroups(alice@acct.example) users = %v, want %v", users, want)
	}
	if n := len(q.IdleJobsForSubmitter("bob@acct.example")); n != 2 {
		t.Errorf("IdleJobsForSubmitter(bob@acct.example) = %d jobs, want 2", n)
	}

	// Without ACCOUNTING_DOMAIN the submitter is in UID_DOMAIN.
	q2 := openTestQueue(t, t.TempDir())
	defer func() { _ = q2.Close() }()
	submitJobs(t, q2, "carol@otherpool", 1, nil, nil)
	if scs := q2.SubmitterCounts(); len(scs) != 1 || scs[0].Name != "carol@example.net" {
		t.Errorf("SubmitterCounts = %+v, want carol@example.net", scs)
	}
}

// A super user may submit as a user the schedd knows -- one with a job in the
// queue or the history -- and as no other, unless
// QUEUE_SUPER_USER_MAY_IMPERSONATE is set, when the user name must match it
// instead (SuperUserAllowedToSetOwnerTo, qmgmt.cpp). No one submits as root
// or LOCAL_SYSTEM.
func TestSuperUserImpersonation(t *testing.T) {
	q := openAuthzQueue(t, Options{})
	defer func() { _ = q.Close() }()
	impersonate := func(owner string) error {
		return q.Begin("condor@family").SetEffectiveOwner(owner)
	}

	for _, owner := range []string{"carol", "carol@example.net", "dave"} {
		if err := impersonate(owner); err == nil {
			t.Errorf("SetEffectiveOwner(%s) with no jobs succeeded, want refused", owner)
		}
	}
	submitJobs(t, q, "carol@example.net", 1, nil, nil)
	done := submitJobs(t, q, "dave@example.net", 1, nil, nil)
	q.Complete(done, 0)
	if _, ok := q.Get(done, 0); ok {
		t.Fatalf("job %d.0 still in the queue after Complete", done)
	}
	for _, owner := range []string{"carol", "carol@example.net", "carol@EXAMPLE.NET", "dave"} {
		if err := impersonate(owner); err != nil {
			t.Errorf("SetEffectiveOwner(%s): %v", owner, err)
		}
	}
	for _, owner := range []string{"Carol", "carol@otherpool", "erin", "root", "LOCAL_SYSTEM"} {
		if err := impersonate(owner); err == nil {
			t.Errorf("SetEffectiveOwner(%s) succeeded, want refused", owner)
		}
	}
	if err := q.Begin("carol@example.net").SetEffectiveOwner("dave"); err == nil {
		t.Error("non-super user SetEffectiveOwner(dave) succeeded, want refused")
	}

	q.SetAuthz(Options{SuperUsers: []string{"condor"}, MayImpersonate: regexp.MustCompile(`^svc_|^root$|^LOCAL_SYSTEM$`)})
	for _, owner := range []string{"svc_erin", "svc_erin@example.net"} {
		if err := impersonate(owner); err != nil {
			t.Errorf("SetEffectiveOwner(%s) under QUEUE_SUPER_USER_MAY_IMPERSONATE: %v", owner, err)
		}
	}
	for _, owner := range []string{"carol", "erin", "root", "LOCAL_SYSTEM"} {
		if err := impersonate(owner); err == nil {
			t.Errorf("SetEffectiveOwner(%s) under QUEUE_SUPER_USER_MAY_IMPERSONATE succeeded, want refused", owner)
		}
	}

	txn := q.Begin("condor@family")
	if err := txn.SetEffectiveOwner("svc_erin"); err != nil {
		t.Fatal(err)
	}
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
	ad, _ := q.Get(c, 0)
	if u, _ := ad.EvaluateAttrString("User"); u != "svc_erin@example.net" {
		t.Errorf("impersonated job User = %q, want svc_erin@example.net", u)
	}
}
