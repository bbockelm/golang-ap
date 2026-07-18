package negotiate

import (
	"fmt"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-ap/internal/queue"
)

func TestBuildProjection(t *testing.T) {
	header := classad.New()
	_ = header.Set("AutoClusterAttrs", "RequestMemory, DiskUsage,RequestCpus")
	got := buildProjection(header)
	// Negotiator attrs first (order-preserving, trimmed), then the always-significant
	// set, de-duplicated (RequestMemory/RequestCpus already present are not repeated).
	want := []string{
		"RequestMemory", "DiskUsage", "RequestCpus",
		"Requirements", "Rank", "ConcurrencyLimits", "RequestDisk",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("buildProjection = %v, want %v", got, want)
	}
}

func TestBuildProjectionNoHeaderAttrs(t *testing.T) {
	got := buildProjection(classad.New())
	want := []string{"Requirements", "Rank", "ConcurrencyLimits", "RequestCpus", "RequestMemory", "RequestDisk"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("buildProjection (empty) = %v, want %v", got, want)
	}
}

func TestParseRejectRep(t *testing.T) {
	rep, ok := parseRejectRep("no match found |987|12.3|")
	if !ok || rep != (queue.JobID{Cluster: 12, Proc: 3}) {
		t.Fatalf("parseRejectRep = %+v ok=%v, want {12 3} true", rep, ok)
	}
	if _, ok := parseRejectRep("plain reason with no suffix"); ok {
		t.Fatalf("parseRejectRep should fail on a reason without the |ac|c.p| suffix")
	}
}

// TestGroupStateNextIdleSkipsNonIdle verifies a batched group assigns matches to
// successive still-idle jobs, skipping any member that left Idle (held/removed)
// since the round began, and stops once the group is exhausted or rejected.
func TestGroupStateNextIdleSkipsNonIdle(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(queue.Options{Dir: dir, ScheddName: "s", UIDDomain: "example.net"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = q.Close() }()

	txn := q.Begin("alice")
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := txn.NewProc(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := txn.Commit(); err != nil {
		t.Fatal(err)
	}

	// Hold proc 1 so it is no longer Idle.
	if !q.Modify(c, 1, func(ad *classad.ClassAd) { _ = ad.Set("JobStatus", int64(queue.StatusHeld)) }) {
		t.Fatal("hold failed")
	}

	gs := &groupState{
		rep: queue.JobID{Cluster: c, Proc: 0},
		ids: []queue.JobID{{Cluster: c, Proc: 0}, {Cluster: c, Proc: 1}, {Cluster: c, Proc: 2}},
	}

	got1, ok := gs.nextIdle(q)
	if !ok || got1 != (queue.JobID{Cluster: c, Proc: 0}) {
		t.Fatalf("first nextIdle = %+v ok=%v, want {%d 0} true", got1, ok, c)
	}
	got2, ok := gs.nextIdle(q) // must skip held proc 1
	if !ok || got2 != (queue.JobID{Cluster: c, Proc: 2}) {
		t.Fatalf("second nextIdle = %+v ok=%v, want {%d 2} true (skipping held proc 1)", got2, ok, c)
	}
	if _, ok := gs.nextIdle(q); ok {
		t.Fatalf("third nextIdle should report the group exhausted")
	}

	// A rejected group yields nothing regardless of remaining idle jobs.
	gs2 := &groupState{ids: []queue.JobID{{Cluster: c, Proc: 0}}, rejected: true}
	if _, ok := gs2.nextIdle(q); ok {
		t.Fatalf("rejected group should yield no jobs")
	}
}
