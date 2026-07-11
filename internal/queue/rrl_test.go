package queue

import (
	"fmt"
	"iter"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// submitJobs commits a cluster of len(mems) procs for owner. procAttrs[i] is
// applied to proc i (attribute name -> ClassAd literal); clusterAttrs is applied
// to the shared cluster ad. Returns the cluster id.
func submitJobs(t *testing.T, q *Queue, owner string, nProcs int, clusterAttrs map[string]string, procAttrs func(p int) map[string]string) int {
	t.Helper()
	txn := q.Begin(owner)
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatalf("NewCluster: %v", err)
	}
	if err := txn.SetAttribute(c, -1, "Cmd", `"/bin/sleep"`); err != nil {
		t.Fatalf("SetAttribute cluster Cmd: %v", err)
	}
	for name, lit := range clusterAttrs {
		if err := txn.SetAttribute(c, -1, name, lit); err != nil {
			t.Fatalf("SetAttribute cluster %s: %v", name, err)
		}
	}
	for i := 0; i < nProcs; i++ {
		p, err := txn.NewProc(c)
		if err != nil {
			t.Fatalf("NewProc: %v", err)
		}
		if procAttrs != nil {
			for name, lit := range procAttrs(p) {
				if err := txn.SetAttribute(c, p, name, lit); err != nil {
					t.Fatalf("SetAttribute proc %d %s: %v", p, name, err)
				}
			}
		}
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return c
}

func collectGroups(seq iter.Seq[RequestGroup]) []RequestGroup {
	var out []RequestGroup
	for g := range seq {
		out = append(out, g)
	}
	return out
}

// TestRRLGroupingRuns verifies that consecutive idle jobs sharing a projection
// checksum fold into one group, and that a non-adjacent repeat of an earlier
// projection starts a NEW run (run-length, not global dedup).
func TestRRLGroupingRuns(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	// One cluster, 7 procs. RequestMemory: 128,128,128,128,256,128,128.
	// In proc order that is runs of 4, 1, 2.
	mems := []int{128, 128, 128, 128, 256, 128, 128}
	submitJobs(t, q, "alice", len(mems), nil, func(p int) map[string]string {
		return map[string]string{"RequestMemory": fmt.Sprintf("%d", mems[p])}
	})

	groups := collectGroups(q.IdleRequestGroups("alice@example.net", []string{"RequestMemory"}))
	var sizes []int
	for _, g := range groups {
		sizes = append(sizes, len(g.JobIDs))
	}
	want := []int{4, 1, 2}
	if fmt.Sprint(sizes) != fmt.Sprint(want) {
		t.Fatalf("group sizes = %v, want %v", sizes, want)
	}
	// Groups on the same projection value (the first and third) must share a checksum.
	if groups[0].Checksum != groups[2].Checksum {
		t.Errorf("runs with equal projection have different checksums: %d vs %d", groups[0].Checksum, groups[2].Checksum)
	}
	if groups[0].Checksum == groups[1].Checksum {
		t.Errorf("runs with different projection share a checksum")
	}
	// The representative is the first job of the run, in proc order.
	if repC, _ := groups[0].Rep.EvaluateAttrInt("ProcId"); repC != 0 {
		t.Errorf("first run representative should be proc 0, got %d", repC)
	}
	if groups[1].JobIDs[0].Proc != 4 {
		t.Errorf("second run should start at proc 4, got %d", groups[1].JobIDs[0].Proc)
	}
}

// TestRRLPriorityOrdering verifies the cursor yields jobs in PrioRec order:
// higher JobPrio first, regardless of submission (cluster id) order.
func TestRRLPriorityOrdering(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	// Submit the low-priority cluster first (it gets the smaller cluster id).
	low := submitJobs(t, q, "bob", 2, map[string]string{"JobPrio": "5"}, nil)
	high := submitJobs(t, q, "bob", 2, map[string]string{"JobPrio": "10"}, nil)
	if !(low < high) {
		t.Fatalf("expected low cluster id %d < high %d", low, high)
	}

	// Project on JobPrio so each cluster is its own group; the higher-priority
	// cluster must come first even though it has the larger cluster id.
	groups := collectGroups(q.IdleRequestGroups("bob@example.net", []string{"JobPrio"}))
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	if groups[0].JobIDs[0].Cluster != high {
		t.Errorf("first group cluster = %d, want the high-prio cluster %d", groups[0].JobIDs[0].Cluster, high)
	}
	// Within a group, jobs are in proc order.
	if groups[0].JobIDs[0].Proc != 0 || groups[0].JobIDs[1].Proc != 1 {
		t.Errorf("intra-group order wrong: %+v", groups[0].JobIDs)
	}
}

// TestRRLCursorSnapshotStable verifies the open cursor iterates a stable snapshot:
// a job held after iteration begins still appears in a not-yet-yielded group,
// because the cursor pins the snapshot taken when iteration started. (Mid-round
// churn is handled at match time by the NEGOTIATE handler, not in the cursor.)
func TestRRLCursorSnapshotStable(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	// Two groups: clusterA (mem 128) then clusterB (mem 256), two procs each.
	submitJobs(t, q, "carol", 2, map[string]string{"RequestMemory": "128"}, nil)
	clusterB := submitJobs(t, q, "carol", 2, map[string]string{"RequestMemory": "256"}, nil)

	next, stop := iter.Pull(q.IdleRequestGroups("carol@example.net", []string{"RequestMemory"}))
	defer stop()

	g1, ok := next() // pins the snapshot
	if !ok || len(g1.JobIDs) != 2 {
		t.Fatalf("first group: ok=%v size=%d, want ok=true size=2", ok, len(g1.JobIDs))
	}

	// Now hold both procs of clusterB. A fresh iteration would drop them from the
	// idle index; the open cursor's snapshot predates the change, so group two must
	// still surface both jobs.
	for p := 0; p < 2; p++ {
		if !q.Modify(clusterB, p, func(ad *classad.ClassAd) { _ = ad.Set("JobStatus", int64(StatusHeld)) }) {
			t.Fatalf("holding %d.%d failed", clusterB, p)
		}
	}

	g2, ok := next()
	if !ok || len(g2.JobIDs) != 2 {
		t.Fatalf("second group after hold: ok=%v size=%d, want ok=true size=2 (snapshot stable)", ok, len(g2.JobIDs))
	}

	// A fresh iteration, by contrast, sees only the still-idle clusterA group.
	fresh := collectGroups(q.IdleRequestGroups("carol@example.net", []string{"RequestMemory"}))
	if len(fresh) != 1 || len(fresh[0].JobIDs) != 2 {
		t.Fatalf("fresh iteration after hold = %d groups, want 1 (held jobs dropped)", len(fresh))
	}
}

// TestRRLChecksumStable verifies a group's checksum is identical across repeated
// iterations of an unchanged queue.
func TestRRLChecksumStable(t *testing.T) {
	q := openTestQueue(t, t.TempDir())
	defer q.Close()

	submitJobs(t, q, "dave", 3, nil, func(p int) map[string]string {
		return map[string]string{"RequestMemory": "512", "RequestCpus": "1"}
	})

	proj := []string{"RequestCpus", "RequestMemory", "Requirements"}
	first := collectGroups(q.IdleRequestGroups("dave@example.net", proj))
	if len(first) != 1 || len(first[0].JobIDs) != 3 {
		t.Fatalf("unexpected first grouping: %d groups", len(first))
	}
	for i := 0; i < 20; i++ {
		g := collectGroups(q.IdleRequestGroups("dave@example.net", proj))
		if len(g) != 1 || g[0].Checksum != first[0].Checksum {
			t.Fatalf("checksum unstable across iterations")
		}
	}
}
