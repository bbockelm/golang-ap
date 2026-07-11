// rrl.go builds the schedd's resource-request list (RRL) for negotiation: the
// batched, priority-ordered stream of idle jobs the NEGOTIATE handler offers to
// the condor_negotiator. It is the pure-Go port of BuildPrioRecArray + the
// resource_request_list construction in schedd.cpp / schedd_negotiate.cpp.
//
// A maintained ordered index over the job collection (configured in Open, see
// idleOrderSpec) keeps idle jobs of each submitter in negotiator priority order --
// the PrioRec ordering. IdleRequestGroups iterates that index as a live cursor and
// run-length-folds consecutive jobs whose significant-attribute projection hashes
// equal into one group (one resource request with a count), exactly as the C++
// schedd collapses consecutive same-autocluster PrioRec entries.
package queue

import (
	"iter"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
)

// idleOrderedIndex is the position of the idle-job priority index in the
// collection's Options.Ordered slice (see Open). There is exactly one.
const idleOrderedIndex = 0

// idleOrderSpec is the maintained ordered index that reproduces the C++ schedd's
// PrioRec ordering for negotiation. Members are the idle jobs (JobStatus == 1),
// partitioned by submitter (the User attribute, which the negotiator names as the
// Submitter/Owner in its negotiation header), ordered within a submitter by the
// same keys as struct prio_compar in qmgmt.cpp:
//
//	PreJobPrio1 desc, PreJobPrio2 desc, JobPrio desc,
//	PostJobPrio1 desc, PostJobPrio2 desc, then ClusterId asc, ProcId asc.
//
// (Insertion sequence is the index's implicit final tiebreaker; ClusterId/ProcId
// already make the order total, matching the C++ cluster/proc tiebreak.) The RRL
// grouping checksum is computed at read time from the negotiator's significant
// attributes, so this index carries no cluster signature of its own.
func idleOrderSpec() collections.OrderSpec {
	return collections.OrderSpec{
		Partition: "User",
		Where:     "JobStatus == 1",
		Keys: []collections.SortKey{
			{Expr: "PreJobPrio1", Desc: true},
			{Expr: "PreJobPrio2", Desc: true},
			{Expr: "JobPrio", Desc: true},
			{Expr: "PostJobPrio1", Desc: true},
			{Expr: "PostJobPrio2", Desc: true},
			{Expr: "ClusterId", Desc: false},
			{Expr: "ProcId", Desc: false},
		},
	}
}

// JobID identifies a job (proc ad) by cluster and proc.
type JobID struct {
	Cluster, Proc int
}

// RequestGroup is one resource-request-list entry: a maximal run of consecutive
// idle jobs (in PrioRec order) whose significant-attribute projection hashes
// equal. Rep is the representative (first, highest-priority) job's flattened ad --
// the ad offered to the negotiator. JobIDs holds every job in the run in priority
// order, Rep's id first; its length is the ResourceRequestCount for the group.
type RequestGroup struct {
	Checksum uint64
	Rep      *classad.ClassAd
	JobIDs   []JobID
}

// IdleRequestGroups returns a lazy iterator over the RRL groups for one
// submitter, in negotiator priority order. projection is the set of significant
// attributes (the negotiator's AutoClusterAttrs plus the always-significant ones)
// whose combined per-job value defines a group: a group is a maximal run of
// consecutive idle jobs sharing a projection checksum.
//
// The iterator drives the maintained ordered index as a single open cursor over
// an O(1) snapshot taken when iteration begins; groups form lazily as the cursor
// advances, so the caller can pull one group per negotiator request without
// re-sorting or re-scanning. Because the snapshot is fixed at the start of the
// round, a job held or removed mid-round still appears in a group here; the
// NEGOTIATE handler re-verifies each job is still idle when it assigns a match, so
// such a job is skipped at match time.
func (q *Queue) IdleRequestGroups(submitter string, projection []string) iter.Seq[RequestGroup] {
	return func(yield func(RequestGroup) bool) {
		part := classad.NewStringValue(submitter)
		var cur RequestGroup
		have := false
		for oa := range q.coll.Ordered(idleOrderedIndex, part, collections.OrderCursor{}) {
			ad := oa.Ad
			c, okc := ad.EvaluateAttrInt("ClusterId")
			p, okp := ad.EvaluateAttrInt("ProcId")
			if !okc || !okp {
				continue
			}
			sum := collections.ProjectionChecksum(ad, projection)
			if have && sum == cur.Checksum {
				cur.JobIDs = append(cur.JobIDs, JobID{int(c), int(p)})
				continue
			}
			if have && !yield(cur) {
				return
			}
			cur = RequestGroup{Checksum: sum, Rep: ad, JobIDs: []JobID{{int(c), int(p)}}}
			have = true
		}
		if have {
			yield(cur)
		}
	}
}
