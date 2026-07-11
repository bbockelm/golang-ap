package queue

import (
	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// Spool-support helpers for the SPOOL_JOB_FILES / TRANSFER_DATA command handlers
// (internal/spool). Kept in their own file so the spool feature touches the queue
// package only through this additive surface (the core queue.go / actions.go /
// txn.go remain owned elsewhere). These wrap the unexported owner short-naming
// and the history archive, which the out-of-package spool handler cannot reach.

// OwnsJobAd reports whether authUser may spool for / retrieve the sandbox of the
// job described by ad: either a queue super user, or the ad's short Owner name
// matches the authenticated user's short name. Mirrors UserCheck2 in the C++
// schedd's spoolJobFiles path.
func (q *Queue) OwnsJobAd(authUser string, ad *classad.ClassAd) bool {
	if ad == nil {
		return false
	}
	if q.IsSuperUser(authUser) {
		return true
	}
	owner, _ := ad.EvaluateAttrString("Owner")
	return owner != "" && owner == shortName(authUser)
}

// SpoolQuery returns the flattened proc ads matching the ClassAd constraint
// expression from BOTH the live queue and the history archive, deduplicated by
// cluster.proc (live wins). condor_transfer_data (TRANSFER_DATA) uses it: a
// -spool job is retrievable both while it sits in the queue and after it has
// completed and been archived (its output sandbox persists on disk in $(SPOOL)
// regardless of where the ad now lives).
func (q *Queue) SpoolQuery(constraint string) ([]*classad.ClassAd, error) {
	query, err := vm.Parse(constraint)
	if err != nil {
		return nil, err
	}
	seen := map[[2]int]bool{}
	var out []*classad.ClassAd
	add := func(ad *classad.ClassAd) {
		c, p, ok := jobIDs(ad)
		if !ok {
			return
		}
		key := [2]int{c, p}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ad)
	}
	for ad := range q.coll.Query(query) {
		add(ad)
	}
	for ad := range q.hist.Query(query) {
		add(ad)
	}
	return out, nil
}
