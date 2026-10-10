package queue

import (
	"github.com/PelicanPlatform/classad/classad"
)

// SubmitterCount holds one submitter's live job tallies for the Submitter ad the
// schedd advertises so the negotiator will negotiate for it.
type SubmitterCount struct {
	// Name is the submitter name the negotiator keys on: the owner at the
	// ACCOUNTING_DOMAIN (e.g. "alice@example.com").
	Name string
	// Owner is the bare owner name the submitter's jobs carry.
	Owner         string
	Idle, Running int
	Held, Removed int
	Total         int
}

// jobOwner returns the bare owner name a job is negotiated under: its Owner,
// or the user part of its User. The C++ schedd takes the submitter from the
// user part of the job's User (get_submitter_and_owner, schedd.cpp
// ~5217-5233), which is what Begin stores as Owner.
func (q *Queue) jobOwner(ad *classad.ClassAd) string {
	if o, ok := ad.EvaluateAttrString("Owner"); ok && o != "" {
		return o
	}
	return shortName(q.JobUser(ad))
}

// submitterName returns the submitter name advertised for owner:
// owner@ACCOUNTING_DOMAIN, as the C++ schedd names its Submitter ads
// (schedd.cpp ~1593-1596; ACCOUNTING_DOMAIN defaults to $(UID_DOMAIN) in
// param_info.in). Jobs of alice@pool and alice@otherpool are both alice's
// submitter, as in C++. With neither domain configured it is the bare owner.
func (q *Queue) submitterName(owner string) string {
	if q.acctDomain == "" {
		return owner
	}
	return owner + "@" + q.acctDomain
}

// SubmitterCounts scans the live queue and tallies jobs per submitter (see
// submitterName). The schedd advertises one Submitter ad per returned entry.
func (q *Queue) SubmitterCounts() []SubmitterCount {
	byName := map[string]*SubmitterCount{}
	for ad := range q.coll.Scan() {
		owner := q.jobOwner(ad)
		if owner == "" {
			continue
		}
		name := q.submitterName(owner)
		sc := byName[name]
		if sc == nil {
			sc = &SubmitterCount{Name: name, Owner: owner}
			byName[name] = sc
		}
		sc.Total++
		st, _ := ad.EvaluateAttrInt("JobStatus")
		switch int(st) {
		case StatusIdle:
			sc.Idle++
		case StatusRunning:
			sc.Running++
		case StatusHeld:
			sc.Held++
		case StatusRemoved:
			sc.Removed++
		}
	}
	out := make([]SubmitterCount, 0, len(byName))
	for _, sc := range byName {
		out = append(out, *sc)
	}
	return out
}

// IdleJobsForSubmitter returns the flattened proc ads that are Idle and belong to
// the given submitter: the jobs whose owner is the submitter name's user part.
// The C++ schedd likewise truncates the negotiator's submitter at its last '@'
// before looking it up (schedd.cpp ~9534-9541).
func (q *Queue) IdleJobsForSubmitter(submitter string) []*classad.ClassAd {
	owner := shortName(submitter)
	var out []*classad.ClassAd
	for ad := range q.coll.Scan() {
		st, _ := ad.EvaluateAttrInt("JobStatus")
		if int(st) != StatusIdle {
			continue
		}
		if q.jobOwner(ad) == owner {
			out = append(out, ad)
		}
	}
	return out
}

// Modify applies fn to the flattened ad of job c.p and writes it back atomically.
// It is the scheduler core's single-writer path for the running/terminal attribute
// updates a job accrues as it is claimed, activated, and reaped. Returns false if
// the job no longer exists (e.g. it was removed while running).
func (q *Queue) Modify(c, p int, fn func(ad *classad.ClassAd)) bool {
	ad, ok := q.Get(c, p)
	if !ok {
		return false
	}
	fn(ad)
	if err := q.coll.Put(jobKey(c, p), ad); err != nil {
		return false
	}
	return true
}

// JobStatus returns the current JobStatus of c.p (0 if the job is gone).
func (q *Queue) JobStatus(c, p int) int {
	ad, ok := q.Get(c, p)
	if !ok {
		return 0
	}
	st, _ := ad.EvaluateAttrInt("JobStatus")
	return int(st)
}

// SetOnVacateRunning registers a hook the queue invokes when a running job is
// removed (condor_rm) or held (condor_hold), so the scheduler core can tear
// down the job's live shadow and release its claim before the job's status is
// rewritten (and, for remove, before it leaves the queue). The hook should
// block until the teardown completes or a short timeout elapses.
func (q *Queue) SetOnVacateRunning(fn func(c, p int)) {
	q.onVacateRunning = fn
}
