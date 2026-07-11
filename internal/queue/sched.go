package queue

import (
	"github.com/PelicanPlatform/classad/classad"
)

// SubmitterCount holds one submitter's live job tallies for the Submitter ad the
// schedd advertises so the negotiator will negotiate for it.
type SubmitterCount struct {
	// Name is the fully-qualified submitter identity (the queue's User attribute,
	// e.g. "alice@example.com"); it is the ATTR_NAME the negotiator keys on.
	Name string
	// Owner is the bare owner short name (for the negotiator's owner match).
	Owner         string
	Idle, Running int
	Held, Removed int
	Total         int
}

// SubmitterCounts scans the live queue and tallies jobs per submitter (keyed by
// the User attribute, falling back to Owner when User is unset). The schedd
// advertises one Submitter ad per returned entry.
func (q *Queue) SubmitterCounts() []SubmitterCount {
	byName := map[string]*SubmitterCount{}
	for ad := range q.coll.Scan() {
		name, _ := ad.EvaluateAttrString("User")
		owner, _ := ad.EvaluateAttrString("Owner")
		if name == "" {
			if owner != "" && q.domain != "" {
				name = owner + "@" + q.domain
			} else {
				name = owner
			}
		}
		if name == "" {
			continue
		}
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
// the given submitter (matched by User == submitter, or by short Owner name as a
// fallback). The negotiate handler turns these into resource-request job ads.
func (q *Queue) IdleJobsForSubmitter(submitter string) []*classad.ClassAd {
	short := shortName(submitter)
	var out []*classad.ClassAd
	for ad := range q.coll.Scan() {
		st, _ := ad.EvaluateAttrInt("JobStatus")
		if int(st) != StatusIdle {
			continue
		}
		user, _ := ad.EvaluateAttrString("User")
		owner, _ := ad.EvaluateAttrString("Owner")
		if user == submitter || owner == short || owner == submitter {
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
