package queue

import (
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
)

// Txn is a per-QMGMT-connection transaction: an overlay of staged edits layered
// over committed state. Reads within the transaction see staged state; Commit
// validates, materializes forced attributes, and applies one atomic batch;
// Abort discards. Only one active cluster may receive NewProc, matching
// qmgmt.cpp's active_cluster_num restriction. A Txn is used from a single
// connection goroutine and needs no internal locking.
type Txn struct {
	q        *Queue
	authUser string
	owner    string // effective short owner name
	user     string // owner@domain
	isSuper  bool

	active    int                         // active cluster for NewProc, or -1
	pending   map[string]*classad.ClassAd // key -> staged ad (own attrs only)
	nextProc  map[int]int                 // cluster -> next proc id in this txn
	delAttrs  map[string]map[string]bool  // key -> deleted attr names
	destroyed map[string]bool             // keys destroyed in this txn
	newProcs  map[string]bool             // proc keys created via NewProc (get a SUBMIT event)
	errs      []string                    // deferred (NoAck) errors
}

// AddError records a deferred error (e.g. from a NoAck SetAttribute) that will
// fail the commit.
func (t *Txn) AddError(msg string) { t.errs = append(t.errs, msg) }

// SetEffectiveOwner changes the owner for jobs created in this transaction. Only
// honored for super users (non-supers are pinned to their authenticated user),
// matching QmgmtSetEffectiveOwner.
func (t *Txn) SetEffectiveOwner(owner string) error {
	if owner == "" {
		return nil
	}
	if !t.isSuper && shortName(owner) != t.owner {
		return fmt.Errorf("user %q may not set effective owner to %q", t.authUser, owner)
	}
	t.owner = shortName(owner)
	if t.q.domain != "" {
		t.user = t.owner + "@" + t.q.domain
	} else {
		t.user = owner
	}
	return nil
}

// NewCluster allocates a new cluster id, makes it the active cluster, and stages
// its (initially empty) cluster ad.
func (t *Txn) NewCluster() (int, error) {
	id, err := t.q.allocClusterID()
	if err != nil {
		return -1, err
	}
	t.active = id
	t.nextProc[id] = 0
	t.stagedAd(clusterKeyStr(id))
	return id, nil
}

// NewProc allocates the next proc id in the active cluster and stages its ad.
func (t *Txn) NewProc(cluster int) (int, error) {
	if cluster != t.active {
		return -1, fmt.Errorf("NewProc for cluster %d but active cluster is %d", cluster, t.active)
	}
	p := t.nextProc[cluster]
	t.nextProc[cluster] = p + 1
	t.stagedAd(string(jobKey(cluster, p)))
	t.newProcs[string(jobKey(cluster, p))] = true
	return p, nil
}

// SetAttribute stages attr=value (value is a ClassAd expression) on job c.p, or
// on the cluster ad when p == -1.
func (t *Txn) SetAttribute(c, p int, name, value string) error {
	if value == "" {
		return fmt.Errorf("empty value for attribute %s", name)
	}
	ad := t.stagedAd(string(jobKey(c, p)))
	expr, err := classad.ParseExpr(value)
	if err != nil {
		// Fall back to treating the value as a string literal so a malformed
		// expression does not desync the stream; record it but keep going.
		if serr := ad.Set(name, value); serr != nil {
			return fmt.Errorf("parsing value for %s: %w", name, err)
		}
		return nil
	}
	ad.InsertExpr(name, expr)
	if m := t.delAttrs[string(jobKey(c, p))]; m != nil {
		delete(m, name)
	}
	return nil
}

// DeleteAttribute stages removal of an attribute.
func (t *Txn) DeleteAttribute(c, p int, name string) {
	key := string(jobKey(c, p))
	if ad, ok := t.pending[key]; ok {
		ad.Delete(name)
	}
	if t.delAttrs[key] == nil {
		t.delAttrs[key] = map[string]bool{}
	}
	t.delAttrs[key][name] = true
}

// DestroyProc stages removal of a proc ad.
func (t *Txn) DestroyProc(c, p int) {
	t.destroyed[string(jobKey(c, p))] = true
	delete(t.pending, string(jobKey(c, p)))
}

// DestroyCluster stages removal of an entire cluster (its cluster ad and any of
// its committed proc ads).
func (t *Txn) DestroyCluster(c int) {
	t.destroyed[clusterKeyStr(c)] = true
	delete(t.pending, clusterKeyStr(c))
	for ad := range t.q.coll.Scan() {
		if cc, _, ok := jobIDs(ad); ok && cc == c {
			pp, _ := ad.EvaluateAttrInt("ProcId")
			t.destroyed[string(jobKey(c, int(pp)))] = true
		}
	}
}

// GetAttribute returns the staged-or-committed expression string for c.p's attr.
func (t *Txn) GetAttribute(c, p int, name string) (string, bool) {
	key := string(jobKey(c, p))
	if m := t.delAttrs[key]; m != nil && m[name] {
		return "", false
	}
	if ad, ok := t.pending[key]; ok {
		if expr, ok := ad.Lookup(name); ok {
			return expr.String(), true
		}
	}
	// Inherited from the staged/committed cluster ad for proc reads.
	if p >= 0 {
		if ad, ok := t.pending[clusterKeyStr(c)]; ok {
			if expr, ok := ad.Lookup(name); ok {
				return expr.String(), true
			}
		}
	}
	if ad, ok := t.q.coll.Get(jobKey(c, p)); ok {
		if expr, ok := ad.Lookup(name); ok {
			return expr.String(), true
		}
	}
	return "", false
}

// GetJobAd returns the merged staged-over-committed ad for c.p.
func (t *Txn) GetJobAd(c, p int) (*classad.ClassAd, bool) {
	base, ok := t.q.coll.Get(jobKey(c, p))
	if !ok {
		base = classad.New()
	}
	staged, hasStaged := t.pending[string(jobKey(c, p))]
	if !ok && !hasStaged {
		return nil, false
	}
	if hasStaged {
		for _, name := range staged.GetAttributes() {
			if expr, ok := staged.Lookup(name); ok {
				base.InsertExpr(name, expr)
			}
		}
	}
	return base, true
}

// Abort discards the transaction. It is a no-op on the store.
func (t *Txn) Abort() {
	t.pending = nil
	t.destroyed = nil
}

// Commit validates and materializes staged jobs, then applies them plus any
// destructions as one atomic batch per cluster (a cluster's ads share a shard).
func (t *Txn) Commit() error {
	if len(t.errs) > 0 {
		return fmt.Errorf("transaction has %d deferred error(s): %s", len(t.errs), t.errs[0])
	}
	now := nowUnix()

	// Ensure a cluster ad exists for every cluster referenced by staged procs.
	clusters := map[int]bool{}
	for key := range t.pending {
		if c, _, ok := parseJobKey([]byte(key)); ok {
			clusters[c] = true
		}
	}
	for c := range clusters {
		t.stagedAd(clusterKeyStr(c))
	}

	batch := make([]collections.AdUpdate, 0, len(t.pending))
	for key, ad := range t.pending {
		if t.destroyed[key] {
			continue
		}
		c, p, ok := parseJobKey([]byte(key))
		if !ok {
			continue
		}
		t.materialize(ad, c, p, now)
		batch = append(batch, collections.AdUpdate{Key: []byte(key), Ad: ad})
	}
	if len(batch) > 0 {
		if err := t.q.coll.Update(batch); err != nil {
			return fmt.Errorf("committing job batch: %w", err)
		}
	}
	for key := range t.destroyed {
		t.q.coll.Delete([]byte(key))
	}
	// SUBMIT user-log event: the C++ schedd writes it at commit of a new proc
	// (qmgmt.cpp CommitTransaction -> WriteSubmitToUserLog), not condor_submit.
	// Emit it here for each newly created proc, reading the flattened (cluster
	// attrs merged) ad so UserLog/Iwd are resolvable. Done after the durable
	// write so a failed commit logs nothing.
	//
	// CRITICAL (ROADMAP #1): this runs AFTER coll.Update/Delete have returned,
	// so no collection/shard lock is held here. Submit applies user-log
	// backpressure (a bounded-blocking enqueue) when the submitter's log FS is
	// behind; keeping it outside the collection lock ensures a slow log FS
	// throttles only this submitter, never stalls commits for other writers on
	// the same shard. Do not move this inside the locked region above.
	if t.q.ulog != nil {
		for key := range t.newProcs {
			if t.destroyed[key] {
				continue
			}
			c, p, ok := parseJobKey([]byte(key))
			if !ok {
				continue
			}
			if ad, ok := t.q.coll.Get(jobKey(c, p)); ok {
				t.q.ulog.Submit(ad)
			}
		}
	}
	return nil
}

// materialize sets the attributes the schedd forces onto every job at commit.
func (t *Txn) materialize(ad *classad.ClassAd, c, p int, now int64) {
	if p < 0 {
		// Cluster ad: forced identity attrs the proc ads inherit via chaining.
		_ = ad.Set("ClusterId", int64(c))
		ad.InsertAttrString("Owner", t.owner)
		ad.InsertAttrString("User", t.user)
		if _, ok := ad.Lookup("JobUniverse"); !ok {
			_ = ad.Set("JobUniverse", int64(5)) // vanilla
		}
		ad.InsertAttrString("MyType", "Job")
		return
	}
	// Proc ad.
	_ = ad.Set("ProcId", int64(p))
	_ = ad.Set("ClusterId", int64(c))
	if _, ok := ad.Lookup("JobStatus"); !ok {
		_ = ad.Set("JobStatus", int64(StatusIdle))
	}
	if _, ok := ad.Lookup("QDate"); !ok {
		_ = ad.Set("QDate", now)
	}
	qdate := now
	if v, ok := ad.EvaluateAttrInt("QDate"); ok {
		qdate = v
	}
	ad.InsertAttrString("GlobalJobId", t.q.globalJobID(c, p, qdate))
	ad.InsertAttrString("MyType", "Job")
}

// stagedAd returns the staged ad for key, creating an empty one if absent.
func (t *Txn) stagedAd(key string) *classad.ClassAd {
	if ad, ok := t.pending[key]; ok {
		return ad
	}
	ad := classad.New()
	t.pending[key] = ad
	return ad
}

// jobIDs extracts (cluster, proc) from an ad's ClusterId/ProcId attributes.
func jobIDs(ad *classad.ClassAd) (c, p int, ok bool) {
	cv, cok := ad.EvaluateAttrInt("ClusterId")
	pv, pok := ad.EvaluateAttrInt("ProcId")
	if !cok || !pok {
		return 0, 0, false
	}
	return int(cv), int(pv), true
}
