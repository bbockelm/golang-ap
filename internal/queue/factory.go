package queue

import (
	"fmt"
	"iter"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// Factory ClassAd attribute names set on the cluster ad (proc -1). These mirror
// HTCondor's condor_attributes.h ATTR_JOB_MATERIALIZE_* and are the persistent
// bookkeeping the materialization engine reads and advances. The queue owns this
// schema (the factory materializer package must not import the queue).
const (
	AttrMaterializeDigestFile = "JobMaterializeDigestFile" // spooled digest path
	AttrMaterializeItemsFile  = "JobMaterializeItemsFile"  // spooled itemdata path
	AttrMaterializeLimit      = "JobMaterializeLimit"      // max total procs (max_materialize)
	AttrMaterializeMaxIdle    = "JobMaterializeMaxIdle"    // max idle-at-once (max_idle)
	AttrMaterializeNextProcId = "JobMaterializeNextProcId" // next proc id to materialize
	AttrMaterializeNextRow    = "JobMaterializeNextRow"    // next itemdata row index
	AttrMaterializePaused     = "JobMaterializePaused"     // 0 running, !=0 paused/done
	AttrMaterializeDate       = "JobMaterializeDate"       // unix time the factory was set up
	AttrMaterializeItemCount  = "JobMaterializeItemCount"  // number of itemdata rows
)

// PauseNoMoreItems is the JobMaterializePaused value the engine writes once a
// factory has materialized every row (mirrors HTCondor mmNoMoreItems). Any
// non-zero JobMaterializePaused stops further materialization.
const PauseNoMoreItems = 3

// FactoryInfo is a snapshot of one factory cluster's bookkeeping plus live proc
// counts, used by the materialization engine to decide how many procs to add.
type FactoryInfo struct {
	Cluster    int
	DigestFile string
	ItemsFile  string
	Limit      int // max total procs (JobMaterializeLimit); <=0 means unlimited
	MaxIdle    int // max idle-at-once (JobMaterializeMaxIdle); <0 means unset/unlimited
	NextProcId int
	NextRow    int
	ItemCount  int
	Paused     int
	TotalProcs int // procs currently materialized in this cluster
	IdleProcs  int // of those, how many are Idle (JobStatus==1)
}

// IsFactoryCluster reports whether cluster c is a registered job factory.
func (q *Queue) IsFactoryCluster(c int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.factories[c]
}

// FactoryClusters returns the ids of all registered factory clusters.
func (q *Queue) FactoryClusters() []int {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]int, 0, len(q.factories))
	for c := range q.factories {
		out = append(out, c)
	}
	return out
}

// noteFactory records cluster c as a factory (called when its cluster ad, bearing
// a digest file, commits). unnoteFactory drops it (on cluster destroy/cleanup).
func (q *Queue) noteFactory(c int) {
	q.mu.Lock()
	if q.factories == nil {
		q.factories = map[int]bool{}
	}
	newly := !q.factories[c]
	q.factories[c] = true
	nudge := q.onFactory
	q.mu.Unlock()
	// Wake the materialization engine so a freshly submitted factory materializes
	// its first batch immediately instead of waiting for the next sweep tick.
	if newly && nudge != nil {
		nudge()
	}
}

// SetFactoryNudge installs a callback invoked (non-blocking) when a new factory
// cluster is registered, so the materialization engine can sweep promptly. Call
// once at startup before serving.
func (q *Queue) SetFactoryNudge(fn func()) {
	q.mu.Lock()
	q.onFactory = fn
	q.mu.Unlock()
}

func (q *Queue) unnoteFactory(c int) {
	q.mu.Lock()
	delete(q.factories, c)
	q.mu.Unlock()
}

// recoverFactories rebuilds the factory set at Open by probing each allocated
// cluster ad for a digest-file attribute. This is a one-time O(clusters) startup
// cost; a factory that crashed after SetJobFactory but before its first commit
// (thus with no persisted cluster ad) is simply re-driven when condor_submit
// retries, matching the C++ schedd's recovery tolerance.
func (q *Queue) recoverFactories() {
	q.factories = map[int]bool{}
	for c := 1; c < q.nextID; c++ {
		ad, ok := q.coll.Get(jobKey(c, -1))
		if !ok {
			continue
		}
		if s, ok := ad.EvaluateAttrString(AttrMaterializeDigestFile); ok && s != "" {
			q.factories[c] = true
		}
	}
}

// FactoryInfo snapshots factory cluster c: its bookkeeping attributes plus a live
// count of its materialized/idle procs. Returns false if c is not a factory or
// its cluster ad is gone.
func (q *Queue) FactoryInfo(c int) (*FactoryInfo, bool) {
	ad, ok := q.coll.Get(jobKey(c, -1))
	if !ok {
		return nil, false
	}
	digest, ok := ad.EvaluateAttrString(AttrMaterializeDigestFile)
	if !ok || digest == "" {
		return nil, false
	}
	fi := &FactoryInfo{Cluster: c, DigestFile: digest, MaxIdle: -1, Limit: -1}
	fi.ItemsFile, _ = ad.EvaluateAttrString(AttrMaterializeItemsFile)
	fi.Limit = intAttr(ad, AttrMaterializeLimit, -1)
	fi.MaxIdle = intAttr(ad, AttrMaterializeMaxIdle, -1)
	fi.NextProcId = intAttr(ad, AttrMaterializeNextProcId, 0)
	fi.NextRow = intAttr(ad, AttrMaterializeNextRow, 0)
	fi.ItemCount = intAttr(ad, AttrMaterializeItemCount, 0)
	fi.Paused = intAttr(ad, AttrMaterializePaused, 0)
	fi.TotalProcs, fi.IdleProcs = q.clusterProcCounts(c)
	return fi, true
}

// clusterProcCounts returns (total procs, idle procs) currently in cluster c.
func (q *Queue) clusterProcCounts(c int) (total, idle int) {
	cc := q.clusterStatusCounts(c)
	return cc.Total, cc.Idle
}

// clusterCounts holds a live status breakdown of one cluster's procs.
type clusterCounts struct {
	Total, Idle, Running, Held int
}

// clusterStatusCounts scans the live queue once and tallies cluster c's procs by
// JobStatus. Used both by the materialization engine (idle/total) and by
// condor_q -factory (the per-factory RUN/IDLE/HOLD columns).
func (q *Queue) clusterStatusCounts(c int) clusterCounts {
	var cc clusterCounts
	tally := func(ad *classad.ClassAd) {
		cc.Total++
		switch st, _ := ad.EvaluateAttrInt("JobStatus"); int(st) {
		case StatusIdle:
			cc.Idle++
		case StatusRunning, StatusTransferOut, StatusSuspended:
			cc.Running++
		case StatusHeld:
			cc.Held++
		}
	}
	query, err := vm.Parse(fmt.Sprintf("ClusterId == %d", c))
	if err != nil {
		// Fall back to a full scan filter if the constraint fails to compile.
		for ad := range q.coll.Scan() {
			if cv, _ := ad.EvaluateAttrInt("ClusterId"); int(cv) == c {
				tally(ad)
			}
		}
		return cc
	}
	for ad := range q.coll.Query(query) {
		tally(ad)
	}
	return cc
}

// FactoryClusterAds yields each registered factory's cluster ad (proc -1),
// annotated with the live JobsRunning/JobsIdle/JobsHeld/JobsPresent counts that
// condor_q -factory prints. It deliberately bypasses the structural-hide that
// Scan/Query apply to cluster ads: the default condor_q path never calls this, so
// factory cluster ads stay hidden there, but the -factory query surfaces them.
// Each yielded ad is a fresh decode (coll.Get), so annotating it is safe.
func (q *Queue) FactoryClusterAds() iter.Seq[*classad.ClassAd] {
	return func(yield func(*classad.ClassAd) bool) {
		for _, c := range q.FactoryClusters() {
			ad, ok := q.coll.Get(jobKey(c, -1))
			if !ok {
				continue
			}
			cc := q.clusterStatusCounts(c)
			_ = ad.Set("JobsRunning", int64(cc.Running))
			_ = ad.Set("JobsIdle", int64(cc.Idle))
			_ = ad.Set("JobsHeld", int64(cc.Held))
			_ = ad.Set("JobsPresent", int64(cc.Total))
			if !yield(ad) {
				return
			}
		}
	}
}

// MaterializeProc commits one materialized proc ad into factory cluster c and
// advances the cluster ad's NextProcId/NextRow in the same atomic batch (a
// cluster's ads share a shard, so the two-ad Update is atomic and crash-safe:
// on recovery the advanced NextProcId is durable iff the proc is). override
// carries only the digest-derived per-proc attributes; the identity attributes
// the schedd forces at submit are added here, and every common attribute is
// inherited from the cluster ad by chaining. paused, when non-zero, additionally
// marks the factory done (no more rows).
//
// Serialized by factoryMu so NextProcId can never be advanced concurrently.
func (q *Queue) MaterializeProc(c, proc int, override *classad.ClassAd, nextProcId, nextRow, paused int) error {
	q.factoryMu.Lock()
	defer q.factoryMu.Unlock()

	cluster, ok := q.coll.Get(jobKey(c, -1))
	if !ok {
		return fmt.Errorf("factory cluster %d has no cluster ad", c)
	}

	// Build the proc ad: digest override + forced identity attrs (mirrors
	// Txn.materialize for a proc). Only these live on the proc ad; the rest is
	// chained from the cluster ad.
	procAd := override
	if procAd == nil {
		procAd = classad.New()
	}
	now := nowUnix()
	_ = procAd.Set("ProcId", int64(proc))
	_ = procAd.Set("ClusterId", int64(c))
	if _, ok := procAd.Lookup("JobStatus"); !ok {
		_ = procAd.Set("JobStatus", int64(StatusIdle))
	}
	if _, ok := procAd.Lookup("QDate"); !ok {
		_ = procAd.Set("QDate", now)
	}
	qdate := now
	if v, ok := procAd.EvaluateAttrInt("QDate"); ok {
		qdate = v
	}
	procAd.InsertAttrString("GlobalJobId", q.globalJobID(c, proc, qdate))
	procAd.InsertAttrString("MyType", "Job")

	// Advance the cluster ad's bookkeeping.
	_ = cluster.Set(AttrMaterializeNextProcId, int64(nextProcId))
	_ = cluster.Set(AttrMaterializeNextRow, int64(nextRow))
	if paused != 0 {
		_ = cluster.Set(AttrMaterializePaused, int64(paused))
	}

	batch := []collections.AdUpdate{
		{Key: jobKey(c, proc), Ad: procAd},
		{Key: jobKey(c, -1), Ad: cluster},
	}
	if err := q.coll.Update(batch); err != nil {
		return fmt.Errorf("materializing proc %d.%d: %w", c, proc, err)
	}

	// SUBMIT user-log event for the freshly materialized proc, after the durable
	// write and outside any collection lock (see Txn.Commit rationale).
	if q.ulog != nil {
		if ad, ok := q.coll.Get(jobKey(c, proc)); ok {
			q.ulog.Submit(ad)
		}
	}
	return nil
}

// PauseFactory marks factory cluster c paused/done with the given non-zero code
// (e.g. PauseNoMoreItems) without materializing a proc, so the engine stops
// visiting it. A no-op if the cluster ad is gone.
func (q *Queue) PauseFactory(c, code int) {
	q.factoryMu.Lock()
	defer q.factoryMu.Unlock()
	cluster, ok := q.coll.Get(jobKey(c, -1))
	if !ok {
		return
	}
	_ = cluster.Set(AttrMaterializePaused, int64(code))
	_ = q.coll.Put(jobKey(c, -1), cluster)
}

// intAttr reads an integer attribute with a default.
func intAttr(ad *classad.ClassAd, name string, def int) int {
	if v, ok := ad.EvaluateAttrInt(name); ok {
		return int(v)
	}
	return def
}
