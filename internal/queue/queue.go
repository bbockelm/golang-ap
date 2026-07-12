// Package queue is the job-queue authority for the pure-Go schedd: a persistent,
// crash-safe store of job ClassAds backed by a collections.Collection in $(SPOOL),
// plus a collections.Archive history for terminal jobs. It owns the HTCondor
// JobQueueKey scheme (proc ad "c.p" chained to cluster ad "c.-1"), a crash-safe
// cluster-id counter, per-connection transactions, commit-time attribute
// materialization, and the JobStatus state machine used by condor_hold/release/rm.
//
// Semantics were verified against HTCondor's C++ schedd: qmgmt.cpp (NewCluster/
// NewProc active_cluster_num, forced attributes, GlobalJobId) and schedd.cpp
// (actOnJobs status transitions).
package queue

import (
	"fmt"
	"iter"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// JobStatus values (HTCondor's JobStatus attribute).
const (
	StatusIdle        = 1
	StatusRunning     = 2
	StatusRemoved     = 3
	StatusCompleted   = 4
	StatusHeld        = 5
	StatusTransferOut = 6
	StatusSuspended   = 7
)

// counterKey holds the persistent cluster-id counter. It is a structural key
// (hidden from Scan/Query) that never participates in the parent/child chain.
const counterKey = "counter"

// Options configures a Queue.
type Options struct {
	// Dir is the spool directory ($(SPOOL)); the live queue lives in Dir/queue
	// and the history archive in Dir/history.
	Dir string
	// ScheddName is used to build each job's GlobalJobId.
	ScheddName string
	// UIDDomain is appended to the owner to form the User attribute.
	UIDDomain string
	// SuperUsers are the QUEUE_SUPER_USERS who may set Owner/User to another
	// identity and use SetEffectiveOwner.
	SuperUsers []string

	// ImmutableAttrs / ProtectedAttrs / SecureAttrs are operator-supplied extra
	// attribute names (from IMMUTABLE_JOB_ATTRS / PROTECTED_JOB_ATTRS /
	// SECURE_JOB_ATTRS) folded on top of the SYSTEM_* defaults for per-attribute
	// QMGMT authorization. See authz.go.
	ImmutableAttrs []string
	ProtectedAttrs []string
	SecureAttrs    []string

	// AllUsersTrusted maps QUEUE_ALL_USERS_TRUSTED: when true, client
	// SetAttribute/DeleteAttribute skips the per-job ownership and protected-attr
	// checks (matching qmgmt_all_users_trusted). Immutable attrs remain immutable.
	AllUsersTrusted bool

	// IgnoreSecureAttrs maps IGNORE_ATTEMPTS_TO_SET_SECURE_JOB_ATTRS (default
	// true): silently ignore a client attempt to set a secure attribute instead
	// of rejecting it.
	IgnoreSecureAttrs bool
}

// Queue is the job-queue authority. It is safe for concurrent use: the backing
// collection is internally sharded/locked and cluster-id allocation is guarded
// by mu. Per-connection transactions (see Begin) stage their edits privately and
// commit as one atomic batch.
type Queue struct {
	coll   *collections.Collection
	hist   *History
	name   string
	domain string
	supers map[string]bool

	authz  authzConfig // per-attribute / ownership QMGMT authorization (see authz.go)

	mu     sync.Mutex // guards nextID + counter persistence + factories set
	nextID int

	// factories is the set of cluster ids that are job factories (late
	// materialization). Maintained on commit/destroy and recovered at Open.
	// Guarded by mu.
	factories map[int]bool

	// onFactory, if set, is invoked when a new factory cluster is registered so
	// the materialization engine sweeps promptly (see SetFactoryNudge). Guarded
	// by mu.
	onFactory func()

	// factoryMu serializes late-materialization proc commits so the cluster ad's
	// NextProcId/NextRow can never be advanced concurrently (see MaterializeProc).
	factoryMu sync.Mutex

	// onVacateRunning, if set, is invoked when a running job is removed or held
	// so the scheduler core can tear down its shadow/claim first (see
	// SetOnVacateRunning). It should block until the teardown finishes (or a
	// short timeout elapses) so the status write/archival that follows observes
	// a quiesced job.
	onVacateRunning func(c, p int)

	// ulog, if set, writes standard user-job-log events (SUBMIT at commit;
	// HELD/RELEASED/ABORTED on the queue-action path) so condor_wait / DAGMan
	// can follow a job. See SetUserLog. nil disables all user-log writing.
	ulog UserLogger
}

// Open opens (creating if necessary) the persistent queue and history under
// opts.Dir, recovering any previously committed state.
func Open(opts Options) (*Queue, error) {
	coll, err := collections.Open(collections.Options{
		Dir:              opts.Dir + "/queue",
		ParentKeyFor:     parentKeyFor,
		IsStructural:     isStructural,
		CategoricalAttrs: []string{"Owner", "User"},
		ValueAttrs:       []string{"ClusterId", "ProcId", "JobStatus", "JobUniverse"},
		// Maintained idle-job priority index for negotiation (see rrl.go).
		Ordered: []collections.OrderSpec{idleOrderSpec()},
	})
	if err != nil {
		return nil, fmt.Errorf("opening job queue collection: %w", err)
	}
	hist, err := openHistory(opts.Dir + "/history")
	if err != nil {
		_ = coll.Close()
		return nil, fmt.Errorf("opening job history: %w", err)
	}
	supers := map[string]bool{}
	for _, s := range opts.SuperUsers {
		if s = strings.TrimSpace(s); s != "" {
			supers[s] = true
		}
	}
	q := &Queue{
		coll:   coll,
		hist:   hist,
		name:   opts.ScheddName,
		domain: opts.UIDDomain,
		supers: supers,
		authz:  buildAuthzConfig(opts),
		nextID: 1,
	}
	// Recover the cluster-id counter.
	if ad, ok := coll.Get([]byte(counterKey)); ok {
		if v, ok := ad.EvaluateAttrInt("NextClusterId"); ok && int(v) > q.nextID {
			q.nextID = int(v)
		}
	}
	// Recover the set of factory clusters (one-time probe of cluster ads).
	q.recoverFactories()
	return q, nil
}

// Close flushes and closes the queue and history.
func (q *Queue) Close() error {
	var firstErr error
	if err := q.hist.Flush(); err != nil {
		firstErr = err
	}
	if err := q.hist.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := q.coll.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// IsSuperUser reports whether user is a queue super user.
func (q *Queue) IsSuperUser(user string) bool {
	return q.supers[user] || q.supers[shortName(user)]
}

// allocClusterID returns the next cluster id and persists the advanced counter
// durably, so ids are never reused across a crash (matching HTCondor).
func (q *Queue) allocClusterID() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := q.nextID
	q.nextID++
	ad := classad.New()
	ad.InsertAttr("NextClusterId", int64(q.nextID))
	if err := q.coll.Put([]byte(counterKey), ad); err != nil {
		q.nextID-- // roll back the in-memory advance on persist failure
		return 0, fmt.Errorf("persisting cluster-id counter: %w", err)
	}
	return id, nil
}

// Begin starts a new transaction owned by authUser. effectiveOwner is honored
// only for super users; otherwise the owner is forced to authUser.
func (q *Queue) Begin(authUser string) *Txn {
	owner := shortName(authUser)
	user := authUser
	if !strings.Contains(user, "@") && q.domain != "" {
		user = owner + "@" + q.domain
	}
	return &Txn{
		q:         q,
		authUser:  authUser,
		owner:     owner,
		user:      user,
		isSuper:   q.IsSuperUser(authUser),
		active:    -1,
		pending:   map[string]*classad.ClassAd{},
		nextProc:  map[int]int{},
		delAttrs:  map[string]map[string]bool{},
		destroyed: map[string]bool{},
		newProcs:  map[string]bool{},
	}
}

// Get returns the flattened (parent attributes merged) job ad for c.p, or nil.
func (q *Queue) Get(c, p int) (*classad.ClassAd, bool) {
	return q.coll.Get(jobKey(c, p))
}

// Scan iterates the flattened proc ads currently in the live queue (cluster ads
// are structural and hidden).
func (q *Queue) Scan() iter.Seq[*classad.ClassAd] {
	return q.coll.Scan()
}

// Query iterates the flattened proc ads matching q's constraint.
func (q *Queue) Query(query *vm.Query) iter.Seq[*classad.ClassAd] {
	return q.coll.Query(query)
}

// Counts holds live job-status tallies for the schedd ad and query summaries.
type Counts struct {
	Total, Idle, Running, Removed, Completed, Held, Suspended int
	Owners                                                    int
}

// Counts scans the live queue and tallies job statuses.
func (q *Queue) Counts() Counts {
	var c Counts
	owners := map[string]bool{}
	for ad := range q.coll.Scan() {
		c.Total++
		if o, ok := ad.EvaluateAttrString("Owner"); ok {
			owners[o] = true
		}
		st, _ := ad.EvaluateAttrInt("JobStatus")
		switch int(st) {
		case StatusIdle:
			c.Idle++
		case StatusRunning:
			c.Running++
		case StatusRemoved:
			c.Removed++
		case StatusCompleted:
			c.Completed++
		case StatusHeld:
			c.Held++
		case StatusSuspended:
			c.Suspended++
		}
	}
	c.Owners = len(owners)
	return c
}

// ----- key scheme -----

// jobKey builds the "c.p" key for a proc ad (p>=0) or the "c.-1" cluster ad.
func jobKey(c, p int) []byte {
	return []byte(strconv.Itoa(c) + "." + strconv.Itoa(p))
}

func clusterKeyStr(c int) string { return strconv.Itoa(c) + ".-1" }

// parseJobKey parses a "c.p" key. ok is false for non-job keys (e.g. counter).
func parseJobKey(key []byte) (c, p int, ok bool) {
	s := string(key)
	dot := strings.LastIndexByte(s, '.')
	if dot < 0 {
		return 0, 0, false
	}
	var err error
	if c, err = strconv.Atoi(s[:dot]); err != nil {
		return 0, 0, false
	}
	if p, err = strconv.Atoi(s[dot+1:]); err != nil {
		return 0, 0, false
	}
	return c, p, true
}

// parentKeyFor chains a proc ad "c.p" (p>=0) to its cluster ad "c.-1". Cluster
// ads and non-job keys have no parent.
func parentKeyFor(key []byte) []byte {
	c, p, ok := parseJobKey(key)
	if !ok || p < 0 {
		return nil
	}
	return []byte(clusterKeyStr(c))
}

// isStructural marks cluster ads and the counter as structural (present in the
// store to anchor the chain / persist state, but hidden from Scan/Query).
func isStructural(key []byte) bool {
	c, p, ok := parseJobKey(key)
	if !ok {
		return true // counter and any non-job key
	}
	_ = c
	return p < 0 // cluster ad
}

// shortName strips a trailing @domain from a fully-qualified user.
func shortName(user string) string {
	if i := strings.IndexByte(user, '@'); i >= 0 {
		return user[:i]
	}
	return user
}

// globalJobID builds "<ScheddName>#<c>.<p>#<QDate>".
func (q *Queue) globalJobID(c, p int, qdate int64) string {
	return fmt.Sprintf("%s#%d.%d#%d", q.name, c, p, qdate)
}

// nowUnix is a var so tests can pin time.
var nowUnix = func() int64 { return time.Now().Unix() }
