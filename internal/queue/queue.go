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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
	"github.com/bbockelm/cedar/security"
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
	// UIDDomain is UID_DOMAIN: the domain of a user named without one.
	UIDDomain string
	// AccountingDomain is ACCOUNTING_DOMAIN, the domain of the submitter
	// names the schedd advertises. Empty means UIDDomain.
	AccountingDomain string
	// SuperUsers are the QUEUE_SUPER_USERS who may set Owner/User to another
	// identity and use SetEffectiveOwner. An entry without a domain names
	// that user in UIDDomain.
	SuperUsers []string
	// MayImpersonate is QUEUE_SUPER_USER_MAY_IMPERSONATE: when set, the user
	// names (without domain) a super user may submit as. When nil, a super
	// user may submit only as a user the schedd already knows (see
	// Queue.mayImpersonate).
	MayImpersonate *regexp.Regexp

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
	coll       *collections.Collection
	hist       *History
	name       string
	domain     string // UID_DOMAIN
	acctDomain string // ACCOUNTING_DOMAIN

	// authzMu guards supers + authz so condor_reconfig can swap the QUEUE_SUPER_USERS
	// / *_JOB_ATTRS / QUEUE_ALL_USERS_TRUSTED authorization live while QMGMT handler
	// goroutines read it (see SetAuthz / authzSnapshot / IsSuperUser).
	authzMu sync.RWMutex
	supers  map[string]bool // canonical user@domain (see canonicalUser)
	authz   authzConfig     // per-attribute / ownership QMGMT authorization (see authz.go)

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
	acctDomain := opts.AccountingDomain
	if acctDomain == "" {
		acctDomain = opts.UIDDomain
	}
	q := &Queue{
		coll:       coll,
		hist:       hist,
		name:       opts.ScheddName,
		domain:     opts.UIDDomain,
		acctDomain: acctDomain,
		authz:      buildAuthzConfig(opts),
		nextID:     1,
	}
	q.supers = q.buildSupers(opts.SuperUsers)
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

// IsSuperUser reports whether user, an authenticated user@domain, is a queue
// super user. The whole name is compared: condor@<other domain> is not the
// super user condor.
func (q *Queue) IsSuperUser(user string) bool {
	if user == "" {
		return false
	}
	q.authzMu.RLock()
	defer q.authzMu.RUnlock()
	return q.supers[q.canonicalUser(user)]
}

// buildSupers resolves the QUEUE_SUPER_USERS entries to the set of identities
// IsSuperUser admits, as the C++ schedd's InitQmgmt does (qmgmt.cpp
// ~1481-1513): an entry without a domain names that user in UID_DOMAIN, and
// "condor" also admits condor@child, condor@parent and condor@family, the
// identities of the sessions condor_master shares with its children.
func (q *Queue) buildSupers(entries []string) map[string]bool {
	supers := map[string]bool{}
	for _, s := range entries {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		supers[q.canonicalUser(s)] = true
		if s == "condor" {
			for _, fam := range []string{"condor@child", "condor@parent", "condor@family"} {
				supers[q.canonicalUser(fam)] = true
			}
		}
	}
	return supers
}

// authzSnapshot returns the current QMGMT authorization config under the read
// lock. The returned struct shares the (immutable-after-publish) maps SetAuthz
// installs, so callers must treat them as read-only.
func (q *Queue) authzSnapshot() authzConfig {
	q.authzMu.RLock()
	defer q.authzMu.RUnlock()
	return q.authz
}

// SetAuthz replaces the queue's QMGMT authorization live (condor_reconfig): the
// QUEUE_SUPER_USERS set and the immutable/protected/secure attribute sets plus
// the QUEUE_ALL_USERS_TRUSTED / IgnoreSecureAttrs flags, rebuilt from opts exactly
// as Open does. Transactions already in flight keep the isSuper decision they were
// stamped with at Begin; new transactions and every subsequent authorize() see the
// new config. Safe to call from any goroutine.
func (q *Queue) SetAuthz(opts Options) {
	supers := q.buildSupers(opts.SuperUsers)
	az := buildAuthzConfig(opts)
	q.authzMu.Lock()
	q.supers = supers
	q.authz = az
	q.authzMu.Unlock()
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

// Begin starts a new transaction owned by authUser, the caller's authenticated
// user@domain ("" for an anonymous caller). Jobs it creates get the user part
// as their Owner and the full name as their User, as the C++ schedd records
// the socket's owner and fully-qualified user. An identity in the "unmapped"
// domain (an SSL or SciTokens peer no map file named) is not an account, so
// such a transaction is anonymous: it may read but not write.
func (q *Queue) Begin(authUser string) *Txn {
	if isUnmapped(authUser) {
		authUser = ""
	}
	user := q.qualify(authUser)
	owner := shortName(user)
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

// shortName returns the user part of a fully-qualified user, the name before
// its last '@' (split_canonical_name).
func shortName(user string) string {
	name, _ := security.SplitFQU(user)
	return name
}

// isUnmapped reports whether user is in the "unmapped" domain, which HTCondor
// gives an SSL or SciTokens identity no map file renamed and an
// unauthenticated peer (UNMAPPED_DOMAIN, authentication.cpp). Such a name is
// not a local account.
func isUnmapped(user string) bool {
	_, domain := security.SplitFQU(user)
	return strings.EqualFold(domain, security.UnmappedDomain)
}

// qualify returns user as user@domain, giving a name without a domain this
// schedd's UID_DOMAIN, as is_same_user's ASSUME_UID_DOMAIN does
// (src/condor_utils/uids.cpp). With no UID_DOMAIN a bare name stays bare.
func (q *Queue) qualify(user string) string {
	if user == "" || strings.Contains(user, "@") || q.domain == "" {
		return user
	}
	return user + "@" + q.domain
}

// canonicalUser is qualify with the domain lowercased, the form two names are
// compared in: user parts compare exactly, domains ignoring case.
func (q *Queue) canonicalUser(user string) string {
	name, domain := security.SplitFQU(q.qualify(user))
	if domain == "" {
		return name
	}
	return name + "@" + strings.ToLower(domain)
}

// SameUser reports whether a and b name the same user: the same user part and
// the same domain, a name without a domain standing for UID_DOMAIN. An empty
// name matches nothing.
func (q *Queue) SameUser(a, b string) bool {
	if shortName(a) == "" || shortName(b) == "" {
		return false
	}
	return q.canonicalUser(a) == q.canonicalUser(b)
}

// JobUser returns the identity that owns the job described by ad: its User
// attribute, which the C++ schedd keys job ownership on, or for an ad without
// one its Owner in UID_DOMAIN. "" if the ad names neither.
func (q *Queue) JobUser(ad *classad.ClassAd) string {
	if u, ok := ad.EvaluateAttrString("User"); ok && u != "" {
		return u
	}
	if o, ok := ad.EvaluateAttrString("Owner"); ok && o != "" {
		return q.qualify(o)
	}
	return ""
}

// mayImpersonate reports whether a queue super user may submit jobs as
// owner, as SuperUserAllowedToSetOwnerTo (qmgmt.cpp) decides: when
// QUEUE_SUPER_USER_MAY_IMPERSONATE is set, owner's user name must match it;
// otherwise owner must be a user the schedd already knows. The C++ schedd
// knows a user by the user record it keeps once that user has submitted;
// this schedd keeps none, so it knows a user that has a job in the queue or
// in the history.
func (q *Queue) mayImpersonate(owner string) bool {
	if re := q.authzSnapshot().mayImpersonate; re != nil {
		return re.MatchString(shortName(owner))
	}
	return q.knownUser(q.qualify(owner))
}

// knownUser reports whether user owns a job in the live queue or the
// history.
func (q *Queue) knownUser(user string) bool {
	query, err := vm.Parse("User == " + classad.Quote(user))
	if err != nil {
		return false
	}
	// == compares strings ignoring case; SameUser compares the user part
	// exactly.
	for ad := range q.coll.Query(query) {
		if q.SameUser(user, q.JobUser(ad)) {
			return true
		}
	}
	for ad := range q.hist.Query(query) {
		if q.SameUser(user, q.JobUser(ad)) {
			return true
		}
	}
	return false
}

// globalJobID builds "<ScheddName>#<c>.<p>#<QDate>".
func (q *Queue) globalJobID(c, p int, qdate int64) string {
	return fmt.Sprintf("%s#%d.%d#%d", q.name, c, p, qdate)
}

// nowUnix is a var so tests can pin time.
var nowUnix = func() int64 { return time.Now().Unix() }
