package queue

import "github.com/PelicanPlatform/classad/classad"

// UserLogger writes standard HTCondor user-job-log events for a job. The queue
// invokes it (when set via SetUserLog) so the events condor_wait / DAGMan need
// land in the job's `log = ...` file. Implemented by internal/userlog.Manager;
// declared here as an interface to keep the queue decoupled from the writer.
type UserLogger interface {
	// Submit writes the SUBMIT event when a new proc commits into the queue.
	Submit(ad *classad.ClassAd)
	// Held writes the JOB_HELD event on condor_hold.
	Held(ad *classad.ClassAd, reason string, code, subcode int)
	// Released writes the JOB_RELEASED event on condor_release.
	Released(ad *classad.ClassAd, reason string)
	// Aborted writes the JOB_ABORTED event on condor_rm.
	Aborted(ad *classad.ClassAd, reason string)
}

// SetUserLog installs the user-log writer. Call once at startup before serving.
// nil (the default) disables user-log writing.
func (q *Queue) SetUserLog(ul UserLogger) { q.ulog = ul }

// ActionKind is the queue-mutating action requested by condor_hold/release/rm.
type ActionKind int

const (
	ActHold ActionKind = iota
	ActRelease
	ActRemove
	ActRemoveX
)

// Per-job action result codes matching HTCondor's action_result_t
// (src/condor_daemon_client/dc_schedd.h: AR_ERROR=0, AR_SUCCESS=1,
// AR_NOT_FOUND=2, AR_BAD_STATUS=3, AR_ALREADY_DONE=4, AR_PERMISSION_DENIED=5,
// AR_LIMIT_EXCEEDED=6).
const (
	ArError            = 0
	ArSuccess          = 1
	ArNotFound         = 2
	ArBadStatus        = 3
	ArAlreadyDone      = 4
	ArPermissionDenied = 5
	ArLimitExceeded    = 6
)

// ActionRequest describes one condor_hold/release/rm operation.
type ActionRequest struct {
	Kind           ActionKind
	Actor          string // authenticated user performing the action
	Reason         string
	HoldReasonCode int
	HoldReasonSub  int
	// System marks an action initiated by the schedd itself (a periodic /
	// on-exit policy firing) rather than by a user tool. It bypasses the
	// per-user owner permission check, matching the C++ schedd's holdJob /
	// abortJob / releaseJob running with schedd authority when a policy
	// expression fires.
	System bool
}

// CheckAction validates an action against job c.p without mutating anything and
// returns the per-job result code it would produce. The QMGMT-side two-phase
// ACT_ON_JOBS handler uses it to build the result ad it sends BEFORE the tool's
// ack (the C++ schedd likewise defers the commit until after the ack).
func (q *Queue) CheckAction(c, p int, req ActionRequest) int {
	return q.actOnJob(c, p, req, false)
}

// ApplyAction performs the action on job c.p (after the tool acked) and returns
// the per-job result code. Removed jobs are archived to history and deleted from
// the live queue.
func (q *Queue) ApplyAction(c, p int, req ActionRequest) int {
	return q.actOnJob(c, p, req, true)
}

// actOnJob validates (and, when apply is set, performs) an action on one
// committed job. Status-transition rules mirror Scheduler::actOnJobs
// (src/condor_schedd.V6/schedd.cpp).
func (q *Queue) actOnJob(c, p int, req ActionRequest, apply bool) int {
	ad, ok := q.Get(c, p)
	if !ok {
		return ArNotFound
	}
	owner, _ := ad.EvaluateAttrString("Owner")
	if !req.System && !q.IsSuperUser(req.Actor) && shortName(req.Actor) != owner {
		return ArPermissionDenied
	}
	st, _ := ad.EvaluateAttrInt("JobStatus")
	status := int(st)
	now := nowUnix()

	switch req.Kind {
	case ActHold:
		if status == StatusHeld {
			// C++: already held by user request -> ALREADY_DONE.
			if code, _ := ad.EvaluateAttrInt("HoldReasonCode"); code == 1 || code == 16 {
				return ArAlreadyDone
			}
		}
		if status == StatusRemoved || status == StatusCompleted {
			return ArPermissionDenied // matches C++ (schedd.cpp: REMOVED/COMPLETED -> AR_PERMISSION_DENIED)
		}
		if !apply {
			return ArSuccess
		}
		// condor_hold of a running job: tear down its live shadow first (the
		// hook blocks until the vacate completes or times out) so the slot is
		// released and the starter killed before the job is marked Held.
		if status == StatusRunning && q.onVacateRunning != nil {
			q.onVacateRunning(c, p)
		}
		_ = ad.Set("LastJobStatus", int64(status))
		_ = ad.Set("JobStatus", int64(StatusHeld))
		_ = ad.Set("EnteredCurrentStatus", now)
		if status == StatusRunning {
			if host, ok := ad.EvaluateAttrString("RemoteHost"); ok && host != "" {
				_ = ad.Set("LastRemoteHost", host)
			}
			ad.Delete("RemoteHost")
			stripRunAttrs(ad)
		}
		reason := req.Reason
		if reason == "" {
			reason = "via condor_hold (by user " + shortName(req.Actor) + ")"
		}
		ad.InsertAttrString("HoldReason", reason)
		code := req.HoldReasonCode
		if code == 0 {
			code = 1 // CONDOR_HOLD_CODE::UserRequest
		}
		_ = ad.Set("HoldReasonCode", int64(code))
		_ = ad.Set("HoldReasonSubCode", int64(req.HoldReasonSub))
		numHolds, _ := ad.EvaluateAttrInt("NumHolds")
		_ = ad.Set("NumHolds", numHolds+1)
		if err := q.coll.Put(jobKey(c, p), ad); err != nil {
			return ArError
		}
		if q.ulog != nil {
			q.ulog.Held(ad, reason, code, req.HoldReasonSub)
		}
		return ArSuccess

	case ActRelease:
		if status != StatusHeld {
			return ArBadStatus
		}
		// Jobs held for input spooling (HoldReasonCode 16) are not releasable
		// by condor_release (schedd.cpp).
		if code, _ := ad.EvaluateAttrInt("HoldReasonCode"); code == 16 {
			return ArBadStatus
		}
		if !apply {
			return ArSuccess
		}
		release := StatusIdle
		if v, ok := ad.EvaluateAttrInt("JobStatusOnRelease"); ok && v > 0 {
			release = int(v)
		}
		_ = ad.Set("JobStatus", int64(release))
		_ = ad.Set("EnteredCurrentStatus", now)
		ad.Delete("HoldReason")
		ad.Delete("HoldReasonCode")
		ad.Delete("HoldReasonSubCode")
		// A released job gets a clean slate for its consecutive-failure budget:
		// reset the shadow-exception counter (and the vacate bookkeeping that fed
		// it) so a job held for repeated shadow failures is not re-held
		// immediately after the operator releases it. Mirrors the C++ schedd
		// clearing the transient failure counters on release.
		ad.Delete("NumShadowExceptions")
		ad.Delete("VacateReason")
		ad.Delete("VacateReasonCode")
		ad.Delete("VacateReasonSubCode")
		if req.Reason != "" {
			ad.InsertAttrString("ReleaseReason", req.Reason)
		}
		if err := q.coll.Put(jobKey(c, p), ad); err != nil {
			return ArError
		}
		if q.ulog != nil {
			q.ulog.Released(ad, req.Reason)
		}
		return ArSuccess

	case ActRemove, ActRemoveX:
		if status == StatusRemoved {
			return ArAlreadyDone
		}
		if !apply {
			return ArSuccess
		}
		// A REMOVE of a running job first tears down its live shadow: the hook
		// blocks until the vacate (DEACTIVATE_CLAIM_FORCIBLY + RELEASE_CLAIM)
		// completes or times out, so the slot is not left Claimed and the
		// archival below observes a quiesced job.
		if status == StatusRunning && q.onVacateRunning != nil {
			q.onVacateRunning(c, p)
		}
		if status == StatusRunning {
			stripRunAttrs(ad)
		}
		_ = ad.Set("LastJobStatus", int64(status))
		_ = ad.Set("JobStatus", int64(StatusRemoved))
		_ = ad.Set("EnteredCurrentStatus", now)
		if req.Reason != "" {
			ad.InsertAttrString("RemoveReason", req.Reason)
		}
		if q.ulog != nil {
			reason := req.Reason
			if reason == "" {
				reason = "via condor_rm (by user " + shortName(req.Actor) + ")"
			}
			q.ulog.Aborted(ad, reason)
		}
		q.archiveAndDelete(c, p, ad)
		return ArSuccess
	}
	return ArError
}

// stripRunAttrs removes the per-run reconnect bookkeeping (the private claim id
// and lease attributes) from a job leaving the Running state via hold/remove, so
// a stale secret is never archived or left on a non-running job. Mirrors the C++
// schedd deleting ATTR_CLAIM_ID when a job stops running.
func stripRunAttrs(ad *classad.ClassAd) {
	ad.Delete("ClaimId")
	ad.Delete("StartdIpAddr")
	ad.Delete("LastJobLeaseRenewal")
}

// archiveAndDelete appends the flattened ad to history, then removes the job
// from the live queue. Append-then-delete: a crash between the two leaves a
// duplicate in history rather than losing the record.
//
// NB: this runs ON the single-writer scheduler core for a completing job
// (q.Complete). It deliberately does NOT reclaim an exhausted factory's cluster
// ad here: doing so required a full O(N) chained-collection live-proc scan
// (clusterProcCounts) per completion on the core. Factory-cluster reclamation
// now happens off the core, in the materialization engine's sweep
// (MaybeCleanupFactoryCluster), which is nudged when a job leaves the queue --
// keeping the core's completion path cheap.
func (q *Queue) archiveAndDelete(c, p int, ad *classad.ClassAd) {
	_ = q.hist.Append(ad)
	_ = q.hist.Flush()
	q.coll.Delete(jobKey(c, p))
}

// MaybeCleanupFactoryCluster removes an exhausted factory's cluster ad once its
// last materialized proc has left the queue, and drops it from the factory set,
// so the materialization engine stops visiting it (mirrors the C++ schedd's
// ClusterCleanup for a fully-materialized factory). Non-factory cluster ads are
// left untouched. Called OFF the scheduler core, from the materialization engine
// sweep, so the O(N) live-proc scan (FactoryInfo) never runs on the core.
// It returns true iff it removed the factory (so a caller can drop any per-cluster
// cache).
func (q *Queue) MaybeCleanupFactoryCluster(c int) bool {
	if !q.IsFactoryCluster(c) {
		return false
	}
	fi, ok := q.FactoryInfo(c)
	if !ok || fi.TotalProcs > 0 {
		return false
	}
	// No procs remain. Only reclaim once the factory can produce no more (paused
	// or every row/limit consumed); an in-flight factory momentarily at zero
	// procs must keep its cluster ad so materialization can continue.
	done := fi.Paused != 0
	if lim := fi.Limit; lim > 0 && fi.NextProcId >= lim {
		done = true
	}
	if fi.ItemCount > 0 && fi.NextRow >= fi.ItemCount && fi.NextProcId >= fi.NextRow {
		done = true
	}
	if !done {
		return false
	}
	q.factoryMu.Lock()
	q.coll.Delete(jobKey(c, -1))
	q.factoryMu.Unlock()
	q.unnoteFactory(c)
	return true
}

// Complete moves a job to Completed and archives it (used by the scheduler core
// when a job finishes; exercised in later stages).
func (q *Queue) Complete(c, p int) {
	ad, ok := q.Get(c, p)
	if !ok {
		return
	}
	_ = ad.Set("JobStatus", int64(StatusCompleted))
	_ = ad.Set("CompletionDate", nowUnix())
	q.archiveAndDelete(c, p, ad)
}
