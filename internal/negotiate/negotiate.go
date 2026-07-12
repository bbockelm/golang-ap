// Package negotiate implements the schedd side of the NEGOTIATE (416) protocol:
// the inner matchmaking loop a condor_negotiator drives after it locates the
// schedd's Submitter ad. The handler reads the negotiation header, offers the
// submitter's idle jobs as batched resource requests (a resource-request list),
// and, for each PERMISSION_AND_AD the negotiator hands back, forwards the (claim
// id, match ad) to the scheduler core so it can claim the startd and run a shadow.
//
// Wire behavior is a faithful port of ScheddNegotiate (schedd_negotiate.cpp) and
// Scheduler::negotiate (schedd.cpp), driven against the modern
// ResourceRequestList negotiator (matchmaker_negotiate.cpp):
//
//   - header: NEGOTIATE + ClassAd{Owner, AutoClusterAttrs, SubmitterTag, ...} + EOM
//   - inner opcodes, one CEDAR message each:
//     SEND_JOB_INFO(417)                 -> JOB_INFO(419)+ad+EOM | NO_MORE_JOBS(418)+EOM
//     SEND_RESOURCE_REQUEST_LIST(518)+N  -> up to N JOB_INFO ads, then NO_MORE_JOBS
//     PERMISSION_AND_AD(472)             -> secret claim id + match ad (a match!)
//     REJECTED(426) / REJECTED_WITH_REASON(476)
//     END_NEGOTIATE(425)                 -> round over; keep the socket for next cycle
//
// Resource-request-list batching (BuildPrioRecArray + resource_request_list in
// schedd.cpp, sendResourceRequestList/nextJob in schedd_negotiate.cpp): idle jobs
// are streamed from the queue in negotiator priority order and folded into groups
// of consecutive jobs sharing a significant-attribute projection. Each group is
// offered as ONE request carrying ResourceRequestCount = the group size, so the
// negotiator may hand back several matches for a single request. A PERMISSION_AND_AD
// echoes the representative job's _condor_RESOURCE_CLUSTER/PROC; the handler assigns
// that match to the next still-idle job of the group (re-verifying idle against the
// live queue). A REJECTED marks the whole group done for the round.
//
// The negotiator reuses one cached socket across cycles (matchmaker.cpp: on a warm
// socket it writes a bare command int with no re-handshake), so at END_NEGOTIATE we
// Conn.KeepAlive() and return nil: cedar's server then reads the next NEGOTIATE
// command integer on the same encrypted session.
package negotiate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/queue"
	"github.com/bbockelm/golang-ap/internal/stats"
)

// HTCondor resource-request / diagnostic attribute names (condor_attributes.h).
const (
	attrResourceRequestCount   = "_condor_RESOURCE_COUNT"
	attrResourceRequestCluster = "_condor_RESOURCE_CLUSTER"
	attrResourceRequestProc    = "_condor_RESOURCE_PROC"
	attrAutoClusterID          = "AutoClusterId"
	attrWantMatchDiagnostics   = "WantMatchDiagnostics"
	attrWantPslotPreemption    = "WantPslotPreemption"
	attrAutoClusterAttrs       = "AutoClusterAttrs"
)

// alwaysSignificant are the job attributes the schedd always folds into the RRL
// projection regardless of what the negotiator names in AutoClusterAttrs. This
// mirrors the C++ schedd's MinimalSigAttrs (Requirements, Rank, ConcurrencyLimits)
// plus the Request* resources, so jobs differing in a resource ask never collapse
// into one request even if the negotiator's significant-attribute set omits them.
var alwaysSignificant = []string{
	"Requirements", "Rank", "ConcurrencyLimits",
	"RequestCpus", "RequestMemory", "RequestDisk",
}

// Match is one negotiator-granted match handed to the scheduler core.
type Match struct {
	Cluster, Proc int
	ClaimID       string // primary startd claim id
	ExtraClaims   string // space-separated extra claim ids (pslot splitting)
	SlotName      string // matched slot's ATTR_NAME
	MatchAd       *classad.ClassAd
}

// Handler answers NEGOTIATE for one schedd. It reads idle jobs from the queue and
// forwards granted matches to onMatch (the scheduler core's Submit path).
type Handler struct {
	q       *queue.Queue
	log     *logging.Logger
	onMatch func(Match)
	stats   *stats.Collector
}

// New builds a NEGOTIATE handler. onMatch is invoked (from the handler goroutine)
// for every PERMISSION_AND_AD the negotiator sends.
func New(q *queue.Queue, log *logging.Logger, onMatch func(Match)) *Handler {
	return &Handler{q: q, log: log, onMatch: onMatch}
}

// SetStats wires the stats collector so each negotiation round the schedd handles
// is counted (NegotiationCycles). nil-safe.
func (h *Handler) SetStats(s *stats.Collector) { h.stats = s }

// groupState tracks one offered resource-request group for the duration of a
// round: its jobs in priority order, how many have been assigned to matches, and
// whether the negotiator rejected the whole group.
type groupState struct {
	rep       queue.JobID
	acid      int64
	ids       []queue.JobID
	assignIdx int
	rejected  bool
}

// round is the mutable per-negotiation state: the open priority cursor over the
// submitter's idle jobs plus the bookkeeping to reassign batched matches.
type round struct {
	h       *Handler
	owner   string
	next    func() (queue.RequestGroup, bool)
	stop    func()
	byRep   map[queue.JobID]*groupState
	last    *groupState // most recently offered group (for a reasonless REJECTED)
	sent    int
	matched int
}

// Handle serves one NEGOTIATE command (one negotiation round). It runs the inner
// opcode loop until END_NEGOTIATE (then keeps the socket alive for the next cycle)
// or the negotiator closes the connection.
func (h *Handler) Handle(ctx context.Context, c *cedarserver.Conn) error {
	// Header: the leading command int was already consumed (by the handshake on a
	// fresh socket, or by cedar's keepalive read on a warm one). Read the header
	// ClassAd from the same message on a warm socket, or a fresh one otherwise.
	rm := c.Message
	if rm == nil {
		rm = message.NewMessageFromStream(c.Stream)
	}
	header, err := rm.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("negotiate: reading header: %w", err)
	}
	owner, _ := header.EvaluateAttrString("Owner")
	if owner == "" {
		return fmt.Errorf("negotiate: header missing Owner (submitter)")
	}
	projection := buildProjection(header)
	h.stats.IncNegotiationCycles()
	h.log.Info(logging.DestinationGeneral, "NEGOTIATE started",
		"submitter", owner, "remote", c.RemoteAddr, "sig_attrs", strings.Join(projection, ","))

	next, stop := iter.Pull(h.q.IdleRequestGroups(owner, projection))
	r := &round{
		h:     h,
		owner: owner,
		next:  next,
		stop:  stop,
		byRep: map[queue.JobID]*groupState{},
	}
	defer r.stop()

	for {
		msg := message.NewMessageFromStream(c.Stream)
		op, err := msg.GetInt(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				h.log.Debug(logging.DestinationGeneral, "NEGOTIATE socket closed by negotiator", "submitter", owner)
				return nil
			}
			return fmt.Errorf("negotiate: reading opcode: %w", err)
		}

		switch op {
		case commands.SEND_JOB_INFO:
			if err := r.sendRequests(ctx, c, 1); err != nil {
				return err
			}

		case commands.SEND_RESOURCE_REQUEST_LIST:
			n, err := msg.GetInt(ctx)
			if err != nil {
				return fmt.Errorf("negotiate: reading resource-request count: %w", err)
			}
			if err := r.sendRequests(ctx, c, int(n)); err != nil {
				return err
			}

		case commands.PERMISSION_AND_AD:
			m, err := h.readMatch(ctx, msg)
			if err != nil {
				return err
			}
			r.handleMatch(m)

		case commands.REJECTED:
			r.handleReject("")

		case commands.REJECTED_WITH_REASON:
			reason, err := msg.GetString(ctx)
			if err != nil {
				return fmt.Errorf("negotiate: reading reject reason: %w", err)
			}
			// We advertise WantMatchDiagnostics=2 (string, no diagnostics ad), so
			// no ClassAd follows the reason.
			r.handleReject(reason)

		case commands.END_NEGOTIATE:
			h.log.Info(logging.DestinationGeneral, "NEGOTIATE round finished",
				"submitter", owner, "matched", r.matched, "requests_sent", r.sent)
			// Keep the socket for the negotiator's next cycle (it reuses it with a
			// bare NEGOTIATE command int, no re-handshake).
			c.KeepAlive()
			return nil

		default:
			return fmt.Errorf("negotiate: unexpected opcode %d (%s)", op, commands.GetCommandName(op))
		}
	}
}

// buildProjection derives the significant-attribute projection for the round from
// the negotiator's AutoClusterAttrs header (a comma-separated list) unioned with
// the always-significant attributes, order-preserving and de-duplicated.
func buildProjection(header *classad.ClassAd) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	if s, ok := header.EvaluateAttrString(attrAutoClusterAttrs); ok {
		for _, name := range strings.Split(s, ",") {
			add(name)
		}
	}
	for _, name := range alwaysSignificant {
		add(name)
	}
	return out
}

// sendRequests answers a SEND_JOB_INFO (n==1) or SEND_RESOURCE_REQUEST_LIST (n
// requests) by pulling up to n groups off the priority cursor and sending each as
// one JOB_INFO. When the cursor is exhausted mid-batch it sends a single
// NO_MORE_JOBS and stops (matching sendResourceRequestList in schedd_negotiate.cpp).
func (r *round) sendRequests(ctx context.Context, c *cedarserver.Conn, n int) error {
	for i := 0; i < n; i++ {
		g, ok := r.next()
		if !ok {
			return r.sendNoMoreJobs(ctx, c)
		}
		if err := r.sendGroup(ctx, c, g); err != nil {
			return err
		}
	}
	return nil
}

// sendGroup registers a group for match reassignment and sends its representative
// job ad with ResourceRequestCount = the group size.
func (r *round) sendGroup(ctx context.Context, c *cedarserver.Conn, g queue.RequestGroup) error {
	rep := g.JobIDs[0]
	acid := int64(uint32(g.Checksum) & 0x7fffffff)
	gs := &groupState{rep: rep, acid: acid, ids: g.JobIDs}
	r.byRep[rep] = gs
	r.last = gs

	ad := r.h.buildRequestAd(g.Rep, rep, len(g.JobIDs), acid)
	out := message.NewMessageForStream(c.Stream)
	if err := out.PutInt(ctx, commands.JOB_INFO); err != nil {
		return fmt.Errorf("negotiate: sending JOB_INFO: %w", err)
	}
	if err := out.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("negotiate: sending job ad: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("negotiate: finishing JOB_INFO: %w", err)
	}
	r.sent++
	// A batched request (count>1) is logged at Info so the grouping is always
	// visible (and assertable) regardless of debug verbosity; singletons stay quiet.
	logReq := r.h.log.Debug
	if len(g.JobIDs) > 1 {
		logReq = r.h.log.Info
	}
	logReq(logging.DestinationGeneral, "sent resource request",
		"submitter", r.owner, "representative", fmt.Sprintf("%d.%d", rep.Cluster, rep.Proc),
		"count", len(g.JobIDs), "autocluster", acid)
	return nil
}

func (r *round) sendNoMoreJobs(ctx context.Context, c *cedarserver.Conn) error {
	out := message.NewMessageForStream(c.Stream)
	if err := out.PutInt(ctx, commands.NO_MORE_JOBS); err != nil {
		return fmt.Errorf("negotiate: sending NO_MORE_JOBS: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("negotiate: finishing NO_MORE_JOBS: %w", err)
	}
	return nil
}

// handleMatch assigns one PERMISSION_AND_AD to the next still-idle job of the
// group the negotiator matched, then forwards it to the scheduler core. The match
// ad echoes the representative job's _condor_RESOURCE_CLUSTER/PROC; that locates
// the group, and the actual job to run is the next idle member (skipping members
// held/removed since the round began, verified against the live queue).
func (r *round) handleMatch(m Match) {
	rep := queue.JobID{Cluster: m.Cluster, Proc: m.Proc}
	if gs := r.byRep[rep]; gs != nil {
		job, ok := gs.nextIdle(r.h.q)
		if !ok {
			r.h.log.Debug(logging.DestinationGeneral, "match for group with no idle jobs left; releasing",
				"submitter", r.owner, "representative", fmt.Sprintf("%d.%d", rep.Cluster, rep.Proc))
			m.Cluster, m.Proc = -1, -1 // core releases the surplus claim
		} else {
			m.Cluster, m.Proc = job.Cluster, job.Proc
		}
	}
	if m.Cluster >= 0 {
		r.matched++
		r.h.log.Info(logging.DestinationGeneral, "NEGOTIATE match granted",
			"submitter", r.owner, "job", fmt.Sprintf("%d.%d", m.Cluster, m.Proc), "slot", m.SlotName)
	}
	if r.h.onMatch != nil {
		r.h.onMatch(m)
	}
}

// nextIdle returns the next unassigned, still-idle job of the group, advancing the
// assignment cursor past every job it inspects. A group the negotiator rejected
// yields nothing.
func (gs *groupState) nextIdle(q *queue.Queue) (queue.JobID, bool) {
	if gs.rejected {
		return queue.JobID{}, false
	}
	for gs.assignIdx < len(gs.ids) {
		id := gs.ids[gs.assignIdx]
		gs.assignIdx++
		if q.JobStatus(id.Cluster, id.Proc) == queue.StatusIdle {
			return id, true
		}
	}
	return queue.JobID{}, false
}

// handleReject marks the rejected group done for the round. With
// WantMatchDiagnostics set, the negotiator appends "|autocluster|cluster.proc|" to
// the reason, naming the representative job; that identifies the group. A reasonless
// REJECTED (or one without the suffix) falls back to the most recently offered group.
func (r *round) handleReject(reason string) {
	gs := r.last
	if rep, ok := parseRejectRep(reason); ok {
		if g := r.byRep[rep]; g != nil {
			gs = g
		}
	}
	if gs != nil {
		gs.rejected = true
	}
	r.h.log.Debug(logging.DestinationGeneral, "NEGOTIATE request rejected",
		"submitter", r.owner, "reason", trimReason(reason))
}

// buildRequestAd builds the ad offered to the negotiator for a group: the full
// flattened representative job ad plus the attributes sendJobInfo always adds. rep
// is the representative's id (echoed back in matches); count is the group size.
func (h *Handler) buildRequestAd(job *classad.ClassAd, rep queue.JobID, count int, acid int64) *classad.ClassAd {
	ad := classad.New()
	for _, name := range job.GetAttributes() {
		if expr, ok := job.Lookup(name); ok {
			ad.InsertExpr(name, expr)
		}
	}
	_ = ad.Set("ClusterId", int64(rep.Cluster))
	_ = ad.Set("ProcId", int64(rep.Proc))
	_ = ad.Set(attrResourceRequestCount, int64(count))
	_ = ad.Set(attrAutoClusterID, acid)
	_ = ad.Set(attrWantMatchDiagnostics, int64(2))
	_ = ad.Set(attrWantPslotPreemption, true)
	return ad
}

// readMatch reads a PERMISSION_AND_AD body: secret claim id (a string on the
// encrypted session) + the startd match ad. The claim id may carry extra claims
// after a space. The representative job id lives in the match ad's
// _condor_RESOURCE_CLUSTER/PROC.
func (h *Handler) readMatch(ctx context.Context, msg *message.Message) (Match, error) {
	claimBlob, err := msg.GetString(ctx)
	if err != nil {
		return Match{}, fmt.Errorf("negotiate: reading claim id: %w", err)
	}
	matchAd, err := msg.GetClassAd(ctx)
	if err != nil {
		return Match{}, fmt.Errorf("negotiate: reading match ad: %w", err)
	}
	claimID, extra := claimBlob, ""
	if i := strings.IndexByte(claimBlob, ' '); i >= 0 {
		claimID = claimBlob[:i]
		extra = strings.TrimSpace(claimBlob[i+1:])
	}
	m := Match{ClaimID: claimID, ExtraClaims: extra, MatchAd: matchAd, Cluster: -1, Proc: -1}
	if v, ok := matchAd.EvaluateAttrInt(attrResourceRequestCluster); ok {
		m.Cluster = int(v)
	}
	if v, ok := matchAd.EvaluateAttrInt(attrResourceRequestProc); ok {
		m.Proc = int(v)
	}
	m.SlotName, _ = matchAd.EvaluateAttrString("Name")
	return m, nil
}

// parseRejectRep extracts the representative "cluster.proc" from a reject reason of
// the form "reason |autocluster|cluster.proc|" (the suffix the negotiator appends
// when WantMatchDiagnostics is set).
func parseRejectRep(reason string) (queue.JobID, bool) {
	parts := strings.Split(reason, "|")
	if len(parts) < 3 {
		return queue.JobID{}, false
	}
	jid := strings.TrimSpace(parts[2])
	dot := strings.IndexByte(jid, '.')
	if dot < 0 {
		return queue.JobID{}, false
	}
	c, err1 := strconv.Atoi(jid[:dot])
	p, err2 := strconv.Atoi(jid[dot+1:])
	if err1 != nil || err2 != nil {
		return queue.JobID{}, false
	}
	return queue.JobID{Cluster: c, Proc: p}, true
}

// trimReason drops the " |autocluster|cluster.proc|" job-id suffix the negotiator
// appends to a reject reason when WantMatchDiagnostics is set.
func trimReason(reason string) string {
	if i := strings.IndexByte(reason, '|'); i >= 0 {
		return strings.TrimSpace(reason[:i])
	}
	return reason
}
