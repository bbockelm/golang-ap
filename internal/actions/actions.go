// Package actions implements the schedd's ACT_ON_JOBS (478) command handler:
// the wire protocol condor_hold, condor_release, and condor_rm speak.
//
// Framing verified against Scheduler::actOnJobs (src/condor_schedd.V6/schedd.cpp
// ~7430-8080) and DCSchedd::actOnJobs (src/condor_daemon_client/dc_schedd.cpp):
//
//  1. tool -> schedd: command ClassAd (JobAction, ActionResultType, exactly one
//     of ActionConstraint/ActionIds, optional reason attrs) + EOM
//  2. schedd -> tool: result ClassAd (ActionResultType, result_total_<N>,
//     JobAction, ActionResult 0/1, TotalJobAds, IsQueueSuperUser) + EOM
//  3. If nothing succeeded the schedd just closes (no phase 2).
//  4. tool -> schedd: OK int (8-byte CEDAR int, value 1) + EOM
//  5. schedd commits, then -> tool: OK int + EOM.
package actions

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/queue"
)

// JobAction values from the command ad (src/condor_utils/enum_utils.h).
const (
	jaError          = 0
	jaHoldJobs       = 1
	jaReleaseJobs    = 2
	jaRemoveJobs     = 3
	jaRemoveXJobs    = 4
	jaVacateJobs     = 5
	jaVacateFastJobs = 6
	jaClearDirty     = 7
	jaSuspendJobs    = 8
	jaContinueJobs   = 9
)

const wireOK = 1 // HTCondor's OK reply constant

// Server applies job actions against a queue.
type Server struct {
	q   *queue.Queue
	log *logging.Logger
}

// New builds an actions server bound to the given queue.
func New(q *queue.Queue, log *logging.Logger) *Server {
	return &Server{q: q, log: log}
}

// Handle serves one ACT_ON_JOBS request.
func (s *Server) Handle(ctx context.Context, c *cedarserver.Conn) error {
	rm := c.Message
	if rm == nil {
		rm = message.NewMessageFromStream(c.Stream)
	}
	cmdAd, err := rm.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("reading ACT_ON_JOBS command ad: %w", err)
	}

	authUser := ""
	if c.Negotiation != nil {
		authUser = c.Negotiation.User
	}

	actionNum64, ok := cmdAd.EvaluateAttrInt("JobAction")
	if !ok {
		return fmt.Errorf("ACT_ON_JOBS command ad missing JobAction")
	}
	actionNum := int(actionNum64)

	resultType := 0 // AR_TOTALS
	if v, ok := cmdAd.EvaluateAttrInt("ActionResultType"); ok && v == 1 {
		resultType = 1 // AR_LONG
	}

	req := queue.ActionRequest{Actor: authUser}
	var reasonAttr string
	mutating := true
	switch actionNum {
	case jaHoldJobs:
		req.Kind = queue.ActHold
		reasonAttr = "HoldReason"
		if v, ok := cmdAd.EvaluateAttrInt("HoldReasonSubCode"); ok {
			req.HoldReasonSub = int(v)
		}
	case jaReleaseJobs:
		req.Kind = queue.ActRelease
		reasonAttr = "ReleaseReason"
	case jaRemoveJobs:
		req.Kind = queue.ActRemove
		reasonAttr = "RemoveReason"
	case jaRemoveXJobs:
		req.Kind = queue.ActRemoveX
		reasonAttr = "RemoveReason"
	case jaVacateJobs, jaVacateFastJobs, jaSuspendJobs, jaContinueJobs, jaClearDirty:
		// Stage 5: nothing is running to vacate/suspend, and no dirty attrs are
		// tracked, so these politely report zero jobs affected.
		mutating = false
	default:
		return fmt.Errorf("ACT_ON_JOBS: invalid JobAction %d", actionNum)
	}
	if reasonAttr != "" {
		if r, ok := cmdAd.EvaluateAttrString(reasonAttr); ok && r != "" {
			// Match the C++: annotate the reason with who did it.
			req.Reason = r + " (by user " + authUser + ")"
		}
	}

	// Resolve the target job list: exactly one of ActionConstraint / ActionIds.
	var targets [][2]int
	constraintExpr, hasConstraint := cmdAd.Lookup("ActionConstraint")
	idsStr, hasIDs := cmdAd.EvaluateAttrString("ActionIds")
	if hasConstraint && hasIDs {
		return fmt.Errorf("ACT_ON_JOBS: both ActionConstraint and ActionIds present")
	}
	switch {
	case hasConstraint && constraintExpr != nil:
		targets = s.matchConstraint(constraintExpr.String())
	case hasIDs:
		targets = s.parseIDs(idsStr)
	default:
		return fmt.Errorf("ACT_ON_JOBS: neither ActionConstraint nor ActionIds present")
	}

	// Phase 1: validate every target without mutating, build the result ad.
	codes := make([]int, len(targets))
	totals := map[int]int{}
	numSuccess := 0
	for i, t := range targets {
		code := queue.ArBadStatus
		if mutating {
			code = s.q.CheckAction(t[0], t[1], req)
		}
		codes[i] = code
		totals[code]++
		if code == queue.ArSuccess {
			numSuccess++
		}
	}

	resultAd := classad.New()
	_ = resultAd.Set("ActionResultType", int64(resultType))
	if resultType == 1 {
		// AR_LONG: per-job attributes job_<cluster>_<proc> = <code>.
		for i, t := range targets {
			_ = resultAd.Set(fmt.Sprintf("job_%d_%d", t[0], t[1]), int64(codes[i]))
		}
	} else {
		for code := queue.ArError; code <= queue.ArLimitExceeded; code++ {
			_ = resultAd.Set(fmt.Sprintf("result_total_%d", code), int64(totals[code]))
		}
	}
	_ = resultAd.Set("JobAction", int64(actionNum))
	actionResult := 0
	if numSuccess > 0 {
		actionResult = 1
	}
	_ = resultAd.Set("ActionResult", int64(actionResult))
	_ = resultAd.Set("TotalJobAds", int64(s.q.Counts().Total))
	_ = resultAd.Set("IsQueueSuperUser", s.q.IsSuperUser(authUser))

	wm := message.NewMessageForStream(c.Stream)
	if err := wm.PutClassAd(ctx, resultAd); err != nil {
		return err
	}
	if err := wm.FinishMessage(ctx); err != nil {
		return err
	}

	if numSuccess == 0 {
		// Nothing to do: the C++ schedd aborts here without a second phase.
		return nil
	}

	// Phase 2: wait for the tool's ack, then commit the changes.
	ackMsg := message.NewMessageFromStream(c.Stream)
	ack, err := ackMsg.GetInt(ctx)
	if err != nil || ack != wireOK {
		s.log.Warn(logging.DestinationGeneral, "ACT_ON_JOBS: tool did not ack; aborting action",
			"err", errString(err), "ack", ack)
		return nil
	}

	for i, t := range targets {
		if codes[i] == queue.ArSuccess {
			s.q.ApplyAction(t[0], t[1], req)
		}
	}

	fin := message.NewMessageForStream(c.Stream)
	if err := fin.PutInt(ctx, wireOK); err != nil {
		return err
	}
	return fin.FinishMessage(ctx)
}

// matchConstraint returns the (cluster, proc) ids of live jobs matching the
// constraint expression.
func (s *Server) matchConstraint(constraint string) [][2]int {
	var out [][2]int
	collect := func(ad *classad.ClassAd) {
		cv, cok := ad.EvaluateAttrInt("ClusterId")
		pv, pok := ad.EvaluateAttrInt("ProcId")
		if cok && pok {
			out = append(out, [2]int{int(cv), int(pv)})
		}
	}
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "true" || constraint == "TRUE" {
		for ad := range s.q.Scan() {
			collect(ad)
		}
		return out
	}
	q, err := vm.Parse(constraint)
	if err != nil {
		return nil
	}
	for ad := range s.q.Query(q) {
		collect(ad)
	}
	return out
}

// parseIDs expands a comma/space separated id list ("2.0, 3.1, 4") into
// (cluster, proc) pairs; a bare cluster id expands to all of its live procs.
func (s *Server) parseIDs(ids string) [][2]int {
	var out [][2]int
	for _, tok := range strings.FieldsFunc(ids, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if tok == "" {
			continue
		}
		if dot := strings.IndexByte(tok, '.'); dot >= 0 {
			c, err1 := strconv.Atoi(tok[:dot])
			p, err2 := strconv.Atoi(tok[dot+1:])
			if err1 == nil && err2 == nil {
				out = append(out, [2]int{c, p})
			}
			continue
		}
		cid, err := strconv.Atoi(tok)
		if err != nil {
			continue
		}
		for ad := range s.q.Scan() {
			cv, cok := ad.EvaluateAttrInt("ClusterId")
			pv, pok := ad.EvaluateAttrInt("ProcId")
			if cok && pok && int(cv) == cid {
				out = append(out, [2]int{cid, int(pv)})
			}
		}
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
