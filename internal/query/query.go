// Package query implements the schedd's QUERY_JOB_ADS (516) and
// QUERY_JOB_ADS_WITH_AUTH (519) command handlers: the wire protocol stock
// condor_q speaks. It reads the query ClassAd, filters the live queue, streams
// each matching (flattened) job ad with ServerTime, and finishes with the
// Owner=0 / MyType="Summary" sentinel ad carrying live job counters.
//
// Framing verified against Scheduler::command_query_job_ads and sendDone in
// src/condor_schedd.V6/schedd.cpp.
package query

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/queue"
)

// Server answers job-ad queries from a queue.
type Server struct {
	q   *queue.Queue
	log *logging.Logger
}

// New builds a query server bound to the given queue.
func New(q *queue.Queue, log *logging.Logger) *Server {
	return &Server{q: q, log: log}
}

// Handle serves one QUERY_JOB_ADS[_WITH_AUTH] request.
func (s *Server) Handle(ctx context.Context, c *cedarserver.Conn) error {
	rm := c.Message
	if rm == nil {
		rm = message.NewMessageFromStream(c.Stream)
	}
	queryAd, err := rm.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("reading query ad: %w", err)
	}

	authUser := ""
	if c.Negotiation != nil {
		authUser = c.Negotiation.User
	}

	query, projection := s.buildQuery(queryAd, authUser)
	sendServerTime := true
	if v, ok := queryAd.EvaluateAttrBool("SendServerTime"); ok {
		sendServerTime = v
	}
	summaryOnly := false
	if v, ok := queryAd.EvaluateAttrBool("SummaryOnly"); ok {
		summaryOnly = v
	}
	limit := -1
	if v, ok := queryAd.EvaluateAttrInt("LimitResults"); ok {
		limit = int(v)
	}
	// condor_q -factory sets IncludeClusterAd (ATTR_QUERY_Q_INCLUDE_CLUSTER_AD) so
	// the schedd also returns the (normally hidden) factory CLUSTER ads carrying
	// the JobMaterialize* bookkeeping; its Requirements carry `ProcId is undefined
	// && JobMaterializeDigestFile isnt undefined` to keep only those. NoProcAds
	// (ATTR_QUERY_Q_NO_PROC_ADS) additionally suppresses the proc scan. Mirrors
	// JOB_QUEUE_ITERATOR_OPT_INCLUDE_CLUSTERS / _NO_PROC_ADS in the C++ schedd's
	// command_query_job_ads.
	includeClusterAds := false
	if v, ok := queryAd.EvaluateAttrBool("IncludeClusterAd"); ok {
		includeClusterAds = v
	}
	noProcAds := false
	if v, ok := queryAd.EvaluateAttrBool("NoProcAds"); ok {
		noProcAds = v
	}

	// Stream each matching job ad as its own CEDAR message (ad + EOM).
	var counts queue.Counts
	if !summaryOnly {
		n := 0
		emit := func(ad *classad.ClassAd) (bool, error) {
			if limit >= 0 && n >= limit {
				return false, nil
			}
			tallyCount(&counts, ad)
			if err := s.streamAd(ctx, c, ad, projection, sendServerTime); err != nil {
				return false, err
			}
			n++
			return true, nil
		}
		if !noProcAds {
			var iter func(func(*classad.ClassAd) bool)
			if query != nil {
				iter = s.q.Query(query)
			} else {
				iter = s.q.Scan()
			}
			for ad := range iter {
				cont, err := emit(ad)
				if err != nil {
					return err
				}
				if !cont {
					break
				}
			}
		}
		// Factory cluster ads (structurally hidden from the proc scan above): only
		// when the query asked for them, and only those passing the query
		// constraint (which for -factory filters to factories).
		if includeClusterAds {
			for ad := range s.q.FactoryClusterAds() {
				if query != nil && !query.Matches(ad) {
					continue
				}
				cont, err := emit(ad)
				if err != nil {
					return err
				}
				if !cont {
					break
				}
			}
		}
	}
	if summaryOnly {
		counts = s.q.Counts()
	}
	return s.sendDone(ctx, c, counts)
}

// buildQuery turns the query ad into a vm.Query (nil = match all) and the
// projection attribute list (nil = all attributes).
func (s *Server) buildQuery(queryAd *classad.ClassAd, authUser string) (*vm.Query, []string) {
	constraint := "true"
	if expr, ok := queryAd.Lookup("Requirements"); ok && expr != nil {
		if str := strings.TrimSpace(expr.String()); str != "" {
			constraint = str
		}
	}

	// Only-my-jobs scoping: when the query carries MyJobs and the caller is not
	// a queue super user, restrict to the caller's own jobs by short owner name.
	ownerClause := ""
	if expr, ok := queryAd.Lookup("MyJobs"); ok && expr != nil {
		mj := strings.TrimSpace(expr.String())
		if mj != "false" && mj != "FALSE" && mj != "0" {
			owner := shortName(authUser)
			if owner != "" && !s.q.IsSuperUser(authUser) {
				ownerClause = fmt.Sprintf("(Owner == %q)", owner)
			}
		}
	}

	full := constraint
	if ownerClause != "" {
		full = "(" + constraint + ") && " + ownerClause
	}

	var query *vm.Query
	if full != "true" && full != "TRUE" {
		if q, err := vm.Parse(full); err == nil {
			query = q
		} else if ownerClause != "" {
			// Fall back to owner-only scoping if the combined expr won't parse.
			if q, err := vm.Parse(ownerClause); err == nil {
				query = q
			}
		}
	}

	var projection []string
	// condor_q sends the projection newline-separated (print_attrs in
	// condor_q.V6/queue.cpp joins the References set with "\n"); accept commas
	// and any whitespace.
	if projStr, ok := queryAd.EvaluateAttrString("Projection"); ok && strings.TrimSpace(projStr) != "" {
		for _, p := range strings.FieldsFunc(projStr, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			if p != "" {
				projection = append(projection, p)
			}
		}
	}
	return query, projection
}

// streamAd writes one job ad (with optional projection whitelist and ServerTime)
// as its own message.
func (s *Server) streamAd(ctx context.Context, c *cedarserver.Conn, ad *classad.ClassAd, projection []string, serverTime bool) error {
	wm := message.NewMessageForStream(c.Stream)
	cfg := &message.PutClassAdConfig{}
	if serverTime {
		cfg.Options |= message.PutClassAdServerTime
	}
	if len(projection) > 0 {
		cfg.Whitelist = projection
	}
	if err := wm.PutClassAdWithOptions(ctx, ad, cfg); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

// sendDone writes the terminating summary ad: Owner=0, ErrorCode=0, ServerTime,
// MyType="Summary", and job counters under the "", "Allusers", and "My" prefixes
// (matching sendDone in schedd.cpp; condor_q keys end-of-results on Owner=0).
func (s *Server) sendDone(ctx context.Context, c *cedarserver.Conn, counts queue.Counts) error {
	ad := classad.New()
	_ = ad.Set("Owner", int64(0))
	_ = ad.Set("ErrorCode", int64(0))
	_ = ad.Set("ServerTime", nowUnix())
	ad.InsertAttrString("MyType", "Summary")
	for _, prefix := range []string{"Allusers", "", "My"} {
		_ = ad.Set(prefix+"Jobs", int64(counts.Total))
		_ = ad.Set(prefix+"Idle", int64(counts.Idle))
		_ = ad.Set(prefix+"Running", int64(counts.Running))
		_ = ad.Set(prefix+"Removed", int64(counts.Removed))
		_ = ad.Set(prefix+"Completed", int64(counts.Completed))
		_ = ad.Set(prefix+"Held", int64(counts.Held))
		_ = ad.Set(prefix+"Suspended", int64(counts.Suspended))
	}
	wm := message.NewMessageForStream(c.Stream)
	if err := wm.PutClassAd(ctx, ad); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

func tallyCount(c *queue.Counts, ad *classad.ClassAd) {
	c.Total++
	st, _ := ad.EvaluateAttrInt("JobStatus")
	switch int(st) {
	case queue.StatusIdle:
		c.Idle++
	case queue.StatusRunning:
		c.Running++
	case queue.StatusRemoved:
		c.Removed++
	case queue.StatusCompleted:
		c.Completed++
	case queue.StatusHeld:
		c.Held++
	case queue.StatusSuspended:
		c.Suspended++
	}
}

func shortName(user string) string {
	if i := strings.IndexByte(user, '@'); i >= 0 {
		return user[:i]
	}
	return user
}

var nowUnix = func() int64 { return time.Now().Unix() }
