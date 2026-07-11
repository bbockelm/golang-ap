// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package shadow implements the shadow side of HTCondor's remote-syscall
// protocol: the request/reply loop a condor_starter drives over the socket
// left over from a successful ACTIVATE_CLAIM. One Shadow owns one activated
// claim connection and one job, serves the starter's pseudo-syscalls
// (get_job_info, register_starter_info, begin_execution, register_job_info,
// ulog, job_exit, ...) until the job finishes, and then winds the claim down
// (DEACTIVATE_CLAIM_JOB_DONE, falling back to graceful DEACTIVATE_CLAIM) and
// releases it.
//
// The wire behavior is a faithful port of the dispatch loop in
// src/condor_shadow.V6.1/NTreceivers.cpp with handler semantics from
// pseudo_ops.cpp; the starter side of the same conversation lives in
// src/condor_starter.V6.1/NTsenders.cpp and jic_shadow.cpp.
package shadow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/startd"
)

// ErrDetached is returned by Run/RunReconnect when the shadow was told to detach
// (a reconnect-preserving schedd shutdown): the serve loop stopped and the
// syscall socket closed, but the claim was left intact so the job keeps running
// and a restarted schedd can reconnect. The scheduler treats it as "leave the
// job Running", not as a completion or a failure.
var ErrDetached = errors.New("shadow: detached for reconnect")

// ErrReconnectFailed wraps any failure to re-establish contact with a running
// job's starter (CA_LOCATE_STARTER / CA_RECONNECT_JOB). RunReconnect returns it
// so the scheduler can requeue the job to Idle without counting a shadow
// exception, mirroring the C++ schedd's reconnect-failure fallback.
var ErrReconnectFailed = errors.New("shadow: reconnect failed")

// Job-exit reason codes from src/condor_includes/exit.h.
const (
	exitCodeOffset = 100
	jobException   = 4  // JOB_EXCEPTION
	dprintfError   = 44 // DPRINTF_ERROR

	// JobExited is the normal "job finished on its own" reason.
	JobExited = 0 + exitCodeOffset // 100
	// JobKilled means the job was forcibly killed.
	JobKilled = 2 + exitCodeOffset // 102
	// JobCoredumped means the job exited on a signal and left a core file.
	JobCoredumped = 3 + exitCodeOffset // 103
	// JobExitedAndClaimClosing is JobExited plus "the claim will close".
	JobExitedAndClaimClosing = 15 + exitCodeOffset // 115
)

// Event types delivered to Config.OnEvent.
const (
	EventStarterInfo     = "starter_info"    // register_starter_info ad
	EventGetJobInfo      = "get_job_info"    // job ad served to the starter
	EventBeginExecution  = "begin_execution" // starter is about to exec the job
	EventJobUpdate       = "job_update"      // register_job_info update ad
	EventJobExit         = "job_exit"        // final update ad from job_exit
	EventJobTermination  = "job_termination" // mock-terminate ad
	EventUlog            = "ulog"            // user-log event ad
	EventNotification    = "event_notification"
	EventGuidanceRequest = "guidance_request"
	EventSetJobAttr      = "set_job_attr"
	EventUnknownOp       = "unknown_op"
)

// Event is a lightweight notification from the serve loop. Ad (and Attr/Expr,
// Op) are set depending on Type. The callback runs synchronously on the serve
// loop; keep it fast.
type Event struct {
	Type string
	Ad   *classad.ClassAd
	Attr string
	Expr string
	Op   int
}

// Result is the outcome of one job run under the shadow.
type Result struct {
	// ExitStatus is the raw wait(2) status the starter reported via job_exit.
	ExitStatus int
	// Reason is the JOB_* reason code (normalized to the >=100 range like
	// pseudo_job_exit does for old starters).
	Reason int
	// ExitAd is the final update ad that accompanied job_exit.
	ExitAd *classad.ClassAd
	// FinalAd is the ad from job_termination, if the starter sent one (it
	// only does on its output-transfer-failure path).
	FinalAd *classad.ClassAd
	// UpdateAd is the most recent register_job_info update ad.
	UpdateAd *classad.ClassAd
}

// ExitedNormally reports whether the job ran to completion on its own.
func (r *Result) ExitedNormally() bool {
	return r.Reason == JobExited || r.Reason == JobExitedAndClaimClosing
}

// ExitCode decodes the wait status into an exit code. ok is false when the
// job died on a signal instead of exiting.
func (r *Result) ExitCode() (code int, ok bool) {
	if r.ExitStatus&0x7f != 0 {
		return 0, false
	}
	return (r.ExitStatus >> 8) & 0xff, true
}

// TermSignal decodes the terminating signal from the wait status; ok is false
// when the job exited normally.
func (r *Result) TermSignal() (sig int, ok bool) {
	if r.ExitStatus&0x7f == 0 {
		return 0, false
	}
	return r.ExitStatus & 0x7f, true
}

// Config configures a Shadow.
type Config struct {
	// JobAd is the job ClassAd served to the starter via get_job_info.
	// Required.
	JobAd *classad.ClassAd
	// ShadowAddr, if set, is published into the get_job_info reply as
	// ShadowIpAddr (a sinful string), mirroring BaseShadow::publishShadowAttrs.
	// The starter uses it to identify (and potentially reconnect to) the
	// shadow.
	ShadowAddr string
	// ShadowVersion, if set, is published as ShadowVersion (a full
	// "$CondorVersion: ...$" string). The starter version-gates several
	// syscalls on it (job_termination >=7.4.4, dprintf_stats >=8.5.8,
	// event_notification >=9.4.1, request_guidance >=24.5.0); leaving it
	// empty keeps the starter on the minimal pre-7.4.4 syscall set.
	ShadowVersion string
	// UIDDomain, if set, is published as UidDomain.
	UIDDomain string
	// Startd, when non-nil, is used by Run to wind down the claim after the
	// job finishes: DEACTIVATE_CLAIM_JOB_DONE (falling back to a graceful
	// DEACTIVATE_CLAIM if the startd predates 24.7), then RELEASE_CLAIM.
	Startd *startd.Client
	// KeepClaim suppresses the RELEASE_CLAIM after deactivation, for callers
	// that will reuse the claim for another job.
	KeepClaim bool
	// ClaimID is the raw startd claim id backing this activation. It is required
	// when TransferEndpoint is set: the reconnect and filetrans security
	// sessions get_sec_session_info hands the starter are derived from it.
	ClaimID string
	// GlobalJobID is the job's GlobalJobId, sent to the startd in a
	// CA_LOCATE_STARTER request during reconnect so it can find the claim.
	// Only used by RunReconnect; taken from JobAd if empty.
	GlobalJobID string
	// ScheddPublicAddr is this schedd's public command sinful, sent to the startd
	// as ScheddIpAddr in a CA_LOCATE_STARTER request. Only used by RunReconnect;
	// defaults to ShadowAddr if empty.
	ScheddPublicAddr string
	// Detach, when set, lets the scheduler tell a running shadow to wind down
	// WITHOUT vacating the claim (a reconnect-preserving schedd shutdown): the
	// serve loop stops, the syscall socket closes, but the claim is neither
	// deactivated nor released, so the starter waits for a reconnecting shadow
	// and the job keeps running. Run/RunReconnect check it after the serve loop
	// and return ErrDetached instead of running the wind-down.
	Detach *atomic.Bool
	// TransferEndpoint, when set, enables stage-4 file transfer: the shadow acts
	// as the file-transfer server for the starter. It generates a TransferKey,
	// registers an input plan / output sink with the endpoint (routed by key),
	// injects TransferKey/TransferSocket into the get_job_info ad, and answers
	// get_sec_session_info with real reconnect + filetrans session material.
	// The endpoint (a cedar server hosting FILETRANS_UPLOAD/DOWNLOAD) is owned
	// by the caller; several shadows may share one.
	TransferEndpoint *Endpoint
	// PrepareJobAd, if set, is invoked on the copy of the job ad about to be
	// served via get_job_info (after the Shadow* and TransferKey/TransferSocket
	// attributes are injected). This is the stage-4 hook: the C++
	// pseudo_get_job_info calls initFileTransfer() here, which is where
	// TransferKey/TransferSocket attributes get added.
	PrepareJobAd func(ad *classad.ClassAd) error
	// OnEvent, if set, receives serve-loop events (synchronously).
	OnEvent func(Event)
	// Logf, if set, receives debug logging (e.g. testing.T.Logf).
	Logf func(format string, args ...any)
	// Privsep, if set, performs the file-transfer per-user filesystem ops as the
	// job Owner: the input sandbox files are READ as the owner (so we never read
	// a file with more privilege than the user has) and the output sandbox lands
	// WRITTEN as the owner (so results are owned by the user, not the schedd
	// uid). nil uses the process-wide native Privsep (droppriv.DefaultPrivsep),
	// which for a personal/unprivileged AP runs as the current user -- identical
	// to the pre-privsep behavior.
	Privsep droppriv.Privsep
}

// Shadow serves one starter over one activated-claim connection. Create it
// with New and drive it with Run. It has no global state; several Shadows can
// run concurrently (stage 6 supervises one goroutine per running job).
type Shadow struct {
	st     *stream.Stream
	closer io.Closer
	cfg    Config

	// transfer holds the stage-4 file-transfer state (nil when transfer is not
	// configured). It is set up in New and torn down after Run.
	transfer *transferState

	mu        sync.Mutex
	starterAd *classad.ClassAd
	updateAd  *classad.ClassAd
	jobAttrs  map[string]string // set_job_attr writes land here
	executing bool
	gotExit   bool
	result    Result
}

// New builds a Shadow serving the given syscall stream. closer, if non-nil,
// is closed by Run when the serve loop finishes (pass the *startd.ActivatedClaim;
// a unit test over a raw pipe can pass nil).
func New(st *stream.Stream, closer io.Closer, cfg Config) (*Shadow, error) {
	if st == nil {
		return nil, fmt.Errorf("shadow: nil stream")
	}
	if cfg.JobAd == nil {
		return nil, fmt.Errorf("shadow: config requires a job ad")
	}
	s := &Shadow{
		st:       st,
		closer:   closer,
		cfg:      cfg,
		jobAttrs: make(map[string]string),
	}
	if cfg.TransferEndpoint != nil {
		ts, err := s.setupTransfer()
		if err != nil {
			return nil, err
		}
		s.transfer = ts
	}
	return s, nil
}

// winddownTimeout bounds the claim wind-down (deactivate + release) when the
// parent context is already dead (the vacate path), so an aborted job cannot
// strand its claim just because the caller's context was canceled.
const winddownTimeout = 10 * time.Second

// Run serves the starter's remote syscalls until the job reports job_exit,
// then closes the syscall connection and, when a startd client is configured,
// deactivates (JOB_DONE, falling back to graceful) and releases the claim.
// It returns the job Result. Cancel ctx to abort the serve loop: the vacate
// path then kicks in, sending DEACTIVATE_CLAIM_FORCIBLY followed by
// RELEASE_CLAIM on a fresh (bounded) context so the slot is not left Claimed.
func (s *Shadow) Run(ctx context.Context) (*Result, error) {
	// If a panic unwinds through the serve loop (e.g. an OnEvent callback), still
	// release the shadow's per-run resources (syscall socket, transfer-endpoint
	// registration) before letting it propagate to the caller's recover.
	finished := false
	defer func() {
		if !finished {
			if s.closer != nil {
				_ = s.closer.Close()
			}
			s.teardownTransfer()
		}
	}()

	serveErr := s.serve(ctx)
	finished = true
	return s.afterServe(ctx, serveErr)
}

// afterServe closes the syscall socket and transfer registration, then decides
// the run's outcome. It is shared by Run (fresh activation) and RunReconnect
// (recovered run). On a reconnect-preserving detach it skips the claim wind-down
// entirely and returns ErrDetached; otherwise it winds the claim down (JOB_DONE
// on a clean exit, forcible vacate when the run was aborted mid-flight).
func (s *Shadow) afterServe(ctx context.Context, serveErr error) (*Result, error) {
	if s.closer != nil {
		_ = s.closer.Close()
	}
	s.teardownTransfer()

	s.mu.Lock()
	gotExit := s.gotExit
	res := s.result
	s.mu.Unlock()

	// Reconnect-preserving shutdown: the scheduler asked us to step away from a
	// still-running job. Do NOT touch the claim -- the starter must keep the job
	// alive for a reconnecting shadow.
	if s.cfg.Detach != nil && s.cfg.Detach.Load() && !gotExit {
		s.logf("shadow: detaching from running job (schedd shutdown); claim left intact for reconnect")
		return nil, ErrDetached
	}

	// Wind down the claim even if the serve loop errored out (after the job
	// finished, or because the caller canceled the run). A canceled context must
	// not strand the claim: give wind-down its own bounded context.
	var windErr error
	if s.cfg.Startd != nil {
		wctx := ctx
		if ctx.Err() != nil {
			var wcancel context.CancelFunc
			wctx, wcancel = context.WithTimeout(context.WithoutCancel(ctx), winddownTimeout)
			defer wcancel()
		}
		// The vacate path: the caller aborted the run before the job finished
		// (condor_rm / condor_hold / shutdown), so kill the job immediately.
		vacate := ctx.Err() != nil && !gotExit
		windErr = s.winddown(wctx, gotExit, vacate)
	}

	if serveErr != nil && !gotExit {
		return nil, serveErr
	}
	if !gotExit {
		return nil, fmt.Errorf("shadow: serve loop ended without a job_exit")
	}
	if windErr != nil {
		return &res, fmt.Errorf("shadow: job finished but claim wind-down failed: %w", windErr)
	}
	return &res, nil
}

// serve runs the syscall dispatch loop until job_exit or an error.
func (s *Shadow) serve(ctx context.Context) error {
	for {
		done, err := s.serveOne(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// winddown deactivates and (unless KeepClaim) releases the claim. On job
// completion the C++ shadow sends DEACTIVATE_CLAIM_JOB_DONE (413) when the
// startd is new enough; we try it first and fall back to the graceful
// DEACTIVATE_CLAIM (403) on any error, matching the brief for older startds.
// On the vacate path (run aborted before the job finished) we instead send
// DEACTIVATE_CLAIM_FORCIBLY (404) so the starter is killed immediately, then
// release; both are best-effort (the startd may already be gone, e.g. on a
// lease expiry).
func (s *Shadow) winddown(ctx context.Context, jobDone, vacate bool) error {
	dt := startd.DeactivateJobDone
	switch {
	case vacate:
		dt = startd.DeactivateForcibly
	case !jobDone:
		dt = startd.DeactivateGraceful
	}
	var derr error
	if _, err := s.cfg.Startd.DeactivateClaim(ctx, dt); err != nil {
		if dt == startd.DeactivateJobDone {
			s.logf("shadow: DEACTIVATE_CLAIM(%d) failed: %v; retrying graceful", dt, err)
			_, derr = s.cfg.Startd.DeactivateClaim(ctx, startd.DeactivateGraceful)
		} else {
			derr = err
		}
		if derr != nil {
			s.logf("shadow: DEACTIVATE_CLAIM(%d) failed: %v", dt, derr)
		}
	}
	if s.cfg.KeepClaim {
		return derr
	}
	if err := s.cfg.Startd.ReleaseClaim(ctx); err != nil {
		return fmt.Errorf("release claim: %w (deactivate error: %v)", err, derr)
	}
	return derr
}

// buildJobInfoAd returns the ad served by get_job_info: a copy of the job ad
// with the shadow attributes BaseShadow::publishShadowAttrs adds (ShadowIpAddr,
// ShadowVersion, UidDomain), run through the PrepareJobAd hook.
func (s *Shadow) buildJobInfoAd() (*classad.ClassAd, error) {
	ad := classad.New()
	for _, name := range s.cfg.JobAd.GetAttributes() {
		if expr, ok := s.cfg.JobAd.Lookup(name); ok {
			ad.InsertExpr(name, expr)
		}
	}
	if s.cfg.ShadowAddr != "" {
		_ = ad.Set("ShadowIpAddr", s.cfg.ShadowAddr)
	}
	if s.cfg.ShadowVersion != "" {
		_ = ad.Set("ShadowVersion", s.cfg.ShadowVersion)
	}
	if s.cfg.UIDDomain != "" {
		_ = ad.Set("UidDomain", s.cfg.UIDDomain)
	}
	// Stage 4: the starter reads TransferKey/TransferSocket from the get_job_info
	// ad to connect back to the shadow's file-transfer server (FileTransfer::Init
	// client side; jic_shadow initWithFileTransfer).
	if s.transfer != nil {
		_ = ad.Set("TransferKey", s.transfer.transKey)
		_ = ad.Set("TransferSocket", s.transfer.transSocket)
	}
	if s.cfg.PrepareJobAd != nil {
		if err := s.cfg.PrepareJobAd(ad); err != nil {
			return nil, err
		}
	}
	return ad, nil
}

// lookupJobAttr serves get_job_attr: attributes written via set_job_attr win,
// then the job ad, unparsed back to ClassAd text.
func (s *Shadow) lookupJobAttr(name string) (string, bool) {
	s.mu.Lock()
	if expr, ok := s.jobAttrs[name]; ok {
		s.mu.Unlock()
		return expr, true
	}
	s.mu.Unlock()
	if expr, ok := s.cfg.JobAd.Lookup(name); ok {
		return expr.String(), true
	}
	return "", false
}

// setJobAttr records a set_job_attr write. Stage 3 keeps them in memory; a
// later stage forwards them to the job queue.
func (s *Shadow) setJobAttr(name, expr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobAttrs[name] = expr
	return nil
}

// JobAttrs returns a copy of the attributes the starter wrote via
// set_job_attr.
func (s *Shadow) JobAttrs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.jobAttrs))
	for k, v := range s.jobAttrs {
		out[k] = v
	}
	return out
}

// StarterAd returns the ad the starter registered, if any.
func (s *Shadow) StarterAd() *classad.ClassAd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starterAd
}

func (s *Shadow) setStarterAd(ad *classad.ClassAd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starterAd = ad
}

func (s *Shadow) setUpdateAd(ad *classad.ClassAd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateAd = ad
	s.result.UpdateAd = ad
	// pseudo_register_job_info: an update carrying JobState implies execution
	// began even if begin_execution was missed (e.g. reconnect).
	if !s.executing {
		if _, ok := ad.Lookup("JobState"); ok {
			s.executing = true
		}
	}
}

func (s *Shadow) markExecuting() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executing = true
}

func (s *Shadow) recordExit(status, reason int, ad *classad.ClassAd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotExit = true
	s.result.ExitStatus = status
	s.result.Reason = reason
	s.result.ExitAd = ad
}

func (s *Shadow) recordTermination(ad *classad.ClassAd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.FinalAd = ad
}

func (s *Shadow) emit(e Event) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(e)
	}
}

func (s *Shadow) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}
