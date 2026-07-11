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

package shadow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
)

// Remote syscall numbers, verified against
// src/condor_includes/condor_sys.h in HTCondor.
const (
	opGetDockerCreds      = -85 // CONDOR_get_docker_creds
	opDprintfStats        = -84 // CONDOR_dprintf_stats
	opJobTermination      = -82 // CONDOR_job_termination
	opRegisterJobInfo     = -81 // CONDOR_register_job_info
	opBeginExecution      = -78 // CONDOR_begin_execution
	opRegisterStarterInfo = -77 // CONDOR_register_starter_info
	opGetUserInfo         = -76 // CONDOR_get_user_info
	opGetFileInfoNew      = -74 // CONDOR_get_file_info_new
	opJobExit             = -65 // CONDOR_job_exit
	opGetJobInfo          = -63 // CONDOR_get_job_info
	opUlog                = 284 // CONDOR_ulog
	opGetJobAttr          = 285 // CONDOR_get_job_attr
	opSetJobAttr          = 286 // CONDOR_set_job_attr
	opConstrain           = 287 // CONDOR_constrain
	opGetSecSessionInfo   = 288 // CONDOR_get_sec_session_info
	opGetcreds            = 302 // CONDOR_getcreds
	opGetDelegatedProxy   = 303 // CONDOR_get_delegated_proxy
	opEventNotification   = 304 // CONDOR_event_notification
	opRequestGuidance     = 305 // CONDOR_request_guidance
)

// opName mirrors shadow_syscall_name in NTreceivers.cpp for the ops we know.
func opName(op int) string {
	switch op {
	case opGetDockerCreds:
		return "get_docker_creds"
	case opDprintfStats:
		return "dprintf_stats"
	case opJobTermination:
		return "job_termination"
	case opRegisterJobInfo:
		return "register_job_info"
	case opBeginExecution:
		return "begin_execution"
	case opRegisterStarterInfo:
		return "register_starter_info"
	case opGetUserInfo:
		return "get_user_info"
	case opGetFileInfoNew:
		return "get_file_info_new"
	case opJobExit:
		return "job_exit"
	case opGetJobInfo:
		return "get_job_info"
	case opUlog:
		return "ulog"
	case opGetJobAttr:
		return "get_job_attr"
	case opSetJobAttr:
		return "set_job_attr"
	case opConstrain:
		return "constrain"
	case opGetSecSessionInfo:
		return "get_sec_session_info"
	case opGetcreds:
		return "getcreds"
	case opGetDelegatedProxy:
		return "get_delegated_proxy"
	case opEventNotification:
		return "event_notification"
	case opRequestGuidance:
		return "request_guidance"
	}
	return "unknown"
}

// errnoNoSys is the errno value returned to the starter for syscalls this
// shadow does not implement. ENOSYS on the shadow host; the value is only
// informational to the peer.
const errnoNoSys = 38 // Linux ENOSYS; the starter only logs it

// serveOne reads one remote-syscall request off the stream, dispatches it, and
// sends the reply. It returns done=true when the request was job_exit (the
// C++ shadow's RemoteSyscallResult::ExpectedClose: the last RPC of the run).
//
// Framing (from NTreceivers.cpp / NTsenders.cpp): each request is a single
// CEDAR message [int syscall#, args..., EOM]; each reply is a single CEDAR
// message [int rval, (int terrno if rval<0), payload..., EOM]. ulog is the one
// op with no reply at all.
func (s *Shadow) serveOne(ctx context.Context) (done bool, err error) {
	in := message.NewMessageFromStream(s.st)
	op, err := in.GetInt(ctx)
	if err != nil {
		return false, fmt.Errorf("shadow: reading syscall number: %w", err)
	}
	s.logf("shadow: got request for syscall %s (%d)", opName(op), op)

	switch op {

	case opRegisterStarterInfo:
		// args: ClassAd. reply: rval.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: register_starter_info ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.setStarterAd(ad)
		s.emit(Event{Type: EventStarterInfo, Ad: ad})
		return false, s.replyInt(ctx, 0, 0)

	case opGetJobInfo:
		// args: none. reply: rval + ClassAd (the job ad).
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		ad, err := s.buildJobInfoAd()
		if err != nil {
			s.logf("shadow: get_job_info: preparing job ad failed: %v", err)
			return false, s.replyInt(ctx, -1, errnoNoSys)
		}
		s.emit(Event{Type: EventGetJobInfo, Ad: ad})
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		// The job ad must be sent WITH private attributes: the starter reads
		// TransferKey (a private-V1 attribute) from this ad to connect back to
		// the shadow's file-transfer server. pseudo_get_job_info sends the full
		// job ad; PutClassAd's default redacts private attributes, which would
		// leave the starter's FileTransfer in (wrong) server mode.
		if err := out.PutClassAdWithOptions(ctx, ad, &message.PutClassAdConfig{
			Options: message.PutClassAdIncludePrivate,
		}); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case opGetUserInfo:
		// args: none. reply: rval + ClassAd{Uid, Gid} (pseudo_get_user_info).
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		ad := classad.New()
		_ = ad.Set("Uid", int64(os.Getuid()))
		_ = ad.Set("Gid", int64(os.Getgid()))
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		if err := out.PutClassAd(ctx, ad); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case opBeginExecution:
		// args: none. reply: rval.
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.markExecuting()
		s.emit(Event{Type: EventBeginExecution})
		return false, s.replyInt(ctx, 0, 0)

	case opRegisterJobInfo:
		// args: ClassAd (periodic update ad). reply: rval.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: register_job_info ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.setUpdateAd(ad)
		s.emit(Event{Type: EventJobUpdate, Ad: ad})
		return false, s.replyInt(ctx, 0, 0)

	case opJobExit:
		// args: int status (wait-status), int reason (JOB_* from exit.h),
		// ClassAd (final update ad). reply: rval. Terminates the serve loop
		// (RemoteSyscallResult::ExpectedClose in NTreceivers.cpp).
		status, err := in.GetInt(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: job_exit status: %w", err)
		}
		reason, err := in.GetInt(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: job_exit reason: %w", err)
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: job_exit ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		// pseudo_job_exit: an old starter sends reasons below
		// EXIT_CODE_OFFSET(100); normalize like the C++ shadow does.
		if reason < exitCodeOffset && reason != jobException && reason != dprintfError {
			reason += exitCodeOffset
		}
		s.recordExit(status, reason, ad)
		s.emit(Event{Type: EventJobExit, Ad: ad})
		// The starter closes up shop right after this reply; a send failure
		// here is not fatal to the result.
		if err := s.replyInt(ctx, 0, 0); err != nil {
			s.logf("shadow: reply to job_exit failed (starter already gone?): %v", err)
		}
		return true, nil

	case opJobTermination:
		// args: ClassAd (mock terminate ad; sent by the starter on the
		// output-transfer-failure path). reply: rval.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: job_termination ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.recordTermination(ad)
		s.emit(Event{Type: EventJobTermination, Ad: ad})
		return false, s.replyInt(ctx, 0, 0)

	case opUlog:
		// args: ClassAd (user-log event). NO reply ("caller does not expect a
		// response" per NTreceivers.cpp).
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: ulog ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.logf("shadow: ulog event: %s", adOneLine(ad))
		s.emit(Event{Type: EventUlog, Ad: ad})
		return false, nil

	case opDprintfStats:
		// args: string message. reply: rval (never a terrno, even on error;
		// see NTreceivers CONDOR_dprintf_stats).
		msg, err := in.GetString(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: dprintf_stats message: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.logf("shadow: starter dprintf stats: %s", msg)
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case opEventNotification:
		// args: ClassAd. reply: rval only (no terrno branch in NTreceivers).
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: event_notification ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.logf("shadow: event notification: %s", adOneLine(ad))
		s.emit(Event{Type: EventNotification, Ad: ad})
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case opRequestGuidance:
		// args: ClassAd (request). reply: rval + ClassAd (guidance) -- the ad
		// is sent regardless of rval. We answer GuidanceResult::Command (0)
		// with {Command="CarryOn"}: the starter proceeds with its default
		// behavior for every request type (starter_guidance.cpp treats any
		// unhandled command as "carry on").
		req, err := in.GetClassAd(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: request_guidance ad: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.logf("shadow: guidance requested: %s", adOneLine(req))
		s.emit(Event{Type: EventGuidanceRequest, Ad: req})
		guidance := classad.New()
		_ = guidance.Set("Command", "CarryOn")
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil { // GuidanceResult::Command
			return false, err
		}
		if err := out.PutClassAd(ctx, guidance); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case opGetSecSessionInfo:
		// args: string starter_reconnect_session_info, string
		// starter_filetrans_session_info. reply: rval; on rval<0 terrno; on
		// success 6 strings (reconnect id/info/key, filetrans id/info/key).
		// Stage 3 does not mint transfer/reconnect sessions, so reply -1;
		// JICShadow::initMatchSecuritySession logs and carries on without
		// them. Stage 4 replaces this with real session material.
		if _, err := in.GetString(ctx); err != nil {
			return false, fmt.Errorf("shadow: get_sec_session_info arg 1: %w", err)
		}
		if _, err := in.GetString(ctx); err != nil {
			return false, fmt.Errorf("shadow: get_sec_session_info arg 2: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		if s.transfer == nil {
			s.logf("shadow: get_sec_session_info: declining (file transfer not configured)")
			return false, s.replyInt(ctx, -1, errnoNoSys)
		}
		// Reply the 6 strings the starter's initMatchSecuritySession consumes:
		// reconnect {id, info, key}, filetrans {id, info, key}, in one message,
		// with rval=0 and no terrno (NTreceivers.cpp CONDOR_get_sec_session_info).
		rc := s.transfer.reconnectSession
		ft := s.transfer.filetransSession
		s.logf("shadow: get_sec_session_info: handing starter reconnect+filetrans sessions (filetrans id %s)", ft.id)
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		for _, str := range []string{rc.id, rc.info, rc.key, ft.id, ft.info, ft.key} {
			if err := out.PutString(ctx, str); err != nil {
				return false, err
			}
		}
		return false, out.FinishMessage(ctx)

	case opGetJobAttr:
		// args: string attrname. reply: rval (+terrno) ; on success the
		// unparsed expression string.
		attr, err := in.GetString(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: get_job_attr name: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		expr, ok := s.lookupJobAttr(attr)
		if !ok {
			return false, s.replyInt(ctx, -1, 2 /* ENOENT */)
		}
		out := message.NewMessageForStream(s.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		if err := out.PutString(ctx, expr); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case opSetJobAttr:
		// args: string expr FIRST, then string attrname (NTreceivers reads
		// expr before attrname). reply: rval (+terrno).
		expr, err := in.GetString(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: set_job_attr expr: %w", err)
		}
		attr, err := in.GetString(ctx)
		if err != nil {
			return false, fmt.Errorf("shadow: set_job_attr name: %w", err)
		}
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		if err := s.setJobAttr(attr, expr); err != nil {
			s.logf("shadow: set_job_attr %s=%s rejected: %v", attr, expr, err)
			return false, s.replyInt(ctx, -1, 13 /* EACCES */)
		}
		s.emit(Event{Type: EventSetJobAttr, Attr: attr, Expr: expr})
		return false, s.replyInt(ctx, 0, 0)

	default:
		// Unknown-op policy: the C++ shadow's default case logs the op and
		// "pretends everything's cool" WITHOUT consuming the request's args,
		// which only stays framed because a matched C++ starter never sends
		// an op the shadow lacks. We can do strictly better: every request is
		// one EOM-delimited CEDAR message, so we drain the remainder of the
		// message and reply [rval=-1, terrno=ENOSYS, EOM]. Every
		// request/reply op in NTsenders tolerates rval<0 with no payload; the
		// only reply-less op (ulog) is handled explicitly above.
		s.logf("shadow: unknown syscall %d; draining request and replying ENOSYS", op)
		if err := drain(ctx, in); err != nil {
			return false, err
		}
		s.emit(Event{Type: EventUnknownOp, Op: op})
		return false, s.replyInt(ctx, -1, errnoNoSys)
	}
}

// replyInt sends the standard reply message: rval, plus terrno when rval<0.
func (s *Shadow) replyInt(ctx context.Context, rval, terrno int) error {
	out := message.NewMessageForStream(s.st)
	if err := out.PutInt(ctx, rval); err != nil {
		return err
	}
	if rval < 0 {
		if err := out.PutInt(ctx, terrno); err != nil {
			return err
		}
	}
	return out.FinishMessage(ctx)
}

// drain consumes the remainder of the current request message through its
// end-of-message marker, the equivalent of the C++ end_of_message() in decode
// mode. It keeps the stream framed even if the peer sent args we did not read.
func drain(ctx context.Context, in *message.Message) error {
	for {
		if _, err := in.GetBytes(ctx, 1); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// adOneLine renders a small ad compactly for logs.
func adOneLine(ad *classad.ClassAd) string {
	if ad == nil {
		return "(nil)"
	}
	return ad.String()
}
