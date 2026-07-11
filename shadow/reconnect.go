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

// This file implements the shadow's reconnect path: how a freshly (re)started
// schedd re-attaches to a job still running on a C++ starter, instead of the
// job being requeued. It is a faithful port of the C++ shadow reconnect flow
// (src/condor_shadow.V6.1/remoteresource.cpp: attemptReconnect /
// locateReconnectStarter / requestReconnect) plus the two ClassAd commands it
// rides (src/condor_daemon_client/dc_startd.cpp DCStartd::locateStarter,
// dc_starter.cpp DCStarter::reconnect, framed by Daemon::sendCACmd).
//
// The wire protocol (all connections dialed shadow -> execute machine, both
// resuming the claim/reconnect security session derived from the claim id):
//
//  1. CA_LOCATE_STARTER to the STARTD (addr from the claim id): the startd is a
//     directory that returns the current StarterIpAddr for our GlobalJobId.
//  2. CA_RECONNECT_JOB to the STARTER (addr from step 1): the very socket we dial
//     with becomes the new remote-syscall socket (the starter adopts it; it never
//     dials back). We hand the starter a fresh TransferKey/TransferSocket so
//     output transfer works against this schedd's file-transfer endpoint.
//
// Both are DaemonCore command CA_CMD (1200) carrying the real sub-command as the
// ATTR_COMMAND string inside a request ClassAd; the reply is a ClassAd whose
// ATTR_RESULT is "Success" on success (src/condor_utils/command_strings.h).
package shadow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// CA command wire constants (src/condor_includes/condor_commands.h,
// command_strings.cpp/.h). CA_LOCATE_STARTER and CA_RECONNECT_JOB both ride the
// non-authenticated CA_CMD DaemonCore command; the sub-command travels as the
// ATTR_COMMAND string in the request ad.
const (
	caCmd              = 1200 // CA_CMD_BASE
	caLocateStarterCmd = "CA_LOCATE_STARTER"
	caReconnectJobCmd  = "CA_RECONNECT_JOB"
	caResultSuccess    = "Success" // getCAResultString(CA_SUCCESS)
)

// NewReconnect builds a reconnect-mode Shadow: one with no syscall stream yet
// (RunReconnect establishes it via the CA_RECONNECT_JOB handshake). File
// transfer is mandatory here -- the reconnect handshake must hand the starter a
// fresh TransferKey/TransferSocket -- so a TransferEndpoint and ClaimID are
// required. It sets up the transfer route (and imports the derived filetrans
// session) exactly like New; RunReconnect then dials the starter and serves.
func NewReconnect(cfg Config) (*Shadow, error) {
	if cfg.JobAd == nil {
		return nil, fmt.Errorf("shadow: reconnect config requires a job ad")
	}
	if cfg.TransferEndpoint == nil {
		return nil, fmt.Errorf("shadow: reconnect requires a transfer endpoint")
	}
	if cfg.ClaimID == "" {
		return nil, fmt.Errorf("shadow: reconnect requires a claim id")
	}
	s := &Shadow{
		cfg:      cfg,
		jobAttrs: make(map[string]string),
	}
	ts, err := s.setupTransfer()
	if err != nil {
		return nil, err
	}
	s.transfer = ts
	return s, nil
}

// DefaultReconnectWindow bounds how long RunReconnect keeps retrying transient
// reconnect failures (startd not answering, starter address not yet known to the
// startd). The C++ shadow retries until the job lease expires (up to 2400s); we
// bound the window so a truly-gone startd requeues the job promptly, per the
// schedd's recovery policy. The lease deadline still applies when shorter.
const DefaultReconnectWindow = 45 * time.Second

// permanentReconnectError marks a reconnect failure that retrying cannot fix:
// the startd/starter answered and said no (claim or job not found, request
// refused). Mirrors the C++ CA_FAILURE / CA_NOT_AUTHENTICATED give-up cases in
// RemoteResource::locateReconnectStarter.
type permanentReconnectError struct{ err error }

func (e *permanentReconnectError) Error() string { return e.err.Error() }
func (e *permanentReconnectError) Unwrap() error { return e.err }

// RunReconnect re-attaches to a job already running on its starter, then serves
// the remote syscalls until the job reports job_exit (or the run is aborted),
// reusing the same tail as Run (Result decoding, claim wind-down or detach).
//
// Transient handshake failures are retried with the C++ shadow's backoff
// (immediate first try, then ceil(2^(n+2))s capped) until the retry window or
// the job lease expires; a definitive refusal (claim/job not found) gives up
// immediately. On failure it returns an error wrapping ErrReconnectFailed and
// leaves the claim untouched, so the caller can requeue the job to Idle without
// counting a shadow exception.
func (s *Shadow) RunReconnect(ctx context.Context) (*Result, error) {
	if err := s.establishReconnectWithRetry(ctx); err != nil {
		// Drop the transfer route we registered in NewReconnect; the run never
		// started.
		s.teardownTransfer()
		return nil, fmt.Errorf("%w: %v", ErrReconnectFailed, err)
	}

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

// establishReconnectWithRetry drives establishReconnect under the C++ shadow's
// retry policy (BaseShadow::nextReconnectDelay): attempt immediately, then back
// off ceil(2^(attempts+2)) seconds (capped), until the retry window -- or the
// persisted job lease, when shorter -- expires. Permanent refusals abort the
// loop at once.
func (s *Shadow) establishReconnectWithRetry(ctx context.Context) error {
	deadline := time.Now().Add(DefaultReconnectWindow)
	// The job lease is the hard upper bound (the startd reaps the claim after
	// it); never retry past it.
	if dur, ok := s.cfg.JobAd.EvaluateAttrInt("JobLeaseDuration"); ok && dur > 0 {
		if renewal, ok := s.cfg.JobAd.EvaluateAttrInt("LastJobLeaseRenewal"); ok && renewal > 0 {
			if leaseEnd := time.Unix(renewal+dur, 0); leaseEnd.Before(deadline) {
				deadline = leaseEnd
			}
		}
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		lastErr = s.establishReconnect(ctx)
		if lastErr == nil {
			return nil
		}
		var perm *permanentReconnectError
		if errors.As(lastErr, &perm) {
			s.logf("shadow: reconnect refused definitively: %v", lastErr)
			return lastErr
		}
		// nextReconnectDelay: 2^(attempts+2) seconds, capped (C++ ceiling is
		// 300s; our bounded window makes a smaller cap moot).
		delay := time.Duration(1<<uint(attempt+2)) * time.Second
		if delay > 32*time.Second {
			delay = 32 * time.Second
		}
		if time.Now().Add(delay).After(deadline) {
			s.logf("shadow: reconnect retry window exhausted: %v", lastErr)
			return lastErr
		}
		s.logf("shadow: reconnect attempt %d failed (%v); retrying in %s", attempt+1, lastErr, delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// establishReconnect performs the two-command reconnect handshake and, on
// success, installs the live starter connection as this shadow's syscall stream.
func (s *Shadow) establishReconnect(ctx context.Context) error {
	startdAddr := claimSinful(s.cfg.ClaimID)
	if startdAddr == "" {
		return fmt.Errorf("claim id carries no startd address")
	}

	// Import the claim-derived security session into a private cache. The same
	// session id authenticates BOTH the CA_LOCATE_STARTER to the startd (it made
	// the claim) and the CA_RECONNECT_JOB to the starter (which registered this
	// id as its reconnect session when we first activated the claim).
	cache := security.NewSessionCache()
	sesid, err := security.ImportClaimSession(cache, s.cfg.ClaimID, security.ClaimSessionOptions{
		PeerAddr: startdAddr,
	})
	if err != nil {
		return fmt.Errorf("import claim session: %w", err)
	}

	starterAddr, err := s.caLocateStarter(ctx, cache, sesid, startdAddr)
	if err != nil {
		return fmt.Errorf("locate starter: %w", err)
	}
	if starterAddr == "" {
		return fmt.Errorf("startd returned no starter address")
	}
	s.logf("shadow: reconnect located starter at %s", starterAddr)

	hc, err := s.caReconnectJob(ctx, cache, sesid, starterAddr)
	if err != nil {
		return fmt.Errorf("reconnect to starter: %w", err)
	}
	s.st = hc.GetStream()
	s.closer = hc
	s.logf("shadow: reconnect accepted by starter %s; resuming syscall serve", starterAddr)
	return nil
}

// caLocateStarter sends CA_LOCATE_STARTER to the startd and returns the current
// starter address (ATTR_STARTER_IP_ADDR) it reports for our job.
func (s *Shadow) caLocateStarter(ctx context.Context, cache *security.SessionCache, sesid, startdAddr string) (string, error) {
	hc, err := caConnect(ctx, cache, sesid, startdAddr)
	if err != nil {
		return "", err
	}
	defer func() { _ = hc.Close() }()

	gjid := s.cfg.GlobalJobID
	if gjid == "" {
		gjid, _ = s.cfg.JobAd.EvaluateAttrString("GlobalJobId")
	}
	scheddAddr := s.cfg.ScheddPublicAddr
	if scheddAddr == "" {
		scheddAddr = s.cfg.ShadowAddr
	}

	req := caRequest(caLocateStarterCmd)
	// ATTR_CLAIM_ID is a private attribute; it must ride in the request so the
	// startd can find the claim (getClaimByGlobalJobIdAndId).
	_ = req.Set("ClaimId", s.cfg.ClaimID)
	if gjid != "" {
		_ = req.Set("GlobalJobId", gjid)
	}
	if scheddAddr != "" {
		_ = req.Set("ScheddIpAddr", scheddAddr)
	}

	reply, err := sendCACmd(ctx, hc.GetStream(), req)
	if err != nil {
		return "", err
	}
	if err := caCheckResult(reply); err != nil {
		// The startd answered and said no: the claim/job is gone (CA_FAILURE in
		// caLocateStarter). Retrying cannot fix this -- requeue.
		return "", &permanentReconnectError{err}
	}
	addr, _ := reply.EvaluateAttrString("StarterIpAddr")
	return addr, nil
}

// caReconnectJob sends CA_RECONNECT_JOB to the starter and, on success, returns
// the live connection whose stream becomes the new remote-syscall socket. The
// request carries the shadow attributes (ShadowIpAddr etc.) and the fresh
// TransferKey/TransferSocket the starter uses to re-point file transfer at this
// schedd's endpoint.
func (s *Shadow) caReconnectJob(ctx context.Context, cache *security.SessionCache, sesid, starterAddr string) (*client.HTCondorClient, error) {
	hc, err := caConnect(ctx, cache, sesid, starterAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = hc.Close()
		}
	}()

	req := caRequest(caReconnectJobCmd)
	// BaseShadow::publishShadowAttrs.
	if s.cfg.ShadowAddr != "" {
		_ = req.Set("ShadowIpAddr", s.cfg.ShadowAddr)
	}
	if s.cfg.ShadowVersion != "" {
		_ = req.Set("ShadowVersion", s.cfg.ShadowVersion)
	}
	if s.cfg.UIDDomain != "" {
		_ = req.Set("UidDomain", s.cfg.UIDDomain)
	}
	// The starter re-establishes its FileTransfer client from these (jic_shadow
	// reconnect -> filetrans->changeServer). TransferKey is private.
	if s.transfer != nil {
		_ = req.Set("TransferKey", s.transfer.transKey)
		_ = req.Set("TransferSocket", s.transfer.transSocket)
	}

	reply, err := sendCACmd(ctx, hc.GetStream(), req)
	if err != nil {
		return nil, err
	}
	if err := caCheckResult(reply); err != nil {
		// The starter answered and refused the reconnect; retrying with the same
		// request will not change its mind.
		return nil, &permanentReconnectError{err}
	}
	ok = true
	return hc, nil
}

// caConnect opens an authenticated connection to addr that resumes the claim
// session (bypassing negotiation) for the CA_CMD command.
func caConnect(ctx context.Context, cache *security.SessionCache, sesid, addr string) (*client.HTCondorClient, error) {
	sec := &security.SecurityConfig{
		Command:      caCmd,
		PeerName:     addr,
		SessionCache: cache,
		SessionID:    sesid,
	}
	hc, err := client.ConnectAndAuthenticate(ctx, addr, sec)
	if err != nil {
		return nil, fmt.Errorf("connect/resume claim session to %s: %w", addr, err)
	}
	return hc, nil
}

// caRequest builds the base CA request ad: the command adtype markers plus the
// ATTR_COMMAND sub-command string (Daemon::sendCACmd / getCommandString).
func caRequest(command string) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString("MyType", "Command")
	ad.InsertAttrString("TargetType", "Reply")
	ad.InsertAttrString("Command", command)
	return ad
}

// sendCACmd writes the request ad (with private attributes -- ClaimId /
// TransferKey must not be redacted) and reads the reply ad, mirroring the
// putClassAd + end_of_message / getClassAd + end_of_message exchange in
// Daemon::sendCACmd.
func sendCACmd(ctx context.Context, st *stream.Stream, req *classad.ClassAd) (*classad.ClassAd, error) {
	out := message.NewMessageForStream(st)
	if err := out.PutClassAdWithOptions(ctx, req, &message.PutClassAdConfig{
		Options: message.PutClassAdIncludePrivate,
	}); err != nil {
		return nil, fmt.Errorf("send CA request: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("finish CA request: %w", err)
	}
	in := message.NewMessageFromStream(st)
	reply, err := in.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("read CA reply: %w", err)
	}
	if err := drain(ctx, in); err != nil {
		return nil, fmt.Errorf("drain CA reply: %w", err)
	}
	return reply, nil
}

// caCheckResult fails unless the reply's ATTR_RESULT is "Success".
func caCheckResult(reply *classad.ClassAd) error {
	result, _ := reply.EvaluateAttrString("Result")
	if result == caResultSuccess {
		return nil
	}
	errStr, _ := reply.EvaluateAttrString("ErrorString")
	if errStr != "" {
		return fmt.Errorf("CA command result %q: %s", result, errStr)
	}
	return fmt.Errorf("CA command result %q", result)
}

// claimSinful returns the startd command address at the head of a claim id
// (everything before the first '#').
func claimSinful(claimID string) string {
	for i := 0; i < len(claimID); i++ {
		if claimID[i] == '#' {
			return claimID[:i]
		}
	}
	return ""
}
