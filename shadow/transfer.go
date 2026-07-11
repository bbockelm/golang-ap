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

// This file implements the shadow's role as HTCondor's file-transfer *server*:
// the endpoint a stock condor_starter connects back to (FILETRANS_UPLOAD /
// FILETRANS_DOWNLOAD) to pull the input sandbox and push the output sandbox.
//
// The wire protocol is driven by golang-htcondor/filetransfer (the shared
// stream core). This file adds the shadow-specific glue:
//
//   - Endpoint: a cedar command server, shared across shadows, that dispatches
//     inbound FILETRANS_* connections to the owning shadow by TransferKey.
//   - the security sessions: the starter resumes the derived "filetrans." claim
//     session on its inbound connection, so the endpoint's session cache must
//     hold it (ImportFileTransferSession). get_sec_session_info hands the
//     starter the material to build the matching session (remoteresource.cpp).
//   - the transfer plan/sink: the input file list (executable + TransferInput)
//     the shadow uploads, and the sink that lands the output sandbox in Iwd.
//
// C++ ground truth: src/condor_utils/file_transfer.cpp (Init/DoUpload/DoDownload,
// TransferKey/TransferSocket), src/condor_shadow.V6.1/remoteresource.cpp
// (filetrans session derivation), src/condor_starter.V6.1/jic_shadow.cpp
// (initMatchSecuritySession, beginInputTransfer/transferOutput).

package shadow

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/filetransfer"
)

// stdout/stderr sandbox names the starter transfers back (file_transfer.cpp
// StdoutRemapName/StderrRemapName). The shadow remaps them to the job's
// requested Out/Err on download.
const (
	stdoutRemapName = "_condor_stdout"
	stderrRemapName = "_condor_stderr"
)

// transferSeq backs the TransferKey sequence number (SequenceNum in C++). It is
// process-global and only needs to be unique, not secret.
var transferSeq atomic.Uint64

// generateTransferKey builds a TransferKey in the C++ format
// "%x#%llx%x%x" (FileTransfer::Init): sequence#, time, and two random 32-bit
// values. The value is opaque; it only needs to be unique and to round-trip
// through the job ad and back on the inbound connection.
func generateTransferKey() string {
	var r [8]byte
	_, _ = rand.Read(r[:])
	seq := transferSeq.Add(1)
	return fmt.Sprintf("%x#%x%x%x",
		seq,
		uint64(time.Now().Unix()),
		binary.BigEndian.Uint32(r[0:4]),
		binary.BigEndian.Uint32(r[4:8]))
}

// transferRoute is one shadow's file-transfer state, looked up by TransferKey
// when the starter connects.
type transferRoute struct {
	plan filetransfer.SendPlan // input files the shadow uploads
	sink filetransfer.Sink     // where the output sandbox lands
	logf func(format string, args ...any)

	// spooled marks a job whose ad was rewritten for input spooling
	// (condor_submit -spool): its Iwd IS the schedd's per-job spool sandbox, so
	// the input plan sources from spool and the output sandbox lands back in
	// spool for a later condor_transfer_data. cluster/proc identify the job for
	// the endpoint's OutputRecorder.
	spooled       bool
	cluster, proc int
}

// Endpoint is a cedar command server hosting FILETRANS_UPLOAD / FILETRANS_DOWNLOAD
// for one or more shadows. In the integration test each test owns an Endpoint;
// in stage 6 the schedd's shared cedar server hosts the same two commands and
// routes by TransferKey across every running shadow.
//
// The endpoint's session cache must be the cache the shadow imports the
// derived "filetrans." session into (NewEndpoint takes it), so the starter's
// session-resumed inbound connection is recognized.
type Endpoint struct {
	srv    *cedarserver.Server
	cache  *security.SessionCache
	logf   func(format string, args ...any)
	sinful atomic.Value // string

	mu     sync.Mutex
	routes map[string]*transferRoute

	// outputRecorder, if set (SetOutputRecorder), is invoked after a spooled
	// job's output sandbox lands (FILETRANS_DOWNLOAD) with the top-level output
	// file names received. The schedd records them as the job's
	// SpooledOutputFiles, mirroring the C++ starter's spooled-files report
	// (jic_shadow.cpp:753) that condor_transfer_data later uses to pick the
	// files to return.
	outputRecorder atomic.Value // func(cluster, proc int, files []string)
}

// SetOutputRecorder installs the hook invoked with the output files received
// for a spooled job (see outputRecorder). Safe to call before Serve.
func (ep *Endpoint) SetOutputRecorder(fn func(cluster, proc int, files []string)) {
	ep.outputRecorder.Store(fn)
}

// NewEndpoint builds an Endpoint over the given session cache (the same cache
// the shadow imports its filetrans session into) and cedar security config. If
// secConfig is nil a default match-password/AES config using cache is built.
// logf, if non-nil, receives endpoint debug logging.
func NewEndpoint(cache *security.SessionCache, secConfig *security.SecurityConfig, logf func(string, ...any)) *Endpoint {
	if cache == nil {
		cache = security.NewSessionCache()
	}
	if secConfig == nil {
		secConfig = &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: security.SecurityOptional,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			SessionCache:   cache,
		}
	} else {
		secConfig.SessionCache = cache
	}
	ep := &Endpoint{
		srv:    cedarserver.New(secConfig),
		cache:  cache,
		logf:   logf,
		routes: map[string]*transferRoute{},
	}
	ep.srv.Handle(commands.FILETRANS_UPLOAD, ep.handleUpload, "WRITE")
	ep.srv.Handle(commands.FILETRANS_DOWNLOAD, ep.handleDownload, "WRITE")
	return ep
}

// NewSharedEndpoint builds a file-transfer router hosted on an existing cedar
// command server (the schedd's shared command port) rather than one it owns. It
// registers FILETRANS_UPLOAD / FILETRANS_DOWNLOAD on srv and reports sinful as
// its command address (the schedd's real command sinful, which every shadow
// injects into its job ad as TransferSocket). cache must be the same session
// cache srv authenticates against, so each shadow's imported "filetrans." session
// is recognized when the starter resumes it on its inbound connection.
func NewSharedEndpoint(srv *cedarserver.Server, cache *security.SessionCache, sinful string, logf func(string, ...any)) *Endpoint {
	if cache == nil {
		cache = security.NewSessionCache()
	}
	ep := &Endpoint{
		srv:    srv,
		cache:  cache,
		logf:   logf,
		routes: map[string]*transferRoute{},
	}
	ep.sinful.Store(sinful)
	srv.Handle(commands.FILETRANS_UPLOAD, ep.handleUpload, "WRITE")
	srv.Handle(commands.FILETRANS_DOWNLOAD, ep.handleDownload, "WRITE")
	return ep
}

// Cache returns the endpoint's session cache.
func (ep *Endpoint) Cache() *security.SessionCache { return ep.cache }

// Serve records the endpoint's command sinful (derived from ln's address) and
// serves inbound FILETRANS_* connections until ctx is cancelled. Run it in a
// goroutine before any shadow injects a TransferSocket pointing at it.
func (ep *Endpoint) Serve(ctx context.Context, ln net.Listener) error {
	ep.sinful.Store(sinfulString(ln.Addr()))
	return ep.srv.Serve(ctx, ln)
}

// Sinful returns the endpoint's command address as an HTCondor sinful string
// ("<ip:port>"), the value injected into a job ad as TransferSocket.
func (ep *Endpoint) Sinful() string {
	if v, ok := ep.sinful.Load().(string); ok {
		return v
	}
	return ""
}

func (ep *Endpoint) register(key string, r *transferRoute) {
	ep.mu.Lock()
	ep.routes[key] = r
	ep.mu.Unlock()
}

func (ep *Endpoint) unregister(key string) {
	ep.mu.Lock()
	delete(ep.routes, key)
	ep.mu.Unlock()
}

func (ep *Endpoint) lookup(key string) *transferRoute {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.routes[key]
}

// readTransKey reads the leading put_secret(TransKey) + end_of_message the
// starter sends after startCommand(FILETRANS_*). On the encrypted filetrans
// session get_secret is an ordinary string read.
func (ep *Endpoint) readTransKey(ctx context.Context, c *cedarserver.Conn) (string, error) {
	in := message.NewMessageFromStream(c.Stream)
	key, err := in.GetString(ctx)
	if err != nil {
		return "", fmt.Errorf("read TransferKey: %w", err)
	}
	// Consume the rest of the request message (its end-of-message marker) so the
	// transfer stream starts on a clean frame boundary.
	for {
		if _, err := in.GetBytes(ctx, 1); err != nil {
			break
		}
	}
	return key, nil
}

// handleUpload serves FILETRANS_UPLOAD: the starter is pulling the input
// sandbox, so the shadow (server) SENDS the route's plan.
func (ep *Endpoint) handleUpload(ctx context.Context, c *cedarserver.Conn) error {
	err := ep.doUpload(ctx, c)
	if err != nil {
		ep.log("shadow: FILETRANS_UPLOAD handler error: %v", err)
	}
	return err
}

func (ep *Endpoint) doUpload(ctx context.Context, c *cedarserver.Conn) error {
	key, err := ep.readTransKey(ctx, c)
	if err != nil {
		return err
	}
	route := ep.lookup(key)
	if route == nil {
		return fmt.Errorf("filetransfer endpoint: no route for upload TransferKey %q", key)
	}
	route.logf("shadow: FILETRANS_UPLOAD: sending %d input entries", len(route.plan.Files))
	return filetransfer.ServeUpload(ctx, c.Stream, route.plan, filetransfer.Options{Logf: route.logf})
}

func (ep *Endpoint) log(format string, args ...any) {
	if ep.logf != nil {
		ep.logf(format, args...)
	}
}

// handleDownload serves FILETRANS_DOWNLOAD: the starter is pushing the output
// sandbox, so the shadow (server) RECEIVES into the route's sink. A modern
// starter performs the final TransferAck exchange, so ReceiveAck is set.
func (ep *Endpoint) handleDownload(ctx context.Context, c *cedarserver.Conn) error {
	err := ep.doDownload(ctx, c)
	if err != nil {
		ep.log("shadow: FILETRANS_DOWNLOAD handler error: %v", err)
	}
	return err
}

func (ep *Endpoint) doDownload(ctx context.Context, c *cedarserver.Conn) error {
	key, err := ep.readTransKey(ctx, c)
	if err != nil {
		return err
	}
	route := ep.lookup(key)
	if route == nil {
		return fmt.Errorf("filetransfer endpoint: no route for download TransferKey %q", key)
	}
	route.logf("shadow: FILETRANS_DOWNLOAD: receiving output sandbox")
	res, err := filetransfer.ServeDownload(ctx, c.Stream, route.sink, filetransfer.Options{Logf: route.logf, ReceiveAck: true})
	if err != nil {
		return err
	}
	route.logf("shadow: FILETRANS_DOWNLOAD: received files=%v dirs=%v", res.Files, res.Dirs)
	// For a spooled job the output sandbox just landed in the schedd's spool;
	// report the spooled output list so the schedd records SpooledOutputFiles
	// (what condor_transfer_data returns). Per the C++ starter's spooled-files
	// list (file_transfer.cpp:5677), only top-level names count and the
	// stdout/stderr sandbox names are excluded (Out/Err are added at
	// TRANSFER_DATA time from the job ad).
	if route.spooled {
		if fn, ok := ep.outputRecorder.Load().(func(int, int, []string)); ok && fn != nil {
			var spooledFiles []string
			for _, name := range res.Files {
				if name == stdoutRemapName || name == stderrRemapName || strings.ContainsRune(name, '/') {
					continue
				}
				spooledFiles = append(spooledFiles, name)
			}
			fn(route.cluster, route.proc, spooledFiles)
		}
	}
	return nil
}

// transferState is the per-shadow file-transfer setup, created in setupTransfer
// when a TransferEndpoint and ClaimID are configured.
type transferState struct {
	endpoint         *Endpoint
	transKey         string
	transSocket      string
	reconnectSession sessionMaterial
	filetransSession sessionMaterial
}

// sessionMaterial is the {id, info, key} triple get_sec_session_info returns for
// one session.
type sessionMaterial struct {
	id   string
	info string
	key  string
}

// setupTransfer wires the shadow for file transfer: it derives the reconnect and
// filetrans sessions from the claim id, imports the filetrans session into the
// endpoint's cache (so the starter's inbound resumption is recognized), builds
// the input plan and output sink from the job ad, and registers the route under
// a freshly generated TransferKey. It returns the state (nil if transfer is not
// configured).
func (s *Shadow) setupTransfer() (*transferState, error) {
	if s.cfg.TransferEndpoint == nil {
		return nil, nil
	}
	if s.cfg.ClaimID == "" {
		return nil, fmt.Errorf("shadow: file transfer requires Config.ClaimID")
	}
	ep := s.cfg.TransferEndpoint
	cid := security.ParseClaimIDStrict(s.cfg.ClaimID)
	baseID := cid.SecSessionID()
	if baseID == "" {
		return nil, fmt.Errorf("shadow: claim id carries no security session")
	}

	// Register the derived filetrans session in the endpoint's cache so the
	// starter's session-resumed FILETRANS_* connection resumes it. Same id/key
	// derivation the starter uses via CreateNonNegotiatedSecuritySession.
	ftID, err := security.ImportFileTransferSession(ep.Cache(), s.cfg.ClaimID, security.ClaimSessionOptions{
		PeerFQU: security.ExecuteSideMatchSessionFQU,
	})
	if err != nil {
		return nil, fmt.Errorf("shadow: import filetrans session: %w", err)
	}

	plan, err := s.buildInputPlan()
	if err != nil {
		return nil, err
	}
	sink, err := s.buildOutputSink()
	if err != nil {
		return nil, err
	}

	// Spool detection: the spool handler's rewriteSpooledJobAd left SUBMIT_Iwd
	// (and StageInFinish) on the ad and pointed Iwd at the per-job spool
	// sandbox, so the plan built above already sources the executable and
	// TransferInput from the spool sandbox, and the sink lands the output back
	// into it (leave-in-spool for condor_transfer_data).
	spooled := false
	if _, ok := s.cfg.JobAd.Lookup("SUBMIT_Iwd"); ok {
		spooled = true
	} else if fin, ok := s.cfg.JobAd.EvaluateAttrInt("StageInFinish"); ok && fin > 0 {
		spooled = true
	}
	cluster64, _ := s.cfg.JobAd.EvaluateAttrInt("ClusterId")
	proc64, _ := s.cfg.JobAd.EvaluateAttrInt("ProcId")
	if spooled {
		iwd, _ := s.cfg.JobAd.EvaluateAttrString("Iwd")
		s.logf("shadow: job %d.%d is spooled; transfer plan sources from spool sandbox %s", cluster64, proc64, iwd)
	}

	key := generateTransferKey()
	ep.register(key, &transferRoute{
		plan: plan, sink: sink, logf: s.logf,
		spooled: spooled, cluster: int(cluster64), proc: int(proc64),
	})

	// Session material handed to the starter in get_sec_session_info. The
	// reconnect session is the claim session itself (remoteresource.cpp uses
	// m_claim_session); the filetrans session carries the shadow's own WRITE
	// policy (encryption + integrity + AES).
	st := &transferState{
		endpoint:    ep,
		transKey:    key,
		transSocket: ep.Sinful(),
		reconnectSession: sessionMaterial{
			id:   baseID,
			info: cid.SecSessionInfo(),
			key:  cid.SecSessionKey(),
		},
		filetransSession: sessionMaterial{
			id:   ftID,
			info: `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`,
			key:  cid.SecSessionKey(),
		},
	}
	return st, nil
}

// teardownTransfer unregisters the shadow's route from the endpoint.
func (s *Shadow) teardownTransfer() {
	if s.transfer != nil && s.transfer.endpoint != nil {
		s.transfer.endpoint.unregister(s.transfer.transKey)
	}
}

// buildInputPlan builds the list of files the shadow uploads to the starter: the
// executable (as basename(Cmd), when TransferExecutable is not false) followed
// by the TransferInput files. Sources are resolved against Iwd for relative
// paths. FinalTransfer is true so the starter lands them in the execute sandbox.
func (s *Shadow) buildInputPlan() (filetransfer.SendPlan, error) {
	ad := s.cfg.JobAd
	iwd, _ := ad.EvaluateAttrString("Iwd")
	plan := filetransfer.SendPlan{FinalTransfer: true}

	seen := map[string]bool{}
	add := func(wireName, source string) error {
		if wireName == "" || seen[wireName] {
			return nil
		}
		info, err := os.Stat(source)
		if err != nil {
			return fmt.Errorf("shadow: input file %q: %w", source, err)
		}
		src := source
		plan.Files = append(plan.Files, filetransfer.FileSpec{
			WireName: wireName,
			Mode:     int64(info.Mode().Perm()),
			Size:     info.Size(),
			Open:     func() (io.ReadCloser, error) { return os.Open(src) },
		})
		seen[wireName] = true
		return nil
	}

	// Executable (TransferExecutable defaults to true).
	transferExe := true
	if v, ok := ad.EvaluateAttrBool("TransferExecutable"); ok {
		transferExe = v
	}
	if cmd, _ := ad.EvaluateAttrString("Cmd"); transferExe && cmd != "" {
		if err := add(filepath.Base(cmd), resolveAgainst(iwd, cmd)); err != nil {
			return plan, err
		}
	}

	// TransferInput files.
	if list, _ := ad.EvaluateAttrString("TransferInput"); list != "" {
		for _, f := range splitFileList(list) {
			if err := add(filepath.Base(f), resolveAgainst(iwd, f)); err != nil {
				return plan, err
			}
		}
	}
	return plan, nil
}

// buildOutputSink builds the sink that lands the starter's output sandbox in the
// job's Iwd, remapping the starter's _condor_stdout/_condor_stderr back to the
// job's requested Out/Err (BaseShadow modifyFileTransferObject).
func (s *Shadow) buildOutputSink() (filetransfer.Sink, error) {
	ad := s.cfg.JobAd
	iwd, _ := ad.EvaluateAttrString("Iwd")
	if iwd == "" {
		return nil, fmt.Errorf("shadow: job ad has no Iwd for output transfer")
	}
	remap := map[string]string{}
	if out, _ := ad.EvaluateAttrString("Out"); out != "" && out != stdoutRemapName && out != "/dev/null" {
		remap[stdoutRemapName] = out
	}
	if errf, _ := ad.EvaluateAttrString("Err"); errf != "" && errf != stderrRemapName && errf != "/dev/null" {
		remap[stderrRemapName] = errf
	}
	return &iwdSink{iwd: iwd, remap: remap, logf: s.logf}, nil
}

// iwdSink writes received output files into the job's Iwd.
type iwdSink struct {
	iwd   string
	remap map[string]string
	logf  func(format string, args ...any)
}

func (s *iwdSink) dest(name string) (string, error) {
	if r, ok := s.remap[name]; ok {
		name = r
	}
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("shadow: refusing output path outside sandbox: %q", name)
	}
	return filepath.Join(s.iwd, clean), nil
}

func (s *iwdSink) Mkdir(name string) error {
	dst, err := s.dest(name)
	if err != nil {
		return err
	}
	return os.MkdirAll(dst, 0o755)
}

func (s *iwdSink) File(name string, mode int64, _ int64) (io.WriteCloser, error) {
	dst, err := s.dest(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	perm := os.FileMode(mode).Perm()
	if perm == 0 {
		perm = 0o644
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	if s.logf != nil {
		s.logf("shadow: writing output file %s (mode %o)", dst, perm)
	}
	return f, nil
}

// resolveAgainst resolves a possibly-relative path against a base directory.
func resolveAgainst(base, p string) string {
	if filepath.IsAbs(p) || base == "" {
		return p
	}
	return filepath.Join(base, p)
}

// splitFileList splits a comma/whitespace separated file list (TransferInput).
func splitFileList(list string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// sinfulString renders a net.Addr as an HTCondor sinful "<ip:port>".
func sinfulString(addr net.Addr) string {
	return fmt.Sprintf("<%s>", addr.String())
}
