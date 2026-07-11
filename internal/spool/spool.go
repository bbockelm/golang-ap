// Package spool implements the pure-Go schedd's sandbox-spooling command
// handlers, the server side of `condor_submit -spool` and `condor_transfer_data`
// (and the golang-htcondor Schedd spool client). It lets a submitter without a
// shared filesystem stage a job's input sandbox into the schedd's $(SPOOL) area
// and later retrieve the output sandbox from it.
//
// Four commands are served, all authenticated at WRITE (C++ schedd
// Scheduler::spoolJobFiles, schedd.cpp):
//
//	SPOOL_JOB_FILES            (480) - upload input sandbox INTO the schedd
//	SPOOL_JOB_FILES_WITH_PERMS (488) - ... with file permission modes + peer version
//	TRANSFER_DATA              (486) - download output sandbox OUT of the schedd
//	TRANSFER_DATA_WITH_PERMS   (489) - ... with file permission modes + peer version
//
// Wire format (verified against src/condor_schedd.V6/schedd.cpp spoolJobFiles /
// generalJobFilesWorkerThread and src/condor_daemon_client/dc_schedd.cpp):
//
//	SPOOL (client uploads):
//	  msg1  client->server: [version string (WITH_PERMS only)] + JobAdsArrayLen(int32)
//	  msg2  client->server: JobAdsArrayLen * {cluster(int32), proc(int32)}
//	  per job: a full FileTransfer sender-stream (preamble + files + Finished + ack)
//	  final client<-server: answer OK(1) int32   (the Go SpoolJobFilesFromFS client
//	                        does not read this; stock condor_submit does)
//
//	TRANSFER_DATA (client downloads):
//	  msg1  client->server: [version string (WITH_PERMS only)] + constraint string
//	  msg2  client<-server: JobAdsArrayLen(int32)
//	  per job: server->client job ClassAd, then a FileTransfer sender-stream
//	  final client->server: answer OK int32 (best-effort)
//
// Job lifecycle (schedd.cpp spoolJobFilesReaper, qmgmt.cpp rewriteSpooledJobAd,
// condor_holdcodes.h SpoolingInput=16): a -spool job arrives HELD with
// HoldReasonCode 16 ("Spooling input data files"). On a successful input spool
// the schedd records StageInStart/StageInFinish, rewrites the job ad so its Iwd
// points at the per-job spool sandbox and its Cmd / TransferInput become
// basenames resolving inside it (originals backed up under SUBMIT_*), and
// RELEASES the code-16 hold (JobStatus -> Idle). The shadow then sources input
// from, and lands output back into, the spool sandbox (its Iwd), so a later
// condor_transfer_data can retrieve the results.
package spool

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/filetransfer"

	"github.com/bbockelm/golang-ap/internal/queue"
)

// SpoolingInput is CONDOR_HOLD_CODE::SpoolingInput (condor_holdcodes.h:108): the
// hold a job wears between submit and a successful input spool.
const SpoolingInput = 16

// Options configures a Handler.
type Options struct {
	// Queue is the job-queue authority whose ads are rewritten/released and whose
	// sandboxes are read/written.
	Queue *queue.Queue
	// SpoolDir is $(SPOOL); per-job sandboxes live under it in the C++ layout.
	SpoolDir string
	// Logf, if set, receives debug logging.
	Logf func(format string, args ...any)
	// Reschedule, if set, is nudged after a successful input spool so the
	// scheduler advertises the freshly-released job promptly (the C++ reaper
	// re-arms the negotiator).
	Reschedule func()
}

// Handler serves the four spool/transfer commands.
type Handler struct {
	q          *queue.Queue
	spoolDir   string
	logf       func(format string, args ...any)
	reschedule func()
}

// New builds a Handler.
func New(opts Options) *Handler {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Handler{q: opts.Queue, spoolDir: opts.SpoolDir, logf: logf, reschedule: opts.Reschedule}
}

// Register wires the four commands onto srv at WRITE (matching the C++ schedd's
// authorization for spoolJobFiles). One additive block; called from main.
func (h *Handler) Register(srv *cedarserver.Server) {
	srv.Handle(commands.SPOOL_JOB_FILES, h.handleSpool, "WRITE")
	srv.Handle(commands.SPOOL_JOB_FILES_WITH_PERMS, h.handleSpool, "WRITE")
	srv.Handle(commands.TRANSFER_DATA, h.handleTransfer, "WRITE")
	srv.Handle(commands.TRANSFER_DATA_WITH_PERMS, h.handleTransfer, "WRITE")
}

func (h *Handler) ftOpts() filetransfer.Options {
	return filetransfer.Options{Logf: h.logf}
}

// SandboxDir returns the per-job spool sandbox directory in the C++ layout
// (spooled_job_files.cpp gen_ckpt_name / getJobSpoolPath):
//
//	$(SPOOL)/<cluster%10000>/<proc%10000>/cluster<c>.proc<p>.subproc0
func SandboxDir(spoolDir string, c, p int) string {
	return filepath.Join(spoolDir,
		strconv.Itoa(c%10000),
		strconv.Itoa(p%10000),
		fmt.Sprintf("cluster%d.proc%d.subproc0", c, p))
}

// ----- SPOOL_JOB_FILES / _WITH_PERMS: receive input sandboxes -----

func (h *Handler) handleSpool(ctx context.Context, c *cedarserver.Conn) error {
	if err := h.doSpool(ctx, c); err != nil {
		h.logf("spool: SPOOL_JOB_FILES handler error: %v", err)
		return err
	}
	return nil
}

func (h *Handler) doSpool(ctx context.Context, c *cedarserver.Conn) error {
	authUser := c.Negotiation.User
	withPerms := c.Command == commands.SPOOL_JOB_FILES_WITH_PERMS

	// msg1: [version] + JobAdsArrayLen.
	m1 := message.NewMessageFromStream(c.Stream)
	if withPerms {
		if _, err := m1.GetString(ctx); err != nil {
			return fmt.Errorf("read peer version: %w", err)
		}
	}
	count, err := m1.GetInt32(ctx)
	if err != nil {
		return fmt.Errorf("read JobAdsArrayLen: %w", err)
	}
	if count <= 0 {
		return fmt.Errorf("bad JobAdsArrayLen %d", count)
	}

	// msg2: the {cluster, proc} pairs.
	m2 := message.NewMessageFromStream(c.Stream)
	jobs := make([][2]int, 0, count)
	for i := int32(0); i < count; i++ {
		cl, err := m2.GetInt32(ctx)
		if err != nil {
			return fmt.Errorf("read cluster for job %d: %w", i, err)
		}
		pr, err := m2.GetInt32(ctx)
		if err != nil {
			return fmt.Errorf("read proc for job %d: %w", i, err)
		}
		jobs = append(jobs, [2]int{int(cl), int(pr)})
	}

	// Per-job pre-transfer validation + StageInStart, matching the C++ read loop.
	now := nowUnix()
	for _, j := range jobs {
		if err := h.preSpoolCheck(authUser, j[0], j[1], now); err != nil {
			return err
		}
	}

	// Per job, receive a full FileTransfer sender-stream into the spool sandbox.
	// The client is the SENDER (DoUpload); the schedd is the RECEIVER
	// (DownloadFiles). A modern uploader performs the final TransferAck, so
	// ReceiveAck is set.
	opts := h.ftOpts()
	opts.ReceiveAck = true
	for _, j := range jobs {
		dir := SandboxDir(h.spoolDir, j[0], j[1])
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create spool sandbox %s: %w", dir, err)
		}
		sink := &dirSink{root: dir, logf: h.logf}
		res, err := filetransfer.ServeDownload(ctx, c.Stream, sink, opts)
		if err != nil {
			return fmt.Errorf("receive sandbox for job %d.%d: %w", j[0], j[1], err)
		}
		h.logf("spool: received sandbox for %d.%d into %s (files=%v dirs=%v)",
			j[0], j[1], dir, res.Files, res.Dirs)
	}

	// Post-transfer: StageInFinish + rewrite ad to point into the spool sandbox +
	// release the code-16 hold. Mirrors spoolJobFilesReaper.
	for _, j := range jobs {
		h.finishSpool(j[0], j[1])
	}

	// Tell the client we succeeded (answer=OK). The stock condor_submit reads
	// this; the Go client does not, so a write error here is benign.
	reply := message.NewMessageForStream(c.Stream)
	if err := reply.PutInt32(ctx, 1); err == nil { // OK == 1
		_ = reply.FinishMessage(ctx)
	}

	if h.reschedule != nil {
		h.reschedule()
	}
	return nil
}

// preSpoolCheck enforces ownership, refuses a double-stagein, requires a held
// job to wear the SpoolingInput hold, and records StageInStart. Mirrors the
// validation in spoolJobFiles' upload read loop.
func (h *Handler) preSpoolCheck(authUser string, c, p int, now int64) error {
	ad, ok := h.q.Get(c, p)
	if !ok {
		return fmt.Errorf("spool: job %d.%d not found", c, p)
	}
	if !h.q.OwnsJobAd(authUser, ad) {
		return fmt.Errorf("spool: user %q may not spool for job %d.%d", authUser, c, p)
	}
	if fin, ok := ad.EvaluateAttrInt("StageInFinish"); ok && fin != 0 {
		return fmt.Errorf("spool: stagein already finished for job %d.%d", c, p)
	}
	status, _ := ad.EvaluateAttrInt("JobStatus")
	if int(status) == queue.StatusHeld {
		code, _ := ad.EvaluateAttrInt("HoldReasonCode")
		if int(code) != SpoolingInput {
			return fmt.Errorf("spool: job %d.%d is held but not for spooling (hold code %d)", c, p, code)
		}
	}
	h.q.Modify(c, p, func(ad *classad.ClassAd) {
		_ = ad.Set("StageInStart", now)
	})
	return nil
}

// finishSpool records StageInFinish, rewrites the job ad for spooling, and
// releases the code-16 hold, in one queue write.
func (h *Handler) finishSpool(c, p int) {
	dir := SandboxDir(h.spoolDir, c, p)
	now := nowUnix()
	ok := h.q.Modify(c, p, func(ad *classad.ClassAd) {
		if fin, ok := ad.EvaluateAttrInt("StageInFinish"); !ok || fin == 0 {
			// -1 mirrors the C++ reaper backing off the NAP second so the job's
			// start can never predate the spooled files' mtimes.
			_ = ad.Set("StageInFinish", now-1)
		}
		rewriteSpooledJobAd(ad, dir)
		releaseSpoolHold(ad, now)
	})
	if !ok {
		h.logf("spool: job %d.%d vanished before release", c, p)
		return
	}
	h.logf("spool: released job %d.%d (Iwd rewritten to %s)", c, p, dir)
}

// ----- TRANSFER_DATA / _WITH_PERMS: send output sandboxes -----

func (h *Handler) handleTransfer(ctx context.Context, c *cedarserver.Conn) error {
	if err := h.doTransfer(ctx, c); err != nil {
		h.logf("spool: TRANSFER_DATA handler error: %v", err)
		return err
	}
	return nil
}

func (h *Handler) doTransfer(ctx context.Context, c *cedarserver.Conn) error {
	authUser := c.Negotiation.User
	withPerms := c.Command == commands.TRANSFER_DATA_WITH_PERMS

	// msg1: [version] + constraint.
	m1 := message.NewMessageFromStream(c.Stream)
	if withPerms {
		if _, err := m1.GetString(ctx); err != nil {
			return fmt.Errorf("read peer version: %w", err)
		}
	}
	constraint, err := m1.GetString(ctx)
	if err != nil {
		return fmt.Errorf("read constraint: %w", err)
	}

	ads, err := h.q.SpoolQuery(constraint)
	if err != nil {
		return fmt.Errorf("parse/evaluate constraint %q: %w", constraint, err)
	}
	// Only jobs this user owns.
	owned := ads[:0]
	for _, ad := range ads {
		if h.q.OwnsJobAd(authUser, ad) {
			owned = append(owned, ad)
		}
	}
	ads = owned
	h.logf("spool: TRANSFER_DATA: %d job(s) match %q", len(ads), constraint)

	// msg2: number of jobs.
	m2 := message.NewMessageForStream(c.Stream)
	if err := m2.PutInt32(ctx, int32(len(ads))); err != nil {
		return fmt.Errorf("send job count: %w", err)
	}
	if err := m2.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish job count: %w", err)
	}

	// Per job: the job ClassAd (carrying SUBMIT_* backups so the client can
	// un-rewrite paths), then the output sandbox as a FileTransfer sender-stream.
	for _, ad := range ads {
		cl, pr, _ := jobIDsOf(ad)
		am := message.NewMessageForStream(c.Stream)
		if err := am.PutClassAd(ctx, ad); err != nil {
			return fmt.Errorf("send job ad %d.%d: %w", cl, pr, err)
		}
		if err := am.FinishMessage(ctx); err != nil {
			return fmt.Errorf("finish job ad %d.%d: %w", cl, pr, err)
		}
		if err := h.sendSandbox(ctx, c.Stream, ad, cl, pr); err != nil {
			return fmt.Errorf("send sandbox for %d.%d: %w", cl, pr, err)
		}
		h.q.Modify(cl, pr, func(ad *classad.ClassAd) {
			_ = ad.Set("StageOutFinish", nowUnix())
		})
	}

	// Best-effort read of the client's final OK (stock condor_transfer_data
	// sends it; the Go client sends OK too). Failure here is harmless: the
	// client already has every byte.
	fin := message.NewMessageFromStream(c.Stream)
	_, _ = fin.GetInt32(ctx)
	return nil
}

// sendSandbox streams the job's output files from the spool sandbox back to the
// client as one FileTransfer sender-stream. File selection follows the C++
// FileTransfer::SimpleInit output-list priority (file_transfer.cpp:605): the
// recorded SpooledOutputFiles if present, else the ad's TransferOutput list,
// plus Out/Err/UserLog; with neither list, the whole sandbox is sent (the C++
// upload-changed-files fallback sends every file, since a fresh FileTransfer's
// catalog is empty). Wire names are relative to the sandbox root. It sends
// CmdFinished + our TransferAck and then best-effort reads the peer's ack: a
// stock condor_transfer_data (PeerDoesTransferAck) completes the exchange; the
// Go ReceiveJobSandbox client returns on CmdFinished, so its OK reply is what
// the best-effort read consumes.
func (h *Handler) sendSandbox(ctx context.Context, st *stream.Stream, ad *classad.ClassAd, c, p int) error {
	dir := SandboxDir(h.spoolDir, c, p)
	specs, size, err := h.outputSpecs(ad, dir)
	if err != nil {
		return err
	}
	opts := h.ftOpts()
	// final_transfer=1: the C++ schedd's TRANSFER_DATA path calls UploadFiles()
	// with its default final_transfer=true (clients ignore the flag on download,
	// but match the stock bytes).
	if err := filetransfer.SendPreamble(ctx, st, size, true, opts); err != nil {
		return err
	}
	state := &filetransfer.SendState{}
	for _, spec := range specs {
		if err := filetransfer.SendFile(ctx, st, spec, state, opts); err != nil {
			return err
		}
	}
	// CmdFinished.
	fm := message.NewMessageForStream(st)
	if err := fm.PutInt32(ctx, int32(filetransfer.CmdFinished)); err != nil {
		return err
	}
	if err := fm.FinishMessage(ctx); err != nil {
		return err
	}
	// Our TransferAck (Result=0).
	ack := classad.New()
	_ = ack.Set("Result", int64(0))
	_ = ack.Set("TransferStats", classad.New())
	am := message.NewMessageForStream(st)
	if err := am.PutClassAd(ctx, ack); err != nil {
		return err
	}
	if err := am.FinishMessage(ctx); err != nil {
		return err
	}
	// Peer's ack (best-effort).
	pk := message.NewMessageFromStream(st)
	_, _ = pk.GetClassAd(ctx)
	return nil
}

// outputSpecs picks the files to return for a TRANSFER_DATA request:
// SpooledOutputFiles (recorded when the spooled job's output landed) or
// TransferOutput/TransferOutputFiles, each augmented with Out/Err/UserLog when
// those live in the sandbox; if neither list exists, the whole sandbox.
// Missing listed files are skipped with a log (e.g. output the job never wrote).
func (h *Handler) outputSpecs(ad *classad.ClassAd, dir string) ([]filetransfer.FileSpec, int64, error) {
	var names []string
	haveList := false
	if s, ok := ad.EvaluateAttrString("SpooledOutputFiles"); ok && s != "" {
		names = splitFileList(s)
		haveList = true
	} else if s, ok := ad.EvaluateAttrString("TransferOutput"); ok && s != "" {
		names = splitFileList(s)
		haveList = true
	} else if s, ok := ad.EvaluateAttrString("TransferOutputFiles"); ok && s != "" {
		names = splitFileList(s)
		haveList = true
	}
	if !haveList {
		return collectSandbox(dir)
	}
	// Out/Err/UserLog ride along when using a fixed list (file_transfer.cpp:620).
	for _, attr := range []string{"Out", "Err", "UserLog"} {
		if v, ok := ad.EvaluateAttrString(attr); ok && !isNullFile(v) && !filepath.IsAbs(v) {
			names = append(names, v)
		}
	}
	seen := map[string]bool{}
	var specs []filetransfer.FileSpec
	var total int64
	for _, name := range names {
		name = filepath.ToSlash(filepath.Clean(name))
		if name == "" || name == "." || seen[name] || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			continue
		}
		seen[name] = true
		src := filepath.Join(dir, filepath.FromSlash(name))
		info, err := os.Stat(src)
		if err != nil || !info.Mode().IsRegular() {
			h.logf("spool: TRANSFER_DATA: skipping listed output %q (not a regular file in %s)", name, dir)
			continue
		}
		open := src
		specs = append(specs, filetransfer.FileSpec{
			WireName: name,
			Mode:     int64(info.Mode().Perm()),
			Size:     info.Size(),
			Open:     func() (io.ReadCloser, error) { return os.Open(open) },
		})
		total += info.Size()
	}
	return specs, total, nil
}

// splitFileList splits a comma/whitespace separated file list.
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

// collectSandbox walks dir and returns a FileSpec per regular file (wire name =
// path relative to dir), plus the total byte size.
func collectSandbox(dir string) ([]filetransfer.FileSpec, int64, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// No sandbox on disk (e.g. an empty spool): nothing to send.
		return nil, 0, nil
	}
	var specs []filetransfer.FileSpec
	var total int64
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		wire := filepath.ToSlash(rel)
		src := p
		specs = append(specs, filetransfer.FileSpec{
			WireName: wire,
			Mode:     int64(info.Mode().Perm()),
			Size:     info.Size(),
			Open:     func() (io.ReadCloser, error) { return os.Open(src) },
		})
		total += info.Size()
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].WireName < specs[j].WireName })
	return specs, total, nil
}

// ----- ad rewriting / hold release -----

// rewriteSpooledJobAd rewrites a spooled job's ad so it resolves inside spoolDir,
// backing up originals under SUBMIT_*. It is the schedd-side equivalent of
// qmgmt.cpp rewriteSpooledJobAd: Iwd -> spoolDir; Cmd / TransferInput / In /
// UserLog -> basenames; TransferOutputRemaps suppressed while output lands in
// spool. Idempotent: a prior rewrite left SUBMIT_Iwd, so it is a no-op then.
func rewriteSpooledJobAd(ad *classad.ClassAd, spoolDir string) {
	if _, done := ad.Lookup("SUBMIT_Iwd"); done {
		return
	}
	// Iwd: back up + point at the spool sandbox.
	if iwd, ok := ad.EvaluateAttrString("Iwd"); ok {
		ad.InsertAttrString("SUBMIT_Iwd", iwd)
	} else {
		ad.InsertAttrString("SUBMIT_Iwd", "")
	}
	ad.InsertAttrString("Iwd", spoolDir)

	// Suppress output remaps while output round-trips into spool; restore-on-
	// retrieve is the client's job (via SUBMIT_TransferOutputRemaps).
	if remaps, ok := ad.EvaluateAttrString("TransferOutputRemaps"); ok && remaps != "" {
		ad.InsertAttrString("SUBMIT_TransferOutputRemaps", remaps)
		ad.Delete("TransferOutputRemaps")
	}

	// Cmd (gated by TransferExecutable != false): to basename so it resolves in
	// the new Iwd. Without this an absolute Cmd would make the shadow source the
	// executable from the submitter's path instead of the spool sandbox.
	if transferExecutable(ad) {
		rewriteBasename(ad, "Cmd")
	}
	// In (gated by TransferInput bool for stdin redirection).
	if b, ok := ad.EvaluateAttrBool("TransferIn"); !ok || b {
		rewriteBasename(ad, "In")
	}
	rewriteBasename(ad, "UserLog")
	rewriteBasenameList(ad, "TransferInput")
}

// transferExecutable reports whether the executable is spooled (default true).
func transferExecutable(ad *classad.ClassAd) bool {
	if b, ok := ad.EvaluateAttrBool("TransferExecutable"); ok {
		return b
	}
	return true
}

// rewriteBasename replaces a single-path attribute with its basename, backing up
// the original under SUBMIT_<attr>. No-op if unset, empty, a null file, or
// already a bare basename.
func rewriteBasename(ad *classad.ClassAd, attr string) {
	val, ok := ad.EvaluateAttrString(attr)
	if !ok || val == "" || isNullFile(val) {
		return
	}
	base := path.Base(filepath.ToSlash(val))
	if base == val {
		return
	}
	ad.InsertAttrString("SUBMIT_"+attr, val)
	ad.InsertAttrString(attr, base)
}

// rewriteBasenameList replaces each entry of a comma-separated file list with
// its basename (URLs left intact), backing up the original under SUBMIT_<attr>.
func rewriteBasenameList(ad *classad.ClassAd, attr string) {
	val, ok := ad.EvaluateAttrString(attr)
	if !ok || val == "" {
		return
	}
	parts := strings.Split(val, ",")
	changed := false
	out := make([]string, 0, len(parts))
	for _, e := range parts {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if isURL(e) {
			out = append(out, e)
			continue
		}
		base := path.Base(filepath.ToSlash(e))
		if base != e {
			changed = true
		}
		out = append(out, base)
	}
	if !changed {
		return
	}
	ad.InsertAttrString("SUBMIT_"+attr, val)
	ad.InsertAttrString(attr, strings.Join(out, ","))
}

// releaseSpoolHold clears the SpoolingInput hold and moves the job to Idle,
// mirroring releaseJobRaw + fixReasonAttrs (schedd.cpp): the live hold-reason
// attrs move to Last* and are deleted, JobStatus -> JobStatusOnRelease (Idle).
func releaseSpoolHold(ad *classad.ClassAd, now int64) {
	status, _ := ad.EvaluateAttrInt("JobStatus")
	if int(status) != queue.StatusHeld {
		return
	}
	release := int64(queue.StatusIdle)
	if v, ok := ad.EvaluateAttrInt("JobStatusOnRelease"); ok && v > 0 {
		release = v
	}
	_ = ad.Set("LastJobStatus", int64(status))
	moveAttr(ad, "HoldReason", "LastHoldReason")
	moveAttr(ad, "HoldReasonCode", "LastHoldReasonCode")
	moveAttr(ad, "HoldReasonSubCode", "LastHoldReasonSubCode")
	ad.Delete("JobStatusOnRelease")
	ad.InsertAttrString("ReleaseReason", "Data files spooled")
	_ = ad.Set("JobStatus", release)
	_ = ad.Set("EnteredCurrentStatus", now)
	_ = ad.Set("LastSuspensionTime", int64(0))
}

// moveAttr copies from -> to (if present) and deletes from.
func moveAttr(ad *classad.ClassAd, from, to string) {
	if expr, ok := ad.Lookup(from); ok {
		ad.InsertExpr(to, expr)
		ad.Delete(from)
	}
}

// ----- small helpers -----

func isNullFile(s string) bool {
	return s == "" || s == "/dev/null" || strings.EqualFold(s, "UNDEFINED")
}

// isURL reports whether s looks like scheme://... (RFC 3986 scheme).
func isURL(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		ch := s[j]
		isAlpha := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
		isOther := (ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.'
		if j == 0 && !isAlpha {
			return false
		}
		if !isAlpha && !isOther {
			return false
		}
	}
	return true
}

func jobIDsOf(ad *classad.ClassAd) (c, p int, ok bool) {
	cv, cok := ad.EvaluateAttrInt("ClusterId")
	pv, pok := ad.EvaluateAttrInt("ProcId")
	if !cok || !pok {
		return 0, 0, false
	}
	return int(cv), int(pv), true
}

// nowUnix is a var so tests can pin time.
var nowUnix = func() int64 { return time.Now().Unix() }

// dirSink is a filetransfer.Sink that lands a received input sandbox under root
// (the per-job spool sandbox), preserving the wire names as relative paths and
// guarding against path traversal outside root.
type dirSink struct {
	root string
	logf func(format string, args ...any)
}

func (s *dirSink) dest(name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("spool: refusing sandbox path outside spool dir: %q", name)
	}
	return filepath.Join(s.root, clean), nil
}

func (s *dirSink) Mkdir(name string) error {
	dst, err := s.dest(name)
	if err != nil {
		return err
	}
	return os.MkdirAll(dst, 0o755)
}

func (s *dirSink) File(name string, mode int64, _ int64) (io.WriteCloser, error) {
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
		s.logf("spool: writing sandbox file %s (mode %o)", dst, perm)
	}
	return f, nil
}
