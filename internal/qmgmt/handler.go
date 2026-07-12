// Package qmgmt implements the server side of HTCondor's QMGMT wire protocol:
// the RPC loop a schedd runs on a QMGMT_WRITE_CMD/QMGMT_READ_CMD socket. It owns
// the socket for the connection's lifetime, reading op integers and dispatching
// them against the job-queue authority until the peer sends CloseSocket (or the
// connection drops).
//
// Framing verified against src/condor_schedd.V6/qmgmt_receivers.cpp (do_Q_request)
// and qmgmt_send_stubs.cpp (the client stubs). Op set and reply conventions live
// in the shared codec package github.com/bbockelm/golang-htcondor/qmgmt.
package qmgmt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"
	hqmgmt "github.com/bbockelm/golang-htcondor/qmgmt"

	"github.com/bbockelm/golang-ap/internal/factory"
	"github.com/bbockelm/golang-ap/internal/queue"
)

// POSIX errno values sent as the QMGMT terrno on failures.
const (
	ePERM  = 1
	eNOENT = 2
	eACCES = 13
	eINVAL = 22
)

// terrnoFor maps a SetAttribute/DeleteAttribute failure to the QMGMT terrno the
// C++ schedd returns: EACCES for an authorization denial (immutable/protected/
// secure attr or a cross-owner edit), EINVAL for a malformed request.
func terrnoFor(err error) int {
	if errors.As(err, new(*queue.AuthzError)) {
		return eACCES
	}
	return eINVAL
}

// Server dispatches QMGMT operations against a job queue.
type Server struct {
	q        *queue.Queue
	log      *logging.Logger
	caps     *classad.ClassAd
	spoolDir string // $(SPOOL): where factory digests/itemdata are stored
}

// New builds a QMGMT server bound to the given queue. spoolDir is $(SPOOL); it is
// where late-materialization digest/itemdata files are written.
func New(q *queue.Queue, log *logging.Logger, spoolDir string) *Server {
	caps := classad.New()
	// Attributes copied from GetSchedulerCapabilities (qmgmt.cpp). Late
	// materialization (job factories) is supported; jobsets are not.
	_ = caps.Set("LateMaterialize", true)
	_ = caps.Set("LateMaterializeVersion", int64(2))
	_ = caps.Set("UseJobsets", false)
	return &Server{q: q, log: log, caps: caps, spoolDir: spoolDir}
}

// Handle runs the QMGMT RPC loop for one connection. It is registered for both
// QMGMT_WRITE_CMD and QMGMT_READ_CMD; the command determines whether write ops
// are permitted. Returning nil closes the connection (the normal end after the
// peer sends CloseSocket or hangs up).
func (s *Server) Handle(ctx context.Context, c *cedarserver.Conn) error {
	authUser := ""
	if c.Negotiation != nil {
		authUser = c.Negotiation.User
	}
	writable := c.Command == hqmgmt.WriteCmd

	// allowProtected is a per-connection flag (like the C++ Q_SOCK's
	// AllowProtectedAttrChanges) toggled by OpSetAllowProtectedChanges. It must
	// survive the implicit transaction resets on Begin/Abort/Commit, so it lives
	// here and is re-applied to every fresh transaction via begin().
	allowProtected := false
	begin := func() *queue.Txn {
		tx := s.q.Begin(authUser)
		tx.SetAllowProtectedChanges(allowProtected)
		return tx
	}
	txn := begin()
	// Per-connection scan cursor for GetNextJobByConstraint iteration.
	var scanState []*classad.ClassAd
	var scanPos int

	for {
		rm := message.NewMessageFromStream(c.Stream)
		op, err := rm.GetInt(ctx)
		if err != nil {
			// EOF or a torn read: the peer finished. Abort any uncommitted work.
			txn.Abort()
			return nil
		}

		switch op {
		case hqmgmt.OpCloseSocket:
			// No reply at all; just end the loop (qmgmt_receivers.cpp).
			txn.Abort()
			return nil

		case hqmgmt.OpGetCapabilities:
			if _, err := rm.GetInt(ctx); err != nil { // mask
				return nil
			}
			wm := message.NewMessageForStream(c.Stream)
			if err := wm.PutClassAd(ctx, s.caps); err != nil {
				return err
			}
			if err := wm.FinishMessage(ctx); err != nil {
				return err
			}

		case hqmgmt.OpBeginTransaction:
			txn.Abort()
			txn = begin()
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpAbortTransaction:
			txn.Abort()
			txn = begin()
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpCommitTransactionNoFlags, hqmgmt.OpCommitTransaction:
			if op == hqmgmt.OpCommitTransaction {
				if _, err := rm.GetInt(ctx); err != nil { // flags
					return nil
				}
			}
			cerr := txn.Commit()
			if err := s.replyCommit(ctx, c, cerr); err != nil {
				return err
			}
			txn = begin() // fresh implicit transaction

		case hqmgmt.OpNewCluster:
			if !writable {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			id, err := txn.NewCluster()
			if err != nil {
				if werr := s.replyNewClusterErr(ctx, c, err); werr != nil {
					return werr
				}
				continue
			}
			if err := s.reply(ctx, c, id, 0); err != nil {
				return err
			}

		case hqmgmt.OpNewProc:
			cluster, err := rm.GetInt(ctx)
			if err != nil {
				return nil
			}
			if !writable {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			p, err := txn.NewProc(cluster)
			if err != nil {
				if e := s.reply(ctx, c, -1, eINVAL); e != nil {
					return e
				}
				continue
			}
			if err := s.reply(ctx, c, p, 0); err != nil {
				return err
			}

		case hqmgmt.OpSetAttribute, hqmgmt.OpSetAttribute2:
			cluster, e1 := rm.GetInt(ctx)
			proc, e2 := rm.GetInt(ctx)
			value, e3 := rm.GetString(ctx)
			name, e4 := rm.GetString(ctx)
			var flags hqmgmt.SetAttributeFlags
			if op == hqmgmt.OpSetAttribute2 {
				b, e5 := rm.GetChar(ctx)
				if e5 != nil {
					return nil
				}
				flags = hqmgmt.SetAttributeFlags(b)
			}
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
				return nil
			}
			noAck := flags&hqmgmt.SetNoAck != 0
			if !writable {
				if !noAck {
					_ = s.reply(ctx, c, -1, ePERM)
				} else {
					txn.AddError("read-only connection")
				}
				continue
			}
			serr := txn.SetAttribute(cluster, proc, name, value)
			if noAck {
				// No reply is ever sent for a NoAck SetAttribute; failures are
				// deferred to commit (qmgmt_receivers.cpp).
				if serr != nil {
					txn.AddError(serr.Error())
				}
				continue
			}
			if serr != nil {
				if e := s.reply(ctx, c, -1, terrnoFor(serr)); e != nil {
					return e
				}
				continue
			}
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpDeleteAttribute:
			cluster, e1 := rm.GetInt(ctx)
			proc, e2 := rm.GetInt(ctx)
			name, e3 := rm.GetString(ctx)
			if e1 != nil || e2 != nil || e3 != nil {
				return nil
			}
			if !writable {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			if derr := txn.DeleteAttribute(cluster, proc, name); derr != nil {
				if e := s.reply(ctx, c, -1, terrnoFor(derr)); e != nil {
					return e
				}
				continue
			}
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpDestroyProc:
			cluster, e1 := rm.GetInt(ctx)
			proc, e2 := rm.GetInt(ctx)
			if e1 != nil || e2 != nil {
				return nil
			}
			if !writable {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			txn.DestroyProc(cluster, proc)
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpDestroyCluster:
			cluster, err := rm.GetInt(ctx)
			if err != nil {
				return nil
			}
			if !writable {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			txn.DestroyCluster(cluster)
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpSetEffectiveOwner:
			owner, err := rm.GetString(ctx)
			if err != nil {
				return nil
			}
			rval, terrno := 0, 0
			if serr := txn.SetEffectiveOwner(owner); serr != nil {
				rval, terrno = -1, eACCES
			}
			if err := s.reply(ctx, c, rval, terrno); err != nil {
				return err
			}

		case hqmgmt.OpSetAllowProtectedChanges:
			val, err := rm.GetInt(ctx) // value
			if err != nil {
				return nil
			}
			// Per-connection toggle (survives transaction resets); the reply is the
			// PREVIOUS value, matching QmgmtSetAllowProtectedAttrChanges.
			allowProtected = val != 0
			old := txn.SetAllowProtectedChanges(allowProtected)
			oldVal := 0
			if old {
				oldVal = 1
			}
			if err := s.reply(ctx, c, oldVal, 0); err != nil {
				return err
			}

		case hqmgmt.OpGetJobAd:
			cluster, e1 := rm.GetInt(ctx)
			proc, e2 := rm.GetInt(ctx)
			if e1 != nil || e2 != nil {
				return nil
			}
			ad, ok := txn.GetJobAd(cluster, proc)
			if !ok {
				if err := s.reply(ctx, c, -1, eNOENT); err != nil {
					return err
				}
				continue
			}
			if err := s.replyAd(ctx, c, ad); err != nil {
				return err
			}

		case hqmgmt.OpGetAttributeInt, hqmgmt.OpGetAttributeFloat,
			hqmgmt.OpGetAttributeString, hqmgmt.OpGetAttributeExpr:
			cluster, e1 := rm.GetInt(ctx)
			proc, e2 := rm.GetInt(ctx)
			name, e3 := rm.GetString(ctx)
			if e1 != nil || e2 != nil || e3 != nil {
				return nil
			}
			if err := s.replyGetAttribute(ctx, c, txn, op, cluster, proc, name); err != nil {
				return err
			}

		case hqmgmt.OpGetJobByConstraint:
			constraint, err := rm.GetString(ctx)
			if err != nil {
				return nil
			}
			ad := s.firstMatch(constraint)
			if ad == nil {
				if err := s.reply(ctx, c, -1, eNOENT); err != nil {
					return err
				}
				continue
			}
			if err := s.replyAd(ctx, c, ad); err != nil {
				return err
			}

		case hqmgmt.OpGetNextJobByConstraint:
			initScan, e1 := rm.GetInt(ctx)
			constraint, e2 := rm.GetString(ctx)
			if e1 != nil || e2 != nil {
				return nil
			}
			if initScan == 1 {
				scanState = s.snapshot(constraint)
				scanPos = 0
			}
			if scanPos >= len(scanState) {
				if err := s.reply(ctx, c, -1, eNOENT); err != nil {
					return err
				}
				continue
			}
			ad := scanState[scanPos]
			scanPos++
			if err := s.replyAd(ctx, c, ad); err != nil {
				return err
			}

		case hqmgmt.OpGetAllJobsByConstraint:
			constraint, e1 := rm.GetString(ctx)
			_, e2 := rm.GetString(ctx) // projection
			if e1 != nil || e2 != nil {
				return nil
			}
			if err := s.streamAllJobs(ctx, c, constraint); err != nil {
				return err
			}

		case hqmgmt.OpSendSpoolFile:
			if _, err := rm.GetString(ctx); err != nil { // filename
				return nil
			}
			// Unsupported: rval=-2, terrno unconditionally (qmgmt_receivers.cpp).
			wm := message.NewMessageForStream(c.Stream)
			_ = wm.PutInt(ctx, -2)
			_ = wm.PutInt(ctx, eINVAL)
			if err := wm.FinishMessage(ctx); err != nil {
				return err
			}

		case hqmgmt.OpSendSpoolFileIfNeeded:
			if _, err := rm.GetClassAd(ctx); err != nil {
				return nil
			}
			// Unsupported: rval=-2 only (no terrno), matching the C++ stub.
			wm := message.NewMessageForStream(c.Stream)
			_ = wm.PutInt(ctx, -2)
			if err := wm.FinishMessage(ctx); err != nil {
				return err
			}

		case hqmgmt.OpSetJobFactory, hqmgmt.OpSetMaterializeData:
			// SetJobFactory(cluster, num, filename, digest_text). Read order and
			// reply verified against qmgmt_receivers.cpp CONDOR_SetJobFactory:
			// code(cluster); code(num); code(filename); code(text); reply
			// code(rval); if rval<0 code(terrno). num is max_materialize ->
			// JobMaterializeLimit. The obsolete CONDOR_SetMaterializeData shares
			// the arg shape but is rejected with EPERM.
			cluster, e1 := rm.GetInt(ctx)
			num, e2 := rm.GetInt(ctx)
			_, e3 := rm.GetString(ctx) // filename (legacy/unused; schedd picks the spool path)
			text, e4 := rm.GetString(ctx)
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
				return nil
			}
			if op == hqmgmt.OpSetMaterializeData {
				_ = s.reply(ctx, c, -1, ePERM) // obsolete op
				continue
			}
			if !writable {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			if cluster != txn.ActiveCluster() {
				_ = s.reply(ctx, c, -1, ePERM)
				continue
			}
			if err := s.setJobFactory(txn, cluster, num, text); err != nil {
				s.log.Warn(logging.DestinationGeneral, "SetJobFactory failed", "cluster", cluster, "err", err)
				_ = s.reply(ctx, c, -1, eINVAL)
				continue
			}
			if err := s.reply(ctx, c, 0, 0); err != nil {
				return err
			}

		case hqmgmt.OpSendMaterializeData:
			// SendMaterializeData(cluster, flags, <itemdata bytes until EOM>).
			// Reply verified against CONDOR_SendMaterializeData: code(filename);
			// code(row_count); code(rval); if rval<0 code(terrno).
			cluster, e1 := rm.GetInt(ctx)
			_, e2 := rm.GetInt(ctx) // flags (submit sends 0)
			data, e3 := rm.GetRemainingBytes(ctx)
			if e1 != nil || e2 != nil || e3 != nil {
				return nil
			}
			if !writable || cluster != txn.ActiveCluster() {
				if err := s.replyMaterializeData(ctx, c, "", 0, -1, ePERM); err != nil {
					return err
				}
				continue
			}
			path, count, err := s.sendMaterializeData(txn, cluster, data)
			if err != nil {
				s.log.Warn(logging.DestinationGeneral, "SendMaterializeData failed", "cluster", cluster, "err", err)
				if err := s.replyMaterializeData(ctx, c, "", 0, -1, eINVAL); err != nil {
					return err
				}
				continue
			}
			if err := s.replyMaterializeData(ctx, c, path, count, 0, 0); err != nil {
				return err
			}

		default:
			// Any other op (jobsets SendJobQueueAd 10040, ...): we cannot safely
			// read unknown argument shapes, so end the connection cleanly rather
			// than risk desyncing the stream. UseJobsets=false keeps modern
			// condor_submit from sending these.
			s.log.Warn(logging.DestinationGeneral, "unsupported QMGMT op; closing connection", "op", op)
			txn.Abort()
			return nil
		}
	}
}

// setJobFactory stores the submit digest to the spool and stages the factory
// bookkeeping on the cluster ad (proc -1) in the current transaction, so it
// commits atomically with the rest of the submit. Mirrors
// QmgmtHandleSetJobFactory (qmgmt.cpp): num -> JobMaterializeLimit, the digest
// text -> $(SPOOL)/<c%10000>/condor_submit.<c>.digest -> JobMaterializeDigestFile,
// and NextProcId/NextRow/Paused initialized to 0.
func (s *Server) setJobFactory(txn *queue.Txn, cluster, num int, digest string) error {
	path := factory.SpooledDigestPath(s.spoolDir, cluster)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(digest), 0o644); err != nil {
		return err
	}
	set := func(name, expr string) error { return txn.SetAttribute(cluster, -1, name, expr) }
	if err := set(queue.AttrMaterializeLimit, strconv.Itoa(num)); err != nil {
		return err
	}
	if err := set(queue.AttrMaterializeDigestFile, strconv.Quote(path)); err != nil {
		return err
	}
	if err := set(queue.AttrMaterializeNextProcId, "0"); err != nil {
		return err
	}
	if err := set(queue.AttrMaterializeNextRow, "0"); err != nil {
		return err
	}
	if err := set(queue.AttrMaterializePaused, "0"); err != nil {
		return err
	}
	return set(queue.AttrMaterializeDate, strconv.FormatInt(nowUnix(), 10))
}

// sendMaterializeData stores the streamed itemdata to the spool and stages the
// itemdata file + row count on the cluster ad. Returns the spool path and row
// count for the reply. Mirrors QmgmtHandleSendMaterializeData (qmgmt.cpp).
func (s *Server) sendMaterializeData(txn *queue.Txn, cluster int, data []byte) (string, int, error) {
	path := factory.SpooledItemsPath(s.spoolDir, cluster)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", 0, err
	}
	count := len(factory.ParseItems(data))
	if err := txn.SetAttribute(cluster, -1, queue.AttrMaterializeItemsFile, strconv.Quote(path)); err != nil {
		return "", 0, err
	}
	if err := txn.SetAttribute(cluster, -1, queue.AttrMaterializeItemCount, strconv.Itoa(count)); err != nil {
		return "", 0, err
	}
	return path, count, nil
}

// replyMaterializeData writes the SendMaterializeData reply: filename, row_count,
// rval, and terrno when rval < 0 (qmgmt_receivers.cpp CONDOR_SendMaterializeData).
func (s *Server) replyMaterializeData(ctx context.Context, c *cedarserver.Conn, filename string, count, rval, terrno int) error {
	wm := message.NewMessageForStream(c.Stream)
	if err := wm.PutString(ctx, filename); err != nil {
		return err
	}
	if err := wm.PutInt(ctx, count); err != nil {
		return err
	}
	if err := wm.PutInt(ctx, rval); err != nil {
		return err
	}
	if rval < 0 {
		if err := wm.PutInt(ctx, terrno); err != nil {
			return err
		}
	}
	return wm.FinishMessage(ctx)
}

// nowUnix is a var so tests can pin time.
var nowUnix = func() int64 { return time.Now().Unix() }

// reply writes a standard rval [+terrno] reply and finishes the message.
func (s *Server) reply(ctx context.Context, c *cedarserver.Conn, rval, terrno int) error {
	wm := message.NewMessageForStream(c.Stream)
	if err := hqmgmt.WriteReply(ctx, wm, rval, terrno); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

// replyAd writes rval=0 followed by a ClassAd.
func (s *Server) replyAd(ctx context.Context, c *cedarserver.Conn, ad *classad.ClassAd) error {
	wm := message.NewMessageForStream(c.Stream)
	if err := wm.PutInt(ctx, 0); err != nil {
		return err
	}
	if err := wm.PutClassAd(ctx, ad); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

// replyCommit sends the commit reply: rval, then a trailing ClassAd modern
// clients always expect (empty/warning on success, ErrorCode/ErrorReason on
// failure), matching qmgmt_receivers.cpp for peers >= 8.7.4.
func (s *Server) replyCommit(ctx context.Context, c *cedarserver.Conn, cerr error) error {
	wm := message.NewMessageForStream(c.Stream)
	if cerr != nil {
		if err := wm.PutInt(ctx, -1); err != nil {
			return err
		}
		if err := wm.PutInt(ctx, eINVAL); err != nil {
			return err
		}
		errAd := classad.New()
		_ = errAd.Set("ErrorCode", int64(2))
		errAd.InsertAttrString("ErrorReason", cerr.Error())
		if err := wm.PutClassAd(ctx, errAd); err != nil {
			return err
		}
		return wm.FinishMessage(ctx)
	}
	if err := wm.PutInt(ctx, 0); err != nil {
		return err
	}
	// Success: an (empty) trailing ad. Modern condor_submit peeks for it.
	if err := wm.PutClassAd(ctx, classad.New()); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

// replyNewClusterErr sends the NewCluster failure reply: rval=-1, terrno, then an
// ErrorCode/ErrorReason ad (qmgmt_receivers.cpp).
func (s *Server) replyNewClusterErr(ctx context.Context, c *cedarserver.Conn, cerr error) error {
	wm := message.NewMessageForStream(c.Stream)
	if err := wm.PutInt(ctx, -1); err != nil {
		return err
	}
	if err := wm.PutInt(ctx, eINVAL); err != nil {
		return err
	}
	errAd := classad.New()
	_ = errAd.Set("ErrorCode", int64(eINVAL))
	errAd.InsertAttrString("ErrorReason", cerr.Error())
	if err := wm.PutClassAd(ctx, errAd); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

// replyGetAttribute reads the attribute and sends the typed value payload.
func (s *Server) replyGetAttribute(ctx context.Context, c *cedarserver.Conn, txn *queue.Txn, op, cluster, proc int, name string) error {
	valStr, ok := txn.GetAttribute(cluster, proc, name)
	if !ok {
		return s.reply(ctx, c, -1, eNOENT)
	}
	wm := message.NewMessageForStream(c.Stream)
	if err := wm.PutInt(ctx, 0); err != nil {
		return err
	}
	ad, _ := txn.GetJobAd(cluster, proc)
	switch op {
	case hqmgmt.OpGetAttributeInt:
		v := int64(0)
		if ad != nil {
			v, _ = ad.EvaluateAttrInt(name)
		}
		if err := wm.PutInt(ctx, int(v)); err != nil {
			return err
		}
	case hqmgmt.OpGetAttributeFloat:
		f := float64(0)
		if ad != nil {
			f, _ = ad.EvaluateAttrReal(name)
		}
		if err := wm.PutDouble(ctx, f); err != nil {
			return err
		}
	default: // String, Expr
		if err := wm.PutString(ctx, valStr); err != nil {
			return err
		}
	}
	return wm.FinishMessage(ctx)
}

// streamAllJobs streams every matching committed job in one message: for each,
// rval=0 then the ad (with ServerTime); then a terminating rval=-1 + terrno.
func (s *Server) streamAllJobs(ctx context.Context, c *cedarserver.Conn, constraint string) error {
	wm := message.NewMessageForStream(c.Stream)
	for _, ad := range s.snapshot(constraint) {
		if err := wm.PutInt(ctx, 0); err != nil {
			return err
		}
		cfg := &message.PutClassAdConfig{Options: message.PutClassAdServerTime}
		if err := wm.PutClassAdWithOptions(ctx, ad, cfg); err != nil {
			return err
		}
	}
	if err := wm.PutInt(ctx, -1); err != nil {
		return err
	}
	if err := wm.PutInt(ctx, eNOENT); err != nil {
		return err
	}
	return wm.FinishMessage(ctx)
}

// snapshot returns the committed jobs matching constraint (all jobs if the
// constraint is empty or unparseable).
func (s *Server) snapshot(constraint string) []*classad.ClassAd {
	var out []*classad.ClassAd
	if q := compileConstraint(constraint); q != nil {
		for ad := range s.q.Query(q) {
			out = append(out, ad)
		}
		return out
	}
	for ad := range s.q.Scan() {
		out = append(out, ad)
	}
	return out
}

// firstMatch returns the first committed job matching constraint, or nil.
func (s *Server) firstMatch(constraint string) *classad.ClassAd {
	m := s.snapshot(constraint)
	if len(m) == 0 {
		return nil
	}
	return m[0]
}

// compileConstraint parses a constraint into a vm.Query, or nil for match-all.
func compileConstraint(constraint string) *vm.Query {
	if constraint == "" || constraint == "true" || constraint == "TRUE" {
		return nil
	}
	q, err := vm.Parse(constraint)
	if err != nil {
		return nil
	}
	return q
}
