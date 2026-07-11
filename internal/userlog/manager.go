// Package userlog is the schedd-side glue that writes standard HTCondor
// user-job-log events (the file a submit description names with `log =
// ...`) so condor_wait and DAGMan can follow a job's lifecycle.
//
// It is a thin adapter over github.com/bbockelm/golang-htcondor/userlog
// (the byte-compatible classic-format Writer): the Manager resolves a
// job's log path from its ClassAd (the UserLog attribute, honoring
// absolute vs Iwd-relative paths, matching getPathToUserLog in
// src/condor_utils/write_user_log.cpp) and emits the right event at each
// job-state transition. Every method is a no-op when the job ad has no
// UserLog, so jobs submitted without `log = ...` cost nothing.
//
// Which side writes which event mirrors the C++ daemons for a vanilla
// job (verified against the HTCondor source):
//
//   - SUBMIT: the SCHEDD, at commit of the job into the queue
//     (qmgmt.cpp CommitTransaction -> Scheduler::WriteSubmitToUserLog),
//     NOT condor_submit. So the Go schedd writes it at queue commit.
//   - EXECUTE / TERMINATED / EVICTED: the shadow. The Go schedd embeds
//     the shadow role, so it writes these at the run transitions.
//   - HELD / RELEASED / ABORTED: the SCHEDD, on condor_hold / _release /
//     _rm (schedd.cpp actOnJobs / abort_job_myself). The Go schedd
//     writes these in the queue-action path.
//   - DISCONNECTED / RECONNECTED / RECONNECT_FAILED: the shadow, around
//     a reconnect. The Go schedd writes these on its reconnect path.
package userlog

import (
	"path/filepath"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	hlog "github.com/bbockelm/golang-htcondor/userlog"
)

// Manager writes user-log events for jobs that request one. It is safe for
// concurrent use (each event opens/appends/closes under the underlying
// Writer's advisory lock).
type Manager struct {
	// scheddSinful is this schedd's address, used as the SUBMIT event's
	// submit host (C++ uses daemonCore->privateNetworkIpAddr).
	scheddSinful string
	logf         func(format string, args ...any)
}

// New builds a Manager. scheddSinful is the schedd's sinful string (the
// SUBMIT event's "submitted from host"); logf, if non-nil, receives a
// best-effort message when an event cannot be written.
func New(scheddSinful string, logf func(format string, args ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Manager{scheddSinful: scheddSinful, logf: logf}
}

// writerFor resolves the job's log path from ad and returns a Writer, or
// (nil,false) when the job has no UserLog attribute (no-op case).
func (m *Manager) writerFor(ad *classad.ClassAd) (*hlog.Writer, bool) {
	if ad == nil {
		return nil, false
	}
	path, ok := ad.EvaluateAttrString("UserLog")
	if !ok || path == "" {
		return nil, false
	}
	if !filepath.IsAbs(path) {
		if iwd, ok := ad.EvaluateAttrString("Iwd"); ok && iwd != "" {
			path = filepath.Join(iwd, path)
		}
	}
	c, _ := ad.EvaluateAttrInt("ClusterId")
	p, _ := ad.EvaluateAttrInt("ProcId")
	return hlog.NewWriter(path, int(c), int(p), 0), true
}

// emit writes rec to the job's log (no-op when the job has no UserLog).
func (m *Manager) emit(ad *classad.ClassAd, rec hlog.EventRecord) {
	w, ok := m.writerFor(ad)
	if !ok {
		return
	}
	if err := w.WriteEvent(rec); err != nil {
		m.logf("userlog: %v", err)
	}
}

// Submit writes the SUBMIT event (000) at job commit.
func (m *Manager) Submit(ad *classad.ClassAd) {
	m.emit(ad, hlog.SubmitEvent(time.Now(), m.scheddSinful))
}

// Execute writes the EXECUTE event (001). executeHost is the startd's
// address (falling back to the slot name); slotName, if set, adds the
// SlotName line.
func (m *Manager) Execute(ad *classad.ClassAd, executeHost, slotName string) {
	m.emit(ad, hlog.ExecuteEvent(time.Now(), executeHost, slotName))
}

// Terminated writes the JOB_TERMINATED event (005). On a normal exit pass
// bySignal=false and code=exit status; on a signal exit pass bySignal=true
// and code=signal number.
func (m *Manager) Terminated(ad *classad.ClassAd, bySignal bool, code int) {
	m.emit(ad, hlog.TerminatedEvent(time.Now(), bySignal, code))
}

// Evicted writes the JOB_EVICTED event (004) for a run that was requeued
// (starter death, lease loss, panic requeue).
func (m *Manager) Evicted(ad *classad.ClassAd, reason string) {
	m.emit(ad, hlog.EvictedEvent(time.Now(), reason))
}

// Aborted writes the JOB_ABORTED event (009) on condor_rm.
func (m *Manager) Aborted(ad *classad.ClassAd, reason string) {
	m.emit(ad, hlog.AbortedEvent(time.Now(), reason))
}

// Held writes the JOB_HELD event (012) on condor_hold (or a policy hold).
func (m *Manager) Held(ad *classad.ClassAd, reason string, code, subcode int) {
	m.emit(ad, hlog.HeldEvent(time.Now(), reason, code, subcode))
}

// Released writes the JOB_RELEASED event (013) on condor_release.
func (m *Manager) Released(ad *classad.ClassAd, reason string) {
	m.emit(ad, hlog.ReleasedEvent(time.Now(), reason))
}

// Disconnected writes the JOB_DISCONNECTED event (022) when the schedd
// loses its starter connection and begins a reconnect.
func (m *Manager) Disconnected(ad *classad.ClassAd, reason, startdName, startdAddr string) {
	if startdName == "" || startdAddr == "" || reason == "" {
		return // C++ formatBody refuses to write with any field empty
	}
	m.emit(ad, hlog.DisconnectedEvent(time.Now(), reason, startdName, startdAddr))
}

// Reconnected writes the JOB_RECONNECTED event (023) on a successful
// reconnect.
func (m *Manager) Reconnected(ad *classad.ClassAd, startdName, startdAddr, starterAddr string) {
	if startdName == "" || startdAddr == "" || starterAddr == "" {
		return
	}
	m.emit(ad, hlog.ReconnectedEvent(time.Now(), startdName, startdAddr, starterAddr))
}

// ReconnectFailed writes the JOB_RECONNECT_FAILED event (024) when a
// reconnect could not be established.
func (m *Manager) ReconnectFailed(ad *classad.ClassAd, reason, startdName string) {
	if reason == "" || startdName == "" {
		return
	}
	m.emit(ad, hlog.ReconnectFailedEvent(time.Now(), reason, startdName))
}
