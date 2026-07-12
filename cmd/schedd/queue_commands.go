// Queue-command wiring for the Stage 5 job queue: opens the persistent queue
// authority in $(SPOOL) and registers the QMGMT (condor_submit), QUERY_JOB_ADS
// (condor_q), and ACT_ON_JOBS (condor_hold/release/rm) handlers on the cedar
// command server. Kept in its own file so main.go only needs a single call.
package main

import (
	"strings"

	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/actions"
	"github.com/bbockelm/golang-ap/internal/advertise"
	"github.com/bbockelm/golang-ap/internal/qmgmt"
	"github.com/bbockelm/golang-ap/internal/query"
	"github.com/bbockelm/golang-ap/internal/queue"
)

// resolveSpoolDir returns $(SPOOL), falling back to $(LOG)/spool then "spool",
// matching the C++ schedd. Shared by the job queue and the spool handlers so
// both agree on where per-job sandboxes live.
func resolveSpoolDir(cfg *config.Config) string {
	spool, ok := cfg.Get("SPOOL")
	if !ok || strings.TrimSpace(spool) == "" {
		if logDir, ok := cfg.Get("LOG"); ok && logDir != "" {
			spool = logDir + "/spool"
		} else {
			spool = "spool"
		}
	}
	return strings.TrimSpace(spool)
}

// openJobQueue opens (creating/recovering as needed) the persistent job queue
// under $(SPOOL). The caller must Close it on shutdown.
func openJobQueue(cfg *config.Config, name string, log *logging.Logger) (*queue.Queue, error) {
	spool := resolveSpoolDir(cfg)
	uidDomain, _ := cfg.Get("UID_DOMAIN")
	supers := []string{"condor", "root"}
	if v, ok := cfg.Get("QUEUE_SUPER_USERS"); ok {
		for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if s != "" {
				supers = append(supers, s)
			}
		}
	}
	q, err := queue.Open(queue.Options{
		Dir:        strings.TrimSpace(spool),
		ScheddName: name,
		UIDDomain:  strings.TrimSpace(uidDomain),
		SuperUsers: supers,
		// Per-attribute QMGMT authorization (see internal/queue/authz.go): the
		// SYSTEM_* defaults are baked in; these knobs add operator extras and the
		// trust toggles, mirroring the C++ schedd's config.
		ImmutableAttrs:    attrList(cfg, "IMMUTABLE_JOB_ATTRS"),
		ProtectedAttrs:    attrList(cfg, "PROTECTED_JOB_ATTRS"),
		SecureAttrs:       attrList(cfg, "SECURE_JOB_ATTRS"),
		AllUsersTrusted:   configBool(cfg, "QUEUE_ALL_USERS_TRUSTED", false),
		IgnoreSecureAttrs: configBool(cfg, "IGNORE_ATTEMPTS_TO_SET_SECURE_JOB_ATTRS", true),
	})
	if err != nil {
		return nil, err
	}
	log.Info(logging.DestinationGeneral, "job queue opened", "spool", spool, "jobs", q.Counts().Total)
	return q, nil
}

// attrList splits a comma/space/tab-separated HTCondor attribute-list config
// value (e.g. IMMUTABLE_JOB_ATTRS) into individual attribute names.
func attrList(cfg *config.Config, key string) []string {
	v, ok := cfg.Get(key)
	if !ok {
		return nil
	}
	var out []string
	for _, a := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// registerQueueCommands registers the Stage 5 job-queue command handlers:
// QMGMT read/write, the condor_q query commands, and ACT_ON_JOBS.
func registerQueueCommands(srv *cedarserver.Server, q *queue.Queue, log *logging.Logger, spoolDir string) {
	qm := qmgmt.New(q, log, spoolDir)
	// QMGMT_WRITE_CMD forces authentication (the queue needs the submitting
	// user); registered at WRITE like the C++ schedd. The read variant serves
	// tools that only read the queue.
	srv.Handle(int(commands.QMGMT_WRITE_CMD), qm.Handle, "WRITE")
	srv.Handle(int(commands.QMGMT_READ_CMD), qm.Handle, "READ")

	qs := query.New(q, log)
	srv.Handle(int(commands.QUERY_JOB_ADS), qs.Handle, "READ")
	srv.Handle(int(commands.QUERY_JOB_ADS_WITH_AUTH), qs.Handle, "READ")

	as := actions.New(q, log)
	srv.Handle(int(commands.ACT_ON_JOBS), as.Handle, "WRITE")
}

// queueCountsFn adapts the queue's tallies to the advertiser's QueueCounts.
func queueCountsFn(q *queue.Queue) func() advertise.QueueCounts {
	return func() advertise.QueueCounts {
		c := q.Counts()
		return advertise.QueueCounts{
			Idle:    c.Idle,
			Running: c.Running,
			Held:    c.Held,
			Removed: c.Removed,
			Total:   c.Total,
			Users:   c.Owners,
		}
	}
}
