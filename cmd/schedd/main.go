// Command schedd runs a pure-Go HTCondor condor_schedd as a Go daemon under
// condor_master. Stage 1 is lifecycle-only: it boots like any DaemonCore daemon
// (shared-port endpoint, DC_SET_READY / DC_CHILDALIVE, SIGTERM/SIGHUP), answers
// the standard DC_* commands so condor_ping / condor_reconfig / condor_off work,
// registers RESCHEDULE as a logged no-op, and periodically advertises a
// Scheduler ad so it appears in `condor_status -schedd`. No job handling yet.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/advertise"
	"github.com/bbockelm/golang-ap/internal/match"
	"github.com/bbockelm/golang-ap/internal/negotiate"
	"github.com/bbockelm/golang-ap/internal/queue"
	"github.com/bbockelm/golang-ap/internal/sched"
	"github.com/bbockelm/golang-ap/internal/spool"
	"github.com/bbockelm/golang-ap/internal/userlog"
	"github.com/bbockelm/golang-ap/shadow"
)

func main() {
	// MUST be the very first statement: when the droppriv pool backend spawns a
	// per-user helper it re-execs THIS binary with a private sentinel set;
	// RunHelperIfRequested detects that, serves the helper control protocol, and
	// exits without ever returning. In the normal daemon launch (no sentinel) it
	// returns immediately and main() proceeds untouched.
	droppriv.RunHelperIfRequested()

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "golang-ap schedd:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":0", "fallback TCP listen address when not inheriting a shared-port endpoint")
	// condor_master appends these standard DaemonCore flags when it launches a
	// daemon; accept them so flag.Parse does not reject our launch. -local-name
	// additionally scopes config lookups. -f/-t are accepted for compatibility
	// (the master no longer passes -f to child daemons, but a hand-launch or
	// <SUBSYS>_ARGS might).
	localName := flag.String("local-name", "", "HTCondor subsystem local-name; passed by condor_master")
	_ = flag.String("sock", "", "HTCondor shared-port endpoint name; accepted for compatibility (fd inherited via CONDOR_INHERIT)")
	_ = flag.Bool("f", false, "run in the foreground; accepted for compatibility")
	_ = flag.Bool("t", false, "log to the terminal; accepted for compatibility")
	flag.Parse()

	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "SCHEDD", LocalName: *localName})
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Bootstrap logging and condor_master integration (drops privileges to the
	// condor user when started as root).
	d, err := daemon.New(daemon.Options{Subsys: "SCHEDD", Config: cfg})
	if err != nil {
		return err
	}
	log := d.Logger()
	// Route cedar's security/server slog output into ScheddLog.
	slog.SetDefault(d.Slog())

	// Server-side security policy from the HTCondor configuration (SEC_* knobs),
	// so this schedd authenticates and encrypts exactly like the C++ one.
	sec, err := htcondor.GetServerSecurityConfig(d.Config(), commands.QUERY_SCHEDD_ADS, "DAEMON")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}
	// Advertise our version in the DC_AUTHENTICATE server response. C++ clients
	// record it as the socket's peer version and version-gate wire features on
	// it — without it, condor_transfer_data / condor_submit -spool fall back to
	// the legacy FileTransfer protocol (no go-ahead handshake, no xfer_info ad,
	// no transfer acks) that the spool handlers do not speak.
	if sec.RemoteVersion == "" {
		sec.RemoteVersion = detectCondorVersion()
	}

	// Share one session cache between the command server and the match table so
	// startd keepalives (ALIVE) that resume a claim-derived session are recognized
	// by the server and renew the right match's lease.
	sessionCache := security.NewSessionCache()
	sec.SessionCache = sessionCache

	srv := cedarserver.New(sec)
	// DC_NOP / DC_RECONFIG / DC_OFF so condor_ping, condor_reconfig -daemon, and
	// condor_off -daemon work against our command port.
	d.RegisterDefaultCommands(srv)

	// Match table + ALIVE keepalive handler. Stage 2 wires these in so the schedd
	// can hold claims and answer startd keepalives; the scheduling loop that
	// actually creates matches (via REQUEST_CLAIM) lands in a later stage.
	matches := match.NewTable(sessionCache)
	match.RegisterALIVE(srv, matches, func(e match.AliveEvent) {
		log.Debug(logging.DestinationGeneral, "ALIVE received",
			"claim", e.PublicID, "found", e.Found, "interval", e.AliveInterval, "remote", e.RemoteAddr)
	})

	// The scheduler core is created below (it needs the listener address); the
	// RESCHEDULE handler nudges it, so forward-declare it here.
	var scheduler *sched.Scheduler

	// RESCHEDULE (kick the scheduling loop): nudge the core to advertise fresh
	// counts immediately so the negotiator sees new jobs quickly. Registered at
	// WRITE, matching the C++ schedd's authorization for it.
	srv.Handle(int(commands.RESCHEDULE), func(_ context.Context, c *cedarserver.Conn) error {
		log.Info(logging.DestinationGeneral, "RESCHEDULE received", "remote", c.RemoteAddr)
		if scheduler != nil {
			scheduler.Reschedule()
		}
		return nil
	}, "WRITE")

	// Command-socket listener: the shared-port endpoint inherited from
	// condor_master if present, otherwise a plain TCP bind. Under USE_SHARED_PORT
	// (required) the fallback is not used in practice.
	ln, err := d.Listener(func() (net.Listener, error) {
		return net.Listen("tcp", *listen)
	})
	if err != nil {
		log.Error(logging.DestinationGeneral, "listener setup failed", "err", err.Error())
		return err
	}
	defer func() { _ = ln.Close() }()

	// Publish our command address so tools (condor_status, condor_q) and the
	// collector can find us, exactly like the C++ schedd's SCHEDD_ADDRESS_FILE.
	if path := writeAddressFile(d, cfg, ln); path != "" {
		defer func() { _ = os.Remove(path) }()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Stage 5: the persistent job-queue authority in $(SPOOL) plus the QMGMT /
	// condor_q / condor_hold-release-rm command handlers (see queue_commands.go).
	name := scheddName(cfg, *localName)
	jobQueue, err := openJobQueue(cfg, name, log)
	if err != nil {
		return fmt.Errorf("opening job queue: %w", err)
	}
	defer func() { _ = jobQueue.Close() }()
	registerQueueCommands(srv, jobQueue, log)

	// The schedd's externally reachable command sinful ("<host:port?sock=...>"),
	// used as the ALIVE scheduler address the startd calls back on, the starter's
	// ShadowIpAddr, and the file-transfer TransferSocket (all on the one shared
	// command port).
	scheddSinful := wrapSinful(schedAddr(d, ln))
	uidDomain, _ := cfg.Get("UID_DOMAIN")
	uidDomain = strings.TrimSpace(uidDomain)

	// Stage 6: one file-transfer router hosted on the schedd's shared command
	// server (FILETRANS_UPLOAD/DOWNLOAD registered once, routed to the owning
	// shadow by TransferKey), backed by the schedd's session cache so each
	// shadow's imported "filetrans." session is recognized on the starter's
	// inbound connection.
	endpoint := shadow.NewSharedEndpoint(srv, sessionCache, scheddSinful,
		func(format string, args ...any) { log.Debug(logging.DestinationGeneral, fmt.Sprintf(format, args...)) })

	// The scheduler core owns the running-job registry and every job-queue
	// transition; it also pushes the Scheduler + Submitter ads on each
	// SCHEDD_INTERVAL tick (and on a RESCHEDULE nudge).
	adv := advertise.New(advertise.Options{
		Logger:         log,
		Name:           name,
		Machine:        fullHostname(cfg),
		StartTime:      time.Now(),
		MaxJobsRunning: configInt(cfg, "MAX_JOBS_RUNNING", 10000),
		CollectorsFn:   func() []string { return resolveCollectors(d.Config()) },
		// Advertise the command address as a canonical sinful ("<host:port?sock=..>"):
		// the negotiator builds a Daemon locator from the Submitter ad's ScheddIpAddr,
		// and HTCondor's Sinful parser needs the angle brackets to honor the shared-port
		// ?sock= parameter (without them the negotiator "Failed to connect").
		AddressFn:    func() string { return wrapSinful(schedAddr(d, ln)) },
		CountsFn:     queueCountsFn(jobQueue),
		SubmittersFn: submittersFn(jobQueue),
	})
	// User-job-log events (`log = ...` in the submit file), so condor_wait and
	// DAGMan can follow jobs: the queue writes SUBMIT at commit and
	// HELD/RELEASED/ABORTED on the action path; the scheduler core writes the
	// run-side events (EXECUTE/TERMINATED/EVICTED and the reconnect trio).
	//
	// Writes are asynchronous and off-core: a fixed, bounded pool of writer
	// goroutines drains per-file buffers, so a slow/hung user-log filesystem
	// can never freeze scheduling (core producers drop-on-full; submit and the
	// action/reconnect paths backpressure). See internal/userlog and ROADMAP #1.
	ulogGrace := configSeconds(cfg, "SCHEDD_SHUTDOWN_DRAIN_GRACE", sched.DefaultDrainGrace)
	ulogMgr := userlog.New(scheddSinful, userlog.Config{
		Workers:       configInt(cfg, "SCHEDD_USERLOG_WORKERS", 32),
		QueueDepth:    configInt(cfg, "SCHEDD_USERLOG_QUEUE_DEPTH", 1024),
		SubmitTimeout: configSeconds(cfg, "SCHEDD_USERLOG_BACKPRESSURE_TIMEOUT", 5*time.Second),
		IdleTimeout:   configSeconds(cfg, "SCHEDD_USERLOG_IDLE_TIMEOUT", 60*time.Second),
		MaxFiles:      configInt(cfg, "SCHEDD_USERLOG_MAX_FILES", 8192),
	}, func(format string, args ...any) {
		log.Warn(logging.DestinationGeneral, fmt.Sprintf(format, args...))
	})
	jobQueue.SetUserLog(ulogMgr)

	// Privilege-separation backend: routes the per-user spool + transfer file ops
	// through the job Owner's identity. Defaults to ModeNative, which on a
	// personal/unprivileged AP does no privilege switch and spawns no helpers
	// (byte-for-byte the pre-privsep behavior); a privileged deployment switches
	// for real, and SCHEDD_PRIVSEP_MODE=pool exercises the helper/FD-passing path.
	privsep, err := buildPrivsep(cfg, log)
	if err != nil {
		return fmt.Errorf("building privsep: %w", err)
	}
	// Close after the scheduler stops (LIFO): reaps every pool helper so none leak.
	defer func() { _ = privsep.Close() }()
	// Flush buffered user-log events on shutdown. Registered before
	// scheduler.Stop's defer so (LIFO) it runs AFTER the core drains -- capturing
	// the final EXECUTE/TERMINATED/EVICTED events the drain emits -- and before
	// the queue Close.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), ulogGrace)
		defer cancel()
		ulogMgr.Close(ctx)
	}()
	scheduler = sched.New(sched.Options{
		Logger:            log,
		AdvertiseInterval: configSeconds(cfg, "SCHEDD_INTERVAL", 300*time.Second),
		Advertise:         adv.Advertise,
		Queue:             jobQueue,
		Matches:           matches,
		Endpoint:          endpoint,
		ScheddName:        name,
		ScheddAddr:        scheddSinful,
		UIDDomain:         uidDomain,
		ShadowVersion:     detectCondorVersion(),
		AliveInterval:     configInt(cfg, "ALIVE_INTERVAL", 300),
		// How often the core sweeps claim leases (renewing live runs, reaping dead
		// matches). Configurable so tests can exercise several sweep ticks over a
		// short job instead of a long one; defaults to 30s.
		SweepInterval:     configSeconds(cfg, "SCHEDD_LEASE_SWEEP_INTERVAL", 30*time.Second),
		// How many shadow failures a job may accumulate before it is held with
		// HoldReasonCode 1002 (ShadowException) instead of requeued.
		MaxShadowExceptions: configInt(cfg, "MAX_SHADOW_EXCEPTIONS", sched.DefaultMaxShadowExceptions),
		DrainGrace:          configSeconds(cfg, "SCHEDD_SHUTDOWN_DRAIN_GRACE", sched.DefaultDrainGrace),
		// Chaos-test hook: "cluster.proc" whose first shadow run panics at
		// begin_execution. Config param wins; env var accepted as a fallback.
		PanicJob: configOrEnv(cfg, "GOLANG_AP_SHADOW_PANIC_AFTER_ACTIVATE"),
		// Shadow/claim reconnect: leave running jobs Running across a restart and
		// re-attach to their starters. SCHEDD_RECONNECT=false restores the old
		// drain-and-requeue behavior.
		ReconnectDisabled: !configBool(cfg, "SCHEDD_RECONNECT", true),
		DefaultJobLease:   configInt(cfg, "JOB_DEFAULT_LEASE_DURATION", sched.DefaultJobLeaseDuration),
		UserLog:           ulogMgr,
		Privsep:           privsep,
	})

	// NEGOTIATE (416): the negotiator's matchmaking. Registered at NEGOTIATOR (and
	// WRITE) like the C++ schedd; granted matches feed the scheduler core.
	neg := negotiate.New(jobQueue, log, scheduler.OnMatch)
	srv.Handle(int(commands.NEGOTIATE), neg.Handle, "NEGOTIATOR", "WRITE")

	// Sandbox spooling (condor_submit -spool / condor_transfer_data):
	// SPOOL_JOB_FILES(480) / SPOOL_JOB_FILES_WITH_PERMS(488) receive input
	// sandboxes into $(SPOOL) and release the code-16 hold; TRANSFER_DATA(486) /
	// TRANSFER_DATA_WITH_PERMS(489) send output sandboxes back to the submitter.
	spool.New(spool.Options{
		Queue:    jobQueue,
		SpoolDir: resolveSpoolDir(cfg),
		Logf: func(format string, args ...any) {
			log.Debug(logging.DestinationGeneral, fmt.Sprintf(format, args...))
		},
		Reschedule: func() {
			if scheduler != nil {
				scheduler.Reschedule()
			}
		},
		Privsep: privsep,
	}).Register(srv)
	// When a spooled job's output sandbox lands back in $(SPOOL) (shadow
	// FILETRANS_DOWNLOAD), record the spooled output list on the job ad —
	// the C++ starter's spooled-files report — so TRANSFER_DATA returns
	// exactly those files (plus Out/Err/UserLog).
	endpoint.SetOutputRecorder(func(c, p int, files []string) {
		jobQueue.Modify(c, p, func(ad *classad.ClassAd) {
			ad.InsertAttrString("SpooledOutputFiles", strings.Join(files, ","))
		})
	})

	// condor_rm / condor_hold of a running job: vacate its shadow (forcible
	// deactivate + release) and wait for the teardown to finish (bounded) before
	// the queue rewrites the job's status / archives it, so the slot is not left
	// Claimed.
	jobQueue.SetOnVacateRunning(func(c, p int) { scheduler.TeardownJobAndWait(c, p, 5*time.Second) })

	scheduler.Start(ctx)
	// Startup recovery: re-attach to any job a previous incarnation left Running
	// (persisted JobStatus=2 with a live lease) instead of requeueing it. Runs on
	// the core goroutine; bounded so a slow queue scan cannot wedge startup.
	scheduler.Recover(30 * time.Second)
	// On shutdown (SIGTERM / condor_off), Stop drains first. With reconnect
	// enabled (default) it detaches from running shadows, leaving their jobs
	// Running for the next start to re-attach; with SCHEDD_RECONNECT=false it
	// vacates and requeues them. The deferred queue Close runs after (LIFO).
	defer scheduler.Stop()

	log.Info(logging.DestinationGeneral, "golang-ap schedd starting",
		"listen", ln.Addr().String(), "under_master", d.UnderMaster(), "name", scheddName(cfg, *localName))

	return d.Serve(ctx, ln, srv.Serve)
}

// scheddName derives the schedd's Name attribute: SCHEDD_NAME if configured,
// else <local-name>@<host> when launched with -local-name, else the bare
// hostname. Matches how the C++ schedd names itself closely enough for the
// collector to key/display the ad.
func scheddName(cfg *config.Config, localName string) string {
	if v, ok := cfg.Get("SCHEDD_NAME"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	host := fullHostname(cfg)
	if localName != "" {
		return localName + "@" + host
	}
	return host
}

func fullHostname(cfg *config.Config) string {
	if v, ok := cfg.Get("FULL_HOSTNAME"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}

// resolveCollectors returns the collector endpoints to advertise to, derived
// from COLLECTOR_HOST. HTCondor allows COLLECTOR_HOST to carry port 0 (or no
// port) when the collector runs behind shared port and picks an ephemeral port;
// in that case the real command address lives in COLLECTOR_ADDRESS_FILE, exactly
// as the C++ Daemon locator falls back to the address file. Entries with a
// usable explicit port are used as-is.
func resolveCollectors(cfg *config.Config) []string {
	raw, _ := cfg.Get("COLLECTOR_HOST")
	var out []string
	for _, e := range splitHostList(raw) {
		if hasUsablePort(e) {
			out = append(out, e)
		} else if addr := readCollectorAddressFile(cfg); addr != "" {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		if addr := readCollectorAddressFile(cfg); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

// splitHostList splits a host list on commas/whitespace, dropping empties.
func splitHostList(raw string) []string {
	var out []string
	for _, h := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// hasUsablePort reports whether a host entry carries an explicit non-zero port
// (so it can be dialed directly without consulting the address file).
func hasUsablePort(entry string) bool {
	s := strings.TrimSpace(entry)
	s = strings.TrimPrefix(strings.TrimSuffix(s, ">"), "<")
	if i := strings.IndexByte(s, '?'); i >= 0 { // strip sinful query params
		s = s[:i]
	}
	_, port, err := net.SplitHostPort(s)
	return err == nil && port != "" && port != "0"
}

// readCollectorAddressFile returns the sinful string the collector published to
// COLLECTOR_ADDRESS_FILE (default $(LOG)/.collector_address), or "" if it cannot
// be read yet. Only usable when the collector is co-located with this schedd,
// which is exactly the case where COLLECTOR_HOST carries no usable port.
func readCollectorAddressFile(cfg *config.Config) string {
	path, ok := cfg.Get("COLLECTOR_ADDRESS_FILE")
	if !ok || path == "" {
		logDir, ok := cfg.Get("LOG")
		if !ok || logDir == "" {
			return ""
		}
		path = filepath.Join(logDir, ".collector_address")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

// schedAddr is this schedd's externally reachable command address: the
// shared-port sinful when running under condor_master, otherwise the plain
// listen address.
func schedAddr(d *daemon.Daemon, ln net.Listener) string {
	if sinful, ok := d.AdvertisedSinful(); ok {
		return sinful
	}
	return ln.Addr().String()
}

// writeAddressFile publishes the schedd's command address to SCHEDD_ADDRESS_FILE
// (default $(LOG)/.schedd_address) in the C++ daemon format: the sinful string,
// then the $CondorVersion$ and $CondorPlatform$ banner lines. The version line
// matters: C++ tools (Daemon::readAddressFile) take the local daemon's version
// from it and version-gate wire protocols on it. Without it they scan the
// daemon BINARY for an embedded "$CondorVersion:" string (Daemon::initVersion),
// which in a Go binary matches an unrelated format-string literal that parses
// as ancient — pushing condor_submit -spool onto the legacy SPOOL_JOB_FILES
// protocol this schedd does not speak. Returns the path written (for cleanup),
// or "" if none.
func writeAddressFile(d *daemon.Daemon, cfg *config.Config, ln net.Listener) string {
	path, ok := cfg.Get("SCHEDD_ADDRESS_FILE")
	if !ok || path == "" {
		logDir, ok := cfg.Get("LOG")
		if !ok || logDir == "" {
			return ""
		}
		path = filepath.Join(logDir, ".schedd_address")
	}
	content := "<" + schedAddr(d, ln) + ">\n" +
		detectCondorVersion() + "\n" +
		fmt.Sprintf("$CondorPlatform: %s_%s $\n", runtime.GOARCH, runtime.GOOS)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		slog.Warn("could not write schedd address file", "path", path, "err", err)
		return ""
	}
	return path
}

// buildPrivsep constructs the schedd's droppriv.Privsep from the SCHEDD_PRIVSEP_*
// knobs. It defaults to ModeNative so a personal/single-user AP keeps its exact
// current behavior (no privilege switch, no helper processes); privileged
// deployments get real per-user switching, and SCHEDD_PRIVSEP_MODE=pool selects
// the helper/FD-passing backend (with SCHEDD_PRIVSEP_FORCE_UNPRIVILEGED=true it
// runs the full helper machinery without root, for CI).
func buildPrivsep(cfg *config.Config, log *logging.Logger) (droppriv.Privsep, error) {
	mode := droppriv.ModeNative
	switch strings.ToLower(strings.TrimSpace(configOrEnv(cfg, "SCHEDD_PRIVSEP_MODE"))) {
	case "", "native":
		mode = droppriv.ModeNative
	case "auto":
		mode = droppriv.ModeAuto
	case "pool":
		mode = droppriv.ModePool
	default:
		return nil, fmt.Errorf("SCHEDD_PRIVSEP_MODE must be auto|native|pool, got %q",
			configOrEnv(cfg, "SCHEDD_PRIVSEP_MODE"))
	}
	cfgPS := droppriv.PrivsepConfig{
		Mode:                    mode,
		ForceHelperUnprivileged: configBool(cfg, "SCHEDD_PRIVSEP_FORCE_UNPRIVILEGED", false),
		MaxHelpers:              configInt(cfg, "SCHEDD_PRIVSEP_MAX_HELPERS", 0),
		HelperIdleTimeout:       configSeconds(cfg, "SCHEDD_PRIVSEP_IDLE_TIMEOUT", 0),
	}
	ps, err := droppriv.NewPrivsep(cfgPS)
	if err != nil {
		return nil, err
	}
	log.Info(logging.DestinationGeneral, "privsep backend ready",
		"mode", configOrEnv(cfg, "SCHEDD_PRIVSEP_MODE"),
		"force_unprivileged", cfgPS.ForceHelperUnprivileged,
		"euid", os.Geteuid())
	return ps, nil
}

func configSeconds(cfg *config.Config, key string, def time.Duration) time.Duration {
	if v, ok := cfg.Get(key); ok {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return def
}

// configOrEnv returns the config value for key, falling back to an identically
// named environment variable (used for test hooks).
func configOrEnv(cfg *config.Config, key string) string {
	if v, ok := cfg.Get(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(os.Getenv(key))
}

func configInt(cfg *config.Config, key string, def int) int {
	if v, ok := cfg.Get(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// configBool parses a boolean config knob (HTCondor accepts TRUE/FALSE/1/0/T/F,
// case-insensitively), returning def when unset or unparseable.
func configBool(cfg *config.Config, key string, def bool) bool {
	v, ok := cfg.Get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "t", "1", "yes", "y":
		return true
	case "false", "f", "0", "no", "n":
		return false
	}
	return def
}

// wrapSinful ensures a command address is a canonical HTCondor sinful string
// wrapped in angle brackets (the form the startd/starter expect for callbacks).
func wrapSinful(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "<") {
		return addr
	}
	return "<" + addr + ">"
}

// submittersFn adapts the queue's per-submitter tallies to the advertiser's
// Submitter list (one UPDATE_SUBMITTOR_AD per submitter each round).
func submittersFn(q *queue.Queue) func() []advertise.Submitter {
	return func() []advertise.Submitter {
		var out []advertise.Submitter
		for _, sc := range q.SubmitterCounts() {
			out = append(out, advertise.Submitter{
				Name:    sc.Name,
				Idle:    sc.Idle,
				Running: sc.Running,
				Held:    sc.Held,
			})
		}
		return out
	}
}

// detectCondorVersion returns a "$CondorVersion: ...$" string for the shadow to
// present to the starter, so the starter treats us as a modern peer (enabling
// job_termination, event_notification, request_guidance). It reads condor_version
// from the environment, falling back to a plausible modern string.
func detectCondorVersion() string {
	if out, err := exec.Command("condor_version").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "$CondorVersion:") {
				return line
			}
		}
	}
	return "$CondorVersion: 25.0.0 2025-01-01 BuildID: golang-ap $"
}
