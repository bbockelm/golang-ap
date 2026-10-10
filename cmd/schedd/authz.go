package main

import (
	"context"
	"log/slog"
	"net"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
)

// scheddAuthz is the ALLOW_<level>/DENY_<level> authorization policy for
// every command served on the schedd's command socket: the schedd protocol,
// the DC_* defaults, and the shadows' file-transfer and the startds' ALIVE
// commands that share the socket. It is built once from the configuration
// and rebuilt on reconfig, as the C++ daemons rebuild IpVerify.
type scheddAuthz struct {
	cur atomic.Pointer[authzState]
}

type authzState struct {
	policy *authz.Policy
	cfg    authz.ConfigGetter
}

// authzSubsys is the subsystem whose ALLOW_<level>_<subsys> variants apply.
const authzSubsys = "SCHEDD"

// punchedHoles are the levels C++ DaemonCore grants the identities of the
// sessions condor_master shares with its children whatever ALLOW_/DENY_ say
// (IpVerify::PunchHole in daemon_core.cpp, for the family session and the
// inherited parent session), with the levels each one implies. cedar
// attributes these identities only to a peer resuming the inherited session.
var punchedHoles = map[string][]authz.Perm{
	"condor@family": {
		authz.PermAdministrator, authz.PermDaemon, authz.PermNegotiator,
		authz.PermAdvertiseMaster, authz.PermAdvertiseSchedd, authz.PermAdvertiseStartd,
		authz.PermWrite, authz.PermRead,
	},
	"condor@parent": {authz.PermAdministrator, authz.PermDaemon, authz.PermWrite, authz.PermRead},
}

func newScheddAuthz(cfg authz.ConfigGetter) (*scheddAuthz, error) {
	a := &scheddAuthz{}
	if err := a.reload(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

// reload rebuilds the policy from cfg; commands dispatched afterwards are
// checked against the new one.
func (a *scheddAuthz) reload(cfg authz.ConfigGetter) error {
	p, err := authz.NewPolicy(cfg, authzSubsys)
	if err != nil {
		return err
	}
	a.cur.Store(&authzState{policy: p, cfg: cfg})
	return nil
}

// Authorize reports whether user, connecting from peerAddr, holds the
// authorization level perm. It has the signature of cedar's
// Server.Authorizer.
func (a *scheddAuthz) Authorize(perm, peerAddr, user string) bool {
	for _, p := range punchedHoles[user] {
		if string(p) == perm {
			return true
		}
	}
	return a.cur.Load().policy.Authorize(perm, peerAddr, user)
}

// policyKnob returns the setting that supplies prefix+perm (prefix "ALLOW_"
// or "DENY_"), or "" if none is set. An unset level falls back to DEFAULT,
// and at each level the _SCHEDD variant is consulted first, as in
// authz.Policy.
func (a *scheddAuthz) policyKnob(prefix, perm string) string {
	cfg := a.cur.Load().cfg
	for _, p := range []string{perm, string(authz.PermDefault)} {
		for _, k := range []string{prefix + p + "_" + authzSubsys, prefix + p} {
			if _, ok := cfg.Get(k); ok {
				return k
			}
		}
	}
	return ""
}

// refusedRE matches the error cedar's Server.ServeConn returns when the
// Authorizer refuses a command: it names the command and the identity. The
// denial tests in authz_test.go fail if cedar changes that wording.
var refusedRE = regexp.MustCompile(`command (\d+) \([^)]*\) refused: identity ("(?:[^"\\]|\\.)*") is not authorized`)

// logDenial logs err if it is a command the authorization policy refused,
// with the command, its authorization level, the peer, the identity, and
// the ALLOW_/DENY_ settings that decide that level.
func (a *scheddAuthz) logDenial(log *slog.Logger, srv *cedarserver.Server, peerAddr string, err error) {
	m := refusedRE.FindStringSubmatch(err.Error())
	if m == nil {
		return
	}
	cmd, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return
	}
	user, convErr := strconv.Unquote(m[2])
	if convErr != nil {
		return
	}
	if user == "" {
		user = "unauthenticated"
	}
	perms := srv.CommandPerms(cmd)
	var allow, deny []string
	for _, perm := range perms {
		k := a.policyKnob("ALLOW_", perm)
		if k == "" {
			k = "ALLOW_" + perm + " (unset)"
		}
		allow = append(allow, k)
		if k := a.policyKnob("DENY_", perm); k != "" {
			deny = append(deny, k)
		}
	}
	log.Warn("PERMISSION DENIED",
		"command", commandName(cmd),
		"command_id", cmd,
		"level", strings.Join(perms, ","),
		"peer", peerAddr,
		"user", user,
		"allow_knob", strings.Join(allow, ","),
		"deny_knob", strings.Join(deny, ","),
		"destination", "security")
}

// commandNames names the commands this socket serves that cedar's command
// table does not.
var commandNames = map[int]string{
	commands.QMGMT_READ_CMD:             "QMGMT_READ_CMD",
	commands.QMGMT_WRITE_CMD:            "QMGMT_WRITE_CMD",
	commands.SPOOL_JOB_FILES:            "SPOOL_JOB_FILES",
	commands.SPOOL_JOB_FILES_WITH_PERMS: "SPOOL_JOB_FILES_WITH_PERMS",
	commands.TRANSFER_DATA:              "TRANSFER_DATA",
	commands.TRANSFER_DATA_WITH_PERMS:   "TRANSFER_DATA_WITH_PERMS",
	commands.ALIVE:                      "ALIVE",
	commands.FILETRANS_UPLOAD:           "FILETRANS_UPLOAD",
	commands.FILETRANS_DOWNLOAD:         "FILETRANS_DOWNLOAD",
	commands.DC_RECONFIG:                "DC_RECONFIG",
	commands.DC_RECONFIG_FULL:           "DC_RECONFIG_FULL",
	commands.DC_OFF_GRACEFUL:            "DC_OFF_GRACEFUL",
	commands.DC_OFF_PEACEFUL:            "DC_OFF_PEACEFUL",
	commands.DC_OFF_FAST:                "DC_OFF_FAST",
	commands.DC_NOP_READ:                "DC_NOP_READ",
	commands.DC_NOP_WRITE:               "DC_NOP_WRITE",
	commands.DC_NOP_NEGOTIATOR:          "DC_NOP_NEGOTIATOR",
}

// commandName returns cmd's HTCondor name, or its number if it has none.
func commandName(cmd int) string {
	if n := commands.GetCommandName(cmd); n != "" {
		return n
	}
	if n, ok := commandNames[cmd]; ok {
		return n
	}
	return strconv.Itoa(cmd)
}

// serveCommands returns a serve loop for srv: like cedar's Server.Serve, it
// accepts connections on a listener and serves each on srv until ctx is
// cancelled, and it also logs every command the authorization policy refused.
// cedar closes a refused connection without logging it, so this is the
// operator's record of a denial.
func serveCommands(srv *cedarserver.Server, az *scheddAuthz, log *slog.Logger) func(context.Context, net.Listener) error {
	return func(ctx context.Context, ln net.Listener) error {
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			_ = srv.KeepAlive.Apply(conn)
			go func() {
				peer := conn.RemoteAddr().String()
				defer func() {
					if r := recover(); r != nil {
						log.Error("panic in connection handler; recovered",
							"panic", r, "remote", peer, "stack", string(debug.Stack()))
						_ = conn.Close()
					}
				}()
				if err := srv.ServeConn(ctx, conn); err != nil {
					az.logDenial(log, srv, peer, err)
				}
			}()
		}
	}
}

// forceAuthCommands are the commands the C++ schedd registers with
// force_authentication (Scheduler::Register, schedd.cpp): they are negotiated
// with authentication required whatever SEC_<level>_AUTHENTICATION says.
var forceAuthCommands = map[int]bool{
	commands.ACT_ON_JOBS:                true,
	commands.SPOOL_JOB_FILES:            true,
	commands.TRANSFER_DATA:              true,
	commands.SPOOL_JOB_FILES_WITH_PERMS: true,
	commands.TRANSFER_DATA_WITH_PERMS:   true,
	commands.QUERY_JOB_ADS_WITH_AUTH:    true,
	commands.QMGMT_WRITE_CMD:            true,
}

// securityLevels are the authorization levels schedd commands are registered
// at, each negotiated with its own SEC_<level>_* policy.
var securityLevels = []string{"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "DAEMON"}

// installAuthz makes srv enforce az on every command it dispatches and
// negotiate each command's security with the SEC_<level>_* policy of the
// level it is registered at, as DaemonCore does, with authentication
// required for forceAuthCommands. base is srv's SecurityConfig; each
// level's policy is a copy of it (sharing its session cache, post-auth
// policy and credentials) with that level's authentication, encryption,
// integrity and methods. Call it after cedarserver.New.
func installAuthz(srv *cedarserver.Server, az *scheddAuthz, cfg *config.Config, base *security.SecurityConfig) error {
	srv.Authorizer = az.Authorize
	// With an Authorizer, cedar's post-auth reply lists every command the
	// peer is authorized for, so a C++ client resumes the session for its
	// next command. That reply lacks TriedAuthentication, so a resuming C++
	// client that forces authentication (condor_submit -spool's
	// SPOOL_JOB_FILES_WITH_PERMS after QMGMT_WRITE_CMD) re-authenticates
	// mid-command, which cedar does not serve. Keep advertising only the
	// negotiated command, as without an Authorizer; every command is still
	// authorized when it is dispatched.
	if post := base.PostAuthPolicy; post != nil {
		base.PostAuthPolicy = func(authUser, peerAddr string, authenticated, encrypted bool) (string, []int) {
			fqu, _ := post(authUser, peerAddr, authenticated, encrypted)
			return fqu, nil
		}
	}
	byLevel := map[string]*security.SecurityConfig{}
	forced := map[string]*security.SecurityConfig{}
	for _, lvl := range securityLevels {
		s, err := htcondor.GetServerSecurityConfig(cfg, commands.QUERY_SCHEDD_ADS, lvl)
		if err != nil {
			return err
		}
		c := *base
		c.Authentication = s.Authentication
		c.Encryption = s.Encryption
		c.Integrity = s.Integrity
		c.AuthMethods = s.AuthMethods
		c.CryptoMethods = s.CryptoMethods
		byLevel[lvl] = &c
		f := c
		f.Authentication = security.SecurityRequired
		forced[lvl] = &f
	}
	srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		perms := srv.CommandPerms(command)
		if len(perms) == 0 {
			return nil
		}
		if forceAuthCommands[command] {
			return forced[perms[0]]
		}
		return byLevel[perms[0]]
	}
	return nil
}
