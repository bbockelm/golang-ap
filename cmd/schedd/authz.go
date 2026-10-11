package main

import (
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/daemon"
)

// authzOptions is the schedd's ALLOW_<level>/DENY_<level> authorization for
// every command served on its command socket: the schedd protocol, the DC_*
// defaults, and the shadows' file-transfer and the startds' ALIVE commands
// that share the socket. It punches the holes every DaemonCore daemon does
// plus the one the schedd grants the negotiator's match session.
func authzOptions() daemon.AuthzOptions {
	return daemon.AuthzOptions{
		Subsys:       "SCHEDD",
		Holes:        append(authz.DaemonCoreHoles(), authz.ScheddMatchSessionHoles()),
		CommandNames: commandNames,
	}
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

// installAuthz makes srv enforce az on every command it dispatches and
// negotiate each command under the SEC_<level>_* policy of the level it is
// registered at, as DaemonCore does (Daemon.InstallSecurityLevels, rebuilt on
// reconfig), with authentication required for forceAuthCommands. Call it
// after d.Listener and cedarserver.New.
func installAuthz(d *daemon.Daemon, srv *cedarserver.Server, az *daemon.Authz) error {
	srv.Authorizer = az.Authorize
	if err := d.InstallSecurityLevels(srv); err != nil {
		return err
	}
	forceAuthentication(srv)
	return nil
}

// forceAuthentication wraps srv's per-command policy so forceAuthCommands
// are negotiated with authentication required, as DaemonCore negotiates a
// command registered with force_authentication, and so every policy
// advertises srv.SecurityConfig's RemoteVersion, which the per-level
// policies do not carry and C++ clients gate wire features on.
func forceAuthentication(srv *cedarserver.Server) {
	levelConfig := srv.SecurityConfigForCommand
	srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		cfg := levelConfig(command)
		if cfg == nil {
			return nil
		}
		c := *cfg
		if c.RemoteVersion == "" {
			c.RemoteVersion = srv.SecurityConfig.RemoteVersion
		}
		if forceAuthCommands[command] {
			c.Authentication = security.SecurityRequired
		}
		return &c
	}
}
