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

// securityLevels are the authorization levels schedd commands are registered
// at, each negotiated with its own SEC_<level>_* policy.
var securityLevels = []string{"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "DAEMON"}

// installAuthz makes srv enforce az on every command it dispatches and
// negotiate each command's security with the SEC_<level>_* policy of the
// level it is registered at, as DaemonCore does, with authentication
// required for forceAuthCommands. base is srv's SecurityConfig; each
// level's policy is a copy of it (sharing its session cache, post-auth
// policy and credentials) with that level's authentication, encryption,
// integrity and methods, as levelConfig (Daemon.ServerSecurityConfig)
// builds them. Call it after cedarserver.New.
func installAuthz(srv *cedarserver.Server, az *daemon.Authz, base *security.SecurityConfig,
	levelConfig func(command int, secContext string) (*security.SecurityConfig, error)) error {
	srv.Authorizer = az.Authorize
	byLevel := map[string]*security.SecurityConfig{}
	forced := map[string]*security.SecurityConfig{}
	for _, lvl := range securityLevels {
		s, err := levelConfig(commands.QUERY_SCHEDD_ADS, lvl)
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
