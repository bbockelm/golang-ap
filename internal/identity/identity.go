// Package identity answers "who is the caller" for a schedd command handler.
// Every handler that makes an ownership or authorization decision from the peer
// of a CEDAR connection must get the peer's name from Caller, never from
// Negotiation.User directly.
//
// The security negotiation can carry a User on a connection that did not
// authenticate (a resumed session, or the "unauthenticated@unmapped" name a
// server advertises to an anonymous peer). That name is not an identity. Caller
// mirrors the C++ schedd, which keys QMGMT and job-ownership checks on
// Sock::isAuthenticated() / Sock::isMappedFQU() (src/condor_io/sock.cpp) and
// treats a socket without a mapped identity as anonymous: QmgmtPeer::
// isAuthenticated() returns isMappedFQU(), SetAttribute refuses with EACCES
// ("Authentication is required to set attributes"), and UserCheck2 refuses a
// NULL user ("anonymous user not permitted") (src/condor_schedd.V6/qmgmt.cpp).
package identity

import (
	"strings"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// HTCondor's placeholder user name for a peer without a mapped identity
// (UNAUTHENTICATED_USER, src/condor_io/authentication.cpp).
const unauthenticatedUser = "unauthenticated"

// Caller returns the authenticated identity of the peer on c, the full
// user@domain HTCondor gives it (e.g. alice@pool for an IDTOKEN, owner@UID_DOMAIN
// for FS), or "" when the connection has none. "" means anonymous: callers must
// refuse anything that needs an owner and must not match it against a job's
// User or the queue super users.
//
// It starts from the identity cedar authorizes the peer as, which is
// unauthenticated@unmapped for a session that did not authenticate
// (cedarserver.Conn.AuthorizationUser), and refuses every name in the
// "unmapped" domain: an SSL or SciTokens peer no map file named (ssl@unmapped,
// scitokens@unmapped) is not a local account.
func Caller(c *cedarserver.Conn) string {
	if c == nil {
		return ""
	}
	user := strings.TrimSpace(c.AuthorizationUser())
	name, domain := security.SplitFQU(user)
	if name == "" || strings.EqualFold(name, unauthenticatedUser) || strings.EqualFold(domain, security.UnmappedDomain) {
		return ""
	}
	return user
}
