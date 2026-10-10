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

// HTCondor's placeholder names for a peer without a mapped identity
// (UNAUTHENTICATED_USER / UNMAPPED_DOMAIN, src/condor_io/authentication.cpp).
const (
	unauthenticatedUser = "unauthenticated"
	unmappedDomain      = "unmapped"
)

// Caller returns the authenticated identity of the peer on c, or "" when the
// connection has none. "" means anonymous: callers must refuse anything that
// needs an owner and must not match it against a job's Owner or the queue
// super users.
func Caller(c *cedarserver.Conn) string {
	if c == nil {
		return ""
	}
	return FromNegotiation(c.Negotiation)
}

// FromNegotiation returns n's user only when the negotiation actually
// authenticated the peer and the user is a mapped identity; otherwise "".
func FromNegotiation(n *security.SecurityNegotiation) string {
	if n == nil || !n.Authentication {
		return ""
	}
	user := strings.TrimSpace(n.User)
	if user == "" {
		return ""
	}
	name, domain, _ := strings.Cut(user, "@")
	if name == "" || strings.EqualFold(name, unauthenticatedUser) || strings.EqualFold(domain, unmappedDomain) {
		return ""
	}
	return user
}
