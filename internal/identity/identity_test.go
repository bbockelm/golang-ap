package identity

import (
	"testing"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

func TestCaller(t *testing.T) {
	cases := []struct {
		name string
		neg  *security.SecurityNegotiation
		want string
	}{
		{"nil negotiation", nil, ""},
		{"authenticated", &security.SecurityNegotiation{User: "alice@pool", Authentication: true}, "alice@pool"},
		{"authenticated bare name", &security.SecurityNegotiation{User: "alice", Authentication: true}, "alice"},
		{"kerberos host principal", &security.SecurityNegotiation{User: "condor@example.org", Authentication: true}, "condor@example.org"},
		{"unauthenticated daemon name", &security.SecurityNegotiation{User: "condor@pool", Authentication: false}, ""},
		{"unauthenticated user name", &security.SecurityNegotiation{User: "alice@pool", Authentication: false}, ""},
		{"authenticated empty user", &security.SecurityNegotiation{User: "", Authentication: true}, ""},
		{"unauthenticated placeholder", &security.SecurityNegotiation{User: "unauthenticated@unmapped", Authentication: true}, ""},
		{"ssl without map", &security.SecurityNegotiation{User: "ssl@unmapped", Authentication: true}, ""},
		{"scitokens without map", &security.SecurityNegotiation{User: "scitokens@unmapped", Authentication: true}, ""},
		{"unmapped domain", &security.SecurityNegotiation{User: "alice@unmapped", Authentication: true}, ""},
		{"unmapped domain upper case", &security.SecurityNegotiation{User: "alice@UNMAPPED", Authentication: true}, ""},
		{"unmapped after last at", &security.SecurityNegotiation{User: "alice@pool@unmapped", Authentication: true}, ""},
		{"at in user part", &security.SecurityNegotiation{User: "alice@unmapped@pool", Authentication: true}, "alice@unmapped@pool"},
		{"empty name", &security.SecurityNegotiation{User: "@pool", Authentication: true}, ""},
	}
	for _, tc := range cases {
		if got := Caller(&cedarserver.Conn{Negotiation: tc.neg}); got != tc.want {
			t.Errorf("%s: Caller = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := Caller(nil); got != "" {
		t.Errorf("Caller(nil) = %q, want empty", got)
	}
	if got := Caller(&cedarserver.Conn{}); got != "" {
		t.Errorf("Caller(raw conn) = %q, want empty", got)
	}
}
