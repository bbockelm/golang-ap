package identity

import (
	"testing"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

func TestFromNegotiation(t *testing.T) {
	cases := []struct {
		name string
		neg  *security.SecurityNegotiation
		want string
	}{
		{"nil negotiation", nil, ""},
		{"authenticated", &security.SecurityNegotiation{User: "alice@pool", Authentication: true}, "alice@pool"},
		{"authenticated bare name", &security.SecurityNegotiation{User: "alice", Authentication: true}, "alice"},
		{"unauthenticated daemon name", &security.SecurityNegotiation{User: "condor@pool", Authentication: false}, ""},
		{"unauthenticated user name", &security.SecurityNegotiation{User: "alice@pool", Authentication: false}, ""},
		{"authenticated empty user", &security.SecurityNegotiation{User: "", Authentication: true}, ""},
		{"unauthenticated placeholder", &security.SecurityNegotiation{User: "unauthenticated@unmapped", Authentication: true}, ""},
		{"unmapped domain", &security.SecurityNegotiation{User: "alice@unmapped", Authentication: true}, ""},
		{"empty name", &security.SecurityNegotiation{User: "@pool", Authentication: true}, ""},
	}
	for _, tc := range cases {
		if got := FromNegotiation(tc.neg); got != tc.want {
			t.Errorf("%s: FromNegotiation = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := Caller(nil); got != "" {
		t.Errorf("Caller(nil) = %q, want empty", got)
	}
	if got := Caller(&cedarserver.Conn{}); got != "" {
		t.Errorf("Caller(raw conn) = %q, want empty", got)
	}
}
