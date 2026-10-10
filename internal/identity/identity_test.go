package identity

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
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

func TestJobAccount(t *testing.T) {
	for _, tc := range []struct {
		owner, user string
		want        string
		ok          bool
	}{
		{"alice", "alice@pool", "alice", true},
		{"alice", "", "alice", true},
		{"condor", "condor@pool", "", true},
		{"", "", "", true},
		{"ssl", "ssl@unmapped", "", false},
		{"alice", "alice@Unmapped", "", false},
		{"unauthenticated", "unauthenticated@unmapped", "", false},
		{"Unauthenticated", "Unauthenticated@pool", "", false},
		{"root", "root@pool", "", false},
		{"LOCAL_SYSTEM", "LOCAL_SYSTEM@pool", "", false},
	} {
		ad := classad.New()
		if tc.owner != "" {
			_ = ad.Set("Owner", tc.owner)
		}
		if tc.user != "" {
			_ = ad.Set("User", tc.user)
		}
		got, err := JobAccount(ad)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("JobAccount(Owner=%q User=%q) = %q, %v; want %q, ok=%v", tc.owner, tc.user, got, err, tc.want, tc.ok)
		}
	}
}
