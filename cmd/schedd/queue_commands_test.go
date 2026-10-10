package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"

	"github.com/bbockelm/golang-ap/internal/queue"
)

// The queue super users are as the C++ schedd's InitQmgmt builds them:
// QUEUE_SUPER_USERS replaces the default root and condor, and the account
// the schedd runs as is added unless PERSONAL_CONDOR_IS_SUPER_USER is false.
func TestQueueSuperUsersMatchCxx(t *testing.T) {
	orig := condorUsername
	condorUsername = func() string { return "svcacct" }
	t.Cleanup(func() { condorUsername = orig })

	for _, tc := range []struct {
		name  string
		knobs map[string]string
		super []string
		not   []string
	}{
		{"default", nil,
			[]string{"root@pool", "condor@pool", "condor@family", "svcacct@pool"}, []string{"alice@pool"}},
		{"replaced", map[string]string{"QUEUE_SUPER_USERS": "alice, condor"},
			[]string{"alice@pool", "condor@pool", "condor@family", "svcacct@pool"}, []string{"root@pool"}},
		{"replaced without condor", map[string]string{"QUEUE_SUPER_USERS": "alice"},
			[]string{"alice@pool", "svcacct@pool"}, []string{"root@pool", "condor@pool", "condor@family"}},
		{"empty", map[string]string{"QUEUE_SUPER_USERS": ""},
			[]string{"root@pool", "svcacct@pool"}, []string{"condor@pool", "alice@pool"}},
		{"not personal", map[string]string{"QUEUE_SUPER_USERS": "alice", "PERSONAL_CONDOR_IS_SUPER_USER": "false"},
			[]string{"alice@pool"}, []string{"svcacct@pool", "root@pool"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewEmpty()
			for k, v := range tc.knobs {
				cfg.Set(k, v)
			}
			opts, err := queueAuthzOptions(cfg)
			if err != nil {
				t.Fatal(err)
			}
			opts.Dir = t.TempDir()
			opts.UIDDomain = "pool"
			q, err := queue.Open(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = q.Close() }()
			for _, u := range tc.super {
				if !q.IsSuperUser(u) {
					t.Errorf("%s is not a super user, want one", u)
				}
			}
			for _, u := range tc.not {
				if q.IsSuperUser(u) {
					t.Errorf("%s is a super user, want none", u)
				}
			}
		})
	}
}

// QUEUE_SUPER_USER_MAY_IMPERSONATE is compiled into the queue options; an
// invalid expression is an error, which fails startup and leaves a reconfig
// on the previous settings.
func TestQueueMayImpersonateKnob(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("QUEUE_SUPER_USER_MAY_IMPERSONATE", "^svc_")
	opts, err := queueAuthzOptions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.MayImpersonate == nil || !opts.MayImpersonate.MatchString("svc_a") || opts.MayImpersonate.MatchString("alice") {
		t.Errorf("MayImpersonate = %v, want ^svc_", opts.MayImpersonate)
	}
	cfg.Set("QUEUE_SUPER_USER_MAY_IMPERSONATE", "(")
	if _, err := queueAuthzOptions(cfg); err == nil {
		t.Error("an invalid QUEUE_SUPER_USER_MAY_IMPERSONATE was accepted")
	}
	if opts, err := queueAuthzOptions(config.NewEmpty()); err != nil || opts.MayImpersonate != nil {
		t.Errorf("unset QUEUE_SUPER_USER_MAY_IMPERSONATE = %v, %v; want nil, nil", opts.MayImpersonate, err)
	}
}
