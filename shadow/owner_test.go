package shadow

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/droppriv"
)

// recordingPrivsep records the user each file operation runs as and performs
// it as the current user.
type recordingPrivsep struct {
	droppriv.Privsep // other operations are not expected
	users            []string
}

func (r *recordingPrivsep) OpenFile(_ context.Context, user, path string, flag int, perm os.FileMode) (*os.File, error) {
	r.users = append(r.users, user)
	return os.OpenFile(path, flag, perm)
}

func (r *recordingPrivsep) MkdirAll(_ context.Context, user, path string, perm os.FileMode) error {
	r.users = append(r.users, user)
	return os.MkdirAll(path, perm)
}

// ownerJobAd is a job in its own Iwd with one input file, owned by owner and
// user.
func ownerJobAd(t *testing.T, owner, user string) *classad.ClassAd {
	t.Helper()
	iwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte("in"), 0o644); err != nil {
		t.Fatal(err)
	}
	ad := classad.New()
	_ = ad.Set("Iwd", iwd)
	_ = ad.Set("TransferExecutable", false)
	_ = ad.Set("TransferInput", "input.dat")
	_ = ad.Set("Owner", owner)
	_ = ad.Set("User", user)
	return ad
}

// The shadow reads a job's input and writes its output as the job's Owner,
// and refuses a job whose Owner is no local account before any file
// operation is made for it.
func TestTransferRunsAsJobOwner(t *testing.T) {
	ps := &recordingPrivsep{}
	s := &Shadow{cfg: Config{JobAd: ownerJobAd(t, "alice", "alice@pool"), Privsep: ps, Logf: t.Logf}}
	plan, err := s.buildInputPlan()
	if err != nil {
		t.Fatalf("buildInputPlan: %v", err)
	}
	if len(plan.Files) != 1 {
		t.Fatalf("input plan has %d files, want 1", len(plan.Files))
	}
	r, err := plan.Files[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	sink, err := s.buildOutputSink()
	if err != nil {
		t.Fatalf("buildOutputSink: %v", err)
	}
	if err := sink.Mkdir("out"); err != nil {
		t.Fatal(err)
	}
	if len(ps.users) != 2 || ps.users[0] != "alice" || ps.users[1] != "alice" {
		t.Errorf("file operations ran as %q, want alice for each", ps.users)
	}

	for _, tc := range []struct{ owner, user string }{
		{"ssl", "ssl@unmapped"},
		{"alice", "alice@UNMAPPED"},
		{"unauthenticated", "unauthenticated@unmapped"},
		{"unauthenticated", "unauthenticated@pool"},
		{"root", "root@pool"},
		{"LOCAL_SYSTEM", "LOCAL_SYSTEM@pool"},
	} {
		ps := &recordingPrivsep{}
		s := &Shadow{cfg: Config{JobAd: ownerJobAd(t, tc.owner, tc.user), Privsep: ps, Logf: t.Logf}}
		if _, err := s.buildInputPlan(); err == nil {
			t.Errorf("Owner %q User %q: input plan built, want refused", tc.owner, tc.user)
		}
		if _, err := s.buildOutputSink(); err == nil {
			t.Errorf("Owner %q User %q: output sink built, want refused", tc.owner, tc.user)
		}
		if len(ps.users) != 0 {
			t.Errorf("Owner %q User %q: file operations ran as %q, want none", tc.owner, tc.user, ps.users)
		}
	}
}
