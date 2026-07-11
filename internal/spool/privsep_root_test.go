// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spool

import (
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// TestRootGatedSpoolOwnership proves that when the schedd runs privileged, the
// spool RECEIVE path lands sandbox files OWNED BY THE JOB OWNER (not the schedd
// uid): every write goes through Privsep as the owner and the sandbox tree is
// chowned to the owner. It is gated on euid==0 (skipped in normal CI) and needs
// a target user to switch to, supplied via GOLANG_AP_PRIVSEP_TEST_USER so the
// test does not guess an account that exists on the host.
//
// Run with, e.g.:
//
//	sudo GOLANG_AP_PRIVSEP_TEST_USER=alice go test ./internal/spool/ \
//	    -run TestRootGatedSpoolOwnership -v
func TestRootGatedSpoolOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privilege-drop ownership test requires euid==0")
	}
	target := os.Getenv("GOLANG_AP_PRIVSEP_TEST_USER")
	if target == "" {
		t.Skip("set GOLANG_AP_PRIVSEP_TEST_USER to a non-root user to run the ownership proof")
	}
	u, err := user.Lookup(target)
	if err != nil {
		t.Fatalf("lookup target user %q: %v", target, err)
	}
	wantUID, _ := strconv.Atoi(u.Uid)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ModeAuto -> native credential switching on privileged Linux (real drop).
	ps, err := droppriv.NewPrivsep(droppriv.PrivsepConfig{Mode: droppriv.ModeAuto})
	if err != nil {
		t.Fatalf("NewPrivsep(auto): %v", err)
	}
	defer func() { _ = ps.Close() }()

	// Land a couple of files through the same dirSink the SPOOL handler uses.
	sandbox := t.TempDir()
	if err := ps.MkdirAll(ctx, target, sandbox, 0o755); err != nil {
		t.Fatalf("MkdirAll as %s: %v", target, err)
	}
	sink := &dirSink{root: sandbox, ps: ps, owner: privsepUser(target), ctx: ctx, logf: t.Logf}
	for _, name := range []string{"result.txt", "sub/deep.txt"} {
		w, err := sink.File(name, 0o644, 0)
		if err != nil {
			t.Fatalf("sink.File(%q) as %s: %v", name, target, err)
		}
		if _, err := io.WriteString(w, "owned-content"); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close %q: %v", name, err)
		}
	}

	// Every landed file must be owned by the target user's uid, not root.
	for _, name := range []string{"result.txt", "sub/deep.txt"} {
		fi, err := os.Stat(filepath.Join(sandbox, name))
		if err != nil {
			t.Fatalf("stat %q: %v", name, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("no syscall.Stat_t for %q", name)
		}
		if int(st.Uid) != wantUID {
			t.Errorf("file %q owned by uid %d, want %d (%s)", name, st.Uid, wantUID, target)
		}
	}
}
