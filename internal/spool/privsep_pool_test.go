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
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/filetransfer"
)

// TestMain lets this test binary double as a droppriv pool helper. When the
// pool backend re-execs this binary with the helper sentinel set,
// RunHelperIfRequested serves the control protocol and exits without running
// the suite -- exactly as cmd/schedd's main() wires the same hook. Without this
// the pool backend could not spawn helpers and the plumbing test below would
// fail to route a single file op through the FD-passing path.
func TestMain(m *testing.M) {
	droppriv.RunHelperIfRequested()
	os.Exit(m.Run())
}

// helperChildren counts this process's direct child processes via pgrep. In
// these no-condor unit tests the only children are droppriv pool helpers, so it
// doubles as a helper-leak detector. pgrep exits non-zero (no match) => 0.
func helperChildren(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// memSink collects received files in memory (receiver side of the read-back
// proof).
type memSink struct {
	files map[string][]byte
}

func (m *memSink) Mkdir(string) error { return nil }
func (m *memSink) File(name string, _ int64, _ int64) (io.WriteCloser, error) {
	w := &memWriter{name: name, sink: m}
	return w, nil
}

type memWriter struct {
	name string
	buf  bytes.Buffer
	sink *memSink
}

func (w *memWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *memWriter) Close() error {
	w.sink.files[w.name] = w.buf.Bytes()
	return nil
}

// TestPoolModeSpoolPlumbing proves the spool package's per-user file ops route
// through the droppriv pool backend (helper process + SCM_RIGHTS FD passing)
// end-to-end, with correct file CONTENT and no leaked helpers afterwards. It
// runs unprivileged (ForceHelperUnprivileged) so it is CI-runnable without root.
//
// user "" drives the pool's "self" helper: a real child process that opens the
// file and passes the descriptor back, so this exercises the whole machinery
// without needing a target user to exist on the CI host.
func TestPoolModeSpoolPlumbing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ps, err := droppriv.NewPrivsep(droppriv.PrivsepConfig{
		Mode:                    droppriv.ModePool,
		ForceHelperUnprivileged: true,
	})
	if err != nil {
		t.Fatalf("NewPrivsep(pool): %v", err)
	}

	const owner = "" // self-helper: real child, FD-passing, no credential switch
	payloads := map[string]string{
		"result.txt": "RESULT:hello-from-shadow\n",
		"job.out":    "job stdout ok: hello-from-shadow",
		"sub/deep":   "nested content",
	}

	// ---- Part A: the SPOOL RECEIVE path (dirSink writes via the helper). ----
	sandbox := t.TempDir()
	sink := &dirSink{root: sandbox, ps: ps, owner: owner, ctx: ctx, logf: t.Logf}

	plan := filetransfer.SendPlan{FinalTransfer: true}
	plan.Files = append(plan.Files, filetransfer.FileSpec{WireName: "sub", Dir: true})
	for _, name := range []string{"result.txt", "job.out", "sub/deep"} {
		data := []byte(payloads[name])
		plan.Files = append(plan.Files, filetransfer.FileSpec{
			WireName: name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Open:     func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
		})
	}

	c1, c2 := net.Pipe()
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- filetransfer.SendStream(ctx, stream.NewStream(c1), plan, filetransfer.Options{Logf: t.Logf})
	}()
	if _, err := filetransfer.ServeDownload(ctx, stream.NewStream(c2), sink, filetransfer.Options{Logf: t.Logf, ReceiveAck: true}); err != nil {
		t.Fatalf("ServeDownload (spool receive): %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("SendStream: %v", err)
	}

	// A helper child must have been spawned to service the OpenFile calls.
	if n := helperChildren(t); n < 1 {
		t.Fatalf("expected at least one pool helper child after spool receive, got %d", n)
	}

	// The received files must be on disk with the exact content.
	for name, want := range payloads {
		got, rerr := os.ReadFile(sandbox + "/" + name)
		if rerr != nil {
			t.Fatalf("received file %q missing: %v", name, rerr)
		}
		if string(got) != want {
			t.Errorf("received file %q = %q, want %q", name, got, want)
		}
	}

	// ---- Part B: the TRANSFER_DATA send-back path (outputSpecs reads via the
	//      helper). Build specs from the sandbox and stream them out. ----
	h := New(Options{SpoolDir: sandbox, Logf: t.Logf, Privsep: ps})
	ad := classad.New()
	_ = ad.Set("SpooledOutputFiles", "result.txt")
	_ = ad.Set("Out", "job.out")
	specs, _, err := h.outputSpecs(ctx, owner, ad, sandbox)
	if err != nil {
		t.Fatalf("outputSpecs: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("outputSpecs returned %d specs, want 2", len(specs))
	}
	outPlan := filetransfer.SendPlan{FinalTransfer: true, Files: specs}

	c3, c4 := net.Pipe()
	sendErr2 := make(chan error, 1)
	go func() {
		sendErr2 <- filetransfer.SendStream(ctx, stream.NewStream(c3), outPlan, filetransfer.Options{Logf: t.Logf})
	}()
	got := &memSink{files: map[string][]byte{}}
	if _, err := filetransfer.ServeDownload(ctx, stream.NewStream(c4), got, filetransfer.Options{Logf: t.Logf, ReceiveAck: true}); err != nil {
		t.Fatalf("ServeDownload (transfer send-back): %v", err)
	}
	if err := <-sendErr2; err != nil {
		t.Fatalf("SendStream (send-back): %v", err)
	}
	for _, name := range []string{"result.txt", "job.out"} {
		if string(got.files[name]) != payloads[name] {
			t.Errorf("send-back file %q = %q, want %q", name, got.files[name], payloads[name])
		}
	}

	// ---- No leaked helpers after Close. ----
	if err := ps.Close(); err != nil {
		t.Fatalf("Privsep.Close: %v", err)
	}
	if n := helperChildren(t); n != 0 {
		t.Fatalf("%d helper child process(es) leaked after Close", n)
	}
}
