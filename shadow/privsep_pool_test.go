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

package shadow

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/filetransfer"
)

// TestMain lets this test binary double as a droppriv pool helper (see the
// identical hook in cmd/schedd/main.go); without it the pool backend cannot
// re-exec a helper and the FD-passing plumbing test below could not run.
func TestMain(m *testing.M) {
	droppriv.RunHelperIfRequested()
	os.Exit(m.Run())
}

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

type memSink struct{ files map[string][]byte }

func (m *memSink) Mkdir(string) error { return nil }
func (m *memSink) File(name string, _ int64, _ int64) (io.WriteCloser, error) {
	return &memWriter{name: name, sink: m}, nil
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

// TestPoolModeTransferPlumbing proves the shadow's file-transfer per-user file
// ops (input READS via buildInputPlan, output WRITES via buildOutputSink) route
// through the droppriv pool backend (helper process + SCM_RIGHTS FD passing)
// end-to-end with correct file CONTENT and no leaked helpers. Unprivileged, so
// it is CI-runnable without root; user "" drives the pool's self helper.
func TestPoolModeTransferPlumbing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ps, err := droppriv.NewPrivsep(droppriv.PrivsepConfig{
		Mode:                    droppriv.ModePool,
		ForceHelperUnprivileged: true,
	})
	if err != nil {
		t.Fatalf("NewPrivsep(pool): %v", err)
	}

	// A job Iwd with an executable + one input file the shadow will READ (as the
	// owner) and upload to the "starter".
	iwd := t.TempDir()
	const exeContent = "#!/bin/sh\necho hi\n"
	const inputContent = "hello-from-shadow"
	if err := os.WriteFile(filepath.Join(iwd, "job.sh"), []byte(exeContent), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatal(err)
	}

	ad := classad.New()
	_ = ad.Set("Cmd", filepath.Join(iwd, "job.sh"))
	_ = ad.Set("Iwd", iwd)
	_ = ad.Set("TransferExecutable", true)
	_ = ad.Set("TransferInput", "input.dat")
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Owner", "") // self-helper path (no target user needed on CI host)

	s := &Shadow{cfg: Config{JobAd: ad, Privsep: ps, Logf: t.Logf}}

	// ---- Part A: input plan READS via the helper, uploaded to a mem receiver. ----
	plan, err := s.buildInputPlan()
	if err != nil {
		t.Fatalf("buildInputPlan: %v", err)
	}
	c1, c2 := net.Pipe()
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- filetransfer.SendStream(ctx, stream.NewStream(c1), plan, filetransfer.Options{Logf: t.Logf})
	}()
	got := &memSink{files: map[string][]byte{}}
	if _, err := filetransfer.ServeDownload(ctx, stream.NewStream(c2), got, filetransfer.Options{Logf: t.Logf, ReceiveAck: true}); err != nil {
		t.Fatalf("ServeDownload (input upload): %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("SendStream (input): %v", err)
	}
	if n := helperChildren(t); n < 1 {
		t.Fatalf("expected at least one pool helper child after input reads, got %d", n)
	}
	if string(got.files["job.sh"]) != exeContent {
		t.Errorf("uploaded job.sh = %q, want %q", got.files["job.sh"], exeContent)
	}
	if string(got.files["input.dat"]) != inputContent {
		t.Errorf("uploaded input.dat = %q, want %q", got.files["input.dat"], inputContent)
	}

	// ---- Part B: output sink WRITES via the helper (starter -> shadow). ----
	sink, err := s.buildOutputSink()
	if err != nil {
		t.Fatalf("buildOutputSink: %v", err)
	}
	outputs := map[string]string{
		"_condor_stdout": "captured stdout\n", // remapped to job.out
		"result.txt":     "RESULT:hello\n",
	}
	outPlan := filetransfer.SendPlan{FinalTransfer: true}
	for _, name := range []string{"_condor_stdout", "result.txt"} {
		data := []byte(outputs[name])
		outPlan.Files = append(outPlan.Files, filetransfer.FileSpec{
			WireName: name, Mode: 0o644, Size: int64(len(data)),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
		})
	}
	c3, c4 := net.Pipe()
	sendErr2 := make(chan error, 1)
	go func() {
		sendErr2 <- filetransfer.SendStream(ctx, stream.NewStream(c3), outPlan, filetransfer.Options{Logf: t.Logf})
	}()
	if _, err := filetransfer.ServeDownload(ctx, stream.NewStream(c4), sink, filetransfer.Options{Logf: t.Logf, ReceiveAck: true}); err != nil {
		t.Fatalf("ServeDownload (output landing): %v", err)
	}
	if err := <-sendErr2; err != nil {
		t.Fatalf("SendStream (output): %v", err)
	}
	// _condor_stdout is remapped to the job's Out (job.out) in the Iwd.
	if b, rerr := os.ReadFile(filepath.Join(iwd, "job.out")); rerr != nil || string(b) != outputs["_condor_stdout"] {
		t.Errorf("landed job.out = %q err=%v, want %q", b, rerr, outputs["_condor_stdout"])
	}
	if b, rerr := os.ReadFile(filepath.Join(iwd, "result.txt")); rerr != nil || string(b) != outputs["result.txt"] {
		t.Errorf("landed result.txt = %q err=%v, want %q", b, rerr, outputs["result.txt"])
	}

	// ---- No leaked helpers after Close. ----
	if err := ps.Close(); err != nil {
		t.Fatalf("Privsep.Close: %v", err)
	}
	if n := helperChildren(t); n != 0 {
		t.Fatalf("%d helper child process(es) leaked after Close", n)
	}
}
