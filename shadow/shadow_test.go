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
	"context"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// fakeStarter drives one side of a loopback syscall stream with the exact
// framing NTsenders.cpp uses: each request is one CEDAR message
// [int op, args..., EOM]; replies are read back as [int rval, ...].
type fakeStarter struct {
	t  *testing.T
	st *stream.Stream
}

func (f *fakeStarter) call(ctx context.Context, op int, put func(*message.Message) error) *message.Message {
	f.t.Helper()
	out := message.NewMessageForStream(f.st)
	if err := out.PutInt(ctx, op); err != nil {
		f.t.Fatalf("put op %d: %v", op, err)
	}
	if put != nil {
		if err := put(out); err != nil {
			f.t.Fatalf("put args for op %d: %v", op, err)
		}
	}
	if err := out.FinishMessage(ctx); err != nil {
		f.t.Fatalf("finish op %d: %v", op, err)
	}
	return message.NewMessageFromStream(f.st)
}

// rpcInt performs a request expecting a bare int reply and returns rval.
func (f *fakeStarter) rpcInt(ctx context.Context, op int, put func(*message.Message) error) int {
	f.t.Helper()
	in := f.call(ctx, op, put)
	rval, err := in.GetInt(ctx)
	if err != nil {
		f.t.Fatalf("read rval for op %d: %v", op, err)
	}
	if rval < 0 {
		if terrno, err := in.GetInt(ctx); err == nil {
			f.t.Logf("op %d replied rval=%d terrno=%d", op, rval, terrno)
		}
	}
	return rval
}

func loopbackStreams(t *testing.T) (*stream.Stream, *stream.Stream) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	srv := <-ch
	if srv.err != nil {
		t.Fatalf("accept: %v", srv.err)
	}
	t.Cleanup(func() { _ = cli.Close(); _ = srv.c.Close() })
	return stream.NewStream(cli), stream.NewStream(srv.c)
}

// TestShadowVanillaRun scripts the syscall sequence a stock starter performs
// for a vanilla no-transfer job (plus a job_termination, an ulog, a
// get_sec_session_info decline, and an unknown op to exercise those paths)
// and asserts the Shadow's Result.
func TestShadowVanillaRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	starterSt, shadowSt := loopbackStreams(t)

	jobAd := classad.New()
	_ = jobAd.Set("ClusterId", int64(7))
	_ = jobAd.Set("ProcId", int64(0))
	_ = jobAd.Set("Cmd", "/bin/sh")
	_ = jobAd.Set("Iwd", "/tmp")

	var events []string
	sh, err := New(shadowSt, nil, Config{
		JobAd:         jobAd,
		ShadowAddr:    "<127.0.0.1:12345>",
		ShadowVersion: "$CondorVersion: 25.0.0 2025-01-01 BuildID: 0 $",
		OnEvent:       func(e Event) { events = append(events, e.Type) },
		Logf:          t.Logf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resCh := make(chan *Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := sh.Run(ctx)
		if err != nil {
			errCh <- err
			return
		}
		resCh <- res
	}()

	fs := &fakeStarter{t: t, st: starterSt}

	// (1) get_job_info: expect rval=0 + the job ad with shadow attrs injected.
	{
		in := fs.call(ctx, opGetJobInfo, nil)
		rval, err := in.GetInt(ctx)
		if err != nil || rval != 0 {
			t.Fatalf("get_job_info rval=%d err=%v", rval, err)
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			t.Fatalf("get_job_info ad: %v", err)
		}
		if v, _ := ad.EvaluateAttrString("Cmd"); v != "/bin/sh" {
			t.Errorf("job ad Cmd = %q, want /bin/sh", v)
		}
		if v, _ := ad.EvaluateAttrString("ShadowVersion"); v == "" {
			t.Errorf("job ad missing injected ShadowVersion")
		}
		if v, _ := ad.EvaluateAttrString("ShadowIpAddr"); v != "<127.0.0.1:12345>" {
			t.Errorf("job ad ShadowIpAddr = %q", v)
		}
	}

	// (2) register_starter_info.
	starterAd := classad.New()
	_ = starterAd.Set("CondorVersion", "$CondorVersion: 25.0.0 $")
	if rval := fs.rpcInt(ctx, opRegisterStarterInfo, func(m *message.Message) error {
		return m.PutClassAd(ctx, starterAd)
	}); rval != 0 {
		t.Fatalf("register_starter_info rval=%d", rval)
	}

	// (3) get_sec_session_info: shadow declines with rval<0 (stage 3).
	{
		in := fs.call(ctx, opGetSecSessionInfo, func(m *message.Message) error {
			if err := m.PutString(ctx, ""); err != nil {
				return err
			}
			return m.PutString(ctx, "")
		})
		rval, err := in.GetInt(ctx)
		if err != nil {
			t.Fatalf("get_sec_session_info rval: %v", err)
		}
		if rval >= 0 {
			t.Fatalf("get_sec_session_info rval=%d, want <0 in stage 3", rval)
		}
		if terrno, err := in.GetInt(ctx); err != nil {
			t.Fatalf("get_sec_session_info terrno: %v", err)
		} else {
			t.Logf("get_sec_session_info declined with terrno=%d", terrno)
		}
	}

	// (4) an unknown op with args must be drained and answered rval<0
	// without desyncing the stream.
	{
		in := fs.call(ctx, 9999, func(m *message.Message) error {
			if err := m.PutString(ctx, "some-arg"); err != nil {
				return err
			}
			return m.PutInt(ctx, 42)
		})
		rval, err := in.GetInt(ctx)
		if err != nil || rval >= 0 {
			t.Fatalf("unknown op rval=%d err=%v, want rval<0", rval, err)
		}
		if _, err := in.GetInt(ctx); err != nil {
			t.Fatalf("unknown op terrno: %v", err)
		}
	}

	// (5) begin_execution.
	if rval := fs.rpcInt(ctx, opBeginExecution, nil); rval != 0 {
		t.Fatalf("begin_execution rval=%d", rval)
	}

	// (6) register_job_info with a running-state update ad.
	update := classad.New()
	_ = update.Set("JobState", "Running")
	_ = update.Set("ImageSize", int64(1024))
	if rval := fs.rpcInt(ctx, opRegisterJobInfo, func(m *message.Message) error {
		return m.PutClassAd(ctx, update)
	}); rval != 0 {
		t.Fatalf("register_job_info rval=%d", rval)
	}

	// (7) ulog: no reply expected; follow immediately with the next op to
	// prove the loop did not send one.
	ulogAd := classad.New()
	_ = ulogAd.Set("MyType", "ExecuteEvent")
	{
		out := message.NewMessageForStream(starterSt)
		if err := out.PutInt(ctx, opUlog); err != nil {
			t.Fatalf("ulog op: %v", err)
		}
		if err := out.PutClassAd(ctx, ulogAd); err != nil {
			t.Fatalf("ulog ad: %v", err)
		}
		if err := out.FinishMessage(ctx); err != nil {
			t.Fatalf("ulog finish: %v", err)
		}
	}

	// (8) job_termination (mock terminate ad).
	termAd := classad.New()
	_ = termAd.Set("OnExitCode", int64(0))
	_ = termAd.Set("ExitBySignal", false)
	if rval := fs.rpcInt(ctx, opJobTermination, func(m *message.Message) error {
		return m.PutClassAd(ctx, termAd)
	}); rval != 0 {
		t.Fatalf("job_termination rval=%d", rval)
	}

	// (9) job_exit: status 0 (clean exit), reason JOB_EXITED, final ad.
	exitAd := classad.New()
	_ = exitAd.Set("JobState", "Exited")
	if rval := fs.rpcInt(ctx, opJobExit, func(m *message.Message) error {
		if err := m.PutInt(ctx, 0); err != nil {
			return err
		}
		if err := m.PutInt(ctx, JobExited); err != nil {
			return err
		}
		return m.PutClassAd(ctx, exitAd)
	}); rval != 0 {
		t.Fatalf("job_exit rval=%d", rval)
	}

	var res *Result
	select {
	case res = <-resCh:
	case err := <-errCh:
		t.Fatalf("Run: %v", err)
	case <-ctx.Done():
		t.Fatal("Run did not finish")
	}

	if res.ExitStatus != 0 {
		t.Errorf("ExitStatus = %d, want 0", res.ExitStatus)
	}
	if res.Reason != JobExited {
		t.Errorf("Reason = %d, want %d (JOB_EXITED)", res.Reason, JobExited)
	}
	if !res.ExitedNormally() {
		t.Errorf("ExitedNormally() = false")
	}
	if code, ok := res.ExitCode(); !ok || code != 0 {
		t.Errorf("ExitCode() = %d,%v want 0,true", code, ok)
	}
	if res.ExitAd == nil {
		t.Errorf("ExitAd not captured")
	} else if v, _ := res.ExitAd.EvaluateAttrString("JobState"); v != "Exited" {
		t.Errorf("ExitAd JobState = %q", v)
	}
	if res.FinalAd == nil {
		t.Errorf("FinalAd (job_termination) not captured")
	}
	if res.UpdateAd == nil {
		t.Errorf("UpdateAd (register_job_info) not captured")
	} else if v, _ := res.UpdateAd.EvaluateAttrString("JobState"); v != "Running" {
		t.Errorf("UpdateAd JobState = %q", v)
	}
	if sa := sh.StarterAd(); sa == nil {
		t.Errorf("starter ad not captured")
	}

	wantOrder := []string{
		EventGetJobInfo, EventStarterInfo, EventUnknownOp, EventBeginExecution,
		EventJobUpdate, EventUlog, EventJobTermination, EventJobExit,
	}
	got := map[string]bool{}
	for _, e := range events {
		got[e] = true
	}
	for _, w := range wantOrder {
		if !got[w] {
			t.Errorf("missing event %q (got %v)", w, events)
		}
	}
}

// TestShadowOldStarterReason checks the pseudo_job_exit reason normalization
// for pre-EXIT_CODE_OFFSET starters (reason 0 -> 100).
func TestShadowOldStarterReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	starterSt, shadowSt := loopbackStreams(t)
	jobAd := classad.New()
	_ = jobAd.Set("Cmd", "/bin/true")
	sh, err := New(shadowSt, nil, Config{JobAd: jobAd, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resCh := make(chan *Result, 1)
	go func() {
		res, err := sh.Run(ctx)
		if err != nil {
			t.Errorf("Run: %v", err)
			resCh <- nil
			return
		}
		resCh <- res
	}()

	fs := &fakeStarter{t: t, st: starterSt}
	if rval := fs.rpcInt(ctx, opJobExit, func(m *message.Message) error {
		if err := m.PutInt(ctx, 256); err != nil { // exit code 1
			return err
		}
		if err := m.PutInt(ctx, 0); err != nil { // old-style JOB_EXITED
			return err
		}
		return m.PutClassAd(ctx, classad.New())
	}); rval != 0 {
		t.Fatalf("job_exit rval=%d", rval)
	}

	res := <-resCh
	if res == nil {
		t.Fatal("no result")
	}
	if res.Reason != JobExited {
		t.Errorf("Reason = %d, want %d after old-starter normalization", res.Reason, JobExited)
	}
	if code, ok := res.ExitCode(); !ok || code != 1 {
		t.Errorf("ExitCode() = %d,%v want 1,true", code, ok)
	}
}
