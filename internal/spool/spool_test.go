package spool

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/droppriv"

	"github.com/bbockelm/golang-ap/internal/queue"
)

func TestSandboxDir(t *testing.T) {
	got := SandboxDir("/var/spool", 12345, 3)
	want := filepath.Join("/var/spool", "2345", "3", "cluster12345.proc3.subproc0")
	if got != want {
		t.Errorf("SandboxDir = %q, want %q", got, want)
	}
	got = SandboxDir("/s", 7, 0)
	want = filepath.Join("/s", "7", "0", "cluster7.proc0.subproc0")
	if got != want {
		t.Errorf("SandboxDir = %q, want %q", got, want)
	}
}

func TestRewriteSpooledJobAd(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("Iwd", "/home/alice/submit")
	_ = ad.Set("Cmd", "/home/alice/submit/job.sh")
	_ = ad.Set("TransferInput", "/home/alice/data/input.dat,sub/other.txt")
	_ = ad.Set("UserLog", "/home/alice/submit/job.log")
	_ = ad.Set("TransferOutputRemaps", `out.txt=/home/alice/results/out.txt`)

	rewriteSpooledJobAd(ad, "/spool/1/0/cluster1.proc0.subproc0")

	check := func(attr, want string) {
		t.Helper()
		got, _ := ad.EvaluateAttrString(attr)
		if got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
	check("Iwd", "/spool/1/0/cluster1.proc0.subproc0")
	check("SUBMIT_Iwd", "/home/alice/submit")
	check("Cmd", "job.sh")
	check("SUBMIT_Cmd", "/home/alice/submit/job.sh")
	check("TransferInput", "input.dat,other.txt")
	check("SUBMIT_TransferInput", "/home/alice/data/input.dat,sub/other.txt")
	check("UserLog", "job.log")
	check("SUBMIT_TransferOutputRemaps", `out.txt=/home/alice/results/out.txt`)
	if _, ok := ad.Lookup("TransferOutputRemaps"); ok {
		t.Error("TransferOutputRemaps should be removed while output lands in spool")
	}

	// Idempotent: a second rewrite must not clobber the SUBMIT_ backups.
	rewriteSpooledJobAd(ad, "/other/dir")
	check("Iwd", "/spool/1/0/cluster1.proc0.subproc0")
	check("SUBMIT_Cmd", "/home/alice/submit/job.sh")
}

func TestRewriteRespectsTransferExecutableFalse(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("Iwd", "/home/bob")
	_ = ad.Set("Cmd", "/bin/echo")
	_ = ad.Set("TransferExecutable", false)
	rewriteSpooledJobAd(ad, "/spool/x")
	if got, _ := ad.EvaluateAttrString("Cmd"); got != "/bin/echo" {
		t.Errorf("Cmd = %q, want untouched /bin/echo when TransferExecutable=false", got)
	}
}

func TestRewriteLeavesURLInputs(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("Iwd", "/home/carol")
	_ = ad.Set("TransferInput", "https://example.com/data.bin,/tmp/local.txt")
	rewriteSpooledJobAd(ad, "/spool/y")
	if got, _ := ad.EvaluateAttrString("TransferInput"); got != "https://example.com/data.bin,local.txt" {
		t.Errorf("TransferInput = %q, want URL preserved + basename", got)
	}
}

func TestReleaseSpoolHold(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("JobStatus", int64(queue.StatusHeld))
	_ = ad.Set("HoldReasonCode", int64(SpoolingInput))
	_ = ad.Set("HoldReason", "Spooling input data files")

	releaseSpoolHold(ad, 1234567)

	if st, _ := ad.EvaluateAttrInt("JobStatus"); st != queue.StatusIdle {
		t.Errorf("JobStatus = %d, want Idle(%d)", st, queue.StatusIdle)
	}
	if _, ok := ad.Lookup("HoldReasonCode"); ok {
		t.Error("HoldReasonCode should be cleared on release")
	}
	if v, _ := ad.EvaluateAttrInt("LastHoldReasonCode"); v != SpoolingInput {
		t.Errorf("LastHoldReasonCode = %d, want %d", v, SpoolingInput)
	}
	if v, _ := ad.EvaluateAttrString("ReleaseReason"); v != "Data files spooled" {
		t.Errorf("ReleaseReason = %q", v)
	}
	if v, _ := ad.EvaluateAttrInt("EnteredCurrentStatus"); v != 1234567 {
		t.Errorf("EnteredCurrentStatus = %d", v)
	}

	// Non-held jobs are untouched.
	ad2 := classad.New()
	_ = ad2.Set("JobStatus", int64(queue.StatusIdle))
	releaseSpoolHold(ad2, 1)
	if _, ok := ad2.Lookup("ReleaseReason"); ok {
		t.Error("releaseSpoolHold must be a no-op on non-held jobs")
	}
}

func TestOutputSpecsPriority(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name, content string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("input.dat", "in")
	mustWrite("result.txt", "out")
	mustWrite("job.out", "stdout")

	h := New(Options{SpoolDir: dir})

	names := func(ad *classad.ClassAd) []string {
		specs, _, err := h.outputSpecs(context.Background(), "", ad, dir)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range specs {
			out = append(out, s.WireName)
		}
		return out
	}

	// SpooledOutputFiles wins; Out rides along; missing Err skipped.
	ad := classad.New()
	_ = ad.Set("SpooledOutputFiles", "result.txt")
	_ = ad.Set("TransferOutput", "ignored.txt")
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Err", "job.err") // not on disk -> skipped
	got := names(ad)
	want := map[string]bool{"result.txt": true, "job.out": true}
	if len(got) != len(want) {
		t.Fatalf("outputSpecs = %v, want keys %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected output file %q", n)
		}
	}

	// No lists at all: whole sandbox.
	got = names(classad.New())
	if len(got) != 3 {
		t.Errorf("whole-sandbox fallback = %v, want 3 files", got)
	}
}

func TestDirSinkTraversalGuard(t *testing.T) {
	s := &dirSink{root: t.TempDir(), ps: droppriv.DefaultPrivsep(), ctx: context.Background()}
	if _, err := s.File("../evil", 0o644, 0); err == nil {
		t.Error("dirSink accepted ../ traversal")
	}
	if _, err := s.File("/abs/evil", 0o644, 0); err == nil {
		t.Error("dirSink accepted absolute path")
	}
	if err := s.Mkdir("sub/dir"); err != nil {
		t.Errorf("dirSink rejected valid subdir: %v", err)
	}
	w, err := s.File("sub/ok.txt", 0o600, 2)
	if err != nil || w == nil {
		t.Fatalf("dirSink rejected valid file: %v", err)
	}
	if _, err := w.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.root, "sub", "ok.txt"))
	if err != nil || string(data) != "hi" {
		t.Errorf("sink file content = %q err=%v", data, err)
	}
}
