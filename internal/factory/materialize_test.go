package factory

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func strAttr(t *testing.T, ad *classad.ClassAd, name string) (string, bool) {
	t.Helper()
	return ad.EvaluateAttrString(name)
}

// TestMaterializeNamedVars reproduces the ground-truth ads stock condor_submit
// -dry-run produces for a two-variable foreach digest. With named vars, $(Item)
// is empty and $(color) carries the row field.
func TestMaterializeNamedVars(t *testing.T) {
	// Digest as produced by condor_submit's make_digest + append_queue_statement
	// for: arguments=hello $(Process) item=$(item) row=$(Row) color=$(color)
	//      output=out.$(Process).$(item) ; queue color,shape from (3 rows)
	digest := "FACTORY.Requirements=MY.Requirements\n" +
		"arguments=hello $(Process) item=$(item) row=$(Row) color=$(color)\n" +
		"FACTORY.Iwd=/tmp/fac\n" +
		"output=out.$(Process).$(item)\n" +
		"\nQueue 1 color,shape from /tmp/condor_submit.1.items\n"

	d, err := ParseDigest(digest)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if d.QueueNum() != 1 {
		t.Fatalf("queueNum = %d, want 1", d.QueueNum())
	}
	if got := d.VarNames(); len(got) != 2 || got[0] != "color" || got[1] != "shape" {
		t.Fatalf("varNames = %v, want [color shape]", got)
	}

	rows := []string{"red circle", "green square", "blue triangle"}
	// Ground truth from stock condor_submit -dry-run (Args V1 form, item empty):
	wantArgs := []string{
		"hello 0 item= row=0 color=red",
		"hello 1 item= row=1 color=green",
		"hello 2 item= row=2 color=blue",
	}
	wantOut := []string{"out.0.", "out.1.", "out.2."}

	for proc := 0; proc < 3; proc++ {
		ad, err := d.Materialize(1, proc, rows[proc])
		if err != nil {
			t.Fatalf("Materialize proc %d: %v", proc, err)
		}
		args, ok := strAttr(t, ad, "Args")
		if !ok {
			t.Fatalf("proc %d: no Args attribute; ad=%s", proc, ad.String())
		}
		if args != wantArgs[proc] {
			t.Errorf("proc %d Args = %q, want %q", proc, args, wantArgs[proc])
		}
		out, _ := strAttr(t, ad, "Out")
		if out != wantOut[proc] {
			t.Errorf("proc %d Out = %q, want %q", proc, out, wantOut[proc])
		}
		iwd, _ := strAttr(t, ad, "Iwd")
		if iwd != "/tmp/fac" {
			t.Errorf("proc %d Iwd = %q, want /tmp/fac", proc, iwd)
		}
		// Requirements must NOT be materialized onto the proc (it comes from the
		// cluster ad via chaining; FACTORY.Requirements=MY.Requirements is a
		// directive, not a proc attribute).
		if _, ok := ad.Lookup("Requirements"); ok {
			t.Errorf("proc %d unexpectedly has Requirements override", proc)
		}
	}
}

// TestMaterializeNoVars covers a "queue N from items" foreach with no named vars:
// $(Item) is the whole row, Step is the inner index, Row is the item index.
func TestMaterializeNoVars(t *testing.T) {
	digest := "arguments=item=[$(Item)] step=$(Step) row=$(Row) proc=$(Process)\n" +
		"\nQueue 2 from /tmp/x.items\n"
	d, err := ParseDigest(digest)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if d.QueueNum() != 2 {
		t.Fatalf("queueNum = %d, want 2", d.QueueNum())
	}
	rowsByIndex := []string{"alpha", "beta"}
	// Ground truth from stock condor_submit -dry-run (queue 2 from 2 items),
	// where row = proc/N and step = proc%N:
	expect := []string{
		"item=[alpha] step=0 row=0 proc=0",
		"item=[alpha] step=1 row=0 proc=1",
		"item=[beta] step=0 row=1 proc=2",
		"item=[beta] step=1 row=1 proc=3",
	}
	for proc := 0; proc < 4; proc++ {
		row := d.RowIndex(proc)
		ad, err := d.Materialize(7, proc, rowsByIndex[row])
		if err != nil {
			t.Fatalf("Materialize proc %d: %v", proc, err)
		}
		args, ok := strAttr(t, ad, "Args")
		if !ok {
			t.Fatalf("proc %d: no Args; ad=%s", proc, ad.String())
		}
		if args != expect[proc] {
			t.Errorf("proc %d Args = %q, want %q", proc, args, expect[proc])
		}
	}
}

// TestMaterializeUnitSeparator verifies multi-field rows split on the ASCII Unit
// Separator condor_submit uses on the wire.
func TestMaterializeUnitSeparator(t *testing.T) {
	digest := "arguments=a=$(a) b=$(b)\n\nQueue a,b from /tmp/x.items\n"
	d, err := ParseDigest(digest)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	ad, err := d.Materialize(1, 0, "left"+ItemSeparator+"right side")
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	args, _ := strAttr(t, ad, "Args")
	if args != "a=left b=right side" {
		t.Errorf("Args = %q, want %q", args, "a=left b=right side")
	}
}

// TestMaterializeExprAndCustom checks numeric request_* map to expressions and
// +Attr becomes a bare ClassAd attribute.
func TestMaterializeExprAndCustom(t *testing.T) {
	digest := "request_cpus=$(Process)\n+MyIndex=$(Process)\n\nQueue 3\n"
	d, err := ParseDigest(digest)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	ad, err := d.Materialize(1, 2, "")
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if v, ok := ad.EvaluateAttrInt("RequestCpus"); !ok || v != 2 {
		t.Errorf("RequestCpus = %v (ok=%v), want 2", v, ok)
	}
	if v, ok := ad.EvaluateAttrInt("MyIndex"); !ok || v != 2 {
		t.Errorf("MyIndex = %v (ok=%v), want 2", v, ok)
	}
}
