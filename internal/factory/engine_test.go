package factory

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/queue"
)

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	return log
}

// setupFactory commits a factory cluster to q: a cluster ad with common attrs
// plus the factory bookkeeping, and writes the digest/items files to spoolDir.
// It returns the cluster id. queueNum*len(rows) is the total; maxIdle/limit as
// given (limit<=0 means unlimited/total).
func setupFactory(t *testing.T, q *queue.Queue, spoolDir, digest string, rows []string, maxIdle, limit int) int {
	t.Helper()
	txn := q.Begin("alice")
	c, err := txn.NewCluster()
	if err != nil {
		t.Fatalf("NewCluster: %v", err)
	}
	digestPath := SpooledDigestPath(spoolDir, c)
	if err := os.MkdirAll(filepath.Dir(digestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(digestPath, []byte(digest), 0o644); err != nil {
		t.Fatal(err)
	}
	set := func(name, expr string) {
		if err := txn.SetAttribute(c, -1, name, expr); err != nil {
			t.Fatalf("SetAttribute %s: %v", name, err)
		}
	}
	set("Cmd", `"/bin/sleep"`)
	set("RequestCpus", "1")
	set(queue.AttrMaterializeDigestFile, strconv.Quote(digestPath))
	set(queue.AttrMaterializeNextProcId, "0")
	set(queue.AttrMaterializeNextRow, "0")
	set(queue.AttrMaterializePaused, "0")
	if maxIdle >= 0 {
		set(queue.AttrMaterializeMaxIdle, strconv.Itoa(maxIdle))
	}
	if limit > 0 {
		set(queue.AttrMaterializeLimit, strconv.Itoa(limit))
	}
	if len(rows) > 0 {
		itemsPath := SpooledItemsPath(spoolDir, c)
		var buf []byte
		for _, r := range rows {
			buf = append(buf, []byte(r+"\n")...)
		}
		if err := os.WriteFile(itemsPath, buf, 0o644); err != nil {
			t.Fatal(err)
		}
		set(queue.AttrMaterializeItemsFile, strconv.Quote(itemsPath))
		set(queue.AttrMaterializeItemCount, strconv.Itoa(len(rows)))
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return c
}

func countProcs(q *queue.Queue, c int) (total, idle int) {
	for ad := range q.Scan() {
		if cc, _ := ad.EvaluateAttrInt("ClusterId"); int(cc) != c {
			continue
		}
		total++
		if st, _ := ad.EvaluateAttrInt("JobStatus"); int(st) == queue.StatusIdle {
			idle++
		}
	}
	return total, idle
}

// TestEngineLazyMaterialization proves the engine keeps at most max_idle idle
// procs and materializes more only as jobs leave Idle, up to the total.
func TestEngineLazyMaterialization(t *testing.T) {
	dir := t.TempDir()
	q, err := queue.Open(queue.Options{Dir: dir, ScheddName: "s", UIDDomain: "x"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// queue 10 with max_idle=3, arguments referencing $(Process).
	digest := "arguments=run $(Process)\noutput=out.$(Process)\n\nQueue 10\n"
	c := setupFactory(t, q, dir, digest, nil, 3, 0)

	eng := NewEngine(q, testLogger(t), 0)

	// First sweep: should materialize exactly max_idle (3), NOT all 10.
	eng.sweep()
	total, idle := countProcs(q, c)
	if total != 3 || idle != 3 {
		t.Fatalf("after first sweep: total=%d idle=%d, want 3/3 (lazy, not eager)", total, idle)
	}

	// Nothing new until a job leaves Idle.
	eng.sweep()
	if total, _ := countProcs(q, c); total != 3 {
		t.Fatalf("second sweep with no idle churn added procs: total=%d, want 3", total)
	}

	// Simulate jobs starting to run (leaving Idle), sweeping after each; the
	// engine must top back up to 3 idle without ever exceeding it, until all 10
	// have been materialized.
	for started := 0; started < 10; started++ {
		// Move the lowest idle proc to Running.
		for p := 0; p < 10; p++ {
			if q.JobStatus(c, p) == queue.StatusIdle {
				q.Modify(c, p, func(ad *classad.ClassAd) {
					_ = ad.Set("JobStatus", int64(queue.StatusRunning))
				})
				break
			}
		}
		eng.sweep()
		if _, idle := countProcs(q, c); idle > 3 {
			t.Fatalf("idle=%d exceeded max_idle=3 after churn", idle)
		}
	}

	// Eventually all 10 are materialized.
	if total, _ := countProcs(q, c); total != 10 {
		t.Fatalf("final total=%d, want 10 materialized overall", total)
	}
	// Factory marked done.
	if fi, ok := q.FactoryInfo(c); ok && fi.Paused == 0 {
		t.Errorf("factory not marked paused/done after materializing all rows")
	}
}
