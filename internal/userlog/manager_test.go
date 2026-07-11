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

package userlog

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	hlog "github.com/bbockelm/golang-htcondor/userlog"
)

// fakeWriter records the events written to one path and can optionally block
// forever in WriteEvent to simulate a hung filesystem.
type fakeWriter struct {
	path  string
	block chan struct{} // if non-nil, WriteEvent blocks until it is closed

	mu     sync.Mutex
	events []hlog.EventRecord
}

func (w *fakeWriter) WriteEvent(rec hlog.EventRecord) error {
	if w.block != nil {
		<-w.block // hang until released (or forever)
	}
	w.mu.Lock()
	w.events = append(w.events, rec)
	w.mu.Unlock()
	return nil
}

func (w *fakeWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events)
}

// fakeFS hands out fakeWriters per path and lets a test find them by path.
type fakeFS struct {
	mu       sync.Mutex
	writers  map[string]*fakeWriter
	blockAll bool          // new writers block in WriteEvent
	block    chan struct{} // shared block gate for blockAll writers
}

func newFakeFS() *fakeFS {
	return &fakeFS{writers: map[string]*fakeWriter{}, block: make(chan struct{})}
}

func (f *fakeFS) factory() writerFactory {
	return func(path string, _, _, _ int) eventWriter {
		f.mu.Lock()
		defer f.mu.Unlock()
		w, ok := f.writers[path]
		if !ok {
			w = &fakeWriter{path: path}
			if f.blockAll {
				w.block = f.block
			}
			f.writers[path] = w
		}
		return w
	}
}

func (f *fakeFS) writer(path string) *fakeWriter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writers[path]
}

// release unblocks every blocking writer.
func (f *fakeFS) release() { close(f.block) }

// jobAd builds a minimal job ad with an (absolute) UserLog path.
func jobAd(path string, cluster, proc int) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString("UserLog", path)
	_ = ad.Set("ClusterId", int64(cluster))
	_ = ad.Set("ProcId", int64(proc))
	return ad
}

func newTestManager(t *testing.T, cfg Config, fs *fakeFS) *Manager {
	t.Helper()
	m := newWithFactory("<schedd:1>", cfg, func(string, ...any) {}, fs.factory())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		m.Close(ctx)
	})
	return m
}

// waitFor polls cond until true or the deadline; returns whether it became true.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// TestCorePathDropsWhenFull proves an EXECUTE/TERMINATED (core) enqueue never
// blocks and drops+counts when the file's buffer is full behind a hung FS.
func TestCorePathDropsWhenFull(t *testing.T) {
	fs := newFakeFS()
	fs.blockAll = true // every writer hangs in WriteEvent
	// One worker so a single hung file ties up the whole pool; tiny buffer.
	m := newTestManager(t, Config{Workers: 1, QueueDepth: 2, SubmitTimeout: 50 * time.Millisecond}, fs)

	path := "/logs/hung.log"
	ad := jobAd(path, 1, 0)

	// First event is dequeued by the worker and blocks in WriteEvent. The next
	// QueueDepth events fill the buffer; everything after must be dropped.
	for i := 0; i < 50; i++ {
		done := make(chan struct{})
		go func() { m.Execute(ad, "host", "slot1"); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("core Execute blocked on a hung FS (event %d) — the core must never block", i)
		}
	}
	if got := m.Dropped(); got == 0 {
		t.Fatalf("expected core events to be dropped when the buffer is full, got Dropped()=%d", got)
	}
	t.Logf("core path dropped %d events without ever blocking", m.Dropped())
	fs.release()
}

// TestBackpressureBlocksThenTimesOut proves a Submit (non-core) enqueue applies
// bounded backpressure: it blocks up to SubmitTimeout, then drops.
func TestBackpressureBlocksThenTimesOut(t *testing.T) {
	fs := newFakeFS()
	fs.blockAll = true
	timeout := 150 * time.Millisecond
	m := newTestManager(t, Config{Workers: 1, QueueDepth: 1, SubmitTimeout: timeout}, fs)

	path := "/logs/hung.log"
	ad := jobAd(path, 7, 0)

	// Prime: first Submit is picked up by the worker (blocks in WriteEvent),
	// second fills the depth-1 buffer.
	m.Submit(ad)
	if !waitFor(time.Second, func() bool { return fs.writer(path) != nil }) {
		t.Fatal("worker never opened the file")
	}
	m.Submit(ad) // fills buffer (no worker to drain it — first is hung)

	// The next Submit must block ~SubmitTimeout then return (dropped).
	start := time.Now()
	m.Submit(ad)
	elapsed := time.Since(start)
	if elapsed < timeout {
		t.Fatalf("Submit returned in %s; expected to backpressure for at least %s", elapsed, timeout)
	}
	if elapsed > 5*timeout {
		t.Fatalf("Submit blocked %s; expected a bounded block near %s", elapsed, timeout)
	}
	if m.Dropped() == 0 {
		t.Fatal("expected the backpressured Submit to be dropped after timeout")
	}
	t.Logf("Submit backpressured for %s then dropped (bounded)", elapsed)
	fs.release()
}

// TestPerFileFIFOOrdering proves events for one file are written in enqueue
// order by the single owning worker, even with many workers in the pool.
func TestPerFileFIFOOrdering(t *testing.T) {
	fs := newFakeFS()
	m := newTestManager(t, Config{Workers: 16, QueueDepth: 4096}, fs)

	path := "/logs/order.log"
	const n = 500
	// Submit is a backpressure enqueue; issue them serially so their causal
	// order is well-defined (as in the real schedd: a job's events are emitted
	// one state-transition at a time). Encode the sequence in the (exported)
	// event timestamp so we can verify the worker preserved FIFO order.
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < n; i++ {
		ad := jobAd(path, 1, 0)
		m.emitBackpressure(ad, hlog.SubmitEvent(base.Add(time.Duration(i)*time.Second), "h"))
	}
	if !waitFor(2*time.Second, func() bool {
		w := fs.writer(path)
		return w != nil && w.count() == n
	}) {
		w := fs.writer(path)
		got := 0
		if w != nil {
			got = w.count()
		}
		t.Fatalf("expected %d events written, got %d", n, got)
	}
	w := fs.writer(path)
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, ev := range w.events {
		want := base.Add(time.Duration(i) * time.Second)
		if !ev.When.Equal(want) {
			t.Fatalf("event %d out of order: When=%s, want %s", i, ev.When, want)
		}
	}
	t.Logf("all %d events written in FIFO order by the owning worker", n)
}

// TestFlushDrainsPending proves Close drains buffered events before returning.
func TestFlushDrainsPending(t *testing.T) {
	fs := newFakeFS() // non-blocking writers
	m := newWithFactory("<schedd:1>", Config{Workers: 4, QueueDepth: 4096},
		func(string, ...any) {}, fs.factory())

	paths := []string{"/logs/a.log", "/logs/b.log", "/logs/c.log"}
	const per = 100
	for _, p := range paths {
		for i := 0; i < per; i++ {
			m.emitBackpressure(jobAd(p, 1, 0), hlog.SubmitEvent(time.Now(), "h"))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.Close(ctx)

	for _, p := range paths {
		w := fs.writer(p)
		if w == nil || w.count() != per {
			got := 0
			if w != nil {
				got = w.count()
			}
			t.Fatalf("file %s: Close drained %d events, want %d", p, got, per)
		}
	}
	if m.Dropped() != 0 {
		t.Fatalf("no events should have been dropped on a fast FS, got %d", m.Dropped())
	}
	t.Logf("Close drained all %d files x %d events", len(paths), per)
}

// TestBoundedGoroutinesManyFiles is the anti-regression guard: enqueuing across
// thousands of DISTINCT log files must NOT spawn a goroutine (or hold an FD) per
// file. Goroutine count must stay ~ Workers + baseline, independent of file
// count.
func TestBoundedGoroutinesManyFiles(t *testing.T) {
	fs := newFakeFS() // fast, non-blocking writers
	const workers = 24
	m := newTestManager(t, Config{Workers: workers, QueueDepth: 8, MaxFiles: 100000}, fs)

	// Let the pool settle so the baseline reflects the started workers/reaper.
	time.Sleep(20 * time.Millisecond)
	base := runtime.NumGoroutine()

	const nFiles = 5000
	var peak int
	for i := 0; i < nFiles; i++ {
		path := fmt.Sprintf("/logs/job_%d.log", i)
		m.emitCore(jobAd(path, i, 0), hlog.SubmitEvent(time.Now(), "h"))
		if g := runtime.NumGoroutine(); g > peak {
			peak = g
		}
	}
	// Allow generous slack for transient scheduler/test goroutines, but the
	// point is: NOT growing with nFiles. A goroutine-per-file bug would blow
	// past base+workers+slack by thousands.
	limit := base + workers + 64
	if peak > limit {
		t.Fatalf("goroutines grew with file count: peak=%d, base=%d, limit=%d (a goroutine-per-file regression?)",
			peak, base, limit)
	}
	t.Logf("enqueued across %d distinct files with peak goroutines=%d (base=%d, workers=%d) — bounded",
		nFiles, peak, base, workers)

	// And every file's events must still drain (in order, one event each here).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m.Close(ctx)
	written := 0
	fs.mu.Lock()
	for _, w := range fs.writers {
		written += w.count()
	}
	fs.mu.Unlock()
	if written != nFiles-int(m.Dropped()) {
		t.Fatalf("written(%d) + dropped(%d) != enqueued(%d)", written, m.Dropped(), nFiles)
	}
	t.Logf("drained %d files (%d dropped) after the burst", written, m.Dropped())
}
