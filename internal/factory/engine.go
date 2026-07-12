package factory

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ap/internal/queue"
)

// DefaultInterval is how often the materialization engine sweeps factories even
// without a nudge (a backstop; job start/exit nudges drive the common case).
const DefaultInterval = 5 * time.Second

// Engine is the late-materialization driver. It runs OFF the scheduler core (its
// own goroutine, like the periodic-policy evaluator), sweeping factory clusters
// on a timer and whenever nudged (a job left Idle). For each factory it
// materializes just enough proc ads to keep JobMaterializeMaxIdle jobs idle,
// respecting JobMaterializeLimit and the itemdata row count, committing each proc
// via queue.MaterializeProc (which advances NextProcId/NextRow atomically and is
// serialized per cluster). Mirrors the C++ schedd's JobMaterializeTimerCallback /
// MaterializeJobs loop.
type Engine struct {
	q        *queue.Queue
	log      *logging.Logger
	interval time.Duration
	nudge    chan struct{}

	mu    sync.Mutex
	cache map[int]*factoryCache // parsed digest + item rows, keyed by cluster
}

type factoryCache struct {
	digest *Digest
	rows   []string
}

// NewEngine builds a materialization engine bound to the queue. interval <= 0
// uses DefaultInterval.
func NewEngine(q *queue.Queue, log *logging.Logger, interval time.Duration) *Engine {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Engine{
		q:        q,
		log:      log,
		interval: interval,
		nudge:    make(chan struct{}, 1),
		cache:    map[int]*factoryCache{},
	}
}

// Nudge asks the engine to sweep promptly. Non-blocking and safe from any
// goroutine (e.g. the scheduler core on a job start/exit); coalesces with a
// pending nudge.
func (e *Engine) Nudge() {
	select {
	case e.nudge <- struct{}{}:
	default:
	}
}

// Run drives the engine until ctx is cancelled. Call once (typically in a
// goroutine). It sweeps once immediately so a factory submitted while the engine
// was idle materializes its first batch without waiting a full interval.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	e.log.Info(logging.DestinationGeneral, "late-materialization engine started",
		"interval", e.interval.String())
	e.sweep()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sweep()
		case <-e.nudge:
			e.sweep()
		}
	}
}

// sweep materializes pending procs for every factory cluster.
func (e *Engine) sweep() {
	for _, c := range e.q.FactoryClusters() {
		e.materializeCluster(c)
	}
}

// materializeCluster tops up one factory cluster to max_idle, respecting the
// total limit and the itemdata row count.
func (e *Engine) materializeCluster(c int) {
	fi, ok := e.q.FactoryInfo(c)
	if !ok {
		e.dropCache(c)
		return
	}
	if fi.Paused != 0 {
		// Paused or complete: reclaim the cluster ad once its last proc has drained.
		// Done here in the engine (off the scheduler core) so a completing job never
		// pays for the O(N) live-proc scan this reclamation check needs.
		if e.q.MaybeCleanupFactoryCluster(c) {
			e.dropCache(c)
		}
		return
	}
	fc, err := e.loadFactory(c, fi)
	if err != nil {
		e.log.Warn(logging.DestinationGeneral, "cannot load factory digest/items; pausing",
			"cluster", c, "err", err)
		e.q.PauseFactory(c, queue.PauseNoMoreItems)
		return
	}

	// Total procs this factory can ever produce: queueNum * rowCount, capped by
	// JobMaterializeLimit (max_materialize). A "queue N" factory has no items, so
	// it has a single implicit row.
	rowCount := len(fc.rows)
	if rowCount == 0 {
		rowCount = 1
	}
	total := fc.digest.QueueNum() * rowCount
	limit := total
	if fi.Limit > 0 && fi.Limit < limit {
		limit = fi.Limit
	}

	idle := fi.IdleProcs
	next := fi.NextProcId
	materialized := 0
	for next < limit {
		// max_idle: keep at most MaxIdle idle jobs (MaxIdle < 0 means unbounded,
		// i.e. materialize everything up to the limit at once).
		if fi.MaxIdle >= 0 && idle >= fi.MaxIdle {
			break
		}
		proc := next
		row := fc.digest.RowIndex(proc)
		rawRow := ""
		if row < len(fc.rows) {
			rawRow = fc.rows[row]
		}
		override, merr := fc.digest.Materialize(c, proc, rawRow)
		if merr != nil {
			e.log.Warn(logging.DestinationGeneral, "materialize expansion failed; pausing factory",
				"cluster", c, "proc", proc, "err", merr)
			e.q.PauseFactory(c, queue.PauseNoMoreItems)
			return
		}
		next = proc + 1
		nextRow := fc.digest.RowIndex(next)
		paused := 0
		if next >= limit {
			paused = queue.PauseNoMoreItems // last proc: mark the factory done
		}
		if err := e.q.MaterializeProc(c, proc, override, next, nextRow, paused); err != nil {
			e.log.Warn(logging.DestinationGeneral, "committing materialized proc failed",
				"cluster", c, "proc", proc, "err", err)
			return
		}
		idle++
		materialized++
	}
	if materialized > 0 {
		e.log.Info(logging.DestinationGeneral, "materialized factory procs",
			"cluster", c, "count", materialized, "next_proc", next, "limit", limit, "idle", idle)
	}
	// If the factory produced no procs at all (e.g. limit 0), mark it done so it
	// is not revisited every sweep.
	if next >= limit && fi.Paused == 0 {
		e.q.PauseFactory(c, queue.PauseNoMoreItems)
	}
}

// loadFactory returns the cached (parsed digest + item rows) for cluster c,
// loading and parsing the spooled files on first use.
func (e *Engine) loadFactory(c int, fi *queue.FactoryInfo) (*factoryCache, error) {
	e.mu.Lock()
	if fc, ok := e.cache[c]; ok {
		e.mu.Unlock()
		return fc, nil
	}
	e.mu.Unlock()

	digestBytes, err := os.ReadFile(fi.DigestFile)
	if err != nil {
		return nil, err
	}
	d, err := ParseDigest(string(digestBytes))
	if err != nil {
		return nil, err
	}
	var rows []string
	if fi.ItemsFile != "" {
		if itemBytes, err := os.ReadFile(fi.ItemsFile); err == nil {
			rows = ParseItems(itemBytes)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	fc := &factoryCache{digest: d, rows: rows}
	e.mu.Lock()
	e.cache[c] = fc
	e.mu.Unlock()
	return fc, nil
}

func (e *Engine) dropCache(c int) {
	e.mu.Lock()
	delete(e.cache, c)
	e.mu.Unlock()
}
