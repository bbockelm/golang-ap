package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-ap/internal/stats"
)

// scrape drives the /metrics handler and returns the exposition text.
func scrape(t *testing.T, st *stats.Collector) string {
	t.Helper()
	srv := httptest.NewServer(Handler(st))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(body)
}

// mustHaveMetric asserts that a `name value` sample line is present.
func mustHaveMetric(t *testing.T, body, line string) {
	t.Helper()
	for _, l := range strings.Split(body, "\n") {
		if strings.TrimSpace(l) == line {
			return
		}
	}
	t.Errorf("metric line %q not found in output:\n%s", line, body)
}

func TestHandlerExposesScheddMetrics(t *testing.T) {
	st := stats.New()
	// Drive some cumulative counters.
	st.IncJobsStarted()
	st.IncJobsStarted()
	st.IncJobsCompleted()
	st.IncJobsExited()
	st.IncShadowExceptions()
	st.IncMatchesReceived()
	st.IncNegotiationCycles()
	st.AddJobsMaterialized(3)
	// And the live gauges.
	st.SetGauges(stats.GaugeSources{
		Counts: func() stats.Counts {
			return stats.Counts{Total: 6, Idle: 3, Running: 2, Held: 1, Users: 2}
		},
		ShadowsRunning:   func() int { return 2 },
		FactoriesActive:  func() int { return 1 },
		UserlogFilesOpen: func() int { return 4 },
		UserlogDropped:   func() int64 { return 5 },
	})

	body := scrape(t, st)

	mustHaveMetric(t, body, "condor_schedd_jobs_started_total 2")
	mustHaveMetric(t, body, "condor_schedd_jobs_completed_total 1")
	mustHaveMetric(t, body, "condor_schedd_jobs_exited_total 1")
	mustHaveMetric(t, body, "condor_schedd_shadow_exceptions_total 1")
	mustHaveMetric(t, body, "condor_schedd_matches_received_total 1")
	mustHaveMetric(t, body, "condor_schedd_negotiation_cycles_total 1")
	mustHaveMetric(t, body, "condor_schedd_jobs_materialized_total 3")
	mustHaveMetric(t, body, "condor_schedd_userlog_events_dropped_total 5")

	mustHaveMetric(t, body, "condor_schedd_shadows_running 2")
	mustHaveMetric(t, body, "condor_schedd_job_ads 6")
	mustHaveMetric(t, body, "condor_schedd_users 2")
	mustHaveMetric(t, body, "condor_schedd_factories_active 1")
	mustHaveMetric(t, body, "condor_schedd_userlog_files_open 4")

	mustHaveMetric(t, body, `condor_schedd_jobs{status="idle"} 3`)
	mustHaveMetric(t, body, `condor_schedd_jobs{status="running"} 2`)
	mustHaveMetric(t, body, `condor_schedd_jobs{status="held"} 1`)

	// The standard Go/process collectors must be present too.
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("expected go_goroutines from the Go collector in output")
	}
}

// TestHandlerReflectsLiveGaugeChanges proves each scrape re-reads the sources.
func TestHandlerReflectsLiveGaugeChanges(t *testing.T) {
	st := stats.New()
	running := 0
	st.SetGauges(stats.GaugeSources{ShadowsRunning: func() int { return running }})

	if body := scrape(t, st); !strings.Contains(body, "condor_schedd_shadows_running 0") {
		t.Fatalf("want shadows_running 0, got:\n%s", body)
	}
	running = 7
	mustHaveMetric(t, scrape(t, st), "condor_schedd_shadows_running 7")
}
