// Package metrics exposes the SchedD's runtime statistics as Prometheus metrics,
// so an operator can scrape job throughput and queue depth without parsing the
// Scheduler ClassAd. Every value is read live from a single stats.Collector on
// each scrape (a custom prometheus.Collector), so there is no double-bookkeeping
// and the numbers always match the schedd ad.
//
// This mirrors golang-collector's metrics package: a private registry served on
// /metrics, with the Go runtime and process collectors alongside the schedd's own
// gauges/counters.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bbockelm/golang-ap/internal/stats"
)

const namespace = "condor_schedd"

// scheddCollector implements prometheus.Collector over a *stats.Collector. It
// reads a fresh Snapshot on each Collect (rather than caching gauges), so the
// exported numbers are exact as of the scrape.
type scheddCollector struct {
	st *stats.Collector

	// cumulative counters
	jobsStarted       *prometheus.Desc
	jobsCompleted     *prometheus.Desc
	jobsExited        *prometheus.Desc
	shadowExceptions  *prometheus.Desc
	matchesReceived   *prometheus.Desc
	negotiationCycles *prometheus.Desc
	jobsMaterialized  *prometheus.Desc
	userlogDropped    *prometheus.Desc

	// gauges
	uptime         *prometheus.Desc
	shadowsRunning *prometheus.Desc
	jobs           *prometheus.Desc // labeled by status
	jobAds         *prometheus.Desc
	users          *prometheus.Desc
	factories      *prometheus.Desc
	userlogFiles   *prometheus.Desc
}

func newScheddCollector(st *stats.Collector) *scheddCollector {
	return &scheddCollector{
		st: st,
		jobsStarted: prometheus.NewDesc(namespace+"_jobs_started_total",
			"Cumulative number of jobs that entered Running (a shadow started).", nil, nil),
		jobsCompleted: prometheus.NewDesc(namespace+"_jobs_completed_total",
			"Cumulative number of jobs that terminated normally and left the queue.", nil, nil),
		jobsExited: prometheus.NewDesc(namespace+"_jobs_exited_total",
			"Cumulative number of job runs whose shadow reported an exit (any terminal action).", nil, nil),
		shadowExceptions: prometheus.NewDesc(namespace+"_shadow_exceptions_total",
			"Cumulative number of shadow exceptions (abnormal run failures charged against a job).", nil, nil),
		matchesReceived: prometheus.NewDesc(namespace+"_matches_received_total",
			"Cumulative number of matches received from the negotiator (PERMISSION_AND_AD).", nil, nil),
		negotiationCycles: prometheus.NewDesc(namespace+"_negotiation_cycles_total",
			"Cumulative number of NEGOTIATE rounds the schedd handled.", nil, nil),
		jobsMaterialized: prometheus.NewDesc(namespace+"_jobs_materialized_total",
			"Cumulative number of proc ads materialized by job factories.", nil, nil),
		userlogDropped: prometheus.NewDesc(namespace+"_userlog_events_dropped_total",
			"Cumulative number of user-log events dropped (backpressure / hung log filesystem).", nil, nil),

		uptime: prometheus.NewDesc(namespace+"_uptime_seconds",
			"Seconds since the schedd started.", nil, nil),
		shadowsRunning: prometheus.NewDesc(namespace+"_shadows_running",
			"Number of shadows currently running (jobs the core is supervising).", nil, nil),
		jobs: prometheus.NewDesc(namespace+"_jobs",
			"Number of jobs in the live queue, by status.", []string{"status"}, nil),
		jobAds: prometheus.NewDesc(namespace+"_job_ads",
			"Total number of job ads in the live queue.", nil, nil),
		users: prometheus.NewDesc(namespace+"_users",
			"Number of distinct job owners with jobs in the queue.", nil, nil),
		factories: prometheus.NewDesc(namespace+"_factories_active",
			"Number of active job-factory clusters.", nil, nil),
		userlogFiles: prometheus.NewDesc(namespace+"_userlog_files_open",
			"Number of user-log files the writer pool currently holds open.", nil, nil),
	}
}

func (c *scheddCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.jobsStarted
	ch <- c.jobsCompleted
	ch <- c.jobsExited
	ch <- c.shadowExceptions
	ch <- c.matchesReceived
	ch <- c.negotiationCycles
	ch <- c.jobsMaterialized
	ch <- c.userlogDropped
	ch <- c.uptime
	ch <- c.shadowsRunning
	ch <- c.jobs
	ch <- c.jobAds
	ch <- c.users
	ch <- c.factories
	ch <- c.userlogFiles
}

func (c *scheddCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.st.Snapshot()
	counter := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v)
	}
	gauge := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}

	counter(c.jobsStarted, float64(s.JobsStarted))
	counter(c.jobsCompleted, float64(s.JobsCompleted))
	counter(c.jobsExited, float64(s.JobsExited))
	counter(c.shadowExceptions, float64(s.ShadowExceptions))
	counter(c.matchesReceived, float64(s.MatchesReceived))
	counter(c.negotiationCycles, float64(s.NegotiationCycles))
	counter(c.jobsMaterialized, float64(s.JobsMaterialized))
	counter(c.userlogDropped, float64(s.UserlogDropped))

	gauge(c.uptime, float64(s.UptimeSeconds))
	gauge(c.shadowsRunning, float64(s.ShadowsRunning))
	gauge(c.jobAds, float64(s.Counts.Total))
	gauge(c.users, float64(s.Counts.Users))
	gauge(c.factories, float64(s.FactoriesActive))
	gauge(c.userlogFiles, float64(s.UserlogFilesOpen))

	// Per-status job gauge (matches condor_status's Idle/Running/Held breakdown).
	ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(s.Counts.Idle), "idle")
	ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(s.Counts.Running), "running")
	ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(s.Counts.Held), "held")
	ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(s.Counts.Removed), "removed")
	ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(s.Counts.Completed), "completed")
}

// Registry builds a private Prometheus registry with the schedd's stats collector
// plus the standard Go runtime and process (RSS, open FDs, ...) collectors.
func Registry(st *stats.Collector) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		newScheddCollector(st),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return reg
}

// Handler returns an http.Handler serving the schedd's Prometheus metrics from a
// private registry (so it never collides with any global registry).
func Handler(st *stats.Collector) http.Handler {
	return promhttp.HandlerFor(Registry(st), promhttp.HandlerOpts{})
}
