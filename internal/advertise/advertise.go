// Package advertise builds the SchedD's Scheduler ClassAd and pushes it to the
// pool's collector(s) so that condor_status -schedd and matchmaking can see the
// daemon. Stage 1 publishes an ad with all-zero job counts (no job handling
// yet); later stages will fill in the live queue statistics.
package advertise

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/version"
)

// Advertiser builds and sends the SchedD ad. It is constructed once at startup
// and its Advertise method is called from the scheduler's single-writer event
// loop, so it needs no internal locking.
type Advertiser struct {
	log       *logging.Logger
	name      string
	machine   string
	startTime time.Time
	maxJobs   int
	// collectorsFn returns the collector endpoints to advertise to, resolved
	// fresh on each round. Resolving lazily (rather than once at startup) handles
	// two realities: the collector's address file may not exist yet when the
	// schedd first boots, and a collector restart under shared-port can hand it a
	// new ephemeral port.
	collectorsFn func() []string
	// addrFn returns the SchedD's currently advertised command address; it is a
	// closure over the daemon so the address is resolved lazily (it is only known
	// after the shared-port listener is adopted).
	addrFn func() string
	// countsFn, if set, returns live job-queue tallies for the ad's Total*Jobs
	// attributes; nil keeps the Stage-1 all-zero counters.
	countsFn func() QueueCounts
	// submittersFn, if set, returns per-submitter tallies; the advertiser sends
	// one UPDATE_SUBMITTOR_AD per submitter each round so the negotiator will
	// negotiate for them (a submitter ad is the prerequisite for NEGOTIATE).
	submittersFn func() []Submitter
	seq          int64
	submitSeq    int64
}

// QueueCounts carries the live job-queue tallies published in the Scheduler ad.
type QueueCounts struct {
	Idle, Running, Held, Removed, Total, Users int
}

// Submitter carries one submitter's tallies for its UPDATE_SUBMITTOR_AD.
type Submitter struct {
	// Name is the fully-qualified submitter identity (ATTR_NAME) the negotiator
	// keys on and echoes back as the NEGOTIATE Owner.
	Name          string
	Idle, Running int
	Held          int
}

// Options configures a new Advertiser.
type Options struct {
	Logger         *logging.Logger
	Name           string
	Machine        string
	StartTime      time.Time
	MaxJobsRunning int
	// CollectorsFn returns the collector endpoints (sinful or host:port) to push
	// the ad to; it is called once per advertise round.
	CollectorsFn func() []string
	AddressFn    func() string // returns the SchedD's advertised sinful address
	// CountsFn, if set, supplies live job-queue tallies each advertise round.
	CountsFn func() QueueCounts
	// SubmittersFn, if set, supplies per-submitter tallies each advertise round.
	SubmittersFn func() []Submitter
}

// New builds an Advertiser.
func New(opts Options) *Advertiser {
	return &Advertiser{
		log:          opts.Logger,
		name:         opts.Name,
		machine:      opts.Machine,
		startTime:    opts.StartTime,
		maxJobs:      opts.MaxJobsRunning,
		collectorsFn: opts.CollectorsFn,
		addrFn:       opts.AddressFn,
		countsFn:     opts.CountsFn,
		submittersFn: opts.SubmittersFn,
	}
}

// Advertise builds the current SchedD ad and sends it to every configured
// collector. Individual collector failures are logged but do not abort the
// round: a transient collector outage should not take down the SchedD.
func (a *Advertiser) Advertise(ctx context.Context) {
	var addrs []string
	if a.collectorsFn != nil {
		addrs = a.collectorsFn()
	}
	if len(addrs) == 0 {
		a.log.Warn(logging.DestinationGeneral, "no collector address resolved yet (COLLECTOR_HOST unset/port 0 and no address file); skipping schedd ad update")
		return
	}
	a.seq++
	ad := a.buildAd()
	opts := &htcondor.AdvertiseOptions{Command: commands.UPDATE_SCHEDD_AD, UseTCP: true}
	for _, addr := range addrs {
		col := htcondor.NewCollector(addr)
		if err := col.Advertise(ctx, ad, opts); err != nil {
			a.log.Warn(logging.DestinationGeneral, "schedd ad update failed",
				"collector", addr, "err", err.Error())
			continue
		}
		a.log.Debug(logging.DestinationGeneral, "sent schedd ad", "collector", addr, "name", a.name)
	}
	a.advertiseSubmitters(ctx, addrs)
}

// advertiseSubmitters sends one UPDATE_SUBMITTOR_AD per submitter to each
// collector. Without a submitter ad carrying idle jobs, the negotiator never
// initiates a NEGOTIATE with the schedd, so this is a prerequisite for matching.
func (a *Advertiser) advertiseSubmitters(ctx context.Context, addrs []string) {
	if a.submittersFn == nil {
		return
	}
	subs := a.submittersFn()
	if len(subs) == 0 {
		return
	}
	a.submitSeq++
	opts := &htcondor.AdvertiseOptions{Command: commands.UPDATE_SUBMITTOR_AD, UseTCP: true}
	for _, sub := range subs {
		ad := a.buildSubmitterAd(sub)
		for _, addr := range addrs {
			col := htcondor.NewCollector(addr)
			if err := col.Advertise(ctx, ad, opts); err != nil {
				a.log.Warn(logging.DestinationGeneral, "submitter ad update failed",
					"collector", addr, "submitter", sub.Name, "err", err.Error())
				continue
			}
			a.log.Debug(logging.DestinationGeneral, "sent submitter ad",
				"collector", addr, "submitter", sub.Name, "idle", sub.Idle, "running", sub.Running)
		}
	}
}

// buildSubmitterAd assembles a Submitter ClassAd (MyType="Submitter"), mirroring
// Scheduler::fill_submitter_ad: Name (the fully-qualified submitter the negotiator
// keys on), ScheddName/ScheddIpAddr so the negotiator can locate us, the idle /
// running / held tallies (with their Weighted* mirrors), and an empty
// SubmitterTag (the home pool).
func (a *Advertiser) buildSubmitterAd(sub Submitter) *classad.ClassAd {
	addr := a.addrFn()
	ad := classad.New()
	_ = ad.Set("MyType", "Submitter")
	_ = ad.Set("TargetType", "")
	_ = ad.Set("Name", sub.Name)
	_ = ad.Set("Machine", a.machine)
	_ = ad.Set("ScheddName", a.name)
	_ = ad.Set("ScheddIpAddr", addr)
	_ = ad.Set("MyAddress", addr)
	_ = ad.Set("SubmitterTag", "")
	_ = ad.Set("IdleJobs", sub.Idle)
	_ = ad.Set("RunningJobs", sub.Running)
	_ = ad.Set("HeldJobs", sub.Held)
	_ = ad.Set("WeightedIdleJobs", sub.Idle)
	_ = ad.Set("WeightedRunningJobs", sub.Running)
	_ = ad.Set("FlockedJobs", 0)
	_ = ad.Set("CondorVersion", condorVersionString())
	_ = ad.Set("CondorPlatform", condorPlatformString())
	_ = ad.Set("UpdateSequenceNumber", a.submitSeq)
	return ad
}

// buildAd assembles the Scheduler ClassAd. It mirrors the minimal attribute set
// a C++ condor_schedd publishes -- enough for condor_status -schedd to display
// the daemon and for the collector to key/expire the ad -- with all job-queue
// counters pinned at zero until job handling lands.
func (a *Advertiser) buildAd() *classad.ClassAd {
	addr := a.addrFn()
	ad := classad.New()
	_ = ad.Set("MyType", "Scheduler")
	_ = ad.Set("TargetType", "")
	_ = ad.Set("Name", a.name)
	_ = ad.Set("Machine", a.machine)
	_ = ad.Set("MyAddress", addr)
	_ = ad.Set("ScheddIpAddr", addr)
	_ = ad.Set("CondorVersion", condorVersionString())
	_ = ad.Set("CondorPlatform", condorPlatformString())
	_ = ad.Set("DaemonStartTime", a.startTime.Unix())
	_ = ad.Set("UpdateSequenceNumber", a.seq)
	var counts QueueCounts
	if a.countsFn != nil {
		counts = a.countsFn()
	}
	_ = ad.Set("TotalIdleJobs", counts.Idle)
	_ = ad.Set("TotalRunningJobs", counts.Running)
	_ = ad.Set("TotalHeldJobs", counts.Held)
	_ = ad.Set("TotalRemovedJobs", counts.Removed)
	_ = ad.Set("TotalJobAds", counts.Total)
	_ = ad.Set("NumUsers", counts.Users)
	_ = ad.Set("MaxJobsRunning", a.maxJobs)
	_ = ad.Set("StartSchedulerUniverse", false)
	return ad
}

// condorVersionString renders the "$CondorVersion: ... $" banner the pool uses
// to identify a daemon's build, tagging it as golang-ap.
//
// The leading token MUST parse as a numeric x.y.z: C++ tools feed this ad
// attribute into CondorVersionInfo to version-gate wire protocols, and an
// unparseable version (a "dev" build) reads as pre-6.7.7, pushing e.g.
// condor_submit -spool onto the legacy SPOOL_JOB_FILES protocol (no perms, no
// go-ahead, no transfer acks) that the Go schedd does not speak.
func condorVersionString() string {
	v := version.Get()
	num := v.Version
	if num == "" || num[0] < '0' || num[0] > '9' {
		num = "25.0.0"
	}
	return fmt.Sprintf("$CondorVersion: %s 2025-01-01 BuildID: golang-ap-%s $", num, v.Commit)
}

func condorPlatformString() string {
	return fmt.Sprintf("$CondorPlatform: %s_%s $", runtime.GOARCH, runtime.GOOS)
}
