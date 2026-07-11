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

// Package match holds the schedd's table of claimed startd slots (match
// records) and the ALIVE keepalive handler that renews their leases.
//
// When a schedd claims a slot it holds a match record keyed by the claim's
// public id. The startd periodically sends the schedd an ALIVE command carrying
// the (secret) claim id; the schedd answers with the alive interval and renews
// the claim lease. If the startd misses too many keepalives the schedd lets the
// lease expire and reaps the match. This mirrors HTCondor's match_rec /
// Scheduler::receive_startd_alive (src/condor_schedd.V6/schedd.cpp).
package match

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// claimSinful returns the startd command address at the head of a claim id
// (everything before the first '#').
func claimSinful(claimID string) string {
	if i := strings.IndexByte(claimID, '#'); i >= 0 {
		return claimID[:i]
	}
	return ""
}

// ALIVE is the HTCondor ALIVE command integer (SCHED_VERS+41). The C++ schedd
// registers it at READ authorization (schedd.cpp), which we mirror.
const ALIVE = 441

// DefaultAlivesMissed is how many consecutive keepalives a claim may miss before
// its lease expires; the lease is AlivesMissed*AliveInterval. Matches the
// startd's MAX_CLAIM_ALIVES_MISSED default (6).
const DefaultAlivesMissed = 6

// State is the lifecycle state of a match record.
type State int

const (
	// StateClaimed means the slot is claimed but idle (no job activated yet).
	StateClaimed State = iota
	// StateActive means a job has been activated on the claim.
	StateActive
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "Active"
	default:
		return "Claimed"
	}
}

// MatchRec is one claimed startd slot.
type MatchRec struct {
	// ClaimID is the parsed claim id (public + session parts; the secret key is
	// not retained beyond session import).
	ClaimID *security.ClaimID
	// SlotAd is the startd slot ad the claim was made against (may be nil).
	SlotAd *classad.ClassAd
	// PeerAddr is the startd's command sinful.
	PeerAddr string
	// State is the claim lifecycle state.
	State State
	// AliveInterval is the keepalive interval (seconds) agreed with the startd.
	AliveInterval int
	// LeaseDeadline is when the claim lease expires if no further ALIVE arrives.
	LeaseDeadline time.Time

	// sessionID is the security session id derived from the claim id.
	sessionID string
	// publicID is the map key (the claim's public/session id).
	publicID string
}

// PublicID returns the match record's key (the claim's public id).
func (m *MatchRec) PublicID() string { return m.publicID }

// SessionID returns the security session id derived from the claim.
func (m *MatchRec) SessionID() string { return m.sessionID }

// Table is the schedd's set of match records, keyed by claim public id. It owns
// the security session cache the imported claim sessions live in; the cedar
// server that answers ALIVE must be built with the same cache (see Cache) so the
// startd's session-resumed keepalives are recognized.
type Table struct {
	mu           sync.Mutex
	byPublic     map[string]*MatchRec
	cache        *security.SessionCache
	alivesMissed int
}

// NewTable builds a Table. If cache is nil a fresh cache is allocated; pass the
// cache the ALIVE-answering cedar server uses so imported claim sessions are
// visible to it.
func NewTable(cache *security.SessionCache) *Table {
	if cache == nil {
		cache = security.NewSessionCache()
	}
	return &Table{
		byPublic:     map[string]*MatchRec{},
		cache:        cache,
		alivesMissed: DefaultAlivesMissed,
	}
}

// Cache returns the session cache backing the table's claim sessions.
func (t *Table) Cache() *security.SessionCache { return t.cache }

// SetAlivesMissed overrides how many keepalives may be missed before the lease
// expires (lease = n*AliveInterval). n<=0 restores the default.
func (t *Table) SetAlivesMissed(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n <= 0 {
		n = DefaultAlivesMissed
	}
	t.alivesMissed = n
}

// CreateFromClaim imports the claim-derived security session into the table's
// cache (so the schedd's server resumes it when the startd calls ALIVE) and
// records a claimed match. The session is imported with the submit-side identity
// -- the schedd is the submit side of a claim, so it attributes the startd's
// keepalives to submit-side@matchsession, matching what the startd registered.
func (t *Table) CreateFromClaim(rawClaimID string, slotAd *classad.ClassAd, aliveInterval int) (*MatchRec, error) {
	cid := security.ParseClaimIDStrict(rawClaimID)
	peer := claimSinful(rawClaimID)

	sesid, err := security.ImportClaimSession(t.cache, rawClaimID, security.ClaimSessionOptions{
		PeerAddr:           peer,
		PeerFQU:            security.SubmitSideMatchSessionFQU,
		ExtraValidCommands: []int{ALIVE},
	})
	if err != nil {
		return nil, err
	}

	public := cid.SecSessionID()
	if public == "" {
		public = rawClaimID
	}

	rec := &MatchRec{
		ClaimID:       cid,
		SlotAd:        slotAd,
		PeerAddr:      peer,
		State:         StateClaimed,
		AliveInterval: aliveInterval,
		LeaseDeadline: time.Now().Add(t.leaseDuration(aliveInterval)),
		sessionID:     sesid,
		publicID:      public,
	}

	t.mu.Lock()
	t.byPublic[public] = rec
	t.mu.Unlock()
	return rec, nil
}

// leaseDuration returns the lease length for an alive interval.
func (t *Table) leaseDuration(aliveInterval int) time.Duration {
	n := t.alivesMissed
	if n <= 0 {
		n = DefaultAlivesMissed
	}
	if aliveInterval <= 0 {
		aliveInterval = 1
	}
	return time.Duration(n*aliveInterval) * time.Second
}

// FindByClaimID looks up a match by a (secret or public) claim id, resolving it
// to the public key first. This is how the ALIVE handler finds a record.
func (t *Table) FindByClaimID(claimID string) (*MatchRec, bool) {
	public := security.ParseClaimIDStrict(claimID).SecSessionID()
	if public == "" {
		public = claimID
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byPublic[public]
	return rec, ok
}

// RenewLease pushes a match's lease deadline forward by one lease duration.
// Returns false if the claim id is unknown. Called on each ALIVE.
func (t *Table) RenewLease(claimID string) bool {
	public := security.ParseClaimIDStrict(claimID).SecSessionID()
	if public == "" {
		public = claimID
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byPublic[public]
	if !ok {
		return false
	}
	rec.LeaseDeadline = time.Now().Add(t.leaseDuration(rec.AliveInterval))
	return true
}

// RenewLeaseFor pushes a match's lease deadline to now+d, overriding the
// record's own alive-interval-derived duration. The scheduler's lease sweep uses
// it to keep a live run's match valid comfortably past the next sweep tick, so a
// short alive-interval lease can never race the (longer) sweep interval into a
// false expiry. Returns false if the claim id is unknown.
func (t *Table) RenewLeaseFor(claimID string, d time.Duration) bool {
	public := security.ParseClaimIDStrict(claimID).SecSessionID()
	if public == "" {
		public = claimID
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byPublic[public]
	if !ok {
		return false
	}
	rec.LeaseDeadline = time.Now().Add(d)
	return true
}

// ExpireSweep removes and returns every match whose lease has expired as of now.
func (t *Table) ExpireSweep(now time.Time) []*MatchRec {
	t.mu.Lock()
	defer t.mu.Unlock()
	var expired []*MatchRec
	for k, rec := range t.byPublic {
		if !rec.LeaseDeadline.IsZero() && now.After(rec.LeaseDeadline) {
			expired = append(expired, rec)
			delete(t.byPublic, k)
		}
	}
	return expired
}

// Len returns the number of live match records.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byPublic)
}

// Remove deletes a match record by claim id, returning it if present.
func (t *Table) Remove(claimID string) (*MatchRec, bool) {
	public := security.ParseClaimIDStrict(claimID).SecSessionID()
	if public == "" {
		public = claimID
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byPublic[public]
	if ok {
		delete(t.byPublic, public)
	}
	return rec, ok
}

// UpdateSlotAd replaces the slot ad stored on a match record (used when a
// REQUEST_CLAIM against a partitionable slot returns the carved dynamic slot's
// ad: the claim id is unchanged but the ad now describes the dslot). Returns
// false if the claim id is unknown.
func (t *Table) UpdateSlotAd(claimID string, ad *classad.ClassAd) bool {
	public := security.ParseClaimIDStrict(claimID).SecSessionID()
	if public == "" {
		public = claimID
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byPublic[public]
	if !ok {
		return false
	}
	rec.SlotAd = ad
	return true
}

// AliveEvent reports a received keepalive, for the caller's logging/telemetry.
type AliveEvent struct {
	ClaimID       string // secret claim id as received (do not log verbatim)
	PublicID      string
	Found         bool
	AliveInterval int // interval returned to the startd (-1 if unknown)
	RemoteAddr    string
}

// RegisterALIVE installs the ALIVE command handler on srv, backed by table. The
// handler mirrors Scheduler::receive_startd_alive: read the secret claim id,
// look up the match, reply the alive interval (or -1 if unknown) and renew the
// lease. onAlive, if non-nil, is called after each keepalive for logging.
//
// srv must have been constructed with table.Cache() as its session cache so the
// startd's session-resumed ALIVE is recognized. The command is registered at
// READ, matching the C++ schedd.
func RegisterALIVE(srv *cedarserver.Server, table *Table, onAlive func(AliveEvent)) {
	srv.Handle(ALIVE, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		claimID, err := in.GetString(ctx)
		if err != nil {
			return err
		}

		rec, found := table.FindByClaimID(claimID)
		retInterval := -1
		if found {
			retInterval = rec.AliveInterval
			table.RenewLease(claimID)
		}

		out := message.NewMessageForStream(c.Stream)
		if err := out.PutInt(ctx, retInterval); err != nil {
			return err
		}
		if err := out.FinishMessage(ctx); err != nil {
			return err
		}

		if onAlive != nil {
			public := security.ParseClaimIDStrict(claimID).SecSessionID()
			onAlive(AliveEvent{
				ClaimID:       claimID,
				PublicID:      public,
				Found:         found,
				AliveInterval: retInterval,
				RemoteAddr:    c.RemoteAddr,
			})
		}
		return nil
	}, "READ")
}
