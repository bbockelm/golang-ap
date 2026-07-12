package queue

import (
	"fmt"
	"strings"
)

// Per-attribute QMGMT authorization, mirroring the C++ schedd's SetAttribute
// enforcement in src/condor_schedd.V6/qmgmt.cpp. Three attribute categories are
// recognized (matching the C++ immutable_attrs / protected_attrs / secure_attrs
// References and their SYSTEM_*_JOB_ATTRS / *_JOB_ATTRS config knobs):
//
//   - immutable: may never be changed on a job already committed to the queue,
//     by anyone (not even a queue superuser) over a client SetAttribute. These
//     are the identity/type attributes the schedd owns (Owner, ClusterId, ...).
//     The schedd's own internal write paths (Txn.materialize, Queue.Modify,
//     Queue.MaterializeProc, the action/policy engines) do NOT go through
//     Txn.SetAttribute, so they bypass this gate entirely -- exactly like the
//     C++ schedd's internal SetAttribute calls with a NULL Q_SOCK.
//   - protected: settable on a committed job only by a queue superuser (or when
//     QUEUE_ALL_USERS_TRUSTED) AND only when the connection has enabled
//     SetAllowProtectedAttrChanges. Empty by default.
//   - secure: settable only by the schedd itself; a client attempt is silently
//     ignored by default (IGNORE_ATTEMPTS_TO_SET_SECURE_JOB_ATTRS=true) or
//     rejected when that knob is false.
//
// Independently of the category, a non-superuser may only modify a COMMITTED job
// (cluster) they own (UserCheck / OwnerCheck2 in the C++ schedd). Ads still being
// built in the active transaction (not yet committed) are exempt from all of
// these checks, matching the C++ "new ad in the active cluster" branch -- the
// forced-identity materialize step pins their Owner/User at commit regardless.

// systemImmutableJobAttrs is HTCondor's SYSTEM_IMMUTABLE_JOB_ATTRS default plus
// the accounting-group attributes the stock config appends to IMMUTABLE_JOB_ATTRS
// (param_info.in: "make sure that the user can't qedit these attributes once they
// have been set").
var systemImmutableJobAttrs = []string{
	"Owner", "ClusterId", "JobUniverse", "ProcId", "MyType", "TargetType", "User", "OsUser",
	"AcctGroup", "AcctGroupUser", "AccountingGroup",
}

// systemSecureJobAttrs is HTCondor's SYSTEM_SECURE_JOB_ATTRS default: the
// credential/identity provenance attributes only the schedd may write.
var systemSecureJobAttrs = []string{
	"x509userProxySubject", "x509UserProxyEmail", "x509UserProxyVOName",
	"x509UserProxyFirstFQAN", "x509UserProxyFQAN", "TotalSubmitProcs",
	"AuthTokenSubject", "AuthTokenIssuer", "AuthTokenGroups", "AuthTokenId",
	"AuthTokenScopes", "AuthTokenProject", "OsUser",
}

// systemProtectedJobAttrs is HTCondor's SYSTEM_PROTECTED_JOB_ATTRS default: empty.
var systemProtectedJobAttrs = []string{}

// authzConfig holds the resolved attribute-category sets and trust knobs used to
// authorize client SetAttribute/DeleteAttribute. Attribute names are matched
// case-insensitively (ClassAd attribute names are case-insensitive), so all keys
// are stored lowercased.
type authzConfig struct {
	immutable       map[string]bool
	protected       map[string]bool
	secure          map[string]bool
	allUsersTrusted bool // QUEUE_ALL_USERS_TRUSTED: bypass owner + protected checks
	ignoreSecure    bool // IGNORE_ATTEMPTS_TO_SET_SECURE_JOB_ATTRS (default true)
}

// buildAuthzConfig folds the system defaults together with any operator-supplied
// extra attributes (from IMMUTABLE_JOB_ATTRS / PROTECTED_JOB_ATTRS /
// SECURE_JOB_ATTRS) into lowercased lookup sets.
func buildAuthzConfig(opts Options) authzConfig {
	mk := func(system, extra []string) map[string]bool {
		m := make(map[string]bool, len(system)+len(extra))
		for _, a := range system {
			m[strings.ToLower(a)] = true
		}
		for _, a := range extra {
			if a = strings.TrimSpace(a); a != "" {
				m[strings.ToLower(a)] = true
			}
		}
		return m
	}
	return authzConfig{
		immutable:       mk(systemImmutableJobAttrs, opts.ImmutableAttrs),
		protected:       mk(systemProtectedJobAttrs, opts.ProtectedAttrs),
		secure:          mk(systemSecureJobAttrs, opts.SecureAttrs),
		allUsersTrusted: opts.AllUsersTrusted,
		ignoreSecure:    opts.IgnoreSecureAttrs,
	}
}

// AuthzError is returned by Txn.SetAttribute / Txn.DeleteAttribute when a client
// write is denied by the per-attribute / ownership authorization rules. The QMGMT
// handler maps it to the EACCES terrno the C++ schedd returns (vs. EINVAL for a
// malformed request), so condor_qedit / condor_submit report a permission error.
type AuthzError struct{ msg string }

func (e *AuthzError) Error() string { return e.msg }

func permErr(format string, args ...any) error {
	return &AuthzError{msg: fmt.Sprintf(format, args...)}
}

// authorize applies the per-attribute / ownership rules to a client attempt to
// set or delete attribute name on job c.p. It returns (ignore=true, nil) when the
// write should be silently dropped (a secure-attr set with the ignore knob on),
// (false, err) when it must be rejected, or (false, nil) when it is allowed.
//
// internal writes never call this (they use Queue.Modify / coll.Update directly),
// so this only ever runs for a client-driven Txn.SetAttribute/DeleteAttribute.
func (t *Txn) authorize(c, p int, name string) (ignore bool, err error) {
	az := t.q.authzSnapshot()
	lname := strings.ToLower(name)

	// Secure attributes: only the schedd's internal API may set them. Mirrors the
	// pre-Lookup secure check in the C++ SetAttribute (applies to new and
	// committed ads alike).
	if az.secure[lname] {
		if az.ignoreSecure {
			return true, nil // silently ignore, matching Ignore_Secure_SetAttr_Attempts
		}
		return false, permErr("attempt to edit secure attribute %q in job %d.%d", name, c, p)
	}

	// Ads still being built in this transaction are not yet in the queue; the C++
	// schedd applies no ownership/immutable/protected checks to them (the active-
	// cluster branch), and Txn.materialize pins their identity at commit.
	committedOwner, committed := t.committedOwner(c, p)
	if !committed {
		return false, nil
	}

	// Ownership: a non-superuser may only touch a committed job they own. Skipped
	// when QUEUE_ALL_USERS_TRUSTED (qmgmt_all_users_trusted) is set.
	if !az.allUsersTrusted && !t.isSuper {
		if committedOwner != "" && shortName(t.authUser) != committedOwner {
			return false, permErr("user %q may not change attributes for job %d.%d owned by %q",
				t.authUser, c, p, committedOwner)
		}
	}

	// Immutable: rejected for every client, including superusers, on a committed
	// job (the C++ immutable check is not gated on superuser).
	if az.immutable[lname] {
		return false, permErr("attempt to edit immutable attribute %q in job %d.%d", name, c, p)
	}

	// Protected: allowed on a committed job only for a superuser (or all-trusted)
	// that has enabled SetAllowProtectedAttrChanges on this connection.
	if az.protected[lname] {
		if !((t.isSuper || az.allUsersTrusted) && t.allowProtected) {
			return false, permErr("unauthorized setting of protected attribute %q denied in job %d.%d",
				name, c, p)
		}
	}
	return false, nil
}

// committedOwner returns the Owner of the already-committed job c.p (reading the
// flattened proc ad, or the cluster ad for a cluster-level edit / proc whose Owner
// is inherited). committed is false when no ad for c.p exists in the live queue
// yet -- i.e. it is a new ad being created in the current transaction.
func (t *Txn) committedOwner(c, p int) (owner string, committed bool) {
	ad, ok := t.q.coll.Get(jobKey(c, p))
	if !ok {
		return "", false
	}
	if o, ok := ad.EvaluateAttrString("Owner"); ok {
		return o, true
	}
	// Proc ad without its own Owner: fall back to the cluster ad.
	if p >= 0 {
		if cad, ok := t.q.coll.Get(jobKey(c, -1)); ok {
			if o, ok := cad.EvaluateAttrString("Owner"); ok {
				return o, true
			}
		}
	}
	return "", true
}
