// Package policy implements HTCondor's user job policy: the periodic and
// on-exit expressions that let a job self-manage (retry on failure, hold on a
// bad exit, time out, or be removed by an expression).
//
// It is a faithful, pure-Go port of the decision logic in
// src/condor_utils/user_job_policy.cpp (UserPolicy::AnalyzePolicy). The port is
// deliberately side-effect-free: Analyze reads a job ClassAd and returns a
// Decision; it never mutates the queue. The scheduler core (internal/sched)
// owns applying the decision. Keeping the decision logic isolated here makes it
// unit-testable without a running schedd.
//
// # Evaluation order and precedence (matches AnalyzePolicy)
//
// The first check to fire wins. In both modes the periodic chain runs first, in
// this order:
//
//  1. PeriodicHold   (only when the job is not Held/Completed)
//  2. PeriodicRelease (only when the job is Held and not held by user request)
//  3. PeriodicRemove
//
// Within each of those, the PER-JOB expression (PeriodicHold/PeriodicRelease/
// PeriodicRemove) is checked first; only if it does not fire is the matching
// SYSTEM_PERIODIC_* expression consulted. So a per-job expression takes
// precedence over the system one for the same action, and Hold/Release are
// checked before Remove (a firing hold beats a firing remove on a non-held job;
// a firing release beats a firing remove on a held job).
//
// Then, only in PeriodicThenExit mode (a job that just exited), the on-exit
// chain runs:
//
//  4. OnExitHold
//  5. OnExitRemove (defaults TRUE when absent: the job leaves the queue as
//     Completed; an explicit FALSE keeps it for re-run)
//
// A Removed job is inert: in PeriodicOnly it Stays; in PeriodicThenExit it is
// Removed (the C++ short-circuit for an already-removed job that exited).
//
// # Truthiness
//
// A policy expression "fires" when it evaluates to a numeric non-zero OR the
// boolean true. Undefined, error, string, and list results do NOT fire (they
// leave the job in the queue), matching AnalyzeSinglePeriodicPolicy, which only
// treats a numeric/boolean value as a trigger and ignores undefined/error.
package policy

import (
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
)

// JobStatus values (mirrors internal/queue and HTCondor's JobStatus attribute).
const (
	statusIdle      = 1
	statusRunning   = 2
	statusRemoved   = 3
	statusCompleted = 4
	statusHeld      = 5
)

// Hold reason codes from src/condor_utils/condor_holdcodes.h. A hold fired by a
// per-job expression (PeriodicHold/OnExitHold) records JobPolicy; one fired by a
// SYSTEM_PERIODIC_HOLD expression records SystemPolicy.
const (
	HoldCodeUserRequest  = 1  // CONDOR_HOLD_CODE::UserRequest (condor_hold)
	HoldCodeJobPolicy    = 3  // CONDOR_HOLD_CODE::JobPolicy (per-job PeriodicHold/OnExitHold)
	HoldCodeSystemPolicy = 26 // CONDOR_HOLD_CODE::SystemPolicy (SYSTEM_PERIODIC_HOLD)
)

// Action is the outcome of evaluating policy against a job.
type Action int

const (
	// Stay leaves the job untouched (PeriodicOnly: no expression fired).
	Stay Action = iota
	// Complete archives the job as Completed (status 4): a normal exit whose
	// OnExitRemove is true (the default). PeriodicThenExit only.
	Complete
	// Requeue returns the job to Idle for re-run: OnExitRemove evaluated false.
	// PeriodicThenExit only. This is the substrate max_retries builds on.
	Requeue
	// Remove archives the job as Removed (status 3): a periodic_remove /
	// SYSTEM_PERIODIC_REMOVE firing (or an exited job already Removed).
	Remove
	// Hold moves the job to Held (status 5) with the recorded reason/code.
	Hold
	// Release moves a Held job back to Idle (periodic_release firing).
	Release
)

func (a Action) String() string {
	switch a {
	case Stay:
		return "Stay"
	case Complete:
		return "Complete"
	case Requeue:
		return "Requeue"
	case Remove:
		return "Remove"
	case Hold:
		return "Hold"
	case Release:
		return "Release"
	default:
		return fmt.Sprintf("Action(%d)", int(a))
	}
}

// Mode selects which expressions are evaluated.
type Mode int

const (
	// PeriodicOnly evaluates only the periodic chain (the ticker's job scan).
	PeriodicOnly Mode = iota
	// PeriodicThenExit evaluates the periodic chain and then the on-exit chain
	// (a job that just exited its shadow).
	PeriodicThenExit
)

// SystemConfig carries the raw SYSTEM_PERIODIC_* configuration expression
// strings (empty means the knob is unset). The Reason/SubCode fields are
// themselves expressions evaluated against the job ad, matching how the C++
// UserPolicy resolves SYSTEM_PERIODIC_HOLD_REASON / _SUBCODE. Build a System
// from it with NewSystem.
type SystemConfig struct {
	HoldExpr     string
	HoldReason   string // expression -> string
	HoldSubCode  string // expression -> number
	ReleaseExpr  string
	RemoveExpr   string
	RemoveReason string // expression -> string
}

// System is the compiled pool-wide SYSTEM_PERIODIC_* policy. Its expressions are
// parsed once (NewSystem) so the per-tick, per-job evaluation only re-evaluates,
// never re-parses. A nil *System means no system policy.
type System struct {
	holdExpr, releaseExpr, removeExpr     *classad.Expr
	holdReason, removeReason, holdSubCode *classad.Expr
}

// NewSystem compiles cfg into a System, returning nil when no periodic hold/
// release/remove expression is configured. An expression that fails to parse is
// treated as unset (dropped); it never fires (matching the C++ Config(), which
// logs and ignores an invalid SYSTEM_PERIODIC_* expression).
func NewSystem(cfg SystemConfig) *System {
	if cfg.HoldExpr == "" && cfg.ReleaseExpr == "" && cfg.RemoveExpr == "" {
		return nil
	}
	parse := func(s string) *classad.Expr {
		if s == "" {
			return nil
		}
		e, err := classad.ParseExpr(s)
		if err != nil {
			return nil
		}
		return e
	}
	return &System{
		holdExpr:     parse(cfg.HoldExpr),
		releaseExpr:  parse(cfg.ReleaseExpr),
		removeExpr:   parse(cfg.RemoveExpr),
		holdReason:   parse(cfg.HoldReason),
		removeReason: parse(cfg.RemoveReason),
		holdSubCode:  parse(cfg.HoldSubCode),
	}
}

// Empty reports whether no system periodic expressions are configured (a fast
// path so the evaluator can skip system checks entirely).
func (s *System) Empty() bool {
	return s == nil || (s.holdExpr == nil && s.releaseExpr == nil && s.removeExpr == nil)
}

// Decision is the outcome of Analyze. For Hold it carries the reason string and
// hold reason code/subcode; for the other actions Reason is an informational
// firing description. Firing names the attribute or config knob that fired.
type Decision struct {
	Action      Action
	Reason      string
	HoldCode    int
	HoldSubCode int
	Firing      string
}

// Analyze evaluates the job policy for ad in the given mode and returns the
// action to take. state is the job's current JobStatus; pass a negative value to
// read it from the ad. now is the wall-clock time bound to CurrentTime for the
// evaluation (the caller injects CurrentTime=now onto the ad before calling, so
// expressions referencing CurrentTime resolve; expressions using the time()
// builtin resolve on their own).
//
// Analyze does not mutate ad's policy-relevant attributes.
func Analyze(ad *classad.ClassAd, mode Mode, sys *System, state int) Decision {
	if state < 0 {
		s, _ := ad.EvaluateAttrInt("JobStatus")
		state = int(s)
	}

	// A Removed job is inert. In PeriodicOnly it stays (no policy on removed
	// jobs); in PeriodicThenExit the exited-but-removed job is removed. Mirrors
	// the REMOVED short-circuit at the top of AnalyzePolicy.
	if state == statusRemoved {
		if mode == PeriodicOnly {
			return Decision{Action: Stay}
		}
		return Decision{Action: Remove, Firing: "OnExitRemove", Reason: "Job was removed"}
	}

	// (1) PeriodicHold -- only for a job that is neither Held nor Completed.
	if state != statusHeld && state != statusCompleted {
		if d, ok := checkHold(ad, sys); ok {
			return d
		}
	}

	// (2) PeriodicRelease -- only for a Held job, and never for a job held at
	// user request (HoldReasonCode 1). Mirrors the hold_code != UserRequest gate.
	if state == statusHeld {
		code, _ := ad.EvaluateAttrInt("HoldReasonCode")
		if int(code) != HoldCodeUserRequest {
			if d, ok := checkRelease(ad, sys); ok {
				return d
			}
		}
	}

	// (3) PeriodicRemove.
	if d, ok := checkRemove(ad, sys); ok {
		return d
	}

	if mode == PeriodicOnly {
		return Decision{Action: Stay}
	}

	// PeriodicThenExit: the on-exit chain.

	// (4) OnExitHold.
	if fires(ad, "OnExitHold") {
		return Decision{
			Action:      Hold,
			Reason:      holdReason(ad, "OnExitHold", "job attribute"),
			HoldCode:    HoldCodeJobPolicy,
			HoldSubCode: int(attrNumber(ad, "OnExitHoldSubCode")),
			Firing:      "OnExitHold",
		}
	}

	// (5) OnExitRemove -- defaults TRUE. Only an explicit false (numeric 0 or
	// boolean false) keeps the job for re-run; absent/undefined/anything-else
	// removes (completes) it. Mirrors the tail of AnalyzePolicy.
	if onExitRemoveIsFalse(ad) {
		return Decision{Action: Requeue, Firing: "OnExitRemove", Reason: "OnExitRemove evaluated to false"}
	}
	return Decision{Action: Complete, Firing: "OnExitRemove"}
}

// checkHold evaluates the per-job PeriodicHold, then SYSTEM_PERIODIC_HOLD.
func checkHold(ad *classad.ClassAd, sys *System) (Decision, bool) {
	if fires(ad, "PeriodicHold") {
		return Decision{
			Action:      Hold,
			Reason:      holdReason(ad, "PeriodicHold", "job attribute"),
			HoldCode:    HoldCodeJobPolicy,
			HoldSubCode: int(attrNumber(ad, "PeriodicHoldSubCode")),
			Firing:      "PeriodicHold",
		}, true
	}
	if sys != nil && firesExpr(ad, sys.holdExpr) {
		reason := evalString(ad, sys.holdReason)
		if reason == "" {
			reason = defaultReason("system macro", "SYSTEM_PERIODIC_HOLD")
		}
		return Decision{
			Action:      Hold,
			Reason:      reason,
			HoldCode:    HoldCodeSystemPolicy,
			HoldSubCode: int(evalNumber(ad, sys.holdSubCode)),
			Firing:      "SYSTEM_PERIODIC_HOLD",
		}, true
	}
	return Decision{}, false
}

// checkRelease evaluates the per-job PeriodicRelease, then SYSTEM_PERIODIC_RELEASE.
func checkRelease(ad *classad.ClassAd, sys *System) (Decision, bool) {
	if fires(ad, "PeriodicRelease") {
		return Decision{Action: Release, Firing: "PeriodicRelease",
			Reason: defaultReason("job attribute", "PeriodicRelease")}, true
	}
	if sys != nil && firesExpr(ad, sys.releaseExpr) {
		return Decision{Action: Release, Firing: "SYSTEM_PERIODIC_RELEASE",
			Reason: defaultReason("system macro", "SYSTEM_PERIODIC_RELEASE")}, true
	}
	return Decision{}, false
}

// checkRemove evaluates the per-job PeriodicRemove, then SYSTEM_PERIODIC_REMOVE.
func checkRemove(ad *classad.ClassAd, sys *System) (Decision, bool) {
	if fires(ad, "PeriodicRemove") {
		return Decision{Action: Remove, Firing: "PeriodicRemove",
			Reason: defaultReason("job attribute", "PeriodicRemove")}, true
	}
	if sys != nil && firesExpr(ad, sys.removeExpr) {
		reason := evalString(ad, sys.removeReason)
		if reason == "" {
			reason = defaultReason("system macro", "SYSTEM_PERIODIC_REMOVE")
		}
		return Decision{Action: Remove, Firing: "SYSTEM_PERIODIC_REMOVE", Reason: reason}, true
	}
	return Decision{}, false
}

// fires reports whether the named job attribute exists and evaluates truthy.
func fires(ad *classad.ClassAd, name string) bool {
	if _, ok := ad.Lookup(name); !ok {
		return false
	}
	return truthy(ad.EvaluateAttr(name))
}

// firesExpr reports whether a compiled config expression evaluates truthy
// against ad. A nil expression (unset/unparseable) does not fire.
func firesExpr(ad *classad.ClassAd, expr *classad.Expr) bool {
	if expr == nil {
		return false
	}
	return truthy(expr.Eval(ad))
}

// truthy applies the C++ AnalyzeSinglePeriodicPolicy trigger rule: a numeric
// non-zero or a boolean true fires; everything else (undefined, error, string,
// list) does not.
func truthy(v classad.Value) bool {
	if v.IsBool() {
		b, _ := v.BoolValue()
		return b
	}
	if v.IsNumber() {
		n, _ := v.NumberValue()
		return n != 0
	}
	return false
}

// onExitRemoveIsFalse reports whether OnExitRemove is present AND evaluates to an
// explicit false (numeric 0 or boolean false). Absent or undefined/error is NOT
// false (the job removes/completes), matching AnalyzePolicy's tail.
func onExitRemoveIsFalse(ad *classad.ClassAd) bool {
	if _, ok := ad.Lookup("OnExitRemove"); !ok {
		return false
	}
	v := ad.EvaluateAttr("OnExitRemove")
	if v.IsBool() {
		b, _ := v.BoolValue()
		return !b
	}
	if v.IsNumber() {
		n, _ := v.NumberValue()
		return n == 0
	}
	return false
}

// holdReason returns the job's "<base>Reason" string attribute when set,
// otherwise a default firing description.
func holdReason(ad *classad.ClassAd, base, src string) string {
	if r, ok := ad.EvaluateAttrString(base + "Reason"); ok && r != "" {
		return r
	}
	return defaultReason(src, base)
}

// attrNumber returns the numeric value of a job attribute (0 if absent/non-numeric).
func attrNumber(ad *classad.ClassAd, name string) float64 {
	if _, ok := ad.Lookup(name); !ok {
		return 0
	}
	v := ad.EvaluateAttr(name)
	if v.IsNumber() {
		n, _ := v.NumberValue()
		return n
	}
	return 0
}

// evalString evaluates a compiled config expression against ad, returning its
// string value (or "" on nil/non-string).
func evalString(ad *classad.ClassAd, expr *classad.Expr) string {
	if expr == nil {
		return ""
	}
	v := expr.Eval(ad)
	if !v.IsString() {
		return ""
	}
	s, _ := v.StringValue()
	return s
}

// evalNumber evaluates a compiled config expression against ad, returning its
// numeric value (or 0 on nil/non-number).
func evalNumber(ad *classad.ClassAd, expr *classad.Expr) float64 {
	if expr == nil {
		return 0
	}
	v := expr.Eval(ad)
	if !v.IsNumber() {
		return 0
	}
	n, _ := v.NumberValue()
	return n
}

// defaultReason mirrors the fallback firing string UserPolicy::FiringReason
// builds when no explicit _REASON is provided.
func defaultReason(src, expr string) string {
	return fmt.Sprintf("The %s %s expression evaluated to TRUE", src, expr)
}
