package policy

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// job builds a job ClassAd from literal attrs (int64/bool/string) and expr
// attrs (a "name" -> "expression string" map parsed with ParseExpr).
func job(t *testing.T, lit map[string]any, exprs map[string]string) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	for k, v := range lit {
		if err := ad.Set(k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	for k, s := range exprs {
		e, err := classad.ParseExpr(s)
		if err != nil {
			t.Fatalf("parse %s=%q: %v", k, s, err)
		}
		ad.InsertExpr(k, e)
	}
	return ad
}

func TestOnExitHoldFires(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":         int64(statusRunning),
		"ExitCode":          int64(17),
		"ExitBySignal":      false,
		"OnExitHoldReason":  "bad exit",
		"OnExitHoldSubCode": int64(42),
	}, map[string]string{
		"OnExitHold":   "ExitCode =!= 0",
		"OnExitRemove": "true",
	})
	d := Analyze(ad, PeriodicThenExit, nil, statusRunning)
	if d.Action != Hold {
		t.Fatalf("action = %v, want Hold", d.Action)
	}
	if d.HoldCode != HoldCodeJobPolicy {
		t.Errorf("hold code = %d, want %d (JobPolicy)", d.HoldCode, HoldCodeJobPolicy)
	}
	if d.HoldSubCode != 42 {
		t.Errorf("hold subcode = %d, want 42", d.HoldSubCode)
	}
	if d.Reason != "bad exit" {
		t.Errorf("reason = %q, want %q", d.Reason, "bad exit")
	}
}

func TestOnExitHoldNotFiringOnCleanExit(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":    int64(statusRunning),
		"ExitCode":     int64(0),
		"ExitBySignal": false,
	}, map[string]string{
		"OnExitHold":   "ExitCode =!= 0",
		"OnExitRemove": "true",
	})
	d := Analyze(ad, PeriodicThenExit, nil, statusRunning)
	if d.Action != Complete {
		t.Fatalf("action = %v, want Complete", d.Action)
	}
}

func TestOnExitRemoveFalseRequeues(t *testing.T) {
	// Boolean false and numeric 0 must both requeue.
	for _, expr := range []string{"false", "0", "NumJobCompletions >= 2"} {
		ad := job(t, map[string]any{
			"JobStatus":         int64(statusRunning),
			"ExitCode":          int64(0),
			"ExitBySignal":      false,
			"NumJobCompletions": int64(1),
		}, map[string]string{
			"OnExitRemove": expr,
		})
		d := Analyze(ad, PeriodicThenExit, nil, statusRunning)
		if d.Action != Requeue {
			t.Fatalf("OnExitRemove=%q: action = %v, want Requeue", expr, d.Action)
		}
	}
}

func TestOnExitRemoveTrueCompletes(t *testing.T) {
	for _, expr := range []string{"true", "1", "NumJobCompletions >= 2"} {
		ad := job(t, map[string]any{
			"JobStatus":         int64(statusRunning),
			"ExitCode":          int64(0),
			"ExitBySignal":      false,
			"NumJobCompletions": int64(2),
		}, map[string]string{
			"OnExitRemove": expr,
		})
		d := Analyze(ad, PeriodicThenExit, nil, statusRunning)
		if d.Action != Complete {
			t.Fatalf("OnExitRemove=%q: action = %v, want Complete", expr, d.Action)
		}
	}
}

func TestOnExitRemoveAbsentDefaultsComplete(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":    int64(statusRunning),
		"ExitCode":     int64(0),
		"ExitBySignal": false,
	}, nil)
	d := Analyze(ad, PeriodicThenExit, nil, statusRunning)
	if d.Action != Complete {
		t.Fatalf("action = %v, want Complete (OnExitRemove defaults TRUE)", d.Action)
	}
}

func TestOnExitHoldBeatsOnExitRemove(t *testing.T) {
	// Both would act; OnExitHold is checked first and wins.
	ad := job(t, map[string]any{
		"JobStatus":    int64(statusRunning),
		"ExitCode":     int64(3),
		"ExitBySignal": false,
	}, map[string]string{
		"OnExitHold":   "ExitCode =!= 0",
		"OnExitRemove": "true",
	})
	d := Analyze(ad, PeriodicThenExit, nil, statusRunning)
	if d.Action != Hold {
		t.Fatalf("action = %v, want Hold (OnExitHold precedes OnExitRemove)", d.Action)
	}
}

func TestPeriodicRemoveOnIdle(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":   int64(statusIdle),
		"QDate":       int64(100),
		"CurrentTime": int64(200),
	}, map[string]string{
		"PeriodicRemove": "(CurrentTime - QDate) > 50",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusIdle)
	if d.Action != Remove {
		t.Fatalf("action = %v, want Remove", d.Action)
	}
	if d.Firing != "PeriodicRemove" {
		t.Errorf("firing = %q, want PeriodicRemove", d.Firing)
	}
}

func TestPeriodicRemoveUsesTimeBuiltin(t *testing.T) {
	// Without CurrentTime set, the time() builtin still resolves "now".
	ad := job(t, map[string]any{
		"JobStatus": int64(statusIdle),
		"QDate":     int64(0), // epoch -> time() - 0 is huge
	}, map[string]string{
		"PeriodicRemove": "(time() - QDate) > 5",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusIdle)
	if d.Action != Remove {
		t.Fatalf("action = %v, want Remove (time() builtin)", d.Action)
	}
}

func TestPeriodicHoldOnRunning(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":          int64(statusRunning),
		"PeriodicHoldReason": "held by periodic",
	}, map[string]string{
		"PeriodicHold": "true",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusRunning)
	if d.Action != Hold {
		t.Fatalf("action = %v, want Hold", d.Action)
	}
	if d.HoldCode != HoldCodeJobPolicy {
		t.Errorf("hold code = %d, want %d", d.HoldCode, HoldCodeJobPolicy)
	}
	if d.Reason != "held by periodic" {
		t.Errorf("reason = %q", d.Reason)
	}
}

func TestPeriodicHoldSkippedWhenHeld(t *testing.T) {
	// A Held job must not re-trigger PeriodicHold.
	ad := job(t, map[string]any{
		"JobStatus": int64(statusHeld),
	}, map[string]string{
		"PeriodicHold": "true",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusHeld)
	if d.Action != Stay {
		t.Fatalf("action = %v, want Stay (hold skipped on Held job)", d.Action)
	}
}

func TestHoldBeatsRemove(t *testing.T) {
	// Both PeriodicHold and PeriodicRemove fire on a non-held job; Hold wins.
	ad := job(t, map[string]any{
		"JobStatus": int64(statusRunning),
	}, map[string]string{
		"PeriodicHold":   "true",
		"PeriodicRemove": "true",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusRunning)
	if d.Action != Hold {
		t.Fatalf("action = %v, want Hold (Hold checked before Remove)", d.Action)
	}
}

func TestPeriodicReleaseOnHeld(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":      int64(statusHeld),
		"HoldReasonCode": int64(HoldCodeJobPolicy), // not a user-request hold
	}, map[string]string{
		"PeriodicRelease": "true",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusHeld)
	if d.Action != Release {
		t.Fatalf("action = %v, want Release", d.Action)
	}
}

func TestPeriodicReleaseSkippedForUserHold(t *testing.T) {
	// A job held at user request (HoldReasonCode 1) must not be auto-released.
	ad := job(t, map[string]any{
		"JobStatus":      int64(statusHeld),
		"HoldReasonCode": int64(HoldCodeUserRequest),
	}, map[string]string{
		"PeriodicRelease": "true",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusHeld)
	if d.Action != Stay {
		t.Fatalf("action = %v, want Stay (no release of user-held job)", d.Action)
	}
}

func TestReleaseBeatsRemoveOnHeld(t *testing.T) {
	ad := job(t, map[string]any{
		"JobStatus":      int64(statusHeld),
		"HoldReasonCode": int64(HoldCodeJobPolicy),
	}, map[string]string{
		"PeriodicRelease": "true",
		"PeriodicRemove":  "true",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusHeld)
	if d.Action != Release {
		t.Fatalf("action = %v, want Release (Release checked before Remove)", d.Action)
	}
}

func TestUndefinedExpressionDoesNotFire(t *testing.T) {
	// PeriodicRemove references an undefined attribute -> undefined -> no fire.
	ad := job(t, map[string]any{
		"JobStatus": int64(statusIdle),
	}, map[string]string{
		"PeriodicRemove": "NoSuchAttr > 5",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusIdle)
	if d.Action != Stay {
		t.Fatalf("action = %v, want Stay (undefined must not fire)", d.Action)
	}
}

func TestSystemPeriodicHoldFires(t *testing.T) {
	sys := NewSystem(SystemConfig{
		HoldExpr:    "JobStatus == 2 && RemoteWallClockTime > 100",
		HoldReason:  `"system hold reason"`,
		HoldSubCode: "7",
	})
	if sys.Empty() {
		t.Fatal("system policy should not be empty")
	}
	ad := job(t, map[string]any{
		"JobStatus":           int64(statusRunning),
		"RemoteWallClockTime": int64(200),
	}, nil)
	d := Analyze(ad, PeriodicOnly, sys, statusRunning)
	if d.Action != Hold {
		t.Fatalf("action = %v, want Hold (SYSTEM_PERIODIC_HOLD)", d.Action)
	}
	if d.HoldCode != HoldCodeSystemPolicy {
		t.Errorf("hold code = %d, want %d (SystemPolicy)", d.HoldCode, HoldCodeSystemPolicy)
	}
	if d.HoldSubCode != 7 {
		t.Errorf("hold subcode = %d, want 7", d.HoldSubCode)
	}
	if d.Reason != "system hold reason" {
		t.Errorf("reason = %q", d.Reason)
	}
	if d.Firing != "SYSTEM_PERIODIC_HOLD" {
		t.Errorf("firing = %q", d.Firing)
	}
}

func TestPerJobHoldBeatsSystemHold(t *testing.T) {
	// When both a per-job PeriodicHold and SYSTEM_PERIODIC_HOLD fire, the per-job
	// one wins (checked first) and records the JobPolicy code, not SystemPolicy.
	sys := NewSystem(SystemConfig{HoldExpr: "true"})
	ad := job(t, map[string]any{
		"JobStatus":          int64(statusRunning),
		"PeriodicHoldReason": "per-job wins",
	}, map[string]string{
		"PeriodicHold": "true",
	})
	d := Analyze(ad, PeriodicOnly, sys, statusRunning)
	if d.Action != Hold {
		t.Fatalf("action = %v, want Hold", d.Action)
	}
	if d.HoldCode != HoldCodeJobPolicy {
		t.Errorf("hold code = %d, want %d (per-job precedence)", d.HoldCode, HoldCodeJobPolicy)
	}
	if d.Firing != "PeriodicHold" {
		t.Errorf("firing = %q, want PeriodicHold", d.Firing)
	}
}

func TestSystemPeriodicRemoveFires(t *testing.T) {
	sys := NewSystem(SystemConfig{RemoveExpr: "JobStatus == 1 && (CurrentTime - QDate) > 10"})
	ad := job(t, map[string]any{
		"JobStatus":   int64(statusIdle),
		"QDate":       int64(0),
		"CurrentTime": int64(100),
	}, nil)
	d := Analyze(ad, PeriodicOnly, sys, statusIdle)
	if d.Action != Remove {
		t.Fatalf("action = %v, want Remove (SYSTEM_PERIODIC_REMOVE)", d.Action)
	}
	if d.Firing != "SYSTEM_PERIODIC_REMOVE" {
		t.Errorf("firing = %q", d.Firing)
	}
}

func TestPeriodicOnlyNoFireStays(t *testing.T) {
	ad := job(t, map[string]any{"JobStatus": int64(statusIdle)}, map[string]string{
		"PeriodicRemove": "false",
		"PeriodicHold":   "false",
	})
	d := Analyze(ad, PeriodicOnly, nil, statusIdle)
	if d.Action != Stay {
		t.Fatalf("action = %v, want Stay", d.Action)
	}
}

func TestNewSystemEmpty(t *testing.T) {
	if NewSystem(SystemConfig{}) != nil {
		t.Error("empty SystemConfig should yield nil System")
	}
	var s *System
	if !s.Empty() {
		t.Error("nil System should be Empty")
	}
}
