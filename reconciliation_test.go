package guard

import "testing"

func TestActivationRequiresFreshRecoveryFromEveryChecker(t *testing.T) {
	now := float64(10000)
	pool := row{"interval_seconds": 60, "failure_threshold": 3, "recovery_threshold": 5, "revision": 2}
	agents := []row{
		{"id": "a", "last_seen": now, "healthy": true},
		{"id": "b", "last_seen": now, "healthy": true},
	}
	check := func(successes int, age float64) row {
		return row{"successes": successes, "failures": 0, "outcome": true, "last_checked_at": iso(fromSeconds(now - age))}
	}
	tests := []struct {
		name   string
		checks map[string]row
		ready  bool
	}{
		{"new target", nil, false},
		{"below recovery threshold", map[string]row{"a": check(1, 0), "b": check(1, 0)}, false},
		{"missing second checker", map[string]row{"a": check(5, 0)}, false},
		{"waiting for slowest checker", map[string]row{"a": check(5, 0), "b": check(4, 0)}, false},
		{"stale successes", map[string]row{"a": check(5, 181), "b": check(5, 0)}, false},
		{"all checkers passed", map[string]row{"a": check(5, 0), "b": check(5, 0)}, true},
		{"inconclusive retry", map[string]row{"a": check(5, 0), "b": {"successes": 5, "outcome": nil, "last_checked_at": iso(fromSeconds(now))}}, false},
		{"failure after readiness", map[string]row{"a": check(5, 0), "b": {"failures": 1, "successes": 0, "outcome": false, "last_checked_at": iso(fromSeconds(now))}}, false},
	}
	for _, action := range []string{"enroll", "enable"} {
		for _, test := range tests {
			t.Run(action+"/"+test.name, func(t *testing.T) {
				target := row{"manual_enabled": true, "dns_action": action, "dns_profile_revision": 1, "dns_present": false}
				for _, automation := range []bool{false, true} {
					pool["automation_enabled"] = automation
					summary := summarizeProbes(pool, agents, test.checks, now)
					if got := summary.permitsDNS(target, pool); got != test.ready {
						t.Fatalf("automation=%v: ready=%v, summary=%+v", automation, got, summary)
					}
				}
				target["manual_enabled"] = false
				if summarizeProbes(pool, agents, test.checks, now).permitsDNS(target, pool) {
					t.Fatal("disabled target must not activate")
				}
				target["manual_enabled"] = true
				if summarizeProbes(pool, nil, test.checks, now).permitsDNS(target, pool) {
					t.Fatal("no healthy checker must not activate")
				}
			})
		}
	}
}

func TestAutomaticDNSStillRequiresAutomationAndCurrentProfile(t *testing.T) {
	pool := row{"automation_enabled": true, "revision": 2}
	target := row{"manual_enabled": true, "dns_profile_revision": 2}
	for _, action := range []string{"auto_restore", "auto_remove"} {
		target["dns_action"] = action
		if (probeSummary{}).permitsDNS(target, pool) {
			t.Fatalf("%s allowed without probe evidence", action)
		}
		summary := probeSummary{Restore: action == "auto_restore", Remove: action == "auto_remove"}
		if !summary.permitsDNS(target, pool) {
			t.Fatalf("%s rejected despite valid evidence", action)
		}
		pool["automation_enabled"] = false
		if summary.permitsDNS(target, pool) {
			t.Fatal("paused automation must not change DNS automatically")
		}
		pool["automation_enabled"] = true
		target["dns_profile_revision"] = 1
		if summary.permitsDNS(target, pool) {
			t.Fatal("old profile must not change DNS automatically")
		}
		target["dns_profile_revision"] = 2
	}
}

func TestActivationStatusWaitsForDNSConfirmation(t *testing.T) {
	for _, action := range []string{"enroll", "enable"} {
		target := row{"manual_enabled": true, "dns_present": false, "dns_uncertain": true, "dns_action": action}
		if got := (probeSummary{}).project(target); got["status"] != "unknown" {
			t.Fatalf("new activation should await checks: %v", got)
		}
		summary := probeSummary{Fresh: true, Successes: 5, Restore: true, Latest: row{"last_checked_at": iso(fromSeconds(10000))}}
		if got := summary.project(target); got["status"] != "recovering" {
			t.Fatalf("successful probes must await DNS confirmation: %v", got)
		}
		target["dns_present"], target["dns_uncertain"], target["dns_action"] = true, false, nil
		if got := summary.project(target); got["status"] != "healthy" {
			t.Fatalf("confirmed A record should activate target: %v", got)
		}
	}
}
