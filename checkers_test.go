package guard

import (
	"testing"
	"time"
)

func TestCheckerDecisions(t *testing.T) {
	now := float64(10000)
	pool := row{"interval_seconds": 60, "failure_threshold": 3, "recovery_threshold": 5}
	agent := func(id string, age float64, healthy bool) row {
		return row{"id": id, "last_seen": now - age, "healthy": healthy}
	}
	check := func(id string, failures, successes int, age float64) row {
		return row{"agent_id": id, "failures": failures, "successes": successes, "outcome": successes > 0, "last_checked_at": iso(fromSeconds(now - age)), "last_error": "probe_failed"}
	}
	tests := []struct {
		name                   string
		agents                 []row
		checks                 map[string]row
		remove, restore, fresh bool
		failures, successes    int
	}{
		{"one failure wins over five successes", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 3, 0, 0), "b": check("b", 0, 5, 0)}, true, false, true, 3, 0},
		{"do not sum failures across checkers", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 2, 0, 0), "b": check("b", 2, 0, 0)}, false, false, true, 2, 0},
		{"all checkers recovered", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 0, 5, 0), "b": check("b", 0, 5, 0)}, false, true, true, 0, 5},
		{"recovery waits for slowest checker", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 0, 5, 0), "b": check("b", 0, 4, 0)}, false, false, true, 0, 4},
		{"new checker must first probe", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 0, 5, 0)}, false, false, false, 0, 0},
		{"offline checker cannot remove", []row{agent("a", 91, true), agent("b", 0, true)}, map[string]row{"a": check("a", 3, 0, 0), "b": check("b", 0, 5, 0)}, false, true, true, 0, 5},
		{"unhealthy control cannot remove", []row{agent("a", 0, false), agent("b", 0, true)}, map[string]row{"a": check("a", 3, 0, 0), "b": check("b", 0, 5, 0)}, false, true, true, 0, 5},
		{"stale failure does not remove or restore", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 3, 0, 181), "b": check("b", 0, 5, 0)}, false, false, false, 0, 0},
		{"fresh failure survives missing other result", []row{agent("a", 0, true), agent("b", 0, true)}, map[string]row{"a": check("a", 3, 0, 0)}, true, false, true, 3, 0},
		{"no healthy agents cannot mutate DNS", []row{agent("a", 91, true)}, map[string]row{"a": check("a", 0, 5, 0)}, false, false, false, 0, 0},
		{"empty installation cannot mutate DNS", nil, nil, false, false, false, 0, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := summarizeProbes(pool, test.agents, test.checks, now)
			if got.Remove != test.remove || got.Restore != test.restore || got.Fresh != test.fresh || got.Failures != test.failures || got.Successes != test.successes {
				t.Fatalf("unexpected decision: %+v", got)
			}
		})
	}
	t.Run("inconclusive check never counts as success", func(t *testing.T) {
		c := check("a", 0, 0, 0)
		c["outcome"] = nil
		got := summarizeProbes(pool, []row{agent("a", 0, true)}, map[string]row{"a": c}, now)
		if got.Fresh || got.Restore || got.Remove {
			t.Fatalf("inconclusive vote: %+v", got)
		}
	})
	t.Run("probe freshness follows pool interval", func(t *testing.T) {
		slow := row{"interval_seconds": 120, "failure_threshold": 3, "recovery_threshold": 5}
		got := summarizeProbes(slow, []row{agent("a", 0, true)}, map[string]row{"a": check("a", 3, 0, 300)}, now)
		if !got.Remove {
			t.Fatal("check within three intervals should still be fresh")
		}
	})
}

func TestCheckerTargetProjection(t *testing.T) {
	checked := iso(time.Unix(10000, 0))
	target := row{"manual_enabled": true, "dns_present": true, "status": "healthy", "last_checked_at": checked}
	cases := []struct {
		name    string
		summary probeSummary
		status  string
	}{
		{"missing evidence is stale", probeSummary{}, "stale"},
		{"failure despite other successes", probeSummary{Fresh: true, Failures: 3}, "suspect"},
		{"full coverage is healthy", probeSummary{Fresh: true, Successes: 5}, "healthy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.summary.project(target); got["status"] != c.status {
				t.Fatalf("got %v", got)
			}
		})
	}
	target["status"] = "protected"
	if got := (probeSummary{Fresh: true, Failures: 3}).project(target); got["status"] != "protected" {
		t.Fatal("last A protection lost")
	}
	target["manual_enabled"] = false
	if got := (probeSummary{Fresh: true, Successes: 5}).project(target); got["status"] != "disabled" {
		t.Fatal("manual disable lost")
	}
}
