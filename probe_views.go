package guard

const probeSummaryColumns = "target_id,agent_id,failures,successes,last_checked_at,outcome,route_results"
const probeEligibleTarget = `targets.manual_enabled=1 AND (targets.dns_action IS NULL OR targets.dns_action!='replace_ip')
 AND NOT EXISTS (SELECT 1 FROM replacement_jobs r WHERE r.target_id=targets.id AND r.stage IN ('retire','provision','enrollment','ansible','remnawave'))`

func (s *Store) targetProbeSummary(targetID any, pool row) probeSummary {
	agents := s.all("SELECT * FROM agents ORDER BY id")
	now := nowSeconds()
	return summarizeProbes(pool, agents, s.targetChecks(targetID), now)
}

func (s *Store) probeView(pools []row, checkQuery string, args ...any) probeSnapshot {
	view := probeSnapshot{
		agents: s.all("SELECT * FROM agents ORDER BY id"),
		pools:  make(map[string]row, len(pools)),
		checks: map[string]map[string]row{},
		now:    nowSeconds(),
	}
	for _, pool := range pools {
		view.pools[str(pool["id"])] = pool
	}
	for _, check := range s.all(checkQuery, args...) {
		id := str(check["target_id"])
		if view.checks[id] == nil {
			view.checks[id] = map[string]row{}
		}
		view.checks[id][str(check["agent_id"])] = check
	}
	return view
}

func (s *Store) poolProbeView(pool row, columns string) probeSnapshot {
	return s.probeView([]row{pool}, "SELECT "+columns+" FROM target_checks WHERE target_id IN (SELECT id FROM targets WHERE pool_id=?)", pool["id"])
}

func (p probeSummary) statuses(target row) (status, lastStatus string) {
	checkedAt, action := target["last_checked_at"], target["dns_action"]
	failures, successes := any(p.Failures), any(p.Successes)
	if p.Latest != nil {
		checkedAt = p.Latest["last_checked_at"]
		if !p.Fresh {
			// Keep historical evidence visible separately from today's coverage.
			failures, successes, action = p.Latest["failures"], p.Latest["successes"], nil
		}
	}
	observation := row{
		"manual_enabled": target["manual_enabled"], "last_checked_at": checkedAt,
		"failures": failures, "successes": successes, "dns_action": action,
	}
	lastStatus = observedStatus(observation, truth(target["dns_present"]), truth(target["dns_uncertain"]))
	if p.Failures > 0 && target["status"] == "protected" {
		lastStatus = "protected"
	}
	if truth(target["manual_enabled"]) && checkedAt != nil && !p.Fresh {
		return "stale", lastStatus
	}
	return lastStatus, lastStatus
}
