package guard

import (
	"math"
	"strings"
)

const (
	probeDirect = 1 << iota
	probeSOCKS5
)

const checkerHasProbeState = `next_due!=0 OR failures!=0 OR successes!=0 OR last_checked_at IS NOT NULL
 OR last_latency_ms IS NOT NULL OR last_error IS NOT NULL OR outcome IS NOT NULL OR route_results IS NOT NULL`

// A zero deadline queues immediate work. A missing deadline means the cached
// state will only change after a database write.
func (s *Store) initializeProbeRefresh() {
	s.transaction(func() {
		s.exec(`CREATE TABLE IF NOT EXISTS probe_target_refresh (
 target_id TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE, due_at REAL NOT NULL);
 CREATE INDEX IF NOT EXISTS probe_target_due ON probe_target_refresh(due_at,target_id);
 CREATE TABLE IF NOT EXISTS probe_agent_refresh (
 agent_id TEXT PRIMARY KEY, routes INTEGER NOT NULL DEFAULT 0, due_at REAL, scheduled INTEGER NOT NULL DEFAULT 0);
 CREATE INDEX IF NOT EXISTS probe_agent_due ON probe_agent_refresh(due_at) WHERE due_at IS NOT NULL;
 CREATE TABLE IF NOT EXISTS probe_schedule_targets (
 target_id TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE);
 CREATE INDEX IF NOT EXISTS probe_target_history ON targets(id) WHERE last_checked_at IS NOT NULL;
 CREATE INDEX IF NOT EXISTS probe_check_history ON target_checks(agent_id,target_id) WHERE last_checked_at IS NOT NULL;
 CREATE INDEX IF NOT EXISTS probe_checker_reset ON target_checks(agent_id) WHERE ` + checkerHasProbeState + `;
 CREATE INDEX IF NOT EXISTS probe_job_active_expiry ON jobs(expires) WHERE consumed=0;
 CREATE INDEX IF NOT EXISTS probe_job_consumed_expiry ON jobs(expires) WHERE consumed=1;`)
		const targetID = "SELECT NEW.id AS id"
		const referencedTarget = "SELECT id FROM targets WHERE id=NEW.target_id"
		const formerTarget = "SELECT id FROM targets WHERE id=OLD.target_id"
		s.exec(`CREATE TRIGGER IF NOT EXISTS probe_target_insert AFTER INSERT ON targets BEGIN
 ` + probeDirtyTargetsSQL(targetID) + `;
 INSERT OR IGNORE INTO probe_schedule_targets VALUES (NEW.id);
 END;
 CREATE TRIGGER IF NOT EXISTS probe_target_update
 AFTER UPDATE OF pool_id,ip,manual_enabled,dns_present,dns_uncertain,dns_action,status,last_checked_at ON targets
 WHEN NEW.pool_id IS NOT OLD.pool_id OR NEW.ip IS NOT OLD.ip OR NEW.manual_enabled IS NOT OLD.manual_enabled
 OR NEW.dns_present IS NOT OLD.dns_present OR NEW.dns_uncertain IS NOT OLD.dns_uncertain
 OR NEW.dns_action IS NOT OLD.dns_action OR NEW.status IS NOT OLD.status OR NEW.last_checked_at IS NOT OLD.last_checked_at
 BEGIN ` + probeDirtyTargetsSQL(targetID) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_target_reschedule AFTER UPDATE OF manual_enabled,pool_id ON targets
 WHEN NEW.manual_enabled=1 AND (NEW.manual_enabled IS NOT OLD.manual_enabled OR NEW.pool_id IS NOT OLD.pool_id)
 BEGIN INSERT OR IGNORE INTO probe_schedule_targets VALUES (NEW.id); END;

 CREATE TRIGGER IF NOT EXISTS probe_pool_update
 AFTER UPDATE OF interval_seconds,failure_threshold,recovery_threshold,automation_enabled,revision ON pools
 WHEN NEW.interval_seconds IS NOT OLD.interval_seconds OR NEW.failure_threshold IS NOT OLD.failure_threshold
 OR NEW.recovery_threshold IS NOT OLD.recovery_threshold OR NEW.automation_enabled IS NOT OLD.automation_enabled
 OR NEW.revision IS NOT OLD.revision
 BEGIN ` + probeDirtyTargetsSQL("SELECT id FROM targets WHERE pool_id=NEW.id") + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_pool_reschedule AFTER UPDATE OF profile ON pools
 WHEN OLD.profile IS NULL AND NEW.profile IS NOT NULL
 BEGIN INSERT OR IGNORE INTO probe_schedule_targets SELECT id FROM targets WHERE pool_id=NEW.id AND manual_enabled=1; END;

 CREATE TRIGGER IF NOT EXISTS probe_check_insert AFTER INSERT ON target_checks
 WHEN NEW.last_checked_at IS NOT NULL OR NEW.outcome IS NOT NULL
 BEGIN ` + probeDirtyTargetsSQL(referencedTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_check_update
 AFTER UPDATE OF failures,successes,last_checked_at,last_latency_ms,last_error,outcome,route_results ON target_checks
 WHEN NEW.failures IS NOT OLD.failures OR NEW.successes IS NOT OLD.successes
 OR NEW.last_checked_at IS NOT OLD.last_checked_at OR NEW.last_latency_ms IS NOT OLD.last_latency_ms
 OR NEW.last_error IS NOT OLD.last_error OR NEW.outcome IS NOT OLD.outcome OR NEW.route_results IS NOT OLD.route_results
 BEGIN ` + probeDirtyTargetsSQL(referencedTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_check_delete AFTER DELETE ON target_checks BEGIN
 ` + probeDirtyTargetsSQL(formerTarget+" AND (OLD.last_checked_at IS NOT NULL OR OLD.outcome IS NOT NULL)") + `;
 INSERT OR IGNORE INTO probe_schedule_targets
 SELECT id FROM targets WHERE id=OLD.target_id AND manual_enabled=1 AND EXISTS(SELECT 1 FROM agents WHERE id=OLD.agent_id);
 END;

 CREATE TRIGGER IF NOT EXISTS probe_agent_insert AFTER INSERT ON agents
 BEGIN ` + probeDirtyAgentSQL("NEW") + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_agent_delete AFTER DELETE ON agents BEGIN
 ` + probeDirtyAgentSQL("OLD") + `;
 UPDATE probe_agent_refresh SET scheduled=0 WHERE agent_id=OLD.id;
 UPDATE jobs SET consumed=1 WHERE agent_id=OLD.id AND consumed=0;
 END;
 CREATE TRIGGER IF NOT EXISTS probe_agent_update
 AFTER UPDATE OF last_seen,healthy,version,direct_enabled,socks5_enabled,proxy_url,proxy_revision,proxy_applied_revision,proxy_healthy,proxy_checked_at ON agents
 WHEN NEW.last_seen IS NOT OLD.last_seen OR NEW.healthy IS NOT OLD.healthy OR NEW.version IS NOT OLD.version
 OR NEW.direct_enabled IS NOT OLD.direct_enabled OR NEW.socks5_enabled IS NOT OLD.socks5_enabled
 OR NEW.proxy_url IS NOT OLD.proxy_url OR NEW.proxy_revision IS NOT OLD.proxy_revision
 OR NEW.proxy_applied_revision IS NOT OLD.proxy_applied_revision OR NEW.proxy_healthy IS NOT OLD.proxy_healthy
 OR NEW.proxy_checked_at IS NOT OLD.proxy_checked_at
 BEGIN ` + probeDirtyAgentSQL("NEW") + `; END;

 CREATE TRIGGER IF NOT EXISTS probe_binding_insert AFTER INSERT ON replacement_bindings
 BEGIN ` + probeDirtyTargetsSQL(referencedTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_binding_update AFTER UPDATE OF enabled,blocked_since ON replacement_bindings
 WHEN NEW.enabled IS NOT OLD.enabled OR NEW.blocked_since IS NOT OLD.blocked_since
 BEGIN ` + probeDirtyTargetsSQL(referencedTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_binding_delete AFTER DELETE ON replacement_bindings
 BEGIN ` + probeDirtyTargetsSQL(formerTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_replacement_finished AFTER UPDATE OF stage ON replacement_jobs
 WHEN OLD.stage NOT IN ('complete','cancelled') AND NEW.stage IN ('complete','cancelled')
 BEGIN ` + probeDirtyTargetsSQL(referencedTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_order_delete_started AFTER UPDATE OF stage ON server_orders
 WHEN OLD.stage!='deleting' AND NEW.stage='deleting'
 BEGIN ` + probeDirtyTargetsSQL(referencedTarget) + `; END;
 CREATE TRIGGER IF NOT EXISTS probe_order_delete_stopped AFTER UPDATE OF stage ON server_orders
 WHEN OLD.stage='deleting' AND NEW.stage!='deleting'
 BEGIN ` + probeDirtyTargetsSQL(formerTarget) + `; END;`)
		// On startup re-evaluate cached evidence and replacement timers against
		// the current clock, including databases upgraded from older versions.
		s.exec(probeDirtyTargetsSQL("SELECT id FROM targets"))
		s.exec(`INSERT INTO probe_agent_refresh(agent_id,due_at) SELECT id,0 FROM agents WHERE true
 ON CONFLICT(agent_id) DO UPDATE SET due_at=0`)
	})
}

func probeDirtyTargetsSQL(ids string) string {
	return `INSERT INTO probe_target_refresh(target_id,due_at) SELECT id,0 FROM (` + ids + `) WHERE true
 ON CONFLICT(target_id) DO UPDATE SET due_at=0 WHERE due_at!=0`
}

func probeDirtyAgentSQL(record string) string {
	return `INSERT INTO probe_agent_refresh(agent_id,due_at) VALUES (` + record + `.id,0)
 ON CONFLICT(agent_id) DO UPDATE SET due_at=0 WHERE due_at IS NOT 0`
}

func nextProbeDeadline(first, second float64) float64 {
	if first == 0 || second != 0 && second < first {
		return second
	}
	return first
}

func checkerProbeState(agent row, now float64) (int, float64) {
	if !checkerHealthy(agent, now) {
		return 0, 0
	}
	// Heartbeat freshness uses an inclusive boundary.
	expires := math.Nextafter(num(agent["last_seen"])+controlFreshSeconds, math.Inf(1))
	routes := 0
	if directReady(agent) {
		routes |= probeDirect
	}
	if socksReady(agent, now) {
		routes |= probeSOCKS5
		proxyExpires := math.Nextafter(num(agent["proxy_checked_at"])+controlFreshSeconds, math.Inf(1))
		expires = min(expires, proxyExpires)
	}
	return routes, expires
}

func (s *Store) refreshProbeTargets(now float64) {
	s.refreshProbeAgents(now)
	targets := s.all(`SELECT t.* FROM probe_target_refresh r JOIN targets t ON t.id=r.target_id
 WHERE r.due_at<=? ORDER BY r.due_at,r.target_id`, now)
	if len(targets) == 0 {
		return
	}
	agents := s.all("SELECT * FROM agents ORDER BY id")
	checks := map[string]map[string]row{}
	for _, check := range s.all(`SELECT c.* FROM probe_target_refresh r JOIN target_checks c ON c.target_id=r.target_id
 WHERE r.due_at<=? AND c.last_checked_at IS NOT NULL`, now) {
		id := str(check["target_id"])
		if checks[id] == nil {
			checks[id] = map[string]row{}
		}
		checks[id][str(check["agent_id"])] = check
	}
	pools := map[string]row{}
	for _, pool := range s.all(`SELECT id,interval_seconds,failure_threshold,recovery_threshold,automation_enabled FROM pools WHERE id IN (
 SELECT t.pool_id FROM probe_target_refresh r JOIN targets t ON t.id=r.target_id WHERE r.due_at<=?)`, now) {
		pools[str(pool["id"])] = pool
	}
	bindings := map[string]row{}
	for _, binding := range s.all(replacementObservedBindings+` JOIN probe_target_refresh r ON r.target_id=b.target_id
 WHERE r.due_at<=? AND `+replacementObservedFilter, now) {
		bindings[str(binding["target_id"])] = binding
	}
	deadlines := make([]any, 0, 2*len(targets))
	updates := []any{}
	for _, target := range targets {
		id := str(target["id"])
		pool := pools[str(target["pool_id"])]
		summary := summarizeProbes(pool, agents, checks[id], now)
		replacementDeadline := s.observeReplacement(target, pool, bindings[id], summary, now)
		_, update := summary.cachedUpdate(target)
		updates = append(updates, update...)
		if deadline := nextProbeDeadline(summary.nextExpiry, replacementDeadline); deadline != 0 {
			deadlines = append(deadlines, id, deadline)
		}
	}
	s.updateCachedProbeTargets(updates)
	// The updates above can requeue the same target through database triggers.
	// Retire the processed batch and record only its next deadlines.
	s.exec("DELETE FROM probe_target_refresh WHERE due_at<=?", now)
	for len(deadlines) > 0 {
		count := min(len(deadlines), 2*128)
		s.exec(`INSERT INTO probe_target_refresh(target_id,due_at) VALUES `+strings.Repeat("(?,?),", count/2-1)+"(?,?)", deadlines[:count]...)
		deadlines = deadlines[count:]
	}
}

func (s *Store) updateCachedProbeTargets(updates []any) {
	const columns = 8
	for len(updates) > 0 {
		count := min(len(updates), columns*128)
		s.exec(`WITH next(id,status,failures,successes,last_checked_at,last_latency_ms,last_error,last_agent_id) AS (VALUES `+
			strings.Repeat("(?,?,?,?,?,?,?,?),", count/columns-1)+`(?,?,?,?,?,?,?,?))
 UPDATE targets SET status=next.status,failures=next.failures,successes=next.successes,last_checked_at=next.last_checked_at,
 last_latency_ms=next.last_latency_ms,last_error=next.last_error,last_agent_id=next.last_agent_id
 FROM next WHERE targets.id=next.id`, updates[:count]...)
		updates = updates[count:]
	}
}

func (s *Store) refreshProbeAgents(now float64) {
	coverageChanged := false
	for _, state := range s.all("SELECT agent_id,routes FROM probe_agent_refresh WHERE due_at<=?", now) {
		id := state["agent_id"]
		agent := s.one("SELECT * FROM agents WHERE id=?", id)
		routes, expires := checkerProbeState(agent, now)
		previous := int(num(state["routes"]))
		if (previous == 0) != (routes == 0) {
			coverageChanged = true
		} else if previous != routes {
			// Still healthy, but observations from an affected route may change.
			s.exec(probeDirtyTargetsSQL("SELECT target_id AS id FROM target_checks WHERE agent_id=? AND last_checked_at IS NOT NULL"), id)
		}
		if agent == nil {
			s.exec("DELETE FROM probe_agent_refresh WHERE agent_id=?", id)
		} else {
			s.exec("UPDATE probe_agent_refresh SET routes=?,due_at=NULLIF(?,0) WHERE agent_id=?", routes, expires, id)
		}
	}
	if coverageChanged {
		// A new or disconnected checker can change complete coverage even
		// for targets for which that checker has never returned a result.
		s.exec(probeDirtyTargetsSQL(`SELECT id FROM targets WHERE last_checked_at IS NOT NULL
 UNION SELECT target_id AS id FROM target_checks WHERE last_checked_at IS NOT NULL`))
	}
}

func (s *Store) scheduleProbeRefresh(id any, deadline float64) {
	if deadline == 0 {
		s.exec("DELETE FROM probe_target_refresh WHERE target_id=?", id)
		return
	}
	s.exec(`INSERT INTO probe_target_refresh(target_id,due_at) VALUES (?,?)
 ON CONFLICT(target_id) DO UPDATE SET due_at=excluded.due_at WHERE due_at!=excluded.due_at`, id, deadline)
}

func (s *Store) targetChecks(targetID any) map[string]row {
	checks := map[string]row{}
	for _, check := range s.all("SELECT * FROM target_checks WHERE target_id=?", targetID) {
		checks[str(check["agent_id"])] = check
	}
	return checks
}

func (s *Store) ensureCheckerSchedule(agentID string) {
	if !truth(s.one("SELECT scheduled FROM probe_agent_refresh WHERE agent_id=?", agentID)["scheduled"]) {
		s.exec(`INSERT OR IGNORE INTO target_checks (target_id,agent_id)
 SELECT t.id,? FROM targets t JOIN pools p ON p.id=t.pool_id WHERE t.manual_enabled=1 AND p.profile IS NOT NULL`, agentID)
		s.exec("UPDATE probe_agent_refresh SET scheduled=1 WHERE agent_id=?", agentID)
	}
	if s.one("SELECT 1 FROM probe_schedule_targets LIMIT 1") != nil {
		s.exec(`INSERT OR IGNORE INTO target_checks (target_id,agent_id)
 SELECT q.target_id,a.agent_id FROM probe_schedule_targets q JOIN targets t ON t.id=q.target_id
 JOIN pools p ON p.id=t.pool_id JOIN probe_agent_refresh a ON a.scheduled=1
 WHERE t.manual_enabled=1 AND p.profile IS NOT NULL`)
		s.exec("DELETE FROM probe_schedule_targets")
	}
}
