package guard

import (
	"encoding/json"
	"strings"
	"time"
)

// Registration is implicit in authenticated polls. A checker's schedule and
// evidence belong to (target, agent), never to the target alone.
func (s *Store) initializeCheckers() {
	s.initializeCheckerProxy()
	columns := map[string]bool{}
	for _, c := range s.all("PRAGMA table_info(agents)") {
		columns[str(c["name"])] = true
	}
	if !columns["version"] {
		s.exec("ALTER TABLE agents ADD COLUMN version TEXT DEFAULT ''")
	}
	s.transaction(func() {
		s.exec(`CREATE TABLE IF NOT EXISTS target_checks (
 target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
 agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
 next_due REAL NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
 successes INTEGER NOT NULL DEFAULT 0, last_checked_at TEXT,
 last_latency_ms REAL, last_error TEXT, outcome INTEGER,
 PRIMARY KEY(target_id,agent_id));
 DROP INDEX IF EXISTS target_active_job;
 CREATE UNIQUE INDEX IF NOT EXISTS target_agent_active_job ON jobs(target_id,agent_id) WHERE consumed=0;
 CREATE INDEX IF NOT EXISTS agent_active_jobs ON jobs(agent_id) WHERE consumed=0;
 CREATE INDEX IF NOT EXISTS checker_schedule ON target_checks(agent_id,next_due);`)
		// A one-time marker prevents resurrecting reset evidence on later boots.
		if s.one("SELECT key FROM settings WHERE key='multi_checker_migrated'") == nil {
			s.exec(`INSERT OR IGNORE INTO target_checks (target_id,agent_id,next_due,failures,successes,last_checked_at,last_latency_ms,last_error,outcome)
 SELECT t.id,t.last_agent_id,t.next_due,t.failures,t.successes,t.last_checked_at,t.last_latency_ms,t.last_error,
 CASE WHEN t.failures>0 THEN 0 WHEN t.successes>0 THEN 1 ELSE NULL END
 FROM targets t JOIN agents a ON a.id=t.last_agent_id`)
			s.exec("INSERT INTO settings VALUES ('multi_checker_migrated','1')")
		}
	})
	s.initializeCheckerRoutes()
}

func checkerHealthy(agent row, now float64) bool {
	return agent != nil && (!socksEnabled(agent) || supportsRoutes(str(agent["version"]))) && now-num(agent["last_seen"]) <= controlFreshSeconds && (directReady(agent) || socksReady(agent, now))
}

func checkFresh(check, agent row, interval, now float64) bool {
	if check == nil || check["outcome"] == nil || !checkerHealthy(agent, now) {
		return false
	}
	checked, err := time.Parse(time.RFC3339Nano, str(check["last_checked_at"]))
	return err == nil && now-float64(checked.UnixNano())/1e9 < max(float64(leaseSeconds), interval*3) && routeEvidenceFresh(check, agent, now)
}

type probeSummary struct {
	Failures, Successes, Active, Checked int
	Fresh, Remove, Restore               bool
	Latest, Evidence                     row
}

// One fresh failing checker is enough to remove an IP. Recovery requires a
// fresh recovery streak from EVERY currently healthy, connected checker.
// Missing/unsupported/inconclusive checks cannot vote for recovery.
func summarizeProbes(pool row, agents []row, checks map[string]row, now float64) probeSummary {
	summary := probeSummary{}
	for _, agent := range agents {
		check := checks[str(agent["id"])]
		if check != nil && str(check["last_checked_at"]) != "" && (summary.Latest == nil || str(check["last_checked_at"]) > str(summary.Latest["last_checked_at"])) {
			summary.Latest = check
		}
		if !checkerHealthy(agent, now) {
			continue
		}
		summary.Active++
		successes := 0
		if checkFresh(check, agent, num(pool["interval_seconds"]), now) {
			summary.Checked++
			successes = int(num(check["successes"]))
			if failures := int(num(check["failures"])); failures > summary.Failures {
				summary.Failures, summary.Evidence = failures, check
			}
		}
		if summary.Active == 1 || successes < summary.Successes {
			summary.Successes = successes
		}
	}
	summary.Fresh = summary.Failures > 0 || summary.Active > 0 && summary.Checked == summary.Active
	summary.Remove = summary.Failures >= int(num(pool["failure_threshold"])) && summary.Failures > 0
	summary.Restore = summary.Active > 0 && summary.Checked == summary.Active && summary.Successes >= int(num(pool["recovery_threshold"]))
	return summary
}

func (p probeSummary) project(target row) row {
	value := row{}
	for key, v := range target {
		value[key] = v
	}
	value["failures"], value["successes"] = p.Failures, p.Successes
	if p.Latest != nil {
		value["last_checked_at"], value["last_latency_ms"], value["last_error"], value["last_agent_id"] = p.Latest["last_checked_at"], p.Latest["last_latency_ms"], p.Latest["last_error"], p.Latest["agent_id"]
	}
	if p.Evidence != nil {
		value["last_error"] = p.Evidence["last_error"]
	}
	status := observedStatus(value, truth(target["dns_present"]), truth(target["dns_uncertain"]))
	if !p.Fresh && p.Latest != nil {
		// Preserve the last observation separately from today's missing coverage.
		history := row{"manual_enabled": target["manual_enabled"], "last_checked_at": p.Latest["last_checked_at"], "failures": p.Latest["failures"], "successes": p.Latest["successes"]}
		status = observedStatus(history, truth(target["dns_present"]), truth(target["dns_uncertain"]))
	}
	if p.Failures > 0 && target["status"] == "protected" {
		status = "protected"
	}
	value["last_status"], value["probe_fresh"] = status, p.Fresh
	value["checkers_active"], value["checkers_checked"] = p.Active, p.Checked
	if truth(target["manual_enabled"]) && value["last_checked_at"] != nil && !p.Fresh {
		status = "stale"
	}
	value["status"] = status
	return value
}

type probeSnapshot struct {
	agents []row
	pools  map[string]row
	checks map[string]map[string]row
	now    float64
}

func (s *Store) probeSnapshot() probeSnapshot {
	view := probeSnapshot{agents: s.all("SELECT * FROM agents ORDER BY id"), pools: map[string]row{}, checks: map[string]map[string]row{}, now: nowSeconds()}
	for _, pool := range s.all("SELECT * FROM pools") {
		view.pools[str(pool["id"])] = pool
	}
	for _, check := range s.all("SELECT * FROM target_checks") {
		id := str(check["target_id"])
		if view.checks[id] == nil {
			view.checks[id] = map[string]row{}
		}
		view.checks[id][str(check["agent_id"])] = check
	}
	return view
}

func (v probeSnapshot) summary(target row) probeSummary {
	return summarizeProbes(v.pools[str(target["pool_id"])], v.agents, v.checks[str(target["id"])], v.now)
}

// Cache the same projection used by the API for durable notifications. Clock
// expiry is refreshed by the notifier even if no agents are polling.
func (s *Store) refreshProbeTargets() {
	view := s.probeSnapshot()
	for _, target := range s.all("SELECT * FROM targets") {
		s.cacheProbeTarget(target, view.summary(target))
	}
}

func (s *Store) cacheProbeTarget(target row, summary probeSummary) row {
	value := summary.project(target)
	if target["status"] != value["status"] || num(target["failures"]) != num(value["failures"]) || num(target["successes"]) != num(value["successes"]) || target["last_checked_at"] != value["last_checked_at"] || target["last_error"] != value["last_error"] || target["last_latency_ms"] != value["last_latency_ms"] || target["last_agent_id"] != value["last_agent_id"] {
		s.exec("UPDATE targets SET status=?,failures=?,successes=?,last_checked_at=?,last_latency_ms=?,last_error=?,last_agent_id=? WHERE id=?", value["status"], value["failures"], value["successes"], value["last_checked_at"], value["last_latency_ms"], value["last_error"], value["last_agent_id"], target["id"])
	}
	return value
}

func (s *Store) checkerViews() []row {
	now := nowSeconds()
	views := []row{}
	for _, agent := range s.all("SELECT * FROM agents ORDER BY id") {
		status := "offline"
		if now-num(agent["last_seen"]) <= controlFreshSeconds {
			switch {
			case !routesEnabled(agent):
				status = "paused"
			case checkerHealthy(agent, now):
				status = "online"
			case socksEnabled(agent):
				status = "proxy_unhealthy"
			default:
				status = "control_unhealthy"
			}
		}
		views = append(views, row{"id": agent["id"], "version": agent["version"], "last_seen": iso(fromSeconds(num(agent["last_seen"]))), "healthy": status == "online", "status": status, "proxy": s.checkerProxyView(agent, now), "routes": row{"direct": directEnabled(agent), "socks5": socksEnabled(agent), "revision": agent["proxy_revision"], "supported": supportsRoutes(str(agent["version"]))}, "direct_healthy": directReady(agent) && now-num(agent["last_seen"]) <= controlFreshSeconds})
	}
	return views
}

// Caller holds the store mutex and a transaction.
func (a *App) pollChecker(data Poll) []row {
	s, now := a.s, nowSeconds()
	jobs := []row{}
	previous := s.one("SELECT * FROM agents WHERE id=?", data.AgentID)
	if previous != nil && !checkerHealthy(previous, now) {
		s.exec("UPDATE target_checks SET failures=0,successes=0,next_due=0,last_checked_at=NULL,last_latency_ms=NULL,last_error=NULL,outcome=NULL,route_results=NULL WHERE agent_id=?", data.AgentID)
		s.exec("UPDATE jobs SET consumed=1 WHERE agent_id=? AND consumed=0", data.AgentID)
	}
	s.exec("INSERT INTO agents (id,last_seen,healthy,version) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,healthy=excluded.healthy,version=excluded.version", data.AgentID, now, data.ControlOK, data.Version)
	if previous == nil || truth(previous["healthy"]) != data.ControlOK {
		message, level := "control connectivity unavailable; probing paused", "warning"
		if data.ControlOK {
			message, level = "control connectivity healthy", "info"
		}
		s.event(level, "system", "Agent "+data.AgentID+": "+message, nil, nil)
	}
	for _, job := range s.all("SELECT jobs.*,targets.pool_id FROM jobs JOIN targets ON targets.id=jobs.target_id WHERE consumed=0 AND expires<=?", now) {
		s.exec("UPDATE jobs SET consumed=1 WHERE id=?", job["id"])
		s.exec("UPDATE target_checks SET failures=0,successes=0,next_due=0,last_checked_at=NULL,last_latency_ms=NULL,last_error=NULL,outcome=NULL,route_results=NULL WHERE target_id=? AND agent_id=?", job["target_id"], job["agent_id"])
		s.event("warning", "check", "Agent "+str(job["agent_id"])+": probe lease expired; no failure counted", job["pool_id"], job["target_id"])
	}
	s.exec("DELETE FROM jobs WHERE consumed=1 AND expires<?", now-86400)
	defer s.refreshProbeTargets()
	current := s.one("SELECT * FROM agents WHERE id=?", data.AgentID)
	if !checkerHealthy(current, now) {
		return jobs
	}
	// Newly registered checkers and newly enrolled targets need no setup in Guard.
	s.exec("INSERT OR IGNORE INTO target_checks (target_id,agent_id) SELECT targets.id,? FROM targets JOIN pools ON pools.id=targets.pool_id WHERE manual_enabled=1 AND profile IS NOT NULL", data.AgentID)
	capacity := 4 - int(num(s.one("SELECT COUNT(*) n FROM jobs WHERE agent_id=? AND consumed=0", data.AgentID)["n"]))
	for _, target := range s.all("SELECT targets.* FROM targets JOIN pools ON pools.id=targets.pool_id JOIN target_checks c ON c.target_id=targets.id AND c.agent_id=? WHERE manual_enabled=1 AND profile IS NOT NULL AND c.next_due<=? AND (dns_action IS NULL OR dns_action!='replace_ip') AND NOT EXISTS (SELECT 1 FROM jobs WHERE target_id=targets.id AND agent_id=? AND consumed=0) ORDER BY c.next_due,targets.id", data.AgentID, now, data.AgentID) {
		if len(jobs) >= capacity {
			break
		}
		pool := a.pool(str(target["pool_id"]))
		profile := s.profile(pool)
		if len(profile.XHTTPExtra) > 0 && !supportsXHTTPExtra(data.Version) || len(profile.ALPN) > 0 && !supportsALPN(data.Version) {
			continue
		}
		id := uid()
		s.exec("INSERT INTO jobs (id,target_id,agent_id,revision,issued,expires) VALUES (?,?,?,?,?,?)", id, target["id"], data.AgentID, pool["revision"], now, now+leaseSeconds)
		s.exec("UPDATE target_checks SET next_due=? WHERE target_id=? AND agent_id=?", now+num(pool["interval_seconds"]), target["id"], data.AgentID)
		job := row{"job_id": id, "target_id": target["id"], "ip": target["ip"], "profile": profile, "timeout_seconds": 15}
		if socksEnabled(current) {
			job["proxy_url"] = s.proxyURL(current)
		}
		if supportsRoutes(data.Version) {
			job["routes"] = routeSelection(current)
		}
		jobs = append(jobs, job)
	}
	return jobs
}

func (a *App) recordProbe(target, pool, agent row, result Result, now float64) {
	s, agentID := a.s, str(agent["id"])
	check := s.one("SELECT * FROM target_checks WHERE target_id=? AND agent_id=?", target["id"], agentID)
	failures, successes := 0, 0
	if checkFresh(check, agent, num(pool["interval_seconds"]), now) {
		failures, successes = int(num(check["failures"])), int(num(check["successes"]))
	}
	reason := ""
	if result.Error != nil {
		reason = *result.Error
	}
	var outcome, errorValue any
	if !result.OK && inconclusiveErrors[reason] {
		failures, successes, errorValue = int(num(check["failures"])), int(num(check["successes"])), reason
	} else if result.OK {
		failures, successes, outcome = 0, min(successes+1, int(num(pool["recovery_threshold"]))), true
	} else {
		if !knownErrors[reason] {
			reason = "probe_failed"
		}
		failures, successes, outcome, errorValue = min(failures+1, int(num(pool["failure_threshold"]))), 0, false, reason
	}
	s.exec("INSERT INTO target_checks (target_id,agent_id,failures,successes,last_checked_at,last_latency_ms,last_error,outcome) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(target_id,agent_id) DO UPDATE SET failures=excluded.failures,successes=excluded.successes,last_checked_at=excluded.last_checked_at,last_latency_ms=excluded.last_latency_ms,last_error=excluded.last_error,outcome=excluded.outcome", target["id"], agentID, failures, successes, iso(fromSeconds(now)), result.LatencyMS, errorValue, outcome)
	if result.Routes != nil {
		raw, _ := json.Marshal(result.Routes)
		s.exec("UPDATE target_checks SET route_results=? WHERE target_id=? AND agent_id=?", string(raw), target["id"], agentID)
	} else {
		s.exec("UPDATE target_checks SET route_results=NULL WHERE target_id=? AND agent_id=?", target["id"], agentID)
	}
	summary := s.probeSnapshot().summary(target)
	target = s.cacheProbeTarget(target, summary)
	manualPending := target["dns_action"] != nil && !strings.HasPrefix(str(target["dns_action"]), "auto_")
	if truth(pool["automation_enabled"]) && !manualPending {
		if summary.Remove && (truth(target["dns_present"]) || truth(target["dns_uncertain"])) && target["status"] != "protected" {
			a.reconciler.queueLocked(str(target["id"]), "auto_remove")
		} else if summary.Restore && (!truth(target["dns_present"]) || truth(target["dns_uncertain"])) {
			a.reconciler.queueLocked(str(target["id"]), "auto_restore")
		}
	}
	message, level := "Probe failed: "+reason, "warning"
	if result.OK {
		message, level = "Probe succeeded", "info"
	} else if outcome == nil {
		message, level = "Probe inconclusive: "+reason, "error"
	}
	s.event(level, "check", "Agent "+agentID+": "+message, pool["id"], target["id"])
}
