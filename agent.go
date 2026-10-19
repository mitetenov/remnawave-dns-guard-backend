package guard

import (
	"encoding/json"
	"net/http"
	"strings"
)

var inconclusiveErrors = map[string]bool{"xray_start_failed": true, "xray_config_invalid": true, "invalid_job": true, "control_unhealthy": true, "control_unreachable": true, "proxy_unavailable": true}
var knownErrors = map[string]bool{"probe_failed": true, "probe_timeout": true, "xray_start_failed": true, "xray_config_invalid": true, "control_unhealthy": true, "invalid_job": true, "proxy_unavailable": true, "http_error": true, "tls_error": true, "connection_failed": true, "timeout": true, "target_unreachable": true, "tunnel_unreachable": true}

func (a *App) agentRoutes() {
	a.route("POST /api/agent/poll", "agent", func(w http.ResponseWriter, r *http.Request) any {
		data := Poll{}
		bodyObject(w, r, &data, []string{"agent_id", "version", "control_ok"}, "control_error")
		if !textLength(data.AgentID, 1, 100) || !agentPattern.MatchString(data.AgentID) {
			invalid("agent_id")
		}
		if !textLength(data.Version, 0, 100) {
			invalid("version")
		}
		if data.ControlError != nil && !textLength(*data.ControlError, 0, 1000) {
			invalid("control_error")
		}
		return a.withStore(func() any {
			jobs := []row{}
			a.s.transaction(func() {
				s := a.s
				now := nowSeconds()
				previous := s.one("SELECT * FROM agents WHERE id=?", data.AgentID)
				if previous != nil && now-num(previous["last_seen"]) > controlFreshSeconds {
					s.exec("UPDATE targets SET failures=0,successes=0,next_due=0 WHERE last_agent_id=?", data.AgentID)
				}
				s.exec("INSERT INTO agents VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,healthy=excluded.healthy", data.AgentID, now, data.ControlOK)
				if previous == nil || truth(previous["healthy"]) != data.ControlOK {
					message, level := "Agent control connectivity unavailable; probing paused", "warning"
					if data.ControlOK {
						message, level = "Agent control connectivity healthy", "info"
					}
					s.event(level, "system", message, nil, nil)
				}
				for _, j := range s.all("SELECT jobs.*,targets.pool_id FROM jobs JOIN targets ON targets.id=jobs.target_id WHERE consumed=0 AND expires<=?", now) {
					s.exec("UPDATE jobs SET consumed=1 WHERE id=?", j["id"])
					s.exec("UPDATE targets SET status=CASE WHEN manual_enabled=0 THEN 'disabled' WHEN dns_present=0 THEN 'excluded' ELSE 'unknown' END,failures=0,successes=0,next_due=0 WHERE id=?", j["target_id"])
					s.event("warning", "check", "Probe lease expired; target health unknown, no failure counted", j["pool_id"], j["target_id"])
				}
				s.exec("DELETE FROM jobs WHERE consumed=1 AND expires<?", now-86400)
				if !data.ControlOK {
					s.exec("UPDATE targets SET failures=0,successes=0,next_due=0 WHERE last_agent_id=? OR id IN (SELECT target_id FROM jobs WHERE agent_id=? AND consumed=0)", data.AgentID, data.AgentID)
					s.exec("UPDATE jobs SET consumed=1 WHERE agent_id=? AND consumed=0", data.AgentID)
					return
				}
				for _, t := range s.all("SELECT targets.* FROM targets JOIN pools ON pools.id=targets.pool_id WHERE manual_enabled=1 AND profile IS NOT NULL AND next_due<=? AND NOT EXISTS (SELECT 1 FROM jobs WHERE target_id=targets.id AND consumed=0) ORDER BY next_due,targets.id LIMIT 4", now) {
					p := a.pool(str(t["pool_id"]))
					jid := uid()
					s.exec("INSERT INTO jobs (id,target_id,agent_id,revision,issued,expires) VALUES (?,?,?,?,?,?)", jid, t["id"], data.AgentID, p["revision"], now, now+leaseSeconds)
					s.exec("UPDATE targets SET next_due=? WHERE id=?", now+num(p["interval_seconds"]), t["id"])
					jobs = append(jobs, row{"job_id": jid, "target_id": t["id"], "ip": t["ip"], "profile": s.profile(p), "timeout_seconds": 15})
				}
			})
			return row{"jobs": jobs, "poll_after_seconds": 10}
		})
	})
	a.route("POST /api/agent/results", "agent", func(w http.ResponseWriter, r *http.Request) any {
		data := Results{}
		fields := bodyObject(w, r, &data, []string{"agent_id", "results"})
		if !textLength(data.AgentID, 1, 100) {
			invalid("agent_id")
		}
		if len(data.Results) > 4 {
			invalid("results")
		}
		var rawResults []map[string]json.RawMessage
		if e := json.Unmarshal(fields["results"], &rawResults); e != nil {
			invalid("results")
		}
		for i, raw := range rawResults {
			if raw == nil {
				invalid("results")
			}
			for key, value := range raw {
				if !oneOf(key, "job_id", "ok", "latency_ms", "error") || oneOf(key, "job_id", "ok") && string(value) == "null" {
					invalid("results")
				}
			}
			if _, ok := raw["job_id"]; !ok {
				invalid("results")
			}
			if _, ok := raw["ok"]; !ok {
				invalid("results")
			}
			v := data.Results[i]
			if !textLength(v.JobID, 0, 100) || v.Error != nil && !textLength(*v.Error, 0, 1000) || v.LatencyMS != nil && (*v.LatencyMS < 0 || *v.LatencyMS > 180000) {
				invalid("results")
			}
		}
		return a.withStore(func() any {
			accepted := 0
			a.s.transaction(func() {
				s := a.s
				now := nowSeconds()
				agent := s.one("SELECT * FROM agents WHERE id=?", data.AgentID)
				if agent == nil || !truth(agent["healthy"]) || now-num(agent["last_seen"]) > controlFreshSeconds {
					return
				}
				for _, result := range data.Results {
					j := s.one("SELECT * FROM jobs WHERE id=? AND consumed=0 AND agent_id=? AND expires>?", result.JobID, data.AgentID, now)
					if j == nil {
						continue
					}
					t := a.target(str(j["target_id"]))
					p := a.pool(str(t["pool_id"]))
					if num(p["revision"]) != num(j["revision"]) || !truth(t["manual_enabled"]) {
						continue
					}
					s.exec("UPDATE jobs SET consumed=1 WHERE id=?", j["id"])
					accepted++
					reason := ""
					if result.Error != nil {
						reason = *result.Error
					}
					if !result.OK && inconclusiveErrors[reason] {
						status := "excluded"
						if truth(t["dns_present"]) {
							status = "unknown"
						}
						s.exec("UPDATE targets SET failures=0,successes=0,status=?,last_checked_at=?,last_latency_ms=NULL,last_error=?,last_agent_id=? WHERE id=?", status, iso(fromSeconds(now)), reason, data.AgentID, t["id"])
						s.event("error", "check", "Probe inconclusive: "+reason, p["id"], t["id"])
						continue
					}
					failures, successes := 0, int(num(t["successes"]))+1
					var errorValue any
					status := "recovering"
					if result.OK {
						if truth(t["dns_present"]) && !truth(t["dns_uncertain"]) {
							status = "healthy"
						}
					} else {
						failures, successes = int(num(t["failures"]))+1, 0
						if !knownErrors[reason] {
							reason = "probe_failed"
						}
						errorValue = reason
						status = "excluded"
						if truth(t["dns_present"]) {
							status = "suspect"
						}
						if t["status"] == "protected" {
							status = "protected"
						}
					}
					s.exec("UPDATE targets SET failures=?,successes=?,last_checked_at=?,last_latency_ms=?,last_error=?,status=?,last_agent_id=? WHERE id=?", failures, successes, iso(fromSeconds(now)), result.LatencyMS, errorValue, status, data.AgentID, t["id"])
					manualPending := t["dns_action"] != nil && !strings.HasPrefix(str(t["dns_action"]), "auto_")
					if truth(p["automation_enabled"]) && !manualPending {
						if !result.OK && float64(failures) >= num(p["failure_threshold"]) && (truth(t["dns_present"]) || truth(t["dns_uncertain"])) && status != "protected" {
							a.reconciler.queueLocked(str(t["id"]), "auto_remove")
						} else if result.OK && (!truth(t["dns_present"]) || truth(t["dns_uncertain"])) && float64(successes) >= num(p["recovery_threshold"]) {
							a.reconciler.queueLocked(str(t["id"]), "auto_restore")
						}
					}
					message, level := "Probe failed: "+reason, "warning"
					if result.OK {
						message, level = "Probe succeeded", "info"
					}
					s.event(level, "check", message, p["id"], t["id"])
				}
			})
			return row{"accepted": accepted}
		})
	})
}
