package guard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

var inconclusiveErrors = map[string]bool{"xray_start_failed": true, "xray_config_invalid": true, "invalid_job": true, "control_unhealthy": true, "control_unreachable": true, "proxy_unavailable": true, "no_valid_routes": true}
var knownErrors = map[string]bool{"probe_failed": true, "probe_timeout": true, "xray_start_failed": true, "xray_config_invalid": true, "control_unhealthy": true, "invalid_job": true, "proxy_unavailable": true, "http_error": true, "tls_error": true, "connection_failed": true, "timeout": true, "target_unreachable": true, "tunnel_unreachable": true}

// Older agents use a strict profile decoder and cannot consume new fields.
func agentVersionAtLeast(version string, minor int) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	numbers := [3]int{}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || strconv.Itoa(n) != part {
			return false
		}
		numbers[i] = n
	}
	return numbers[0] > 1 || numbers[0] == 1 && numbers[1] >= minor
}

func supportsXHTTPExtra(version string) bool { return agentVersionAtLeast(version, 1) }
func supportsALPN(version string) bool       { return agentVersionAtLeast(version, 2) }

func (a *App) agentRoutes() {
	a.checkerProxyRoutes()
	a.route("GET /api/agents", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any { return a.s.checkerViews() })
	})
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
				jobs = a.pollChecker(data)
			})
			response := row{"jobs": jobs, "poll_after_seconds": 10}
			if supportsSOCKS5(data.Version) {
				response["proxy"] = a.s.checkerProxyConfig(data.AgentID)
				response["routes"] = routeSelection(a.checker(data.AgentID))
				if supportsProxyPreview(data.Version) {
					if test := a.s.pendingProxyTest(a.checker(data.AgentID)); test != nil {
						response["proxy_test"] = test
					}
				}
			}
			return response
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
				if !oneOf(key, "job_id", "ok", "latency_ms", "error", "routes") || oneOf(key, "job_id", "ok") && string(value) == "null" {
					invalid("results")
				}
			}
			if _, ok := raw["job_id"]; !ok {
				invalid("results")
			}
			if _, ok := raw["ok"]; !ok {
				invalid("results")
			}
			if rawRoutes, ok := raw["routes"]; ok {
				validateRouteResults(rawRoutes)
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
				if agent == nil || now-num(agent["last_seen"]) > controlFreshSeconds || !routesEnabled(agent) {
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
					if supportsRoutes(str(agent["version"])) {
						if result.Routes == nil || (result.Routes.Direct != nil) != directEnabled(agent) || (result.Routes.SOCKS5 != nil) != socksEnabled(agent) {
							continue
						}
						result = aggregateRoutes(result.JobID, normalizeRoutes(agent, result.Routes, now))
					} else if !checkerHealthy(agent, now) {
						continue
					}
					s.exec("UPDATE jobs SET consumed=1 WHERE id=?", j["id"])
					accepted++
					a.recordProbe(t, p, agent, result, now)
				}
			})
			return row{"accepted": accepted}
		})
	})
}
