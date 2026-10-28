package guard

import (
	"encoding/json"
	"net/http"
)

func supportsRoutes(version string) bool { return agentVersionAtLeast(version, 4) }
func directEnabled(agent row) bool {
	value, exists := agent["direct_enabled"]
	return !exists || truth(value)
}
func socksEnabled(agent row) bool            { return truth(agent["socks5_enabled"]) }
func routesEnabled(agent row) bool           { return directEnabled(agent) || socksEnabled(agent) }
func directReady(agent row) bool             { return directEnabled(agent) && truth(agent["healthy"]) }
func socksReady(agent row, now float64) bool { return socksEnabled(agent) && proxyReady(agent, now) }

type RouteSelection struct {
	Direct   bool  `json:"direct"`
	SOCKS5   bool  `json:"socks5"`
	Revision int64 `json:"revision"`
}
type RouteResult struct {
	Outcome   string   `json:"outcome"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
	Error     string   `json:"error,omitempty"`
}
type RouteResults struct {
	Direct *RouteResult `json:"direct,omitempty"`
	SOCKS5 *RouteResult `json:"socks5,omitempty"`
}

func validateRouteResults(raw json.RawMessage) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		invalid("routes")
	}
	for name, value := range object {
		if !oneOf(name, "direct", "socks5") {
			invalid("routes")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil || fields == nil || fields["outcome"] == nil {
			invalid("routes")
		}
		for key, v := range fields {
			if !oneOf(key, "outcome", "latency_ms", "error") || string(v) == "null" {
				invalid("routes")
			}
		}
		var result RouteResult
		if json.Unmarshal(value, &result) != nil || !validRouteResult(&result) {
			invalid("routes")
		}
	}
}

func routeSelection(agent row) RouteSelection {
	return RouteSelection{directEnabled(agent), socksEnabled(agent), int64(num(agent["proxy_revision"]))}
}

func validRouteResult(value *RouteResult) bool {
	if value == nil {
		return true
	}
	if value.LatencyMS != nil && (*value.LatencyMS < 0 || *value.LatencyMS > 180000) {
		return false
	}
	switch value.Outcome {
	case "success":
		return value.Error == ""
	case "failure":
		return knownErrors[value.Error] && !inconclusiveErrors[value.Error]
	case "skipped":
		return inconclusiveErrors[value.Error]
	}
	return false
}

// Aggregate at the server, so a skipped proxy cannot erase a valid direct
// failure and a successful route cannot hide the other route's failure.
func aggregateRoutes(id string, routes *RouteResults) Result {
	result := Result{JobID: id, Routes: routes}
	for _, value := range []*RouteResult{routes.Direct, routes.SOCKS5} {
		if value == nil || value.Outcome == "skipped" {
			continue
		}
		if value.Outcome == "failure" {
			reason := value.Error
			result.OK = false
			result.Error = &reason
			result.LatencyMS = nil
			return result
		}
		result.OK = true
		if value.LatencyMS != nil && (result.LatencyMS == nil || *value.LatencyMS > *result.LatencyMS) {
			result.LatencyMS = value.LatencyMS
		}
	}
	if !result.OK {
		reason := "no_valid_routes"
		result.Error = &reason
	}
	return result
}

func normalizeRoutes(agent row, routes *RouteResults, now float64) *RouteResults {
	value := *routes
	if value.Direct != nil && !directReady(agent) {
		value.Direct = &RouteResult{Outcome: "skipped", Error: "control_unhealthy"}
	}
	if value.SOCKS5 != nil && !socksReady(agent, now) {
		value.SOCKS5 = &RouteResult{Outcome: "skipped", Error: "proxy_unavailable"}
	}
	return &value
}

// Evidence remains usable only when the routes that produced its outcome
// are still available. A proxy outage does not invalidate direct evidence.
func routeEvidenceFresh(check, agent row, now float64) bool {
	if !truth(check["route_results"]) {
		return true
	}
	var routes RouteResults
	if json.Unmarshal([]byte(str(check["route_results"])), &routes) != nil {
		return false
	}
	aggregate := aggregateRoutes("", normalizeRoutes(agent, &routes, now))
	if truth(check["outcome"]) {
		if directReady(agent) && (routes.Direct == nil || routes.Direct.Outcome != "success") {
			return false
		}
		if socksReady(agent, now) && (routes.SOCKS5 == nil || routes.SOCKS5.Outcome != "success") {
			return false
		}
	}
	return aggregate.Error == nil && aggregate.OK && truth(check["outcome"]) || aggregate.Error != nil && !inconclusiveErrors[*aggregate.Error] && !truth(check["outcome"])
}

func (s *Store) initializeCheckerRoutes() {
	agents := map[string]bool{}
	for _, column := range s.all("PRAGMA table_info(agents)") {
		agents[str(column["name"])] = true
	}
	if !agents["direct_enabled"] {
		s.exec("ALTER TABLE agents ADD COLUMN direct_enabled INTEGER NOT NULL DEFAULT 1")
		s.exec("ALTER TABLE agents ADD COLUMN socks5_enabled INTEGER NOT NULL DEFAULT 0")
		// Preserve the previous prototype's explicitly configured proxy route.
		s.exec("UPDATE agents SET direct_enabled=0,socks5_enabled=1 WHERE proxy_url IS NOT NULL")
	}
	columns := map[string]bool{}
	for _, column := range s.all("PRAGMA table_info(target_checks)") {
		columns[str(column["name"])] = true
	}
	if !columns["route_results"] {
		s.exec("ALTER TABLE target_checks ADD COLUMN route_results TEXT")
	}
}

func (a *App) checkerView(id string) row {
	for _, value := range a.s.checkerViews() {
		if value["id"] == id {
			return value
		}
	}
	fail(404, "Checker not found")
	return nil
}

func (a *App) checkerRoutes() {
	a.route("GET /api/agents/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any { return a.checkerView(r.PathValue("id")) })
	})
	a.route("PATCH /api/agents/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var input struct {
			Direct *bool `json:"direct_enabled"`
			SOCKS5 *bool `json:"socks5_enabled"`
		}
		fields := bodyObject(w, r, &input, nil)
		if len(fields) == 0 {
			invalid("request")
		}
		return a.withStore(func() any {
			agent := a.checker(r.PathValue("id"))
			direct, socks := directEnabled(agent), socksEnabled(agent)
			if input.Direct != nil {
				direct = *input.Direct
			}
			if input.SOCKS5 != nil {
				socks = *input.SOCKS5
			}
			if socks && !supportsRoutes(str(agent["version"])) {
				fail(409, "Обновите агент до версии 1.4.0 или новее")
			}
			if socks && !truth(agent["proxy_url"]) {
				fail(409, "Сначала сохраните SOCKS5-прокси")
			}
			if direct != directEnabled(agent) || socks != socksEnabled(agent) {
				a.s.transaction(func() {
					a.s.exec("UPDATE agents SET direct_enabled=?,socks5_enabled=?,proxy_revision=proxy_revision+1,proxy_applied_revision=0,proxy_healthy=0,proxy_test_id=NULL,proxy_test_requested=NULL,proxy_test_result=NULL WHERE id=?", direct, socks, agent["id"])
					a.s.resetChecker(str(agent["id"]))
					a.s.refreshProbeTargets()
					a.s.event("info", "system", "Agent "+str(agent["id"])+": probe routes updated", nil, nil)
				})
			}
			return a.checkerView(str(agent["id"]))
		})
	})
}
