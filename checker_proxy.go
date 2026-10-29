package guard

import (
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func supportsSOCKS5(version string) bool { return supportsRoutes(version) }

// Explicit proxy endpoints may be private (for example an SSH SOCKS tunnel).
// Only the checker connects to them; the panel never dials a submitted URL.
func validProxyURL(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 2048 {
		return false
	}
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	ip, ipErr := netip.ParseAddr(u.Hostname())
	validEndpointHost := validHost(u.Hostname())
	if ipErr == nil {
		validEndpointHost = ip.IsGlobalUnicast() || ip.IsLoopback()
	}
	if err != nil || port < 1 || port > 65535 || !oneOf(u.Scheme, "socks5", "socks5h") || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || strings.ContainsAny(value, "\r\n\t#?") || !validEndpointHost {
		return false
	}
	if u.User != nil {
		pass, ok := u.User.Password()
		if !ok || len(u.User.Username()) < 1 || len(u.User.Username()) > 255 || len(pass) < 1 || len(pass) > 255 || strings.ContainsAny(u.User.Username()+pass, "\x00\r\n") {
			return false
		}
	}
	return true
}

func (s *Store) initializeCheckerProxy() {
	existing := map[string]bool{}
	for _, c := range s.all("PRAGMA table_info(agents)") {
		existing[str(c["name"])] = true
	}
	for name, definition := range map[string]string{
		"proxy_url": "TEXT", "proxy_revision": "INTEGER NOT NULL DEFAULT 0", "proxy_applied_revision": "INTEGER NOT NULL DEFAULT 0", "proxy_healthy": "INTEGER NOT NULL DEFAULT 0", "proxy_checked_at": "REAL", "proxy_latency_ms": "REAL", "proxy_exit_ip": "TEXT", "proxy_test_id": "TEXT", "proxy_test_requested": "REAL", "proxy_test_result": "TEXT", "proxy_test_url": "TEXT", "proxy_test_draft": "INTEGER NOT NULL DEFAULT 0", "proxy_test_latency_ms": "REAL", "proxy_test_exit_ip": "TEXT", "proxy_test_checked_at": "REAL",
	} {
		if !existing[name] {
			s.exec("ALTER TABLE agents ADD COLUMN " + name + " " + definition)
		}
	}
}

func proxyReady(agent row, now float64) bool {
	return truth(agent["proxy_url"]) && supportsSOCKS5(str(agent["version"])) && num(agent["proxy_revision"]) == num(agent["proxy_applied_revision"]) && truth(agent["proxy_healthy"]) && now-num(agent["proxy_checked_at"]) <= controlFreshSeconds
}

func (s *Store) resetChecker(id string) {
	s.exec("UPDATE jobs SET consumed=1 WHERE agent_id=? AND consumed=0", id)
	s.exec("UPDATE target_checks SET failures=0,successes=0,next_due=0,last_checked_at=NULL,last_latency_ms=NULL,last_error=NULL,outcome=NULL,route_results=NULL WHERE agent_id=?", id)
}

func (s *Store) proxyURL(agent row) string {
	if !truth(agent["proxy_url"]) {
		return ""
	}
	value, err := s.cipher.decrypt(str(agent["proxy_url"]))
	mustErr(err)
	return string(value)
}

func proxyView(agent row, now float64) row {
	view := row{"configured": truth(agent["proxy_url"]), "supported": supportsSOCKS5(str(agent["version"])), "endpoint": "", "healthy": proxyReady(agent, now), "checked_at": nil, "latency_ms": agent["proxy_latency_ms"], "exit_ip": agent["proxy_exit_ip"], "test": nil, "draft_test_supported": supportsProxyPreview(str(agent["version"]))}
	if agent["proxy_checked_at"] != nil {
		view["checked_at"] = iso(fromSeconds(num(agent["proxy_checked_at"])))
	}
	if agent["proxy_test_id"] != nil {
		status := str(agent["proxy_test_result"])
		if status == "" {
			status = "pending"
			if now-num(agent["proxy_test_requested"]) > 60 {
				status = "timeout"
			}
		}
		view["test"] = row{"id": agent["proxy_test_id"], "status": status, "draft": truth(agent["proxy_test_draft"]), "endpoint": "", "latency_ms": agent["proxy_test_latency_ms"], "exit_ip": agent["proxy_test_exit_ip"], "checked_at": nil}
		if agent["proxy_test_checked_at"] != nil {
			view["test"].(row)["checked_at"] = iso(fromSeconds(num(agent["proxy_test_checked_at"])))
		}
	}
	return view
}

func (s *Store) checkerProxyView(agent row, now float64) row {
	view := proxyView(agent, now)
	if raw := s.proxyURL(agent); raw != "" {
		u, _ := url.Parse(raw)
		view["endpoint"] = u.Scheme + "://" + u.Host
	}
	if view["test"] != nil {
		view["test"].(row)["endpoint"] = proxyEndpoint(s.proxyTestURL(agent))
	}
	return view
}

func (s *Store) checkerProxyConfig(id string) row {
	agent := s.one("SELECT * FROM agents WHERE id=?", id)
	value := row{"url": s.proxyURL(agent), "revision": agent["proxy_revision"]}
	if !supportsProxyPreview(str(agent["version"])) && !truth(agent["proxy_test_draft"]) && proxyTestPending(agent, nowSeconds()) {
		value["test_id"] = agent["proxy_test_id"]
	}
	return value
}

func (a *App) checker(id string) row {
	agent := a.s.one("SELECT * FROM agents WHERE id=?", id)
	if agent == nil {
		fail(404, "Checker not found")
	}
	return agent
}

type proxyReport struct {
	Checked   *bool    `json:"checked"`
	ControlOK *bool    `json:"control_ok"`
	AgentID   string   `json:"agent_id"`
	Revision  int64    `json:"revision"`
	OK        bool     `json:"ok"`
	LatencyMS *float64 `json:"latency_ms"`
	ExitIP    string   `json:"exit_ip"`
	TestID    string   `json:"test_id"`
}

func (a *App) checkerProxyRoutes() {
	a.checkerRoutes()
	a.proxyPreviewRoute()
	a.route("PUT /api/agents/{id}/proxy", "ui", func(w http.ResponseWriter, r *http.Request) any {
		w.Header().Set("Cache-Control", "no-store")
		var input struct {
			URL string `json:"url"`
		}
		bodyObject(w, r, &input, []string{"url"})
		input.URL = strings.TrimSpace(input.URL)
		if !validProxyURL(input.URL) {
			invalid("url")
		}
		return a.withStore(func() any {
			agent := a.checker(r.PathValue("id"))
			if input.URL != "" && !supportsSOCKS5(str(agent["version"])) {
				fail(409, "Обновите чекер до версии 1.4.0 или новее")
			}
			var encrypted any
			if input.URL != "" {
				encrypted = a.s.cipher.encrypt([]byte(input.URL))
			}
			a.s.transaction(func() {
				a.s.exec("UPDATE agents SET proxy_url=?,socks5_enabled=CASE WHEN ? IS NULL THEN 0 ELSE socks5_enabled END,proxy_revision=proxy_revision+1,proxy_healthy=0,proxy_checked_at=NULL,proxy_latency_ms=NULL,proxy_exit_ip=NULL,proxy_test_id=NULL,proxy_test_requested=NULL,proxy_test_result=NULL,proxy_test_url=NULL,proxy_test_draft=0,proxy_test_latency_ms=NULL,proxy_test_exit_ip=NULL,proxy_test_checked_at=NULL WHERE id=?", encrypted, encrypted, agent["id"])
				a.s.resetChecker(str(agent["id"]))
				a.s.refreshProbeTargets()
				a.s.event("info", "system", "Checker "+str(agent["id"])+": proxy settings updated", nil, nil)
			})
			return a.s.checkerProxyDetail(a.checker(str(agent["id"])), nowSeconds())
		})
	})
	a.route("POST /api/agents/{id}/proxy/test", "ui", func(w http.ResponseWriter, r *http.Request) any {
		w.Header().Set("Cache-Control", "no-store")
		var input struct {
			URL *string `json:"url"`
		}
		if r.ContentLength != 0 {
			bodyObject(w, r, &input, nil)
		}
		if input.URL != nil && (*input.URL == "" || !validProxyURL(*input.URL)) {
			invalid("url")
		}
		return a.withStore(func() any {
			agent := a.checker(r.PathValue("id"))
			value := a.s.proxyURL(agent)
			if input.URL != nil {
				value = *input.URL
			}
			if value == "" {
				fail(409, "Введите SOCKS5-прокси для проверки")
			}
			if !supportsSOCKS5(str(agent["version"])) {
				fail(409, "Обновите агент до версии 1.4.0 или новее")
			}
			draft := value != a.s.proxyURL(agent)
			if draft && !supportsProxyPreview(str(agent["version"])) {
				fail(409, "Для проверки до сохранения обновите агент до версии 1.5.0 или новее")
			}
			if nowSeconds()-num(agent["last_seen"]) > controlFreshSeconds {
				fail(409, "Агент не на связи")
			}
			return a.queueProxyTest(agent, value, draft)
		})
	})

	a.route("POST /api/agent/proxy-status", "agent", func(w http.ResponseWriter, r *http.Request) any {
		var report proxyReport
		bodyObject(w, r, &report, []string{"agent_id", "revision", "ok"}, "latency_ms")
		if !agentPattern.MatchString(report.AgentID) || !textLength(report.AgentID, 1, 100) || report.Revision < 0 || !textLength(report.TestID, 0, 100) || report.LatencyMS != nil && (*report.LatencyMS < 0 || *report.LatencyMS > 180000) {
			invalid("request")
		}
		if report.ExitIP != "" {
			ip, err := netip.ParseAddr(report.ExitIP)
			if err != nil || !ip.IsGlobalUnicast() {
				invalid("exit_ip")
			}
		}
		return a.withStore(func() any {
			agent := a.checker(report.AgentID)
			if num(agent["proxy_revision"]) != float64(report.Revision) || !supportsSOCKS5(str(agent["version"])) {
				return row{"accepted": false}
			}
			a.s.transaction(func() {
				if report.Checked == nil || *report.Checked {
					a.s.exec("UPDATE agents SET proxy_applied_revision=?,proxy_healthy=?,proxy_checked_at=?,proxy_latency_ms=?,proxy_exit_ip=? WHERE id=?", report.Revision, report.OK, nowSeconds(), report.LatencyMS, report.ExitIP, report.AgentID)
					if !supportsProxyPreview(str(agent["version"])) && !truth(agent["proxy_test_draft"]) && proxyTestMatches(agent, report.TestID, nowSeconds()) {
						status := "failed"
						if report.OK {
							status = "passed"
						}
						a.s.exec("UPDATE agents SET proxy_test_result=?,proxy_test_latency_ms=?,proxy_test_exit_ip=?,proxy_test_checked_at=? WHERE id=?", status, report.LatencyMS, report.ExitIP, nowSeconds(), report.AgentID)
					}
				}
				if report.ControlOK != nil {
					a.s.exec("UPDATE agents SET healthy=? WHERE id=?", *report.ControlOK, report.AgentID)
				}
				a.s.refreshProbeTargets()
			})
			return row{"accepted": true}
		})
	})
}
