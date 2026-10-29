package guard

import (
	"net/http"
	"net/netip"
	"net/url"
)

func supportsProxyPreview(version string) bool { return agentVersionAtLeast(version, 5) }

func proxyTestPending(agent row, now float64) bool {
	return truth(agent["proxy_test_id"]) && !truth(agent["proxy_test_result"]) && now-num(agent["proxy_test_requested"]) <= 60
}

func proxyTestMatches(agent row, id string, now float64) bool {
	return id != "" && id == str(agent["proxy_test_id"]) && proxyTestPending(agent, now)
}

func (s *Store) proxyTestURL(agent row) string {
	if !truth(agent["proxy_test_url"]) {
		return s.proxyURL(agent)
	}
	plain, err := s.cipher.decrypt(str(agent["proxy_test_url"]))
	mustErr(err)
	return string(plain)
}

func (s *Store) pendingProxyTest(agent row) row {
	if !proxyTestPending(agent, nowSeconds()) {
		return nil
	}
	value := s.proxyTestURL(agent)
	if value == "" {
		return nil
	}
	return row{"id": agent["proxy_test_id"], "url": value}
}

// Full credentials are exposed only on authenticated agent-detail responses.
// Fleet/settings/overview responses continue to contain the endpoint alone.
func (s *Store) checkerProxyDetail(agent row, now float64) row {
	view := s.checkerProxyView(agent, now)
	view["url"] = s.proxyURL(agent)
	return view
}

func (a *App) queueProxyTest(agent row, value string, draft bool) row {
	if !proxyTestPending(agent, nowSeconds()) || a.s.proxyTestURL(agent) != value {
		a.s.exec("UPDATE agents SET proxy_test_id=?,proxy_test_requested=?,proxy_test_result=NULL,proxy_test_url=?,proxy_test_draft=?,proxy_test_latency_ms=NULL,proxy_test_exit_ip=NULL,proxy_test_checked_at=NULL WHERE id=?", uid(), nowSeconds(), a.s.cipher.encrypt([]byte(value)), draft, agent["id"])
	}
	return a.s.checkerProxyDetail(a.checker(str(agent["id"])), nowSeconds())
}

func (a *App) proxyPreviewRoute() {
	a.route("POST /api/agent/proxy-test-results", "agent", func(w http.ResponseWriter, r *http.Request) any {
		var report struct {
			AgentID   string   `json:"agent_id"`
			TestID    string   `json:"test_id"`
			OK        bool     `json:"ok"`
			LatencyMS *float64 `json:"latency_ms"`
			ExitIP    string   `json:"exit_ip"`
		}
		bodyObject(w, r, &report, []string{"agent_id", "test_id", "ok"}, "latency_ms")
		if !agentPattern.MatchString(report.AgentID) || !textLength(report.AgentID, 1, 100) || !textLength(report.TestID, 1, 100) || report.LatencyMS != nil && (*report.LatencyMS < 0 || *report.LatencyMS > 180000) {
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
			if !supportsProxyPreview(str(agent["version"])) || !proxyTestMatches(agent, report.TestID, nowSeconds()) {
				return row{"accepted": false}
			}
			status := "failed"
			if report.OK {
				status = "passed"
			}
			// A draft test never changes the active URL, revision, health, leases
			// or target evidence, even when its outcome is a failure.
			a.s.exec("UPDATE agents SET proxy_test_result=?,proxy_test_latency_ms=?,proxy_test_exit_ip=?,proxy_test_checked_at=? WHERE id=?", status, report.LatencyMS, report.ExitIP, nowSeconds(), report.AgentID)
			return row{"accepted": true}
		})
	})
}

func proxyEndpoint(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
