package guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"
)

func panelTestApp(t *testing.T) (*App, func(method, path string) *httptest.ResponseRecorder) {
	t.Helper()
	a, err := New(testConfig(":memory:"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	a.s.exec("INSERT INTO sessions VALUES (?,?,?)", digest("test-session"), "admin", nowSeconds()+3600)
	return a, func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-Requested-With", "DNSGuard")
		req.AddCookie(&http.Cookie{Name: "dns_guard_session", Value: "test-session"})
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, req)
		return w
	}
}

func TestEventCursorOrdersTiesAndFiltersDeletedTarget(t *testing.T) {
	a, request := panelTestApp(t)
	const stamp = "2026-11-22T00:00:00.000000Z"
	for _, event := range []struct{ id, stamp, level, pool, target string }{
		{"older", "2026-11-21T00:00:00.000000Z", "warning", "pool", "deleted"},
		{"c", stamp, "warning", "pool", "deleted"},
		{"b", stamp, "warning", "pool", "deleted"},
		{"a", stamp, "warning", "pool", "deleted"},
		{"other", stamp, "warning", "pool", "other"},
		{"wrong-level", stamp, "info", "pool", "deleted"},
		{"wrong-pool", stamp, "warning", "other", "deleted"},
	} {
		a.s.exec("INSERT INTO events VALUES (?,?,?,'dns','test',?,?)", event.id, event.stamp, event.level, event.pool, event.target)
	}

	const query = "/api/events?limit=2&pool_id=pool&target_id=deleted&level=warning"
	legacy := request("GET", query)
	var legacyEvents []row
	if legacy.Code != 200 || json.Unmarshal(legacy.Body.Bytes(), &legacyEvents) != nil || len(legacyEvents) != 2 {
		t.Fatalf("legacy events response: %d %s", legacy.Code, legacy.Body)
	}
	eventPage := func(path string) ([]string, *string) {
		t.Helper()
		w := request("GET", path)
		var result struct {
			Events []row
			Next   *string `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("paginated events response: %d %s", w.Code, w.Body)
		}
		ids := make([]string, 0, len(result.Events))
		for _, event := range result.Events {
			ids = append(ids, str(event["id"]))
		}
		return ids, result.Next
	}
	first, next := eventPage(query + "&paginated=1")
	if !slices.Equal(first, []string{"c", "b"}) || next == nil {
		t.Fatalf("first page %v, next cursor %v", first, next)
	}
	second, next := eventPage(query + "&paginated=1&cursor=" + url.QueryEscape(*next))
	if !slices.Equal(second, []string{"a", "older"}) || next != nil {
		t.Fatalf("second page %v, next cursor %v", second, next)
	}
	if w := request("GET", query+"&paginated=1&cursor=invalid"); w.Code != 422 {
		t.Fatalf("invalid cursor response: %d %s", w.Code, w.Body)
	}
}

func TestManualCheckReportsEligibleAgentsAndTargets(t *testing.T) {
	a, request := panelTestApp(t)
	s := a.s
	s.exec("INSERT INTO pools (id,profile) VALUES ('p',?)", s.encrypt(Profile{Protocol: "hysteria2"}))
	s.exec("INSERT INTO targets (id,pool_id,ip,manual_enabled,dns_action) VALUES ('ready','p','8.8.8.8',1,NULL),('disabled','p','8.8.4.4',0,NULL),('replacing','p','1.1.1.1',1,'replace_ip')")
	now := nowSeconds()
	s.exec("INSERT INTO agents (id,last_seen,healthy,version) VALUES ('ready',?,1,'1.7.0'),('unsupported',?,1,'1.5.0'),('offline',?,1,'1.7.0')", now, now, now-1000)
	s.exec("INSERT INTO target_checks (target_id,agent_id,next_due) VALUES ('ready','ready',?)", now+3600)

	w := request("POST", "/api/pools/p/check")
	var result struct {
		OK             bool
		StartedAt      time.Time `json:"started_at"`
		ExpectedAgents []string  `json:"expected_agents"`
		TargetIDs      []string  `json:"target_ids"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.OK || result.StartedAt.IsZero() ||
		!slices.Equal(result.ExpectedAgents, []string{"ready"}) || !slices.Equal(result.TargetIDs, []string{"ready"}) {
		t.Fatalf("manual check response: %d %s", w.Code, w.Body)
	}
	if got := num(s.one("SELECT next_due FROM target_checks WHERE target_id='ready' AND agent_id='ready'")["next_due"]); got != 0 {
		t.Fatalf("target was not scheduled: next_due=%v", got)
	}

	w = request("GET", "/api/header")
	var header row
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &header) != nil || len(header) != 4 ||
		num(header["pools"]) != 1 || num(header["agents_total"]) != 3 || num(header["agents_healthy"]) != 2 || !truth(header["agent_healthy"]) {
		t.Fatalf("header response: %d %s", w.Code, w.Body)
	}

	s.exec("UPDATE agents SET last_seen=0")
	w = request("POST", "/api/pools/p/check")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.ExpectedAgents == nil || len(result.ExpectedAgents) != 0 {
		t.Fatalf("manual check without healthy agent: %d %s", w.Code, w.Body)
	}
}

func TestPoolSummariesUseEffectiveProbeStatus(t *testing.T) {
	a, request := panelTestApp(t)
	s := a.s
	s.exec("INSERT INTO pools (id,interval_seconds,failure_threshold,recovery_threshold) VALUES ('p',60,3,5),('empty',60,3,5)")
	s.exec(`INSERT INTO targets (id,pool_id,name,ip,status,dns_present,dns_action)
 VALUES ('healthy','p','Healthy','8.8.8.8','unknown',1,NULL),
        ('protected','p','Protected','8.8.4.4','protected',1,NULL),
        ('stale','p','Stale','1.1.1.1','healthy',1,NULL),
        ('excluded','p','Excluded','1.0.0.1','unknown',0,NULL),
        ('pending','p','Pending','9.9.9.9','unknown',1,'enable')`)
	now := time.Now()
	s.exec("INSERT INTO agents (id,last_seen,healthy,version) VALUES ('a',?,1,'1.7.0')", nowSeconds())
	s.exec(`INSERT INTO target_checks (target_id,agent_id,failures,successes,last_checked_at,outcome,route_results)
 VALUES ('healthy','a',0,5,?,1,'{"direct":{"outcome":"success"}}'),
        ('protected','a',3,0,?,0,'{"direct":{"outcome":"failure","error":"timeout"}}'),
        ('stale','a',0,5,?,1,NULL)`, iso(now), iso(now), iso(now.Add(-time.Hour)))

	w := request("GET", "/api/overview")
	var overview row
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &overview) != nil || num(overview["pools"]) != 2 ||
		num(overview["targets"]) != 5 || num(overview["healthy"]) != 1 || num(overview["stale"]) != 1 ||
		num(overview["excluded"]) != 1 {
		t.Fatalf("overview response: %d %s", w.Code, w.Body)
	}
	w = request("GET", "/api/pools")
	var pools []struct {
		ID      string
		Summary poolTargetSummary `json:"target_summary"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pools) != nil || len(pools) != 2 {
		t.Fatalf("pool list response: %d %s", w.Code, w.Body)
	}
	for _, pool := range pools {
		want := poolTargetSummary{Status: "unknown"}
		if pool.ID == "p" {
			want = poolTargetSummary{Active: 3, Total: 5, Status: "suspect"}
		}
		if pool.Summary != want {
			t.Fatalf("pool %q summary %+v, want %+v", pool.ID, pool.Summary, want)
		}
	}
	w = request("GET", "/api/pools/p/targets")
	var targets []struct {
		ID         string
		Status     string
		LastStatus string `json:"last_status"`
		Checks     []row
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &targets) != nil || len(targets) != 5 ||
		targets[0].ID != "excluded" || targets[1].ID != "healthy" || len(targets[1].Checks) != 1 || targets[1].Checks[0]["routes"] == nil ||
		targets[3].Status != "protected" || targets[4].Status != "stale" || targets[4].LastStatus != "healthy" {
		t.Fatalf("target list response: %d %s", w.Code, w.Body)
	}
}
