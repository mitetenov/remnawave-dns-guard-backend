package guard

import (
	"encoding/json"
	"testing"
)

func TestRouteAggregationMatrix(t *testing.T) {
	ok := &RouteResult{Outcome: "success"}
	failed := &RouteResult{Outcome: "failure", Error: "tunnel_unreachable"}
	skipped := &RouteResult{Outcome: "skipped", Error: "proxy_unavailable"}
	for _, test := range []struct {
		name                  string
		direct, socks         *RouteResult
		success, inconclusive bool
	}{
		{"both succeed", ok, ok, true, false}, {"direct failure wins", failed, ok, false, false}, {"SOCKS VLESS failure wins", ok, failed, false, false}, {"broken proxy preserves direct failure", failed, skipped, false, false}, {"broken proxy preserves direct success", ok, skipped, true, false}, {"proxy only broken", nil, skipped, false, true}, {"direct only", ok, nil, true, false}, {"proxy only", nil, ok, true, false}, {"all skipped", skipped, skipped, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := aggregateRoutes("job", &RouteResults{test.direct, test.socks})
			unknown := result.Error != nil && inconclusiveErrors[*result.Error]
			if result.OK != test.success || unknown != test.inconclusive {
				t.Fatalf("unexpected aggregate: %+v", result)
			}
		})
	}
}

func TestRouteReadinessAndEvidenceIsolation(t *testing.T) {
	now := float64(10000)
	agent := row{"id": "agent", "version": "1.4.0", "healthy": true, "last_seen": now, "direct_enabled": true, "socks5_enabled": true, "proxy_url": "encrypted", "proxy_revision": 1, "proxy_applied_revision": 1, "proxy_healthy": false, "proxy_checked_at": now}
	if !checkerHealthy(agent, now) {
		t.Fatal("broken proxy disabled a healthy direct route")
	}
	failed := &RouteResult{Outcome: "failure", Error: "tunnel_unreachable"}
	ok := &RouteResult{Outcome: "success"}
	for _, test := range []struct {
		direct, socks  *RouteResult
		outcome, fresh bool
	}{
		{failed, ok, false, true}, {ok, failed, false, false}, {ok, ok, true, true}, {nil, ok, true, false},
	} {
		raw, _ := json.Marshal(RouteResults{test.direct, test.socks})
		check := row{"outcome": test.outcome, "last_checked_at": iso(fromSeconds(now)), "route_results": string(raw)}
		if checkFresh(check, agent, 60, now) != test.fresh {
			t.Fatalf("proxy outage changed direct evidence: %+v", test)
		}
	}
	agent["direct_enabled"] = false
	if checkerHealthy(agent, now) {
		t.Fatal("no healthy routes should vote")
	}
	agent["proxy_healthy"] = true
	agent["healthy"] = false
	if !checkerHealthy(agent, now) {
		t.Fatal("direct control outage disabled a healthy SOCKS route")
	}
	raw, _ := json.Marshal(RouteResults{Direct: &RouteResult{Outcome: "success"}, SOCKS5: &RouteResult{Outcome: "skipped", Error: "proxy_unavailable"}})
	if routeEvidenceFresh(row{"outcome": true, "route_results": string(raw)}, agent, now) {
		t.Fatal("proxy recovery reused a skipped VLESS result")
	}
	agent["socks5_enabled"] = false
	if checkerHealthy(agent, now) {
		t.Fatal("paused agent still votes")
	}
}

func TestRouteResultValidation(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"other":{}}`, `{"direct":null}`, `{"direct":{"outcome":"invalid"}}`, `{"direct":{"outcome":"success","error":"secret"}}`, `{"direct":{"outcome":"failure","error":"proxy_unavailable"}}`, `{"direct":{"outcome":"skipped","error":"tunnel_unreachable"}}`, `{"direct":{"outcome":"success","latency_ms":-1}}`, `{"direct":{"outcome":"success","secret":"password"}}`} {
		t.Run(raw, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid routes accepted")
				}
			}()
			validateRouteResults(json.RawMessage(raw))
		})
	}
	for _, raw := range []string{`{"direct":{"outcome":"success"}}`, `{"socks5":{"outcome":"skipped","error":"proxy_unavailable"}}`, `{"direct":{"outcome":"failure","error":"tunnel_unreachable"},"socks5":{"outcome":"success","latency_ms":23.1}}`} {
		validateRouteResults(json.RawMessage(raw))
	}
}
