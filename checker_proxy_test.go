package guard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSOCKS5ProxyURLValidation(t *testing.T) {
	for _, value := range []string{"", "socks5://proxy.example.com:1080", "socks5h://user:p%40ss%3Aword@proxy.example.com:1080", "socks5://127.0.0.1:1080", "socks5://10.0.0.2:1080", "socks5://[::1]:1080"} {
		if !validProxyURL(value) {
			t.Errorf("valid URL rejected: %q", value)
		}
	}
	for _, value := range []string{"https://proxy.example.com:1080", "socks4://proxy.example.com:1080", "socks5://proxy.example.com", "socks5://proxy.example.com:0", "socks5://proxy.example.com:65536", "socks5://proxy.example.com:1080/", "socks5://proxy.example.com:1080?", "socks5://proxy.example.com:1080#", "socks5://proxy.example.com:1080\n", "socks5://user@proxy.example.com:1080", "socks5://:pass@proxy.example.com:1080", "socks5://user:@proxy.example.com:1080", "socks5://user:%00@proxy.example.com:1080", "socks5://" + strings.Repeat("u", 256) + ":pass@proxy.example.com:1080"} {
		if validProxyURL(value) {
			t.Errorf("unsafe URL accepted: %q", value)
		}
	}
}

func TestSOCKS5ProxyHealthGatesDNSDecisions(t *testing.T) {
	now := float64(10000)
	base := row{"id": "ru-proxy", "version": "1.4.0", "direct_enabled": false, "socks5_enabled": true, "last_seen": now, "healthy": true, "proxy_url": "encrypted", "proxy_revision": 2, "proxy_applied_revision": 2, "proxy_healthy": true, "proxy_checked_at": now}
	pool := row{"interval_seconds": 60, "failure_threshold": 3, "recovery_threshold": 2}
	checks := map[string]row{"ru-proxy": {"agent_id": "ru-proxy", "last_checked_at": iso(fromSeconds(now)), "failures": 3, "successes": 0, "outcome": false}}
	for _, test := range []struct {
		name, key string
		value     any
		ready     bool
	}{
		{"healthy", "proxy_healthy", true, true}, {"proxy failed", "proxy_healthy", false, false}, {"unapplied revision", "proxy_applied_revision", 1, false}, {"stale health", "proxy_checked_at", now - 91, false}, {"downgraded agent", "version", "1.2.0", false}, {"control failed", "healthy", false, true}, {"offline", "last_seen", now - 91, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := row{}
			for key, value := range base {
				agent[key] = value
			}
			agent[test.key] = test.value
			if checkerHealthy(agent, now) != test.ready {
				t.Fatal("incorrect readiness")
			}
			if got := summarizeProbes(pool, []row{agent}, checks, now); got.Remove != test.ready || got.Restore {
				t.Fatalf("incorrect DNS decision: %+v", got)
			}
		})
	}
}

func TestSOCKS5ProxyViewTestTimeoutAndSecretRedaction(t *testing.T) {
	for _, test := range []struct {
		age            float64
		result, status string
	}{{0, "", "pending"}, {61, "", "timeout"}, {80, "passed", "passed"}, {0, "failed", "failed"}} {
		agent := row{"proxy_url": "encrypted-password", "proxy_test_id": "test-1", "proxy_test_requested": 100 - test.age, "proxy_test_result": test.result}
		view := proxyView(agent, 100)
		if view["test"].(row)["status"] != test.status {
			t.Fatal(view)
		}
		data, _ := json.Marshal(view)
		if strings.Contains(string(data), "encrypted-password") {
			t.Fatal("proxy secret exposed")
		}
	}
	for _, version := range []string{"1.2.0", "1.3.0", "1.3", "v1.3.0", "1.03.0"} {
		if supportsSOCKS5(version) {
			t.Error(version)
		}
	}
	for _, version := range []string{"1.4.0", "1.4.1", "2.0.0"} {
		if !supportsSOCKS5(version) {
			t.Error(version)
		}
	}
}
