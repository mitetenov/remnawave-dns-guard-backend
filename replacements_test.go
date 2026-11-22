package guard

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProviderReadinessReturnsOnlyConfigurationStatus(t *testing.T) {
	a, request := panelTestApp(t)
	a.s.set("upcloud_token", "upcloud-token-fixture")
	a.s.set("virtua_token", "virtua-token-fixture")
	response := request(http.MethodGet, "/api/settings/providers")
	var result row
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		len(result) != 6 || !truth(result["upcloud_configured"]) || !truth(result["virtua_configured"]) ||
		strings.Contains(response.Body.String(), "token-fixture") {
		t.Fatalf("unexpected provider readiness response: %d %s", response.Code, response.Body)
	}
}

func TestReplacementRequiresConfirmedBlockedState(t *testing.T) {
	for _, tc := range []struct {
		name, status                                           string
		present, uncertain, enabled, automation, failure, want bool
	}{
		{"excluded", "excluded", false, false, true, true, true, true},
		{"protected final A", "protected", true, false, true, true, true, true},
		{"threshold before DNS exclusion", "suspect", true, false, true, true, true, false},
		{"new target without DNS", "excluded", false, false, true, true, false, false},
		{"stale observation", "stale", false, false, true, true, false, false},
		{"uncertain DNS", "excluded", false, true, true, true, true, false},
		{"operator disabled", "disabled", false, false, false, true, true, false},
		{"pool paused", "excluded", false, false, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := row{"status": tc.status, "dns_present": tc.present, "dns_uncertain": tc.uncertain, "manual_enabled": tc.enabled, "last_checked_at": iso(time.Now())}
			evidence := probeSummary{}
			if tc.failure {
				evidence = probeSummary{Failures: 3, Remove: true, Fresh: true}
			}
			if got := replacementBlocked(target, row{"automation_enabled": tc.automation}, evidence); got != tc.want {
				t.Fatalf("blocked=%v want %v", got, tc.want)
			}
			target["dns_action"] = "replace_ip"
			if replacementBlocked(target, row{"automation_enabled": true}, evidence) {
				t.Fatal("manual DNS intent must supersede the timer")
			}
		})
	}
}

func TestReplacementUpdatesBoundNodeAndDirectHostsOnce(t *testing.T) {
	job := row{"node_uuid": "node", "old_ip": "8.8.8.8", "new_ip": "1.1.1.1"}
	nodeIP, hostIP := job["old_ip"], job["old_ip"]
	patchCount := 0
	panel, _ := newRemnawave("https://panel.example", "secret", providerClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatal("missing auth")
		}
		if r.Method == "PATCH" {
			var update row
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil || len(update) != 2 || update["address"] != job["new_ip"] {
				t.Fatal(update, err)
			}
			switch {
			case r.URL.Path == "/api/nodes" && update["uuid"] == "node":
				nodeIP = update["address"]
			case r.URL.Path == "/api/hosts" && update["uuid"] == "direct":
				hostIP = update["address"]
			default:
				t.Fatal("mutation outside binding", update)
			}
			patchCount++
			return response(row{}, 200), nil
		}
		if r.URL.Path == "/api/hosts" {
			return response(row{"response": []row{
				{"uuid": "direct", "address": hostIP, "port": 443, "nodes": []string{"node"}},
				{"uuid": "by-name", "address": "pool.example", "port": 443, "nodes": []string{"node"}},
			}}, 200), nil
		}
		return response(row{"response": []row{{"uuid": "node", "name": "A", "address": nodeIP}}}, 200), nil
	})}))
	for _, update := range []bool{false, true, true} {
		if err := panel.checkReplacementNode(job, update); err != nil {
			t.Fatal(err)
		}
		if err := panel.replacementHosts(job, update); err != nil {
			t.Fatal(err)
		}
	}
	if patchCount != 2 {
		t.Fatalf("%d patches after retry", patchCount)
	}
}

func TestReplacementTiming(t *testing.T) {
	if replacementDue(nil, 800) || replacementDue(500, 799.99) || !replacementDue(500, 800) {
		t.Fatal("five continuous minutes are required after an observed start")
	}
	records := []row{
		{"type": "A", "content": "8.8.8.8", "ttl": 1},
		{"type": "A", "content": "1.1.1.1", "ttl": 3600},
	}
	if got := replacementRecordTTL(records, "8.8.8.8", 120); got != 300 {
		t.Fatal("automatic TTL", got)
	}
	if got := replacementRecordTTL(records, "1.1.1.1", 120); got != 3600 {
		t.Fatal("explicit TTL", got)
	}
	if got := replacementRecordTTL(records, "9.9.9.9", 120); got != 0 {
		t.Fatal("unrelated record", got)
	}
}

func TestProbeRefreshStartsResetsAndSchedulesReplacement(t *testing.T) {
	a, err := New(testConfig(filepath.Join(t.TempDir(), "guard.db")), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	s := a.s
	poolID, targetID, agentID := uid(), uid(), uid()
	now := nowSeconds()
	checked := iso(fromSeconds(now))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exec(`INSERT INTO pools(id,name,hostname,ttl,interval_seconds,failure_threshold,recovery_threshold,automation_enabled,revision,created_at)
VALUES(?, 'pool', 'pool.example', 300, 60, 1, 1, 1, 1, ?)`, poolID, checked)
	s.exec(`INSERT INTO targets(id,pool_id,name,ip,manual_enabled,status,dns_present,dns_uncertain,last_checked_at)
VALUES(?,?, 'node', '198.51.100.1', 1, 'excluded', 0, 0, ?)`, targetID, poolID, checked)
	s.exec(`INSERT INTO agents(id,last_seen,healthy,version,direct_enabled,socks5_enabled) VALUES(?,?,1,'1.0.0',1,0)`, agentID, now)
	s.exec(`INSERT INTO target_checks(target_id,agent_id,next_due,failures,successes,last_checked_at,last_error,outcome)
VALUES(?,?,0,1,0,?,'probe_failed',0)`, targetID, agentID, checked)
	s.exec(`INSERT INTO replacement_bindings(target_id,provider,server_uuid,node_uuid,enabled) VALUES(?, 'upcloud', 'server-1', 'node-1', 1)`, targetID)

	s.transaction(func() { s.refreshProbeTargets(nowSeconds()) })
	binding := s.one("SELECT blocked_since FROM replacement_bindings WHERE target_id=?", targetID)
	if binding == nil || binding["blocked_since"] == nil {
		t.Fatal("fresh blocked probe did not start the replacement timer")
	}

	s.exec("UPDATE target_checks SET last_checked_at=? WHERE target_id=?", iso(fromSeconds(now-300)), targetID)
	s.transaction(func() { s.refreshProbeTargets(nowSeconds()) })
	binding = s.one("SELECT blocked_since FROM replacement_bindings WHERE target_id=?", targetID)
	if binding == nil || binding["blocked_since"] != nil {
		t.Fatal("stale blocked evidence did not reset the replacement timer")
	}

	s.exec("UPDATE target_checks SET last_checked_at=? WHERE target_id=?", iso(fromSeconds(nowSeconds())), targetID)
	s.transaction(func() { s.refreshProbeTargets(nowSeconds()) })
	s.exec("UPDATE replacement_bindings SET blocked_since=? WHERE target_id=?", nowSeconds()-replacementDelay.Seconds()-1, targetID)
	s.transaction(func() { s.refreshProbeTargets(nowSeconds()) })
	jobs := s.all("SELECT id,stage FROM replacement_jobs WHERE target_id=?", targetID)
	if len(jobs) != 1 || jobs[0]["stage"] != "preflight" {
		t.Fatalf("due blocked target should schedule exactly one preflight job: %#v", jobs)
	}
}
