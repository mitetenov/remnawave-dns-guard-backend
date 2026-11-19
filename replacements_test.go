package guard

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

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
