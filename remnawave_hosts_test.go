package guard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestDesiredHostDisabled(t *testing.T) {
	tests := []struct {
		name            string
		option, paused  bool
		targets         []row
		summaries       map[string]probeSummary
		disabled, known bool
	}{
		{"default keeps host enabled during outage", false, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "protected"}}, map[string]probeSummary{"last": {Remove: true}}, false, true},
		{"option disables host while preserving last IP", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "protected"}, {"id": "excluded", "manual_enabled": true}}, map[string]probeSummary{"last": {Remove: true}, "excluded": {Remove: true}}, true, true},
		{"one healthy address keeps host enabled", true, false, []row{{"id": "healthy", "manual_enabled": true, "dns_present": true}, {"id": "excluded", "manual_enabled": true}}, map[string]probeSummary{"healthy": {Restore: true}, "excluded": {Remove: true}}, false, true},
		{"last IP recovery enables host", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "protected"}}, map[string]probeSummary{"last": {Restore: true}}, false, true},
		{"wait for recovery threshold", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true}}, map[string]probeSummary{"last": {Fresh: true, Successes: 1}}, false, false},
		{"recovery must be confirmed in DNS", true, false, []row{{"id": "excluded", "manual_enabled": true}}, map[string]probeSummary{"excluded": {Restore: true}}, false, false},
		{"stale excluded evidence cannot prove total outage", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "protected"}, {"id": "stale", "manual_enabled": true}}, map[string]probeSummary{"last": {Remove: true}}, false, false},
		{"unknown probes preserve remote state", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true}}, nil, false, false},
		{"pending DNS preserves remote state", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "dns_action": "auto_remove"}}, map[string]probeSummary{"last": {Remove: true}}, false, false},
		{"confirmed recovery overrides another pending enrollment", true, false, []row{{"id": "recovered", "manual_enabled": true, "dns_present": true}, {"id": "new", "manual_enabled": true, "dns_action": "enroll", "dns_uncertain": true}}, map[string]probeSummary{"recovered": {Restore: true}}, false, true},
		{"pending enrollment before recovered target does not veto recovery", true, false, []row{{"id": "new", "manual_enabled": true, "dns_action": "enroll"}, {"id": "recovered", "manual_enabled": true, "dns_present": true}}, map[string]probeSummary{"recovered": {Restore: true}}, false, true},
		{"uncertain address cannot establish recovery itself", true, false, []row{{"id": "uncertain", "manual_enabled": true, "dns_present": true, "dns_uncertain": true}}, map[string]probeSummary{"uncertain": {Restore: true}}, false, false},
		{"uncertain DNS preserves remote state", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "dns_uncertain": true, "status": "protected"}}, map[string]probeSummary{"last": {Remove: true}}, false, false},
		{"wait until final IP protection is confirmed", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "suspect"}}, map[string]probeSummary{"last": {Remove: true}}, false, false},
		{"manual targets do not vote", true, false, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "protected"}, {"id": "manual", "manual_enabled": false}}, map[string]probeSummary{"last": {Remove: true}}, true, true},
		{"paused automation preserves remote state", true, true, []row{{"id": "last", "manual_enabled": true, "dns_present": true, "status": "protected"}}, map[string]probeSummary{"last": {Remove: true}}, false, false},
		{"paused default preserves remote state", false, true, []row{{"id": "last", "manual_enabled": true}}, nil, false, false},
		{"empty pool preserves remote state", true, false, nil, nil, false, false},
		{"all manually disabled preserves remote state", true, false, []row{{"id": "manual", "manual_enabled": false}}, nil, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := row{"automation_enabled": !test.paused, "disable_host_when_all_down": test.option}
			disabled, known := desiredHostDisabled(pool, test.targets, test.summaries)
			if disabled != test.disabled || known != test.known {
				t.Fatalf("got (%v, %v), want (%v, %v)", disabled, known, test.disabled, test.known)
			}
		})
	}
}

func TestRemnawaveHostStateExactMatchesAndRecovery(t *testing.T) {
	hosts := []row{
		{"uuid": "one", "address": "VPN.EXAMPLE.COM.", "port": 443, "isDisabled": false},
		{"uuid": "two", "address": "vpn.example.com", "port": 8443, "isDisabled": false},
		{"uuid": "other", "address": "other.example.com", "port": 443, "isDisabled": false},
		{"uuid": "child", "address": "child.vpn.example.com", "port": 443, "isDisabled": false},
		{"uuid": "ip", "address": "1.1.1.1", "port": 443, "isDisabled": false},
	}
	patches := 0
	client := providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://panel.example.com/api/hosts" || req.Header.Get("Authorization") != "Bearer hidden-token" {
			t.Fatal("unexpected URL or authorization")
		}
		if req.Method == http.MethodGet {
			return response(row{"response": row{"hosts": hosts}}, 200), nil
		}
		if req.Method != http.MethodPatch || req.Header.Get("Content-Type") != "application/json" {
			t.Fatal("unexpected mutation")
		}
		var body row
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body) != 2 {
			t.Fatal("only uuid and isDisabled may change", body, err)
		}
		found := false
		for _, host := range hosts {
			if host["uuid"] == body["uuid"] {
				if host["uuid"] != "one" && host["uuid"] != "two" {
					t.Fatal("unrelated host changed")
				}
				host["isDisabled"] = body["isDisabled"]
				found = true
			}
		}
		if !found {
			t.Fatal("unknown host")
		}
		patches++
		return response(row{"response": body}, 200), nil
	})})
	r, err := newRemnawave("https://panel.example.com/api/", "hidden-token", client)
	if err != nil {
		t.Fatal(err)
	}
	for _, disabled := range []bool{true, true, false, false} {
		if err := r.ensurePoolHosts("vpn.example.com", disabled); err != nil {
			t.Fatal(err)
		}
		for _, host := range hosts[:2] {
			if host["isDisabled"] != disabled {
				t.Fatal("state not applied", host)
			}
		}
	}
	if patches != 4 {
		t.Fatal("non-idempotent updates", patches)
	}
}

func TestRemnawaveHostUpdateErrorsAndRetry(t *testing.T) {
	for _, mode := range []string{"missing", "missing state", "invalid state", "rejected", "unconfirmed", "disappeared", "lost response"} {
		t.Run(mode, func(t *testing.T) {
			state, patches, reads := false, 0, 0
			client := providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodPatch {
					patches++
					if mode == "rejected" {
						return response("hidden-token", 403), nil
					}
					if mode == "lost response" {
						state = true
						return nil, errors.New("hidden-token")
					}
					return response(row{}, 200), nil
				}
				reads++
				host := row{"uuid": "host", "address": "vpn.example.com", "port": 443, "isDisabled": state}
				if mode == "missing state" {
					delete(host, "isDisabled")
				}
				if mode == "invalid state" {
					host["isDisabled"] = "hidden-token"
				}
				if mode == "missing" || mode == "disappeared" && reads > 1 {
					return response(row{"response": []row{}}, 200), nil
				}
				return response(row{"response": []row{host}}, 200), nil
			})})
			r, err := newRemnawave("https://panel.example.com", "hidden-token", client)
			if err != nil {
				t.Fatal(err)
			}
			err = r.ensurePoolHosts("vpn.example.com", true)
			if err == nil || strings.Contains(err.Error(), "hidden-token") {
				t.Fatal("missing or unsafe error", err)
			}
			if mode == "lost response" {
				if err := r.ensurePoolHosts("vpn.example.com", true); err != nil || patches != 1 {
					t.Fatal("retry did not adopt actual state", err, patches)
				}
			}
		})
	}
}

func TestHostOptionAlwaysPreservesFinalARecord(t *testing.T) {
	for _, option := range []bool{false, true} {
		pool := row{"zone_id": "zone", "hostname": "vpn.example.com", "disable_host_when_all_down": option}
		provider := &Cloudflare{"hidden-token", providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodGet {
				t.Fatal("final A record must never be mutated")
			}
			return response(row{"success": true, "result": []row{{"id": "last", "type": "A", "name": "vpn.example.com", "content": "1.1.1.1", "proxied": false}}}, 200), nil
		})})}
		_, err := provider.ensure(pool, "1.1.1.1", false)
		var integrationError *IntegrationError
		if !errors.As(err, &integrationError) || integrationError.Kind != "last_record" {
			t.Fatal("last record protection bypassed", option, err)
		}
	}
}
