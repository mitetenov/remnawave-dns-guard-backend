package guard

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestALPNSaveRestartLeaseAndCompatibility(t *testing.T) {
	e := newTestEnv(t)
	pool, _ := e.setup(1, false, 3, 5)
	data, err := os.ReadFile("testdata/profile-alpn.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Profile Profile }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	path := "/api/pools/" + str(pool["id"]) + "/profile"
	e.do("PUT", path, fixture.Profile, 200)
	// Invalid input must not replace the previously saved valid profile.
	encoded, _ := json.Marshal(fixture.Profile)
	var body row
	_ = json.Unmarshal(encoded, &body)
	for _, invalid := range []any{nil, "h2", []any{nil}, []string{""}, []string{"h2\r\nX: 1"}, []string{"fromMitm"}} {
		body["alpn"] = invalid
		e.do("PUT", path, body, 422)
	}
	e.app.s.mu.Lock()
	encrypted := str(e.app.s.one("SELECT profile FROM pools WHERE id=?", pool["id"])["profile"])
	e.app.s.mu.Unlock()
	if strings.Contains(encrypted, "http/1.1") {
		t.Fatal("profile not encrypted")
	}
	e.restart(false)
	for _, version := range []string{"1.0.0", "1.1.0", "1.2.0-beta"} {
		jobs := asRows(asRow(e.do("POST", "/api/agent/poll", row{"agent_id": "old-agent", "version": version, "control_ok": true}, 200))["jobs"])
		if len(jobs) != 0 {
			t.Fatal("ALPN leased to incompatible worker")
		}
	}
	jobs := asRows(asRow(e.do("POST", "/api/agent/poll", row{"agent_id": "new-agent", "version": "1.2.0", "control_ok": true}, 200))["jobs"])
	if len(jobs) != 1 {
		t.Fatal("new worker did not receive ALPN profile")
	}
	got, _ := json.Marshal(jobs[0]["profile"])
	var profile Profile
	if err := json.Unmarshal(got, &profile); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(fixture.Profile)
	got, _ = json.Marshal(profile)
	var expected, received any
	_ = json.Unmarshal(want, &expected)
	_ = json.Unmarshal(got, &received)
	if !reflect.DeepEqual(expected, received) {
		t.Fatal("ALPN/extra changed across encrypted restart and lease")
	}
}

func TestALPNAgentVersion(t *testing.T) {
	for _, version := range []string{"1.2.0", "1.2.1", "1.3.0", "2.0.0"} {
		if !supportsALPN(version) {
			t.Error(version)
		}
	}
	for _, version := range []string{"", "1", "1.0.0", "1.1.0", "1.2.0-beta", "1.02.0"} {
		if supportsALPN(version) {
			t.Error(version)
		}
	}
}

func TestPreALPNWorkerStillGetsExtraProfiles(t *testing.T) {
	e := newTestEnv(t)
	alpnPool, _ := e.setup(5, false, 3, 5)
	alpnProfile := testProfile
	alpnProfile.ALPN = []string{"h2", "http/1.1"}
	e.do("PUT", "/api/pools/"+str(alpnPool["id"])+"/profile", alpnProfile, 200)
	pool := asRow(e.do("POST", "/api/pools", row{"name": "Extra pool", "hostname": "extra.example.com", "zone_id": "zone"}, 200))
	extraProfile := testProfile
	extraProfile.Transport = "xhttp"
	extraProfile.XHTTPExtra = json.RawMessage(`{"xPaddingBytes":"100-1000"}`)
	e.do("PUT", "/api/pools/"+str(pool["id"])+"/profile", extraProfile, 200)
	e.do("POST", "/api/pools/"+str(pool["id"])+"/targets", row{"name": "Extra target", "ip": "64.6.64.6"}, 200)
	e.sql("UPDATE targets SET next_due=1 WHERE pool_id=?", pool["id"])
	jobs := asRows(asRow(e.do("POST", "/api/agent/poll", row{"agent_id": "v11-agent", "version": "1.1.0", "control_ok": true}, 200))["jobs"])
	if len(jobs) != 1 {
		t.Fatal("legacy-compatible extra jobs starved by ALPN jobs")
	}
	profile := asRow(jobs[0]["profile"])
	if profile["xhttp_extra"] == nil || profile["alpn"] != nil {
		t.Fatal("wrong wire profile sent to 1.1 worker")
	}
}

func TestALPNValidation(t *testing.T) {
	data, err := os.ReadFile("testdata/profile-alpn.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, raw := range cases.Valid {
		var protocols []string
		if err := json.Unmarshal(raw, &protocols); err != nil || !validALPN(protocols, "tls") {
			t.Errorf("valid ALPN rejected: %s", raw)
		}
	}
	for _, raw := range cases.Invalid {
		// Null is rejected by the strict HTTP/job decoder before slice validation.
		if string(raw) == "null" {
			continue
		}
		var protocols []string
		if err := json.Unmarshal(raw, &protocols); err == nil && validALPN(protocols, "tls") {
			t.Errorf("invalid ALPN accepted: %s", raw)
		}
	}
	if validALPN([]string{"h2"}, "reality") || validALPN(make([]string, 17), "tls") || validALPN([]string{strings.Repeat("a", 256)}, "tls") {
		t.Error("context/length validation failed")
	}
	if !validALPN(nil, "reality") {
		t.Error("legacy profile rejected")
	}
}
