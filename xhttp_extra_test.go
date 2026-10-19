package guard

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestXHTTPExtraEncryptedSaveRestartAndAgentLease(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(1, false, 3, 5)
	path := "/api/pools/" + str(p["id"]) + "/profile"
	profile := testProfile
	profile.Transport = "xhttp"
	profile.XHTTPExtra = json.RawMessage(`{"xPaddingBytes":"100-1000","noGRPCHeader":true,"headers":{"X-Token":"extra-private-marker%2F+"},"xmux":{"maxConcurrency":"16-32"}}`)
	e.do("PUT", path, profile, 200)
	e.app.s.mu.Lock()
	encrypted := str(e.app.s.one("SELECT profile FROM pools WHERE id=?", p["id"])["profile"])
	e.app.s.mu.Unlock()
	if strings.Contains(encrypted, "extra-private-marker") || strings.Contains(encrypted, "xPaddingBytes") {
		t.Fatal("plaintext extra stored")
	}
	// Invalid requests cannot replace the encrypted profile or revise the pool.
	invalidProfile := profile
	invalidProfile.XHTTPExtra = json.RawMessage(`{"downloadSettings":{}}`)
	e.do("PUT", path, invalidProfile, 422)
	e.restart(false)
	// Legacy workers must not receive an unknown field and reject the whole batch.
	if jobs := e.poll(true, "old-agent"); len(jobs) != 0 {
		t.Fatal("extra leased to old agent")
	}
	jobs := asRows(asRow(e.do("POST", "/api/agent/poll", row{"agent_id": "new-agent", "version": "1.1.0", "control_ok": true}, 200))["jobs"])
	if len(jobs) != 1 {
		t.Fatal("new agent did not receive extra job")
	}
	got, _ := json.Marshal(asRow(jobs[0]["profile"])["xhttp_extra"])
	var want any
	_ = json.Unmarshal(profile.XHTTPExtra, &want)
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(got, wantJSON) {
		t.Fatalf("extra changed after encrypted restart: %s", got)
	}
	for _, url := range []string{"/api/pools", "/api/events"} {
		data, _ := json.Marshal(e.do("GET", url, nil, 200))
		if bytes.Contains(data, []byte("extra-private-marker")) || bytes.Contains(data, []byte("xhttp_extra")) {
			t.Fatal("secret extra leaked to UI API")
		}
	}
}

func TestOldAgentSkipsExtraWithoutStarvingOtherPools(t *testing.T) {
	e := newTestEnv(t)
	extraPool, _ := e.setup(5, false, 3, 5)
	profile := testProfile
	profile.Transport = "xhttp"
	profile.XHTTPExtra = json.RawMessage(`{}`)
	e.do("PUT", "/api/pools/"+str(extraPool["id"])+"/profile", profile, 200)
	plainPool := asRow(e.do("POST", "/api/pools", row{"name": "Plain pool", "hostname": "plain.example.com", "zone_id": "zone"}, 200))
	e.do("PUT", "/api/pools/"+str(plainPool["id"])+"/profile", testProfile, 200)
	e.do("POST", "/api/pools/"+str(plainPool["id"])+"/targets", row{"name": "Plain target", "ip": "64.6.64.6"}, 200)
	e.sql("UPDATE targets SET next_due=1 WHERE pool_id=?", plainPool["id"])
	jobs := e.poll(true, "old-agent")
	if len(jobs) != 1 {
		t.Fatalf("legacy jobs starved: %d", len(jobs))
	}
	if _, ok := asRow(jobs[0]["profile"])["xhttp_extra"]; ok {
		t.Fatal("legacy payload changed")
	}
}

func TestXHTTPExtraAgentVersion(t *testing.T) {
	for _, version := range []string{"1.1.0", "1.2.0", "2.0.0"} {
		if !supportsXHTTPExtra(version) {
			t.Error(version)
		}
	}
	for _, version := range []string{"", "1", "1.0.0", "0.9.0", "1.1.0-beta", "garbage", "+1.1.0", "1.01.0"} {
		if supportsXHTTPExtra(version) {
			t.Error(version)
		}
	}
}

func TestXHTTPExtraSchema(t *testing.T) {
	data, err := os.ReadFile("testdata/xhttp-extra.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, value := range cases.Valid {
		if !validXHTTPExtra(value, "xhttp", "stream-up") {
			t.Errorf("rejected valid extra: %s", value)
		}
		if validXHTTPExtra(value, "tcp", "auto") {
			t.Error("TCP extra accepted")
		}
	}
	for _, value := range cases.Invalid {
		if validXHTTPExtra(value, "xhttp", "stream-up") {
			t.Errorf("accepted invalid extra: %s", value)
		}
	}
	if validXHTTPExtra(json.RawMessage(`{"headers":{"X-Pad":"`+strings.Repeat("x", 16384)+`"}}`), "xhttp", "auto") {
		t.Error("oversized extra")
	}
	if validXHTTPExtra(json.RawMessage(`{"headers":{"X-Pad":"`+strings.Repeat("<", 3000)+`"}}`), "xhttp", "auto") {
		t.Error("HTML escaping exceeds wire size")
	}
	if !validXHTTPExtra(nil, "tcp", "auto") {
		t.Error("legacy profile rejected")
	}
	if !validXHTTPExtra(json.RawMessage(`{"uplinkHTTPMethod":"GET","uplinkDataPlacement":"cookie"}`), "xhttp", "packet-up") {
		t.Error("packet-up fields rejected")
	}
}
