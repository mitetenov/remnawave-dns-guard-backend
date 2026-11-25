package guard

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVLESSFragmentProfileStoredAndLeased(t *testing.T) {
	a, _ := panelTestApp(t)
	a.s.exec("INSERT INTO pools (id,name,hostname) VALUES ('pool','Pool','pool.example')")
	a.s.exec("INSERT INTO targets (id,pool_id,ip) VALUES ('target','pool','1.1.1.1')")

	save := func(fragment string) *httptest.ResponseRecorder {
		t.Helper()
		const base = `{"uuid":"550e8400-e29b-41d4-a716-446655440000","port":443,"transport":"tcp","security":"tls","server_name":"edge.example.com"`
		req := httptest.NewRequest(http.MethodPut, "/api/pools/pool/profile", strings.NewReader(base+`,"vless_fragment":`+fragment+"}"))
		req.Header.Set("Origin", "http://testserver")
		req.Header.Set("X-Requested-With", "DNSGuard")
		req.AddCookie(&http.Cookie{Name: "dns_guard_session", Value: "test-session"})
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, req)
		return w
	}
	for _, fragment := range []string{
		`{}`, `null`, `{"packets":"tlshello","length":"0","delay":"0"}`,
		`{"packets":"tlshello","length":"20-10","delay":"0"}`,
		`{"packets":"tlshello","length":"10-20","delay":"2147483648"}`,
		`{"packets":"tlshello","length":"10-20","delay":"0","extra":""}`,
	} {
		if response := save(fragment); response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("invalid fragment %s accepted: %d %s", fragment, response.Code, response.Body)
		}
	}
	if response := save(`{"packets":"tlshello","length":"10-20","delay":"0"}`); response.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", response.Code, response.Body)
	}

	poll := func(version string) []row {
		var jobs []row
		a.s.transaction(func() {
			jobs = a.pollChecker(Poll{AgentID: "checker", Version: version, ControlOK: true})
		})
		return jobs
	}
	if jobs := poll("1.7.0"); len(jobs) != 0 {
		t.Fatal("older checker received a profile with fragmentation")
	}
	jobs := poll("1.8.0")
	if len(jobs) != 1 || jobs[0]["ip"] != "1.1.1.1" {
		t.Fatalf("unexpected jobs: %v", jobs)
	}
	raw, err := json.Marshal(jobs[0]["profile"])
	if err != nil {
		t.Fatal(err)
	}
	var profile Profile
	want := map[string]string{"packets": "tlshello", "length": "10-20", "delay": "0"}
	if err := json.Unmarshal(raw, &profile); err != nil || !maps.Equal(profile.VLESSFragment, want) {
		t.Fatalf("fragmentation changed between save and poll: %s (%v)", raw, err)
	}
}
