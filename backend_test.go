package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testProfile = Profile{Port: 443, UUID: "d74dbd5f-4f3a-40a1-b267-e7e726b192f7", Transport: "tcp", Security: "tls", ServerName: "example.com", Fingerprint: "chrome", Path: "/", XHTTPMode: "auto"}

type fakeProvider struct {
	mu          sync.Mutex
	records     []row
	fail        string
	count       int
	calls       int
	block       chan struct{}
	entered     chan struct{}
	blockMethod string
}
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(value any, status int) *http.Response {
	b, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(b))}
}
func (f *fakeProvider) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	block, entered, blockMethod := f.block, f.entered, f.blockMethod
	f.mu.Unlock()
	if block != nil && req.Method == blockMethod {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == "get" && req.Method == http.MethodGet {
		return response(row{"success": false, "errors": []string{"hidden-token"}}, 403), nil
	}
	if strings.HasSuffix(req.URL.Path, "/zones") {
		return response(row{"success": true, "result": []row{{"id": "zone", "name": "example.com"}}}, 200), nil
	}
	if req.Method == http.MethodGet {
		records := []row{}
		for _, r := range f.records {
			clone := row{}
			for k, v := range r {
				clone[k] = v
			}
			records = append(records, clone)
		}
		return response(row{"success": true, "result": records, "result_info": row{"total_pages": 1}}, 200), nil
	}
	if req.Method == http.MethodPost {
		var data row
		if e := json.NewDecoder(req.Body).Decode(&data); e != nil {
			return nil, e
		}
		f.count++
		data["id"] = fmt.Sprint(f.count)
		f.records = append(f.records, data)
	} else if req.Method == http.MethodDelete {
		id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		out := []row{}
		for _, r := range f.records {
			if r["id"] != id {
				out = append(out, r)
			}
		}
		f.records = out
	}
	if f.fail == strings.ToLower(req.Method) {
		return nil, errors.New("hidden-token secret provider timeout")
	}
	return response(row{"success": true, "result": row{"id": fmt.Sprint(f.count)}}, 200), nil
}
func (f *fakeProvider) add(ip, hostname, kind string, proxied bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	f.records = append(f.records, row{"id": fmt.Sprint(f.count), "type": kind, "name": hostname, "content": ip, "proxied": proxied})
}
func (f *fakeProvider) setFail(value string) { f.mu.Lock(); defer f.mu.Unlock(); f.fail = value }
func (f *fakeProvider) size() int            { f.mu.Lock(); defer f.mu.Unlock(); return len(f.records) }
func (f *fakeProvider) callCount() int       { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type testEnv struct {
	t      *testing.T
	app    *App
	server *httptest.Server
	client *http.Client
	fake   *fakeProvider
	cfg    Config
}

func testConfig(path string) Config {
	return Config{Username: "admin", Password: "password", AppSecret: strings.Repeat("S", 32), AgentToken: strings.Repeat("T", 32), DatabasePath: path, PublicOrigin: "http://testserver", CloudflareAPIToken: "hidden-token"}
}
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{t: t, cfg: testConfig(filepath.Join(t.TempDir(), "guard.db")), fake: &fakeProvider{records: []row{}}}
	e.open(false)
	t.Cleanup(func() { e.server.Close(); _ = e.app.Close() })
	return e
}
func (e *testEnv) open(background bool) {
	var err error
	e.app, err = New(e.cfg, Options{Client: &http.Client{Transport: e.fake}, BackgroundTasks: background})
	if err != nil {
		e.t.Fatal(err)
	}
	e.server = httptest.NewServer(e.app.Handler())
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar, Timeout: 3 * time.Second}
	e.do("POST", "/api/auth/login", row{"username": e.cfg.Username, "password": e.cfg.Password}, 200)
}
func (e *testEnv) restart(background bool) {
	e.server.Close()
	if err := e.app.Close(); err != nil {
		e.t.Fatal(err)
	}
	e.open(background)
}
func (e *testEnv) request(method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.server.URL+path, reader)
	req.Header.Set("X-Requested-With", "DNSGuard")
	req.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/api/agent/") {
		req.Header.Set("Authorization", "Bearer "+e.cfg.AgentToken)
	}
	return e.client.Do(req)
}
func (e *testEnv) do(method, path string, body any, status int) any {
	e.t.Helper()
	resp, err := e.request(method, path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var value any
	if err = json.NewDecoder(resp.Body).Decode(&value); err != nil {
		e.t.Fatal(err)
	}
	if resp.StatusCode != status {
		e.t.Fatalf("%s %s status=%d expected=%d response=%v", method, path, resp.StatusCode, status, value)
	}
	return value
}
func asRow(v any) row { return row(v.(map[string]any)) }
func asRows(v any) []row {
	out := []row{}
	for _, item := range v.([]any) {
		out = append(out, asRow(item))
	}
	return out
}
func (e *testEnv) setup(count int, auto bool, failure, recovery int) (row, []row) {
	e.t.Helper()
	p := asRow(e.do("POST", "/api/pools", row{"name": "Pool", "hostname": "vpn.example.com", "zone_id": "zone", "failure_threshold": failure, "recovery_threshold": recovery}, 200))
	e.do("PUT", "/api/pools/"+str(p["id"])+"/profile", testProfile, 200)
	ts := []row{}
	for i, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4", "1.0.0.1"}[:count] {
		ts = append(ts, asRow(e.do("POST", "/api/pools/"+str(p["id"])+"/targets", row{"name": fmt.Sprint(i), "ip": ip}, 200)))
	}
	if auto {
		e.do("PATCH", "/api/pools/"+str(p["id"]), row{"automation_enabled": true}, 200)
	}
	return p, ts
}
func (e *testEnv) poll(healthy bool, agent string) []row {
	return asRows(asRow(e.do("POST", "/api/agent/poll", row{"agent_id": agent, "version": "1", "control_ok": healthy, "control_error": nil}, 200))["jobs"])
}
func (e *testEnv) result(job row, ok bool, agent, reason string) int {
	var latency, errorValue any
	if ok {
		latency = 12
	} else {
		errorValue = reason
	}
	out := asRow(e.do("POST", "/api/agent/results", row{"agent_id": agent, "results": []row{{"job_id": job["job_id"], "ok": ok, "latency_ms": latency, "error": errorValue}}}, 200))
	e.app.RunOnce()
	return int(num(out["accepted"]))
}
func (e *testEnv) round(p row, ok bool, reason string) []row {
	e.do("POST", "/api/pools/"+str(p["id"])+"/check", nil, 200)
	jobs := e.poll(true, "ru-1")
	for _, j := range jobs {
		if n := e.result(j, ok, "ru-1", reason); n != 1 {
			e.t.Fatalf("result accepted=%d", n)
		}
	}
	return jobs
}
func (e *testEnv) targets(p row) []row {
	return asRows(e.do("GET", "/api/pools/"+str(p["id"])+"/targets", nil, 200))
}
func (e *testEnv) sql(query string, args ...any) {
	e.app.s.mu.Lock()
	defer e.app.s.mu.Unlock()
	e.app.s.exec(query, args...)
}
func (e *testEnv) one(query string, args ...any) row {
	e.app.s.mu.Lock()
	defer e.app.s.mu.Unlock()
	return e.app.s.one(query, args...)
}
func findTarget(targets []row, id any) row {
	for _, t := range targets {
		if t["id"] == id {
			return t
		}
	}
	return nil
}

func TestFailureRecoveryLastRecordReplay(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(2, true, 2, 2)
	first := e.round(p, false, "connection_failed")
	if e.result(first[0], false, "ru-1", "connection_failed") != 0 {
		t.Fatal("replay accepted")
	}
	for _, target := range e.targets(p) {
		if target["status"] != "suspect" {
			t.Fatal(target)
		}
	}
	e.round(p, false, "connection_failed")
	statuses := map[string]int{}
	for _, target := range e.targets(p) {
		statuses[str(target["status"])]++
	}
	if statuses["excluded"] != 1 || statuses["protected"] != 1 || e.fake.size() != 1 {
		t.Fatal(statuses, e.fake.size())
	}
	e.round(p, true, "")
	e.round(p, true, "")
	if e.fake.size() != 2 {
		t.Fatal("not recovered")
	}
	for _, target := range e.targets(p) {
		if target["status"] != "healthy" {
			t.Fatal(target)
		}
	}
}

func TestFinalActualRecordDuplicateAndUnrelated(t *testing.T) {
	e := newTestEnv(t)
	p, ts := e.setup(1, true, 1, 1)
	e.fake.add("9.9.9.9", "other.example.com", "A", false)
	e.fake.add("1.1.1.1", "vpn.example.com", "A", false)
	e.round(p, false, "connection_failed")
	if e.targets(p)[0]["status"] != "protected" || e.fake.size() != 3 {
		t.Fatal(e.targets(p))
	}
	id := str(ts[0]["id"])
	e.do("POST", "/api/targets/"+id+"/disable", nil, 409)
	e.do("DELETE", "/api/targets/"+id+"?delete_dns=true", nil, 409)
	e.fake.add("8.8.4.4", "vpn.example.com", "A", false)
	_, err := e.app.reconciler.scanPool(str(p["id"]), false)
	if err != nil {
		t.Fatal(err)
	}
	e.round(p, false, "connection_failed")
	if e.targets(p)[0]["status"] != "excluded" {
		t.Fatal(e.targets(p))
	}
}

func TestManualDisableStopsLeasesAndNeverRestores(t *testing.T) {
	e := newTestEnv(t)
	p, ts := e.setup(2, true, 1, 1)
	jobs := e.poll(true, "ru-1")
	e.do("POST", "/api/targets/"+str(ts[0]["id"])+"/disable", nil, 200)
	for _, j := range jobs {
		n := e.result(j, true, "ru-1", "")
		if j["target_id"] == ts[0]["id"] && n != 0 {
			t.Fatal("disabled stale job accepted")
		}
	}
	for i := 0; i < 3; i++ {
		for _, j := range e.round(p, true, "") {
			if j["target_id"] == ts[0]["id"] {
				t.Fatal("disabled target probed")
			}
		}
	}
	target := findTarget(e.targets(p), ts[0]["id"])
	if target["status"] != "disabled" || truth(target["dns_present"]) || truth(target["manual_enabled"]) {
		t.Fatal(target)
	}
	if num(asRow(e.do("GET", "/api/overview", nil, 200))["excluded"]) != 0 {
		t.Fatal("disabled counted as excluded")
	}
}

func TestLeasesOfflineExpiryAgentAndProfileBinding(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(2, true, 2, 2)
	if len(e.poll(false, "ru-1")) != 0 {
		t.Fatal("offline jobs")
	}
	jobs := e.poll(true, "ru-1")
	if len(e.poll(true, "ru-1")) != 0 {
		t.Fatal("overlapping leases")
	}
	if e.result(jobs[0], false, "intruder", "connection_failed") != 0 {
		t.Fatal("wrong agent accepted")
	}
	e.sql("UPDATE agents SET last_seen=?", nowSeconds()-1000)
	if e.result(jobs[0], false, "ru-1", "connection_failed") != 0 {
		t.Fatal("stale heartbeat accepted")
	}
	e.poll(false, "ru-1")
	if e.result(jobs[0], false, "ru-1", "connection_failed") != 0 {
		t.Fatal("cancelled accepted")
	}
	e.sql("UPDATE jobs SET expires=?", nowSeconds()-1)
	fresh := e.poll(true, "ru-1")
	if len(fresh) != 2 {
		t.Fatal(fresh)
	}
	profile := testProfile
	profile.Port = 8443
	e.do("PUT", "/api/pools/"+str(p["id"])+"/profile", profile, 200)
	if e.result(fresh[0], false, "ru-1", "connection_failed") != 0 {
		t.Fatal("old profile accepted")
	}
	for _, j := range e.poll(true, "ru-1") {
		if num(asRow(j["profile"])["port"]) != 8443 {
			t.Fatal(j)
		}
	}
}

func TestPauseProbesAndSyncRetainsExcluded(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(2, true, 1, 2)
	e.round(p, false, "connection_failed")
	before := e.targets(p)
	e.do("POST", "/api/pools/"+str(p["id"])+"/sync", nil, 200)
	if len(e.targets(p)) != len(before) {
		t.Fatal("sync dropped excluded")
	}
	e.do("PATCH", "/api/pools/"+str(p["id"]), row{"automation_enabled": false}, 200)
	count := e.fake.size()
	e.round(p, true, "")
	e.round(p, true, "")
	if e.fake.size() != count {
		t.Fatal("paused mutation")
	}
}

func TestManualCommitTimeoutSurvivesRestart(t *testing.T) {
	for _, action := range []string{"enroll", "disable", "enable", "delete"} {
		t.Run(action, func(t *testing.T) {
			e := newTestEnv(t)
			p, ts := e.setup(2, false, 1, 1)
			id := str(ts[0]["id"])
			path, method := "/api/targets/"+id+"/"+action, "POST"
			if action == "enable" {
				e.do("POST", "/api/targets/"+id+"/disable", nil, 200)
			}
			var body any
			failure := "delete"
			if action == "enroll" {
				path = "/api/pools/" + str(p["id"]) + "/targets"
				body = row{"name": "third", "ip": "9.9.9.9"}
				failure = "post"
			} else if action == "enable" {
				failure = "post"
			} else if action == "delete" {
				path = "/api/targets/" + id + "?delete_dns=true"
				method = "DELETE"
			}
			e.fake.setFail(failure)
			out := asRow(e.do(method, path, body, 502))
			if strings.Contains(str(out["detail"]), "hidden-token") {
				t.Fatal(out)
			}
			if action == "enroll" {
				id = str(e.one("SELECT id FROM targets WHERE ip='9.9.9.9'")["id"])
			}
			pending := e.one("SELECT * FROM targets WHERE id=?", id)
			expectedAction := action
			if action == "delete" {
				expectedAction = "delete_dns"
			}
			if pending["dns_action"] != expectedAction || !truth(pending["dns_uncertain"]) {
				t.Fatal(pending)
			}
			if oneOf(action, "disable", "delete") && truth(pending["manual_enabled"]) {
				t.Fatal("pending manual removal still monitored")
			}
			e.fake.setFail("")
			e.restart(false)
			e.sql("UPDATE targets SET dns_next_retry=0")
			e.app.RunOnce()
			target := e.one("SELECT * FROM targets WHERE id=?", id)
			if action == "delete" {
				if target != nil {
					t.Fatal(target)
				}
			} else if target["dns_action"] != nil || truth(target["dns_uncertain"]) || truth(target["dns_present"]) != oneOf(action, "enroll", "enable") {
				t.Fatal(target)
			}
		})
	}
}

func TestDNSFailureSanitizedNoRepeatedProtectedReads(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(2, true, 1, 1)
	e.round(p, false, "connection_failed")
	calls := e.fake.callCount()
	for i := 0; i < 3; i++ {
		e.round(p, false, "connection_failed")
	}
	if e.fake.callCount() != calls {
		t.Fatal("unchanged excluded/protected state queried provider repeatedly")
	}
	e.fake.setFail("get")
	e.do("POST", "/api/integrations/cloudflare/test", nil, 502)
	events := e.do("GET", "/api/events", nil, 200)
	b, _ := json.Marshal(events)
	if strings.Contains(string(b), "hidden-token") || strings.Contains(string(b), "secret") {
		t.Fatal("provider secret leaked")
	}
}

func TestProxyAnyAddressPreflightHasNoLatentEnrollment(t *testing.T) {
	for _, kind := range []string{"A", "AAAA"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			p, _ := e.setup(1, false, 1, 1)
			ip := "9.9.9.9"
			if kind == "AAAA" {
				ip = "2606:4700:4700::1111"
			}
			e.fake.add(ip, "vpn.example.com", kind, true)
			e.do("POST", "/api/pools/"+str(p["id"])+"/targets", row{"name": "bad", "ip": "8.8.8.8"}, 409)
			if e.one("SELECT id FROM targets WHERE ip='8.8.8.8'") != nil {
				t.Fatal("proxy conflict staged latent enrollment")
			}
			e.do("POST", "/api/pools/"+str(p["id"])+"/sync", nil, 409)
		})
	}
}

func TestStaleAgentAndPoolProbeWindow(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(2, false, 1, 1)
	e.round(p, true, "")
	e.sql("UPDATE targets SET last_checked_at=?", iso(time.Now().Add(-181*time.Second)))
	for _, target := range e.targets(p) {
		if target["status"] != "stale" || truth(target["probe_fresh"]) {
			t.Fatal(target)
		}
	}
	e.do("PATCH", "/api/pools/"+str(p["id"]), row{"interval_seconds": 100}, 200)
	for _, target := range e.targets(p) {
		if target["status"] != "healthy" {
			t.Fatal(target)
		}
	}
	e.sql("UPDATE agents SET last_seen=?", nowSeconds()-91)
	if num(asRow(e.do("GET", "/api/overview", nil, 200))["stale"]) != 2 {
		t.Fatal("missing stale targets")
	}
}

func TestPeriodicDriftResetsAndRequiresNewSuccesses(t *testing.T) {
	e := newTestEnv(t)
	p, ts := e.setup(2, true, 2, 2)
	e.round(p, true, "")
	id := str(ts[0]["id"])
	ip := str(ts[0]["ip"])
	e.fake.mu.Lock()
	kept := []row{}
	for _, r := range e.fake.records {
		if r["content"] != ip {
			kept = append(kept, r)
		}
	}
	e.fake.records = kept
	e.fake.mu.Unlock()
	e.sql("UPDATE pools SET dns_next_check=0")
	e.app.RunOnce()
	target := e.one("SELECT * FROM targets WHERE id=?", id)
	if truth(target["dns_present"]) || !truth(target["dns_drift"]) || num(target["successes"]) != 0 {
		t.Fatal(target)
	}
	e.round(p, true, "")
	if e.fake.size() != 1 {
		t.Fatal("restored before fresh threshold")
	}
	e.round(p, true, "")
	if e.fake.size() != 2 {
		t.Fatal("not restored")
	}
	target = e.one("SELECT * FROM targets WHERE id=?", id)
	if truth(target["dns_drift"]) {
		t.Fatal("drift retained after verified operation")
	}
}

func TestSlowProviderDoesNotBlockAgentIngress(t *testing.T) {
	for _, operation := range []string{"manual", "automatic", "scan", "integration"} {
		t.Run(operation, func(t *testing.T) {
			e := newTestEnv(t)
			p, ts := e.setup(2, true, 1, 1)
			jobs := e.poll(true, "ru-1")
			var independentJob row
			for _, job := range jobs {
				if job["target_id"] != ts[0]["id"] {
					independentJob = job
				}
			}
			if operation == "automatic" {
				e.app.s.mu.Lock()
				e.app.s.exec("UPDATE targets SET failures=1,last_agent_id='ru-1' WHERE id=?", ts[0]["id"])
				e.app.reconciler.queueLocked(str(ts[0]["id"]), "auto_remove")
				e.app.s.mu.Unlock()
			}
			block, entered := make(chan struct{}), make(chan struct{}, 1)
			e.fake.mu.Lock()
			e.fake.block, e.fake.entered, e.fake.blockMethod = block, entered, "GET"
			e.fake.mu.Unlock()
			done := make(chan error, 1)
			go func() {
				switch operation {
				case "manual":
					resp, err := e.request("POST", "/api/targets/"+str(ts[0]["id"])+"/disable", nil)
					if resp != nil {
						resp.Body.Close()
					}
					done <- err
				case "automatic":
					done <- e.app.reconciler.execute(str(ts[0]["id"]), false)
				case "scan":
					_, err := e.app.reconciler.scanPool(str(p["id"]), false)
					done <- err
				default:
					resp, err := e.request("POST", "/api/integrations/cloudflare/test", nil)
					if resp != nil {
						resp.Body.Close()
					}
					done <- err
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				close(block)
				t.Fatal("provider not entered")
			}
			start := time.Now()
			e.poll(true, "ru-1")
			out := asRow(e.do("POST", "/api/agent/results", row{"agent_id": "ru-1", "results": []row{{"job_id": independentJob["job_id"], "ok": true}}}, 200))
			if num(out["accepted"]) != 1 || time.Since(start) > time.Second {
				close(block)
				t.Fatal("agent blocked")
			}
			close(block)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConcurrentManualRemovalsPreserveOneActualA(t *testing.T) {
	e := newTestEnv(t)
	_, ts := e.setup(2, false, 1, 1)
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for _, target := range ts {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			resp, err := e.request("POST", "/api/targets/"+id+"/disable", nil)
			if err != nil {
				statuses <- 0
				return
			}
			defer resp.Body.Close()
			statuses <- resp.StatusCode
		}(str(target["id"]))
	}
	wg.Wait()
	close(statuses)
	seen := map[int]int{}
	for status := range statuses {
		seen[status]++
	}
	if seen[200] != 1 || seen[409] != 1 || e.fake.size() != 1 {
		t.Fatal(seen, e.fake.size())
	}
}

func TestPendingAutomaticIntentCancelledByPauseProfileOrStaleAgent(t *testing.T) {
	for _, change := range []string{"pause", "profile", "stale"} {
		t.Run(change, func(t *testing.T) {
			e := newTestEnv(t)
			p, ts := e.setup(2, true, 1, 1)
			e.poll(true, "ru-1")
			id := str(ts[0]["id"])
			e.sql("UPDATE targets SET failures=1,last_agent_id='ru-1' WHERE id=?", id)
			e.app.s.mu.Lock()
			e.app.reconciler.queueLocked(id, "auto_remove")
			e.app.s.mu.Unlock()
			switch change {
			case "pause":
				e.do("PATCH", "/api/pools/"+str(p["id"]), row{"automation_enabled": false}, 200)
			case "profile":
				profile := testProfile
				profile.Port = 8443
				e.do("PUT", "/api/pools/"+str(p["id"])+"/profile", profile, 200)
			case "stale":
				e.sql("UPDATE agents SET last_seen=?", nowSeconds()-91)
			}
			e.app.RunOnce()
			if e.fake.size() != 2 {
				t.Fatal("invalid intent removed DNS")
			}
			target := e.one("SELECT * FROM targets WHERE id=?", id)
			if change == "stale" {
				if target["dns_action"] != "auto_remove" {
					t.Fatal(target)
				}
				e.poll(true, "ru-1")
				if num(e.one("SELECT * FROM targets WHERE id=?", id)["failures"]) != 0 {
					t.Fatal("streak not reset on reconnect")
				}
				e.sql("UPDATE targets SET dns_next_retry=0 WHERE id=?", id)
				e.app.RunOnce()
			} else if target["dns_action"] != nil {
				t.Fatal("cancelled intent retained")
			}
		})
	}
}

func TestInconclusiveProbeNeverRemovesDNS(t *testing.T) {
	for reason := range inconclusiveErrors {
		t.Run(reason, func(t *testing.T) {
			e := newTestEnv(t)
			p, _ := e.setup(2, true, 1, 1)
			for i := 0; i < 2; i++ {
				e.round(p, false, reason)
			}
			for _, target := range e.targets(p) {
				if target["status"] != "unknown" || num(target["failures"]) != 0 || num(target["successes"]) != 0 {
					t.Fatal(target)
				}
			}
			if e.fake.size() != 2 {
				t.Fatal("inconclusive removed DNS")
			}
		})
	}
}

func TestBackgroundManualRetryWithoutAgent(t *testing.T) {
	e := newTestEnv(t)
	p, ts := e.setup(2, false, 1, 1)
	_ = p
	id := str(ts[0]["id"])
	e.fake.setFail("delete")
	e.do("POST", "/api/targets/"+id+"/disable", nil, 502)
	e.fake.setFail("")
	e.restart(true)
	e.sql("UPDATE targets SET dns_next_retry=0")
	e.app.reconciler.signal()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.one("SELECT * FROM targets WHERE id=?", id)["dns_action"] == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background retry did not complete")
}

func TestMaximumFourJobsAndBatchValidation(t *testing.T) {
	e := newTestEnv(t)
	_, _ = e.setup(5, false, 1, 1)
	if len(e.poll(true, "ru-1")) != 4 {
		t.Fatal("batch not limited to four")
	}
	if len(e.poll(true, "ru-2")) != 1 {
		t.Fatal("second agent did not receive independent remaining target")
	}
	e.do("POST", "/api/agent/results", row{"agent_id": "ru-1", "results": []row{{"job_id": "missing"}}}, 422)
	e.do("POST", "/api/agent/results", row{"agent_id": "ru-1", "results": []row{{"job_id": "missing", "ok": false, "password": "never-echo"}}}, 422)
}

func TestAuthOriginSecretsAndLoginRate(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(1, false, 1, 1)
	_ = p
	req, _ := http.NewRequest("PUT", e.server.URL+"/api/settings", strings.NewReader(`{"cloudflare_api_token":"never-echo"}`))
	req.Header.Set("Origin", "https://evil.test")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
	bad := asRow(e.do("PUT", "/api/settings", row{"cloudflare_api_token": row{"secret": "never-echo"}}, 422))
	if strings.Contains(str(bad["detail"]), "never-echo") {
		t.Fatal(bad)
	}
	if strings.Contains(str(e.one("SELECT value FROM settings WHERE key='cloudflare_api_token'")["value"]), "hidden-token") {
		t.Fatal("plaintext storage")
	}
	for i := 0; i < 10; i++ {
		e.do("POST", "/api/auth/login", row{"username": "x", "password": "x"}, 401)
	}
	e.do("POST", "/api/auth/login", row{"username": "admin", "password": "password"}, 429)
	e.app.s.mu.Lock()
	for i := range e.app.loginFailures {
		e.app.loginFailures[i] -= 61
	}
	e.app.s.mu.Unlock()
	e.do("POST", "/api/auth/login", row{"username": "admin", "password": "password"}, 200)
	e.do("POST", "/api/auth/logout", nil, 200)
	e.do("GET", "/api/pools", nil, 401)
}

func TestPublicIPAndProfileValidation(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.0.8", "192.0.0.11", "192.0.0.170", "192.0.0.171", "192.0.0.172", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::1", "::ffff:1.1.1.1", "01.1.1.1"} {
		if publicIPv4(ip) {
			t.Fatalf("unsafe target %s", ip)
		}
	}
	for _, ip := range []string{"192.0.0.9", "192.0.0.10", "192.88.99.1", "192.88.99.2", "1.1.1.1", "8.8.8.8"} {
		if !publicIPv4(ip) {
			t.Fatalf("legacy globally reachable target rejected: %s", ip)
		}
	}
	e := newTestEnv(t)
	p, _ := e.setup(1, false, 1, 1)
	for _, update := range []row{{"server_name": ".."}, {"host": "bad/host"}, {"path": "//bad"}, {"transport": "xhttp", "flow": "xtls-rprx-vision"}, {"security": "reality", "public_key": "short"}, {"short_id": "a"}, {"uuid": "not-uuid"}} {
		b, _ := json.Marshal(testProfile)
		profile := row{}
		_ = json.Unmarshal(b, &profile)
		for k, v := range update {
			profile[k] = v
		}
		e.do("PUT", "/api/pools/"+str(p["id"])+"/profile", profile, 422)
	}
}
