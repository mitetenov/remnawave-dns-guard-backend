package guard

import (
	"net/http"
	"strings"
	"testing"
)

func TestDeletePoolRetainsDNSAndAuditButCancelsJobsAndRetries(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(2, true, 1, 1)
	jobs := e.poll(true, "ru-1")
	e.fake.setFail("post")
	e.do("PATCH", "/api/targets/"+str(targets[0]["id"]), row{"ip": "4.2.2.2"}, 502)
	count, calls := e.fake.size(), e.fake.callCount()
	e.do("DELETE", "/api/pools/"+str(p["id"]), nil, 200)
	if e.one("SELECT id FROM targets") != nil || e.one("SELECT id FROM jobs") != nil || e.one("SELECT id FROM pools") != nil {
		t.Fatal("pool deletion left managed targets, jobs or settings")
	}
	if e.fake.size() != count || e.fake.callCount() != calls {
		t.Fatal("pool deletion changed Cloudflare DNS")
	}
	for _, job := range jobs {
		if e.result(job, true, "ru-1", "") != 0 {
			t.Fatal("deleted pool accepted a probe result")
		}
	}
	if len(e.poll(true, "ru-1")) != 0 || e.fake.callCount() != calls {
		t.Fatal("deleted pool continued probing or DNS retries")
	}
	if event := e.one("SELECT * FROM events WHERE message LIKE 'Pool removed:%'"); event == nil || !strings.Contains(str(event["message"]), str(p["hostname"])) {
		t.Fatal("missing identifiable deletion audit event")
	}
	e.do("GET", "/api/pools/"+str(p["id"])+"/targets", nil, 404)
	e.do("DELETE", "/api/pools/"+str(p["id"]), nil, 404)
	e.do("POST", "/api/pools", row{"name": "Recreated", "hostname": p["hostname"], "zone_id": p["zone_id"]}, 200)
}

func TestDeletePoolIsScopedAndWorksWithoutCloudflare(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(1, false, 1, 1)
	other := asRow(e.do("POST", "/api/pools", row{"name": "Empty", "hostname": "other.example.com", "zone_id": "zone"}, 200))
	e.app.s.mu.Lock()
	e.app.s.set("cloudflare_api_token", "")
	e.app.s.mu.Unlock()
	calls := e.fake.callCount()
	e.do("DELETE", "/api/pools/"+str(other["id"]), nil, 200)
	if got := e.targets(p); len(got) != 1 || got[0]["id"] != targets[0]["id"] || e.fake.callCount() != calls {
		t.Fatal("deleting another pool affected existing targets")
	}
}

func TestRenameTargetPreservesProbeStateAndRemnawaveLink(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(1, false, 1, 1)
	id := str(targets[0]["id"])
	e.sql("UPDATE targets SET remnawave_uuid='node-uuid',failures=2,successes=3 WHERE id=?", id)
	job := e.poll(true, "ru-1")[0]
	calls := e.fake.callCount()
	out := asRow(e.do("PATCH", "/api/targets/"+id, row{"name": "  New name  "}, 200))
	if out["name"] != "New name" || num(out["failures"]) != 2 || num(out["successes"]) != 3 || out["remnawave_uuid"] != "node-uuid" || e.fake.callCount() != calls {
		t.Fatal(out)
	}
	if e.result(job, true, "ru-1", "") != 1 || e.targets(p)[0]["ip"] != targets[0]["ip"] {
		t.Fatal("rename invalidated the probe or changed IP")
	}
}

func TestReplaceFinalTargetIPConfirmsNewRecordBeforeRemovingOld(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(1, true, 1, 1)
	id := str(targets[0]["id"])
	job := e.poll(true, "ru-1")[0]
	e.sql("UPDATE targets SET successes=5,last_latency_ms=42,last_error='timeout',remnawave_uuid='rw-node' WHERE id=?", id)
	transport := e.app.client.Transport
	deletes := 0
	e.app.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodDelete {
			deletes++
			if e.fake.size() != 2 {
				t.Error("old IP removed before replacement existed")
			}
		}
		return transport.RoundTrip(req)
	})
	out := asRow(e.do("PATCH", "/api/targets/"+id, row{"name": "Replacement", "ip": "4.2.2.2"}, 200))
	if out["ip"] != "4.2.2.2" || out["name"] != "Replacement" || out["status"] != "unknown" || !truth(out["dns_present"]) || truth(out["dns_uncertain"]) || out["dns_pending_action"] != nil || out["remnawave_uuid"] != "rw-node" || deletes != 1 || e.fake.size() != 1 {
		t.Fatal(out)
	}
	if out["last_checked_at"] != nil || out["last_latency_ms"] != nil || out["last_error"] != nil || num(out["successes"]) != 0 || num(out["failures"]) != 0 {
		t.Fatal("old probe evidence carried to replacement IP", out)
	}
	if e.result(job, false, "ru-1", "timeout") != 0 {
		t.Fatal("old IP probe accepted")
	}
	jobs := e.poll(true, "ru-1")
	if len(jobs) != 1 || jobs[0]["ip"] != out["ip"] || jobs[0]["target_id"] != id || len(e.targets(p)) != 1 {
		t.Fatal("replacement lost identity or was not scheduled", jobs)
	}
}

func TestReplaceDisabledOrExcludedTargetDoesNotAddDNS(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "excluded"}[enabled], func(t *testing.T) {
			e := newTestEnv(t)
			p, targets := e.setup(2, false, 1, 1)
			id := str(targets[0]["id"])
			e.do("POST", "/api/targets/"+id+"/disable", nil, 200)
			if enabled {
				e.sql("UPDATE targets SET manual_enabled=1,status='excluded' WHERE id=?", id)
			}
			out := asRow(e.do("PATCH", "/api/targets/"+id, row{"ip": "4.2.2.2"}, 200))
			if truth(out["dns_present"]) || truth(out["manual_enabled"]) != enabled || out["status"] != map[bool]string{false: "disabled", true: "excluded"}[enabled] || e.fake.size() != 1 || len(e.targets(p)) != 2 {
				t.Fatal(out)
			}
		})
	}
}

func TestReplaceIPRetriesAfterUncertainProviderResponseAndRestart(t *testing.T) {
	for _, failure := range []string{"post", "delete"} {
		t.Run(failure, func(t *testing.T) {
			e := newTestEnv(t)
			p, targets := e.setup(1, true, 1, 1)
			id := str(targets[0]["id"])
			job := e.poll(true, "ru-1")[0]
			e.fake.setFail(failure)
			e.do("PATCH", "/api/targets/"+id, row{"ip": "4.2.2.2", "name": "New"}, 502)
			out := e.targets(p)[0]
			if out["ip"] != targets[0]["ip"] || out["dns_pending_action"] != "replace_ip" || !truth(out["dns_uncertain"]) || strings.Contains(str(out["dns_error"]), "hidden-token") {
				t.Fatal(out)
			}
			if len(e.poll(true, "ru-1")) != 0 || e.result(job, false, "ru-1", "timeout") != 0 {
				t.Fatal("probes were not suspended during replacement")
			}
			for _, method := range []string{"POST", "DELETE"} {
				path := "/api/targets/" + id
				if method == "POST" {
					path += "/enable"
				}
				e.do(method, path, nil, 409)
			}
			e.do("PATCH", "/api/targets/"+id, row{"ip": "9.9.9.9"}, 409)
			e.do("POST", "/api/pools/"+str(p["id"])+"/targets", row{"name": "Conflict", "ip": "4.2.2.2"}, 409)
			e.do("POST", "/api/pools/"+str(p["id"])+"/sync", nil, 200)
			if len(e.targets(p)) != 1 || num(e.one("SELECT dns_drift_count FROM pools WHERE id=?", p["id"])["dns_drift_count"]) != 0 {
				t.Fatal("sync adopted reserved replacement IP")
			}
			e.restart(false)
			e.fake.setFail("")
			e.sql("UPDATE targets SET dns_next_retry=0 WHERE id=?", id)
			e.app.RunOnce()
			out = e.targets(p)[0]
			if out["ip"] != "4.2.2.2" || out["name"] != "New" || out["dns_pending_action"] != nil || !truth(out["dns_present"]) || e.fake.size() != 1 {
				t.Fatal("replacement failed after restart", out)
			}
		})
	}
}

func TestTargetEditValidationAndPreflightLeaveOriginalIntact(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(2, false, 1, 1)
	path := "/api/targets/" + str(targets[0]["id"])
	calls := e.fake.callCount()
	for _, body := range []row{{"name": " "}, {"name": nil}, {"ip": nil}, {"ip": "127.0.0.1"}, {"ip": "192.168.1.1"}, {"ip": "hostname.example.com"}, {"pool_id": "other"}, {"manual_enabled": false}} {
		e.do("PATCH", path, body, 422)
	}
	e.do("PATCH", path, row{"ip": targets[1]["ip"]}, 409)
	if e.fake.callCount() != calls {
		t.Fatal("invalid edit touched DNS provider")
	}
	e.fake.setFail("get")
	e.do("PATCH", path, row{"name": "Changed", "ip": "4.2.2.2"}, 502)
	e.fake.setFail("")
	e.fake.add("2001:4860:4860::8888", str(p["hostname"]), "AAAA", true)
	e.do("PATCH", path, row{"ip": "4.2.2.2"}, 409)
	out := findTarget(e.targets(p), targets[0]["id"])
	if out["ip"] != targets[0]["ip"] || out["name"] != targets[0]["name"] || out["dns_pending_action"] != nil {
		t.Fatal("preflight changed original target", out)
	}
	e.do("PATCH", "/api/targets/missing", row{"name": "Name"}, 404)
}
