package guard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestVirtuaReplacementRecoversPaidOrderAndPinsNewHostKey(t *testing.T) {
	const zone = "par01fr"
	const oldServer = "35ef20dd-52e2-4747-bb27-86cefed78f74"
	const nodeID = "c37c3ffe-28e8-45e4-9f35-987e22808de3"
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	operation := testVirtuaOrderID
	snap := virtuaOrderSnapshot{operation, zone, "plan-a", "debian-13", "#!/bin/bash\n"}
	snapshot, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	plan := orderCloudPlan{Code: "plan-a", Name: "Plan A", Country: "FR", CPU: 1, MemoryMB: 1024, StorageGB: 20, Price: 0.02, Currency: "EUR"}
	catalogueReads, creates := 0, 0
	scriptPresent, listed, ready := true, false, false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		ok := func(v row) (*http.Response, error) { v["success"] = true; return response(v, 200), nil }
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/offers":
			catalogueReads++
			return ok(row{"currency": "EUR", "zones": []row{{"code": zone, "country": "FR", "state": "available"}},
				"plans": []row{{"name": "Plan A", "os_family": "linux", "vcpus": 1, "memory_mb": 1024, "disk_gb": 20, "price_hour": "0.02",
					"zones": []row{{"code": zone, "offer_id": "plan-a"}}}}})
		case "GET /v1/script":
			scripts := []row{}
			if scriptPresent {
				scripts = append(scripts, row{"uuid": testVirtuaScript, "name": snap.name(), "content": snap.Script})
			}
			return ok(row{"scripts": scripts})
		case "DELETE /v1/script":
			scriptPresent = false
			return ok(row{})
		case "GET /v1/cloud-server":
			servers := []row{}
			if listed {
				servers = append(servers, row{"uuid": testOrderVM, "label": snap.name()})
			}
			return ok(row{"cloud_servers": servers})
		case "POST /v1/cloud/order":
			creates++
			return nil, errors.New("lost response after charge")
		case "GET /v1/cloud-server/" + testOrderVM:
			return ok(row{"cloud_server": row{"uuid": testOrderVM, "is_setup": ready, "is_processing": !ready, "status": "running"}})
		case "GET /v1/network/cloud-server/" + testOrderVM + "/show":
			return ok(row{"ip_addresses": []row{{"address": orderOriginNew, "version": 4}}})
		case "GET /v1/cloud-server/" + oldServer:
			return ok(row{"cloud_server": row{"uuid": oldServer, "is_processing": false}})
		case "GET /v1/network/cloud-server/" + oldServer + "/show":
			return ok(row{"ip_addresses": []row{{"address": orderOriginOld, "version": 4}}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}
	app, err := New(testConfig(filepath.Join(t.TempDir(), "test.sqlite")), Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	s, w := app.s, app.replacements
	s.set("virtua_token", "test-key")
	s.exec("INSERT INTO pools(id,hostname,zone_id,ttl,automation_enabled) VALUES('pool','vpn.example.com','zone',120,1)")
	s.exec("INSERT INTO targets(id,pool_id,ip,remnawave_uuid) VALUES('target','pool',?,?)", orderOriginOld, nodeID)
	s.exec("INSERT INTO sessions(token,username,expires) VALUES(?,'admin',?)", digest("session"), nowSeconds()+300)

	binding, _ := json.Marshal(row{"provider": "virtua", "server_uuid": oldServer, "remnawave_uuid": nodeID, "enabled": true,
		"virtua_zone": zone, "virtua_quote": orderPlanChoice(zone, plan).ID, "virtua_group": "nodes", "virtua_domain": orderOriginDNS})
	req := httptest.NewRequest(http.MethodPut, "/api/replacements/targets/target", strings.NewReader(string(binding)))
	req.AddCookie(&http.Cookie{Name: "dns_guard_session", Value: "session"})
	req.Header.Set("X-Requested-With", "DNSGuard")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("binding could not be saved", rec.Code, rec.Body.String())
	}
	s.exec(`INSERT INTO replacement_jobs(id,target_id,pool_id,name,provider,server_uuid,node_uuid,old_ip,stage,snapshot,enroll_digest,created_at,updated_at)
 VALUES(?,'target','pool','Test node','virtua',?,?,?,'provision',?,?,?,?)`, operation, oldServer, nodeID, orderOriginOld, s.cipher.encrypt(snapshot), digest(strings.Repeat("a", 43)), iso(fromSeconds(nowSeconds())), iso(fromSeconds(nowSeconds())))
	job := func() row { return s.one("SELECT * FROM replacement_jobs WHERE id=?", operation) }
	if err := w.step(job()); err == nil || creates != 1 || !truth(job()["create_attempted"]) {
		t.Fatalf("expected a single unresolved charge: %v, creates=%d", err, creates)
	}
	if err := w.step(job()); !errors.Is(err, errReplacementCreateUnconfirmed) || creates != 1 || catalogueReads != 1 {
		t.Fatalf("unconfirmed charge was retried or re-quoted: %v, creates=%d, quotes=%d", err, creates, catalogueReads)
	}
	listed = true
	if err := w.step(job()); !errors.Is(err, errReplacementPending) || job()["new_server_uuid"] != testOrderVM {
		t.Fatalf("server UUID was not persisted before IP was ready: %v", err)
	}
	listed, ready = false, true
	if err := w.step(job()); err != nil || job()["stage"] != "enrollment" || job()["new_ip"] != orderOriginNew {
		t.Fatalf("could not resume by the saved UUID: %v", err)
	}
	enroll := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/server-orders/"+operation+"/enroll", strings.NewReader(`{"host_key":"`+key+`"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if enroll(strings.Repeat("b", 43)) != http.StatusUnauthorized || enroll(strings.Repeat("a", 43)) != http.StatusOK {
		t.Fatal("replacement enrollment did not require its own credential")
	}
	if err := w.step(job()); err != nil || scriptPresent || job()["stage"] != "ansible" || job()["host_key"] != key ||
		job()["snapshot"] != nil || job()["enroll_digest"] != nil {
		t.Fatalf("server identity or script cleanup did not survive enrollment: %v", err)
	}
}

func TestVirtuaReplacementDeletesOnlyConfirmedOldServer(t *testing.T) {
	ip, deleted, networkFound, deletes := orderOriginNew, false, true, 0
	c := &virtuaOrder{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/cloud-server/" + testOrderVM:
			if deleted {
				return response(row{"success": false, "error": "cloud_server_not_found"}, http.StatusNotFound), nil
			}
			return response(row{"success": true, "cloud_server": row{"uuid": testOrderVM, "is_processing": false}}, 200), nil
		case "GET /v1/network/cloud-server/" + testOrderVM + "/show":
			if !networkFound {
				return response(row{"success": false}, http.StatusNotFound), nil
			}
			return response(row{"success": true, "ip_addresses": []row{{"address": ip, "version": 4}}}, 200), nil
		case "DELETE /v1/cloud-server/" + testOrderVM:
			deletes++
			deleted = true
			return nil, errors.New("lost response after deletion")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}}
	if err := c.deleteReplacementServer(t.Context(), testOrderVM, orderOriginOld); err == nil || deletes != 0 {
		t.Fatal("deleted a server with a mismatched address", err)
	}
	ip, networkFound = orderOriginOld, false
	if err := c.deleteReplacementServer(t.Context(), testOrderVM, orderOriginOld); err == nil || deletes != 0 {
		t.Fatal("network 404 must not be treated as VM deletion", err)
	}
	networkFound = true
	if err := c.deleteReplacementServer(t.Context(), testOrderVM, orderOriginOld); err == nil || deletes != 1 {
		t.Fatal("expected an unconfirmed deletion", err)
	}
	if err := c.deleteReplacementServer(t.Context(), testOrderVM, orderOriginOld); err != nil || deletes != 1 {
		t.Fatal("could not reconcile the previous deletion", err)
	}
}

func TestVirtuaReplacementCleanupWaitsForBothDNSChangesAndTTL(t *testing.T) {
	const targetID = "target"
	const poolDomain = "vpn.example.com"
	oldPoolPresent, newPoolPresent := true, false
	originIP := orderOriginOld
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		records := []row{}
		switch r.URL.Path {
		case "/client/v4/zones":
			records = append(records, row{"id": "zone", "name": "example.com"})
		case "/client/v4/zones/zone/dns_records":
			record := func(id, name, ip string) row {
				return row{"id": id, "name": name, "type": "A", "content": ip, "ttl": 120, "proxied": false}
			}
			switch r.URL.Query().Get("name") {
			case orderOriginDNS:
				records = append(records, record("origin", orderOriginDNS, originIP))
			case poolDomain:
				if oldPoolPresent {
					records = append(records, record("old", poolDomain, orderOriginOld))
				}
				if newPoolPresent {
					records = append(records, record("new", poolDomain, orderOriginNew))
				}
			default:
				t.Fatal("unexpected DNS hostname", r.URL)
			}
		default:
			t.Fatal("unexpected DNS request", r.Method, r.URL)
		}
		return response(row{"success": true, "result": records}, http.StatusOK), nil
	})}
	app, err := New(testConfig(filepath.Join(t.TempDir(), "test.sqlite")), Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	s := app.s
	s.exec("INSERT INTO pools(id,hostname,zone_id,ttl) VALUES('pool',?,'zone',120)", poolDomain)
	s.exec("INSERT INTO targets(id,pool_id,ip) VALUES(?,'pool',?)", targetID, orderOriginNew)
	s.exec("INSERT INTO replacement_bindings(target_id,provider,server_uuid,node_uuid,enabled,virtua_domain) VALUES(?,'virtua','old-vps','node',1,?)", targetID, orderOriginDNS)
	stamp := iso(fromSeconds(nowSeconds()))
	s.exec(`INSERT INTO replacement_jobs(id,target_id,pool_id,name,provider,server_uuid,node_uuid,old_ip,new_ip,new_server_uuid,stage,created_at,updated_at)
 VALUES('job',?,'pool','Test node','virtua','old-vps','node',?,?,'new-vps','cleanup',?,?)`, targetID, orderOriginOld, orderOriginNew, stamp, stamp)
	job := func() row { return s.one("SELECT * FROM replacement_jobs WHERE id='job'") }
	releases := 0
	cleanup := func() error {
		return app.replacements.cleanup(job(), func() error { releases++; return nil })
	}
	if err := cleanup(); err == nil || releases != 0 {
		t.Fatal("released VPS before switching the origin record", err)
	}
	originIP = orderOriginNew
	if err := cleanup(); err == nil || releases != 0 || num(job()["release_after"]) <= nowSeconds() {
		t.Fatal("old pool record did not block release or extend TTL", err)
	}
	oldPoolPresent, newPoolPresent = false, true
	if err := cleanup(); err != nil || releases != 0 {
		t.Fatal("released VPS before TTL expired", err)
	}
	s.exec("UPDATE replacement_jobs SET release_after=0 WHERE id='job'")
	newPoolPresent = false
	if err := cleanup(); err == nil || releases != 0 {
		t.Fatal("released VPS while the new IP was absent from the pool", err)
	}
	newPoolPresent = true
	if err := cleanup(); err != nil || releases != 1 || job()["stage"] != "complete" ||
		s.one("SELECT server_uuid FROM replacement_bindings WHERE target_id=?", targetID)["server_uuid"] != "new-vps" {
		t.Fatal("confirmed cutover did not complete or advance the binding", err)
	}
}
