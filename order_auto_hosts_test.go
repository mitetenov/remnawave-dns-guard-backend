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

func TestOrderAutoHostsReserveAndKeepSubscriptionAddress(t *testing.T) {
	const poolDomain = "vpn.example.com"
	const autoDomain = "dns-guard-auto-de-01." + poolDomain
	const dnsPath = "/client/v4/zones/zone/dns_records"
	hosts := []row{{"uuid": orderPanelHost, "address": poolDomain, "port": 443, "remark": "Pool host",
		"inbound": row{"configProfileUuid": orderPanelProfileID, "configProfileInboundUuid": orderPanelInbound},
		"path":    "/connection/", "overrideSniFromAddress": true, "nodes": []string{orderPanelOldNode}}}
	records := map[string]row{}
	hostCreates, aliasWrites := 0, 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method + " " + req.URL.Path {
		case "GET /api/hosts":
			return response(row{"response": hosts}, 200), nil
		case "POST /api/hosts":
			var host row
			if err := json.NewDecoder(req.Body).Decode(&host); err != nil || host["isHidden"] != true || host["isDisabled"] != false ||
				host["sni"] != poolDomain || host["path"] != "/connection/" || host["nodes"] != nil {
				t.Fatal("unexpected hidden host creation", host, err)
			}
			host["uuid"] = uid()
			hosts = append(hosts, host)
			hostCreates++
			if hostCreates == 1 {
				return nil, errors.New("lost response after creating the first host")
			}
			return response(row{"response": host}, 201), nil
		case "GET /client/v4/zones":
			return response(row{"success": true, "result": []row{{"id": "zone", "name": "example.com"}}}, 200), nil
		case "GET " + dnsPath:
			found := []row{}
			if record := records[req.URL.Query().Get("name")]; record != nil {
				found = append(found, record)
			}
			return response(row{"success": true, "result": found}, 200), nil
		case "POST " + dnsPath:
			var record row
			if err := json.NewDecoder(req.Body).Decode(&record); err != nil || record["name"] != autoDomain || record["type"] != "CNAME" ||
				record["proxied"] != false || record["content"] != orderOriginDNS {
				t.Fatal("unexpected alias creation", record, err)
			}
			aliasWrites++
			record["id"] = "alias"
			records[autoDomain] = record
			return nil, errors.New("lost response after writing the alias")
		case "PATCH " + dnsPath + "/origin":
			var patch row
			if err := json.NewDecoder(req.Body).Decode(&patch); err != nil || len(patch) != 1 || patch["content"] != orderOriginNew {
				t.Fatal("unexpected replacement change", patch, err)
			}
			records[orderOriginDNS]["content"] = patch["content"]
			return response(row{"success": true, "result": records[orderOriginDNS]}, 200), nil
		default:
			if req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/api/hosts/") {
				for _, host := range hosts {
					if req.URL.Path == "/api/hosts/"+str(host["uuid"]) {
						return response(row{"response": host}, 200), nil
					}
				}
			}
			t.Fatalf("unexpected request %s %s", req.Method, req.URL)
			return nil, nil
		}
	})}
	app, err := New(testConfig(filepath.Join(t.TempDir(), "orders.db")), Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	s := app.s
	s.set("remnawave_url", "https://panel.example.com")
	s.set("remnawave_api_token", "test-token")
	s.exec("INSERT INTO pools(id,hostname,zone_id,ttl) VALUES('pool',?,'zone',120)", poolDomain)
	s.exec("INSERT INTO sessions(token,username,expires) VALUES(?,'admin',?)", digest("admin-session"), nowSeconds()+300)

	setup := func(country string, status int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/server-orders/auto-hosts/"+country,
			strings.NewReader(`{"pool_id":"pool","source_uuid":"`+orderPanelHost+`"}`))
		req.AddCookie(&http.Cookie{Name: "dns_guard_session", Value: "admin-session"})
		req.Header.Set("X-Requested-With", "DNSGuard")
		req.Header.Set("Origin", "http://testserver")
		res := httptest.NewRecorder()
		app.Handler().ServeHTTP(res, req)
		if res.Code != status {
			t.Fatalf("setup returned %d, wanted %d: %s", res.Code, status, res.Body.String())
		}
	}
	conflictDomain := "dns-guard-auto-fi-10." + poolDomain
	records[conflictDomain] = row{"id": "foreign", "name": conflictDomain, "type": "A", "content": orderOriginOld}
	setup("FI", http.StatusConflict)
	if hostCreates != 0 {
		t.Fatal("setup mutated Remnawave before checking all reserved names")
	}
	delete(records, conflictDomain)
	setup("FI", http.StatusOK)
	setup("DE", http.StatusOK)
	setup("DE", http.StatusOK)
	if hostCreates != 20 || len(s.all("SELECT * FROM server_order_auto_hosts")) != 20 || len(records) != 0 {
		t.Fatal("setup did not reserve exactly 20 idle slots, or recreated one on retry")
	}
	if _, err = s.freeOrderAutoHost("pool", "DE", orderPanelOther); err == nil {
		t.Fatal("accepted an incompatible profile")
	}
	first, err := s.freeOrderAutoHost("pool", "DE", orderPanelProfileID)
	if err != nil || first["hostname"] != autoDomain {
		t.Fatal("first free slot is unavailable", err)
	}
	s.exec(`INSERT INTO server_orders(id,request_id,selection_hash,pool_id,pool_hostname,zone_id,ttl,zone,country,plan,quote,
 group_name,profile_id,profile_name,inbounds,serial,alias,domain,created_at,updated_at)
 VALUES(?,?,'hash','pool',?,'zone',120,'de-fra1','DE','plan','quote','nodes',?,'profile','[]',1,'de-01',?,'time','time')`,
		orderOriginID, orderOriginID, poolDomain, orderPanelProfileID, orderOriginDNS)
	s.exec("UPDATE server_order_auto_hosts SET order_id=? WHERE hostname=?", orderOriginID, autoDomain)
	second, err := s.freeOrderAutoHost("pool", "DE", orderPanelProfileID)
	if err != nil || num(second["slot"]) != 2 {
		t.Fatal("concurrent order would reuse a reserved slot", err)
	}
	records[orderOriginDNS] = row{"id": "origin", "name": orderOriginDNS, "type": "A", "proxied": false,
		"content": orderOriginOld, "comment": "dns-guard-order:" + orderOriginID, "ttl": 120}
	hosts[0]["nodes"] = []string{orderPanelNode}
	s.exec("INSERT INTO targets(id,pool_id,ip) VALUES('target','pool',?)", orderOriginOld)
	s.exec("UPDATE server_orders SET stage='verify',target_id='target',server_uuid=?,node_uuid=?,ip=?,inbounds=? WHERE id=?",
		orderPanelID, orderPanelNode, orderOriginOld, `["`+orderPanelInbound+`"]`, orderOriginID)
	order := s.one("SELECT * FROM server_orders WHERE id=?", orderOriginID)
	if err = app.orders.finish(order); !errors.Is(err, errReplacementPending) || aliasWrites != 0 {
		t.Fatal("published before the fresh health checks", err)
	}
	now := nowSeconds()
	s.exec("INSERT INTO agents(id,last_seen,healthy) VALUES('checker',?,1)", now)
	s.exec("INSERT INTO target_checks(target_id,agent_id,outcome,successes,last_checked_at) VALUES('target','checker',1,5,?)", iso(fromSeconds(now)))
	if err = app.orders.finish(order); err != nil || s.one("SELECT stage FROM server_orders WHERE id=?", orderOriginID)["stage"] != "complete" {
		t.Fatal("verified order failed to activate the auto host", err)
	}
	dns, _ := app.dnsProvider()
	if err = dns.pointOrderAutoHost(first, order); err != nil {
		t.Fatal("replaying the alias write failed", err)
	}
	if _, err = checkReplacementOrigin(dns, order, orderOriginOld, orderOriginNew, true); err != nil {
		t.Fatal(err)
	}
	if aliasWrites != 1 || records[autoDomain]["content"] != orderOriginDNS || records[orderOriginDNS]["content"] != orderOriginNew {
		t.Fatal("cutover did not preserve the hostname and update the origin A")
	}
	s.exec("DELETE FROM targets WHERE id='target'")
	first, err = s.freeOrderAutoHost("pool", "DE", orderPanelProfileID)
	if err != nil || first["hostname"] != autoDomain {
		t.Fatal("removed target did not free its slot", err)
	}
}
