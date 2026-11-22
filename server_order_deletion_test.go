package guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleteServerOrderProtectsPoolAndResumesAfterLostResponse(t *testing.T) {
	const (
		poolDomain = "vpn.example.com"
		autoDomain = "dns-guard-auto-de-01.vpn.example.com"
		newServer  = "123e4567-e89b-42d3-a456-426614174099"
		dnsPath    = "/client/v4/zones/zone/dns_records"
		serverPath = "/1.3/server/" + newServer
	)
	records := map[string]row{
		"pool-a": {"id": "pool-a", "name": poolDomain, "type": "A", "content": orderOriginNew, "proxied": false},
		"origin": {"id": "origin", "name": orderOriginDNS, "type": "A", "content": orderOriginNew, "proxied": false, "comment": "dns-guard-order:" + orderOriginID},
		"alias":  {"id": "alias", "name": autoDomain, "type": "CNAME", "content": orderOriginDNS, "proxied": false, "comment": "dns-guard-auto:" + orderPanelID},
	}
	var nodeDeletes, serverDeletes int
	serverState := "started"
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method + " " + req.URL.Path {
		case "GET " + dnsPath:
			found := []row{}
			for _, record := range records {
				if record["name"] == req.URL.Query().Get("name") {
					found = append(found, record)
				}
			}
			return response(row{"success": true, "result": found}, http.StatusOK), nil
		case "DELETE " + dnsPath + "/pool-a", "DELETE " + dnsPath + "/origin", "DELETE " + dnsPath + "/alias":
			id := strings.TrimPrefix(req.URL.Path, dnsPath+"/")
			if records[id] == nil {
				t.Fatalf("repeated deletion of DNS record %s", id)
			}
			delete(records, id)
			return response(row{"success": true, "result": row{"id": id}}, http.StatusOK), nil
		case "GET /api/nodes":
			nodes := []row{}
			if nodeDeletes == 0 {
				nodes = append(nodes, row{"uuid": orderPanelNode, "address": orderOriginNew})
			}
			return response(row{"response": nodes}, http.StatusOK), nil
		case "DELETE /api/nodes/" + orderPanelNode:
			nodeDeletes++
			return nil, errors.New("lost response after node was deleted")
		case "GET " + serverPath:
			if serverState == "deleted" {
				return response(row{"error": row{"error_code": "SERVER_NOT_FOUND"}}, http.StatusNotFound), nil
			}
			return response(row{"server": row{"uuid": newServer, "state": serverState, "networking": row{"interfaces": row{
				"interface": []row{{"type": "public", "ip_addresses": row{"ip_address": []row{{"family": "IPv4", "address": orderOriginNew}}}}},
			}}}}, http.StatusOK), nil
		case "POST " + serverPath + "/stop":
			serverState = "stopped"
			return response(nil, http.StatusAccepted), nil
		case "DELETE " + serverPath:
			if serverState != "stopped" || req.URL.Query().Get("storages") != "1" || req.URL.Query().Get("backups") != "keep" {
				t.Fatal("expected deletion of the stopped server and its disks with backups preserved")
			}
			serverDeletes++
			serverState = "deleted"
			return response(nil, http.StatusNoContent), nil
		default:
			t.Fatalf("unexpected provider request %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})}
	app, err := New(testConfig(filepath.Join(t.TempDir(), "orders.db")), Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	s := app.s
	s.set("upcloud_token", "fixture")
	s.set("remnawave_url", "https://panel.example.com")
	s.set("remnawave_api_token", "fixture")
	s.exec("INSERT INTO sessions(token,username,expires) VALUES(?,'admin',?)", digest("session"), nowSeconds()+300)
	s.exec("INSERT INTO pools(id,hostname,zone_id) VALUES('pool',?,'zone')", poolDomain)
	s.exec("INSERT INTO targets(id,pool_id,ip,remnawave_uuid) VALUES('target','pool',?,?)", orderOriginNew, orderPanelNode)
	s.exec(`INSERT INTO server_orders(id,request_id,selection_hash,pool_id,pool_hostname,zone_id,ttl,zone,country,plan,quote,group_name,
 profile_id,profile_name,inbounds,serial,alias,domain,created_at,updated_at,stage,server_uuid,node_uuid,ip,target_id)
 VALUES(?,?,'hash','pool',?,'zone',120,'de-fra1','DE','plan','quote','nodes','profile','name','[]',1,'de-01',?,'time','time','complete',?,?,?,'target')`,
		orderOriginID, orderOriginID, poolDomain, orderOriginDNS, orderPanelID, orderPanelNode, orderOriginOld)
	s.exec(`INSERT INTO replacement_jobs (id,target_id,pool_id,name,provider,server_uuid,node_uuid,old_ip,new_server_uuid,new_ip,stage,created_at,updated_at)
 VALUES('replacement','target','pool','node','upcloud',?,?,?, ?,?,'complete','time','time')`, orderPanelID, orderPanelNode, orderOriginOld, newServer, orderOriginNew)
	s.exec(`INSERT INTO server_order_auto_hosts(country,slot,pool_id,hostname,zone_id,source_uuid,host_uuid,profile_id,inbound_id,port,order_id)
 VALUES('DE',1,'pool',?,'zone','source',?,'profile','inbound',443,?)`, autoDomain, orderPanelID, orderOriginID)
	request := func(body string, status int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "/api/server-orders/"+orderOriginID, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "dns_guard_session", Value: "session"})
		req.Header.Set("X-Requested-With", "DNSGuard")
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("DELETE %s returned %d: %s", body, rec.Code, rec.Body.String())
		}
	}
	order := func() row { return s.one("SELECT * FROM server_orders WHERE id=?", orderOriginID) }
	const all = `{"hosting":true,"remnawave":true,"dns":true}`
	request(`{"hosting":false,"remnawave":false,"dns":false}`, http.StatusUnprocessableEntity)
	request(all, http.StatusOK)
	app.orders.runOnce()
	if len(records) != 3 || order()["stage"] != "complete" || !strings.Contains(str(order()["error"]), "Последняя A-запись") || nodeDeletes != 0 || serverDeletes != 0 {
		t.Fatal("final A record did not prevent deletion", order())
	}

	records["fallback"] = row{"id": "fallback", "name": poolDomain, "type": "A", "content": "1.1.1.1", "proxied": false}
	const withoutHosting = `{"hosting":false,"remnawave":true,"dns":true}`
	request(withoutHosting, http.StatusOK)
	request(withoutHosting, http.StatusOK)
	app.orders.runOnce()
	app.orders.runOnce()
	if nodeDeletes != 1 || order()["error"] == nil || num(order()["deleted_resources"]) != orderDeleteDNS {
		t.Fatal("DNS completion or the failed Remnawave response was not persisted", order())
	}
	s.exec("UPDATE server_orders SET next_retry=0")
	app.orders.runOnce()
	if order()["stage"] != "complete" || num(order()["deleted_resources"]) != orderDeleteDNS|orderDeleteRemnawave ||
		nodeDeletes != 1 || serverState != "started" || len(records) != 1 || records["fallback"] == nil ||
		s.one("SELECT id FROM targets WHERE id='target'") != nil || app.orders.autoHost(orderOriginID) != nil {
		t.Fatal("unexpected state after partial deletion", order())
	}

	request(all, http.StatusOK)
	for range 3 {
		s.exec("UPDATE server_orders SET next_retry=0")
		app.orders.runOnce()
	}
	request(all, http.StatusOK)
	if order()["stage"] != "deleted" || num(order()["deleted_resources"]) != orderDeleteAll || nodeDeletes != 1 || serverDeletes != 1 {
		t.Fatal("hosting deletion did not finish using the replacement server UUID", order())
	}
}
