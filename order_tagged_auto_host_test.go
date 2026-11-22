package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestServerOrderPublishesTaggedAutoHostAfterChecks(t *testing.T) {
	const pool = "finland.example.com"
	const tag = "AUTO_CHEAP_NODE"
	const origin = "fi-02.finland.example.com"
	var host row
	var creates, enables, deletes int
	inbound := row{"configProfileUuid": orderPanelProfileID, "configProfileInboundUuid": orderPanelInbound}
	squads := row{"mode": "INCLUDE", "squads": []any{orderPanelOther}}
	source := row{"uuid": orderPanelHost, "remark": "Finland", "address": pool, "port": 443,
		"inbound": inbound, "nodes": []any{orderPanelNode}, "overrideSniFromAddress": true,
		"internalSquads": squads, "fingerprint": "firefox"}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method + " " + req.URL.Path {
		case "GET /client/v4/zones":
			return response(row{"success": true, "result": []row{{"id": "zone", "name": "example.com", "status": "active"}}}, 200), nil
		case "GET /client/v4/zones/zone/dns_records":
			if req.URL.Query().Get("name") != origin {
				t.Fatal("expected to verify the ordered node's dedicated origin")
			}
			return response(row{"success": true, "result": []row{{"id": "origin", "name": origin, "type": "A", "content": orderOriginNew,
				"proxied": false, "comment": "dns-guard-order:" + orderPanelID}}}, 200), nil
		case "GET /api/hosts":
			hosts := []row{source}
			if host != nil {
				hosts = append(hosts, host)
			}
			return response(row{"response": hosts}, 200), nil
		case "GET /api/hosts/" + orderPanelHost:
			return response(row{"response": source}, 200), nil
		case "GET /api/hosts/" + orderPanelEmpty:
			return response(row{"response": host}, 200), nil
		case "POST /api/hosts":
			creates++
			if err := json.NewDecoder(req.Body).Decode(&host); err != nil {
				t.Fatal(err)
			}
			if host["address"] != origin || host["isHidden"] != true || host["isDisabled"] != true ||
				host["sni"] != pool || host["fingerprint"] != "firefox" ||
				!reflect.DeepEqual(host["inbound"], map[string]any(inbound)) || !reflect.DeepEqual(host["internalSquads"], map[string]any(squads)) ||
				!reflect.DeepEqual(host["tags"], []any{tag}) || !reflect.DeepEqual(host["nodes"], []any{orderPanelNode}) {
				t.Fatalf("auto host did not inherit the order and pool settings: %v", host)
			}
			host["uuid"] = orderPanelEmpty
			return nil, errors.New("lost response after creating the host")
		case "PATCH /api/hosts":
			enables++
			var patch row
			if err := json.NewDecoder(req.Body).Decode(&patch); err != nil || patch["uuid"] != orderPanelEmpty || patch["isDisabled"] != false {
				t.Fatalf("unexpected Remnawave patch: %v", patch)
			}
			host["isDisabled"] = false
			return nil, errors.New("lost response after enabling the host")
		case "DELETE /api/hosts/" + orderPanelEmpty:
			deletes++
			host = nil
			return response(nil, 204), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})}
	config := testConfig(filepath.Join(t.TempDir(), "orders.db"))
	config.OrderAutoHostTag = tag
	config.RemnawaveURL, config.RemnawaveAPIToken = "https://order-panel.example.com", "panel-token"
	app, err := New(config, Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	s := app.s
	s.exec("INSERT INTO pools(id,hostname,zone_id,recovery_threshold) VALUES('pool',?,'zone',1)", pool)
	s.exec("INSERT INTO targets(id,pool_id,ip,remnawave_uuid) VALUES('target','pool',?,?)", orderOriginNew, orderPanelNode)
	s.exec(`INSERT INTO server_orders(id,request_id,selection_hash,pool_id,pool_hostname,zone_id,ttl,zone,country,plan,quote,group_name,
 profile_id,profile_name,inbounds,serial,alias,domain,created_at,updated_at,stage,server_uuid,node_uuid,ip,target_id)
 VALUES(?,?,'hash','pool',?,'zone',120,'fi-hel1','FI','plan','quote','nodes',?,'Finland',?,2,'fi-02',?,'time','time','verify',?,?,?,'target')`,
		orderPanelID, orderPanelID, pool, orderPanelProfileID, `["`+orderPanelInbound+`"]`, origin, orderPanelOldNode, orderPanelNode, orderOriginNew)
	order := func() row { return s.one("SELECT * FROM server_orders WHERE id=?", orderPanelID) }
	if err := app.orders.finish(order()); !errors.Is(err, errReplacementPending) || creates != 0 {
		t.Fatalf("created an auto host before the checkers confirmed readiness: %v", err)
	}
	s.exec("INSERT INTO agents(id,last_seen,healthy) VALUES('checker',?,1)", nowSeconds())
	s.exec("INSERT INTO target_checks(target_id,agent_id,successes,last_checked_at,outcome) VALUES('target','checker',1,?,1)", iso(time.Now()))
	if err := app.orders.finish(order()); err != nil {
		t.Fatal(err)
	}
	completed := order()
	if completed["stage"] != "complete" || completed["auto_host_uuid"] != orderPanelEmpty || creates != 1 || enables != 1 {
		t.Fatalf("order did not persist the published auto host: %v", completed)
	}
	panel, err := app.remnawaveProvider()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if id, err := panel.ensureTaggedOrderHost(ctx, completed, []string{orderPanelInbound}, tag); err != nil || id != orderPanelEmpty || creates != 1 || enables != 1 {
		t.Fatalf("existing auto host was not reused: %q, %v", id, err)
	}
	host["remark"] = "Unrelated host"
	if err := panel.deleteTaggedOrderHost(ctx, completed); err == nil || deletes != 0 {
		t.Fatalf("deleted a host with a conflicting identity: %v", err)
	}
	host["remark"] = taggedOrderHostRemark(orderPanelID)
	for range 2 {
		if err := panel.deleteTaggedOrderHost(ctx, completed); err != nil {
			t.Fatal(err)
		}
	}
	if deletes != 1 {
		t.Fatalf("auto host deletion count = %d, want 1", deletes)
	}
}
