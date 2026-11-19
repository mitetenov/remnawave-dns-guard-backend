package guard

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

const (
	orderOriginID  = "27defb13-fc88-4cd4-9b03-193b25315975"
	orderOriginDNS = "node.vpn.example.com"
	orderOriginOld = "8.8.8.8"
	orderOriginNew = "8.8.4.4"
)

func orderOriginJob() row {
	return row{"id": orderOriginID, "domain": orderOriginDNS, "zone_id": "zone", "ttl": 120}
}

func TestOrderOriginCreateAndReplaceVerifyOnlyOwnedRecord(t *testing.T) {
	var record row
	creates, patches := 0, 0
	c := &Cloudflare{"fixture-token", providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Fatal("unexpected auth")
		}
		switch req.Method + " " + req.URL.Path {
		case "GET /client/v4/zones":
			return response(row{"success": true, "result": []row{{"id": "zone", "name": "example.com"}}}, 200), nil
		case "GET /client/v4/zones/zone/dns_records":
			if req.URL.Query().Get("name") != orderOriginDNS {
				t.Fatal("unscoped DNS query")
			}
			records := []row{{"id": "txt", "type": "TXT", "name": orderOriginDNS, "content": "unrelated verification"}}
			if record != nil {
				records = append(records, record)
			}
			return response(row{"success": true, "result": records}, 200), nil
		case "POST /client/v4/zones/zone/dns_records":
			creates++
			if err := json.NewDecoder(req.Body).Decode(&record); err != nil || record["name"] != orderOriginDNS ||
				record["comment"] != "dns-guard-order:"+orderOriginID || record["type"] != "A" ||
				record["content"] != orderOriginOld || record["proxied"] != false || num(record["ttl"]) != 120 {
				t.Fatal("unexpected DNS creation", record, err)
			}
			record["id"] = "managed-record"
			return nil, errors.New("lost response after Cloudflare created the record")
		case "PATCH /client/v4/zones/zone/dns_records/managed-record":
			patches++
			var body row
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body) != 1 || body["content"] != orderOriginNew {
				t.Fatal("replacement must only change the address of the owned record", body, err)
			}
			record["content"] = body["content"]
			return nil, errors.New("lost response after Cloudflare updated the record")
		default:
			t.Fatal("unexpected cloud operation", req.Method, req.URL.Path)
			return nil, nil
		}
	})})}
	j := orderOriginJob()
	if ttl, err := c.checkOrderOrigin(j, "", "", false); ttl != 0 || err != nil {
		t.Fatal("free-name preflight failed", ttl, err)
	}
	if _, err := c.checkOrderOrigin(j, "", orderOriginOld, false); err == nil {
		t.Fatal("read-only verification accepted a missing origin")
	}
	for range 2 {
		if ttl, err := c.checkOrderOrigin(j, "", orderOriginOld, true); ttl != 120 || err != nil {
			t.Fatal("owned origin was not confirmed", ttl, err)
		}
	}
	if ttl, err := c.checkOrderOrigin(j, orderOriginOld, "", false); ttl != 120 || err != nil {
		t.Fatal("old origin was not confirmed", ttl, err)
	}
	if _, err := c.checkOrderOrigin(j, "1.1.1.1", orderOriginNew, true); err == nil {
		t.Fatal("stale replacement switched the origin")
	}
	record["ttl"] = float64(1)
	for range 2 {
		if ttl, err := c.checkOrderOrigin(j, orderOriginOld, orderOriginNew, true); ttl != 300 || err != nil {
			t.Fatal("replacement was not confirmed with a conservative automatic TTL", ttl, err)
		}
	}
	if ttl, err := c.checkOrderOrigin(j, "", orderOriginNew, false); ttl != 300 || err != nil {
		t.Fatal("new origin verification failed", ttl, err)
	}
	if creates != 1 || patches != 1 {
		t.Fatal("DNS mutations were not idempotent", creates, patches)
	}
}

func TestOrderOriginRejectsConflictsAndWrongZone(t *testing.T) {
	for _, conflict := range []string{"A", "AAAA", "CNAME", "NS", "proxied", "duplicates", "wrong zone", "more specific zone", "inactive zone"} {
		t.Run(conflict, func(t *testing.T) {
			conflictingRecord := row{"id": "conflicting", "name": orderOriginDNS, "type": conflict, "content": orderOriginNew, "proxied": false}
			zones := []row{{"id": "zone", "name": "example.com"}}
			switch conflict {
			case "proxied", "duplicates":
				conflictingRecord["type"] = "A"
				conflictingRecord["proxied"] = conflict == "proxied"
				conflictingRecord["comment"] = "dns-guard-order:" + orderOriginID
			case "wrong zone":
				zones[0]["name"] = "unrelated.com"
			case "more specific zone":
				zones = append(zones, row{"id": "subzone", "name": "vpn.example.com"})
			case "inactive zone":
				zones[0]["status"] = "pending"
			}
			rows := []row{conflictingRecord}
			if conflict == "duplicates" {
				rows = append(rows, conflictingRecord)
			}
			c := &Cloudflare{"token", providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Fatal("unexpected mutation of conflicting origin")
				}
				if req.URL.Path == "/client/v4/zones" {
					return response(row{"success": true, "result": zones}, 200), nil
				}
				if conflict == "wrong zone" || conflict == "more specific zone" || conflict == "inactive zone" {
					t.Fatal("queried records in an ineligible zone")
				}
				return response(row{"success": true, "result": rows}, 200), nil
			})})}
			if _, err := c.checkOrderOrigin(orderOriginJob(), "", orderOriginNew, true); err == nil {
				t.Fatal("accepted conflicting existing record or zone")
			}
		})
	}
}
