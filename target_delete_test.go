package guard

import (
	"strings"
	"testing"
)

func TestDeleteTargetRetainsDNSByDefaultOrExplicitFalse(t *testing.T) {
	for _, query := range []string{"", "?delete_dns=false"} {
		t.Run(query, func(t *testing.T) {
			e := newTestEnv(t)
			p, targets := e.setup(1, true, 1, 1)
			id := str(targets[0]["id"])
			job := e.poll(true, "ru-1")[0]
			e.app.s.mu.Lock()
			e.app.reconciler.queueLocked(id, "auto_remove")
			e.app.s.mu.Unlock()
			calls := e.fake.callCount()
			e.do("DELETE", "/api/targets/"+id+query, nil, 200)
			if len(e.targets(p)) != 0 || e.one("SELECT id FROM jobs WHERE target_id=?", id) != nil || e.fake.size() != 1 || e.fake.callCount() != calls {
				t.Fatal("local deletion changed DNS or left a probe job")
			}
			if e.result(job, false, "ru-1", "connection_failed") != 0 {
				t.Fatal("deleted target accepted a stale probe")
			}
			e.restart(false)
			e.app.RunOnce()
			if len(e.targets(p)) != 0 || len(e.poll(true, "ru-1")) != 0 || e.fake.size() != 1 {
				t.Fatal("deleted target returned to monitoring or removed DNS after restart")
			}
			event := e.one("SELECT * FROM events WHERE target_id=? AND message LIKE 'Target removed:%'", id)
			if event == nil || !strings.Contains(str(event["message"]), "Cloudflare DNS records retained") {
				t.Fatal("missing DNS-retaining deletion audit", event)
			}
			e.do("DELETE", "/api/targets/"+id+query, nil, 404)
		})
	}
}

func TestDeleteTargetWithoutDNSDoesNotRequireCloudflare(t *testing.T) {
	e := newTestEnv(t)
	_, targets := e.setup(1, false, 1, 1)
	e.app.s.mu.Lock()
	e.app.s.set("cloudflare_api_token", "")
	e.app.s.mu.Unlock()
	e.fake.setFail("get")
	calls := e.fake.callCount()
	e.do("DELETE", "/api/targets/"+str(targets[0]["id"]), nil, 200)
	if e.fake.callCount() != calls || e.fake.size() != 1 {
		t.Fatal("deletion required Cloudflare or changed its record")
	}
}

func TestDeleteTargetCancelsPendingIPReplacementWithoutDNSWrites(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(1, false, 1, 1)
	id := str(targets[0]["id"])
	e.fake.setFail("post")
	e.do("PATCH", "/api/targets/"+id, row{"ip": "4.2.2.2"}, 502)
	count, calls := e.fake.size(), e.fake.callCount()
	e.do("DELETE", "/api/targets/"+id+"?delete_dns=false", nil, 200)
	if e.fake.size() != count || e.fake.callCount() != calls || len(e.targets(p)) != 0 {
		t.Fatal("forgetting a replacement changed DNS or left intent")
	}
	e.fake.setFail("")
	e.app.RunOnce()
	if e.fake.size() != count || len(e.targets(p)) != 0 {
		t.Fatal("replacement retried after deletion")
	}
}

func TestLegacyPendingDeleteRetainsDNSAfterRestart(t *testing.T) {
	e := newTestEnv(t)
	_, targets := e.setup(1, false, 1, 1)
	id := str(targets[0]["id"])
	e.app.s.mu.Lock()
	e.app.reconciler.queueLocked(id, "delete")
	e.app.s.mu.Unlock()
	e.sql("UPDATE pools SET dns_next_check=?", nowSeconds()+dnsCheckSeconds)
	e.restart(false)
	calls := e.fake.callCount()
	e.app.RunOnce()
	if e.fake.size() != 1 || e.fake.callCount() != calls || e.one("SELECT id FROM targets WHERE id=?", id) != nil {
		t.Fatal("legacy deletion without explicit DNS choice changed Cloudflare")
	}
}

func TestDeleteTargetDNSRequiresExplicitTrue(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(2, false, 1, 1)
	e.fake.add("9.9.9.9", "other.example.com", "A", false)
	e.do("DELETE", "/api/targets/"+str(targets[0]["id"])+"?delete_dns=true", nil, 200)
	if got := e.targets(p); len(got) != 1 || got[0]["id"] != targets[1]["id"] || e.fake.size() != 2 {
		t.Fatal("explicit DNS removal did not retain unrelated records", got)
	}
	e.do("DELETE", "/api/targets/"+str(targets[1]["id"])+"?delete_dns=true", nil, 409)
	if len(e.targets(p)) != 1 || e.fake.size() != 2 {
		t.Fatal("final actual A record protection was bypassed")
	}
}

func TestDeleteTargetRejectsAmbiguousDNSChoice(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(1, false, 1, 1)
	calls := e.fake.callCount()
	for _, query := range []string{"?delete_dns=", "?delete_dns=1", "?delete_dns=True", "?delete_dns=null", "?delete_dns=true&delete_dns=false"} {
		e.do("DELETE", "/api/targets/"+str(targets[0]["id"])+query, nil, 422)
	}
	if len(e.targets(p)) != 1 || e.fake.callCount() != calls || e.fake.size() != 1 {
		t.Fatal("invalid deletion option changed target or DNS")
	}
}
