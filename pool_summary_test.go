package guard

import "testing"

func expectPoolSummary(t *testing.T, e *testEnv, pool row, active, total int, status string) {
	t.Helper()
	for _, item := range asRows(e.do("GET", "/api/pools", nil, 200)) {
		if item["id"] == pool["id"] {
			summary := asRow(item["target_summary"])
			if int(num(summary["active"])) != active || int(num(summary["total"])) != total || summary["status"] != status {
				t.Fatalf("summary=%v, want %d/%d %s", summary, active, total, status)
			}
			return
		}
	}
	t.Fatal("pool missing from list", pool["id"])
}

func TestPoolSummaryUsesDNSMembershipAndFreshProbeStatuses(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(3, false, 1, 1)
	empty := asRow(e.do("POST", "/api/pools", row{"name": "Empty", "hostname": "empty.example.com", "zone_id": "zone"}, 200))
	expectPoolSummary(t, e, p, 3, 3, "unknown")
	expectPoolSummary(t, e, empty, 0, 0, "unknown")
	e.round(p, true, "")
	expectPoolSummary(t, e, p, 3, 3, "healthy")
	e.do("POST", "/api/pools/"+str(p["id"])+"/check", nil, 200)
	for _, job := range e.poll(true, "ru-1") {
		e.result(job, job["target_id"] != targets[0]["id"], "ru-1", "connection_failed")
	}
	// A failed node still serves DNS while automation is paused.
	expectPoolSummary(t, e, p, 3, 3, "suspect")
	// A known warning takes precedence over missing data on another active node.
	e.sql("UPDATE targets SET last_checked_at=NULL,status='unknown' WHERE id=?", targets[1]["id"])
	expectPoolSummary(t, e, p, 3, 3, "suspect")
	e.round(p, true, "")
	e.do("POST", "/api/targets/"+str(targets[0]["id"])+"/disable", nil, 200)
	expectPoolSummary(t, e, p, 2, 3, "healthy")
	// Freshness must match the statuses returned inside the pool.
	e.sql("UPDATE agents SET last_seen=?", nowSeconds()-controlFreshSeconds-1)
	expectPoolSummary(t, e, p, 2, 3, "unknown")
	for _, target := range e.targets(p) {
		if truth(target["manual_enabled"]) && target["status"] != "stale" {
			t.Fatal("detail status should be stale", target)
		}
	}
	e.round(p, true, "")
	e.sql("UPDATE targets SET last_checked_at='2000-01-01T00:00:00Z' WHERE id=?", targets[1]["id"])
	expectPoolSummary(t, e, p, 2, 3, "unknown")
	expectPoolSummary(t, e, empty, 0, 0, "unknown")
}

func TestPoolSummaryCountsAutomaticExclusionAndRecovery(t *testing.T) {
	e := newTestEnv(t)
	p, _ := e.setup(2, true, 1, 1)
	e.round(p, false, "connection_failed")
	// The final A record remains active and its protected status is a warning.
	expectPoolSummary(t, e, p, 1, 2, "suspect")
	e.round(p, true, "")
	expectPoolSummary(t, e, p, 2, 2, "healthy")
}

func TestPoolSummaryDoesNotCountUnconfirmedDNSAsActive(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(2, false, 1, 1)
	e.round(p, true, "")
	e.sql("UPDATE targets SET dns_uncertain=1 WHERE id=?", targets[0]["id"])
	e.sql("UPDATE targets SET dns_action='disable' WHERE id=?", targets[1]["id"])
	expectPoolSummary(t, e, p, 0, 2, "unknown")
	e.sql("UPDATE targets SET dns_present=0,dns_uncertain=0,dns_action=NULL,status='excluded'")
	expectPoolSummary(t, e, p, 0, 2, "excluded")
}
