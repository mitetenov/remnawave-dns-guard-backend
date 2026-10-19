package guard

import "testing"

func TestManualCheckBeforeEnablingAutomation(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(3, false, 1, 1)
	id := str(p["id"])
	// One excluded node stays monitored, while a manually disabled node is skipped.
	e.do("POST", "/api/targets/"+str(targets[2]["id"])+"/disable", nil, 200)
	e.sql("UPDATE targets SET dns_present=0,status='excluded' WHERE id=?", targets[1]["id"])
	e.fake.mu.Lock()
	records := []row{}
	for _, record := range e.fake.records {
		if record["content"] != targets[1]["ip"] {
			records = append(records, record)
		}
	}
	e.fake.records = records
	e.fake.mu.Unlock()
	e.sql("UPDATE pools SET dns_next_check=? WHERE id=?", nowSeconds()+3600, id)
	e.sql("UPDATE targets SET next_due=?", nowSeconds()+3600)
	if jobs := e.poll(true, "ru-1"); len(jobs) != 0 {
		t.Fatal("targets should not be due before a manual request", jobs)
	}
	calls := e.fake.callCount()
	e.do("POST", "/api/pools/"+id+"/check", nil, 200)
	jobs := e.poll(true, "ru-1")
	if len(jobs) != 2 {
		t.Fatalf("expected present and excluded nodes, got %v", jobs)
	}
	for _, job := range jobs {
		if job["target_id"] == targets[2]["id"] {
			t.Fatal("manually disabled node was checked")
		}
		if asRow(job["profile"])["uuid"] != testProfile.UUID {
			t.Fatal("probe is missing the saved VLESS profile")
		}
		if n := e.result(job, job["target_id"] == targets[1]["id"], "ru-1", "connection_failed"); n != 1 {
			t.Fatalf("result accepted=%d", n)
		}
	}
	present := findTarget(e.targets(p), targets[0]["id"])
	excluded := findTarget(e.targets(p), targets[1]["id"])
	if present["last_checked_at"] == nil || num(present["failures"]) != 1 || !truth(present["dns_present"]) {
		t.Fatal("failed check should be recorded without removing DNS", present)
	}
	if excluded["last_checked_at"] == nil || num(excluded["successes"]) != 1 || truth(excluded["dns_present"]) {
		t.Fatal("successful check should be recorded without restoring DNS", excluded)
	}
	if truth(e.one("SELECT automation_enabled FROM pools WHERE id=?", id)["automation_enabled"]) ||
		e.one("SELECT id FROM targets WHERE dns_action IS NOT NULL") != nil || e.fake.callCount() != calls {
		t.Fatal("manual check enabled automation or initiated DNS work")
	}
	if num(e.one("SELECT next_due FROM targets WHERE id=?", targets[2]["id"])["next_due"]) <= nowSeconds() {
		t.Fatal("manual check rescheduled a manually disabled target")
	}
}

func TestManualCheckRequiresProfileAndEnabledTargets(t *testing.T) {
	e := newTestEnv(t)
	p := asRow(e.do("POST", "/api/pools", row{"name": "Pool", "hostname": "vpn.example.com", "zone_id": "zone"}, 200))
	path := "/api/pools/" + str(p["id"])
	e.do("POST", path+"/check", nil, 409)
	e.do("PUT", path+"/profile", testProfile, 200)
	e.do("POST", path+"/check", nil, 409)
	target := asRow(e.do("POST", path+"/targets", row{"name": "Server", "ip": "1.1.1.1"}, 200))
	e.sql("UPDATE targets SET manual_enabled=0,next_due=? WHERE id=?", nowSeconds()+3600, target["id"])
	e.do("POST", path+"/check", nil, 409)
	if num(e.one("SELECT next_due FROM targets WHERE id=?", target["id"])["next_due"]) <= nowSeconds() {
		t.Fatal("rejected check changed the target schedule")
	}
	e.do("POST", "/api/pools/missing/check", nil, 404)
}
