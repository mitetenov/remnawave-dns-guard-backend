package guard

import (
	"testing"
	"time"
)

func probeRefreshStore(t *testing.T, interval int) *Store {
	t.Helper()
	s, err := openStore(testConfig(":memory:"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	s.exec(`INSERT INTO pools (id, name, hostname, interval_seconds, failure_threshold, recovery_threshold, automation_enabled, profile)
 VALUES ('pool','Pool','pool.example',?,3,5,1,?)`, interval, s.encrypt(defaultProfile()))
	return s
}

func refreshProbeState(s *Store, now float64) {
	s.transaction(func() { s.refreshProbeTargets(now) })
}

func assertCachedProbeStatus(t *testing.T, s *Store, want string) {
	t.Helper()
	if got := s.one("SELECT status FROM targets WHERE id='target'")["status"]; got != want {
		t.Fatalf("cached probe status = %v, want %s", got, want)
	}
}

func TestProbeRefreshCoverageAndEvidenceExpiry(t *testing.T) {
	s := probeRefreshStore(t, 60)
	now := float64(100000)
	s.exec("INSERT INTO targets (id,pool_id,ip) VALUES ('target','pool','1.1.1.1')")
	s.exec("INSERT INTO agents (id,last_seen,healthy) VALUES ('a',?,1)", now)
	s.exec("INSERT INTO target_checks (target_id,agent_id,successes,outcome,last_checked_at) VALUES ('target','a',5,1,?)", iso(fromSeconds(now)))
	refreshProbeState(s, now)
	assertCachedProbeStatus(t, s, "healthy")

	// A registered checker contributes to coverage before its first observation.
	s.exec("INSERT INTO agents (id,last_seen,healthy) VALUES ('b',?,1)", now)
	refreshProbeState(s, now)
	assertCachedProbeStatus(t, s, "stale")

	// Checker A continues to poll. B's expired heartbeat restores full coverage.
	s.exec("UPDATE agents SET last_seen=? WHERE id='a'", now+80)
	refreshProbeState(s, now+80)
	assertCachedProbeStatus(t, s, "stale")
	refreshProbeState(s, now+controlFreshSeconds+1)
	assertCachedProbeStatus(t, s, "healthy")

	// A reconnect and an explicit deletion both change global coverage.
	s.exec("UPDATE agents SET last_seen=? WHERE id='b'", now+100)
	refreshProbeState(s, now+100)
	assertCachedProbeStatus(t, s, "stale")
	s.exec("DELETE FROM agents WHERE id='b'")
	refreshProbeState(s, now+100)
	assertCachedProbeStatus(t, s, "healthy")

	s.exec("UPDATE agents SET last_seen=? WHERE id='a'", now+leaseSeconds-1)
	refreshProbeState(s, now+leaseSeconds-1)
	assertCachedProbeStatus(t, s, "healthy")
	refreshProbeState(s, now+leaseSeconds)
	assertCachedProbeStatus(t, s, "stale")
	if r := s.one("SELECT * FROM probe_target_refresh WHERE target_id='target'"); r != nil {
		t.Fatalf("expired evidence was left scheduled: %v", r)
	}
}

func TestProbeRefreshProxyExpiryWithDirectRouteStillHealthy(t *testing.T) {
	s := probeRefreshStore(t, 60)
	now := float64(100000)
	s.exec("INSERT INTO targets (id,pool_id,ip) VALUES ('target','pool','1.1.1.1')")
	s.exec(`INSERT INTO agents (id,last_seen,healthy,version,socks5_enabled,proxy_url,proxy_healthy,proxy_checked_at)
 VALUES ('a',?,1,'1.4.0',1,'encrypted',1,?)`, now, now)
	s.exec(`INSERT INTO target_checks (target_id,agent_id,failures,outcome,last_checked_at,route_results)
 VALUES ('target','a',3,0,?,'{"direct":{"outcome":"success"},"socks5":{"outcome":"failure","error":"probe_failed"}}')`, iso(fromSeconds(now)))
	refreshProbeState(s, now)
	assertCachedProbeStatus(t, s, "suspect")

	s.exec("UPDATE agents SET last_seen=? WHERE id='a'", now+80)
	refreshProbeState(s, now+80)
	refreshProbeState(s, now+controlFreshSeconds+1)
	assertCachedProbeStatus(t, s, "stale")

	s.exec("UPDATE agents SET proxy_checked_at=? WHERE id='a'", now+100)
	refreshProbeState(s, now+100)
	assertCachedProbeStatus(t, s, "suspect")
}

func TestProbeRefreshReplacementDeadlineAndNotification(t *testing.T) {
	s := probeRefreshStore(t, 120)
	now := float64(100000)
	s.exec("UPDATE notification_control SET enabled=1")
	s.exec("INSERT INTO targets (id,pool_id,name,ip,dns_present) VALUES ('target','pool','Target','1.1.1.1',0)")
	s.exec("INSERT INTO replacement_bindings (target_id,provider,server_uuid,node_uuid,enabled) VALUES ('target','upcloud','server','node',1)")
	s.exec("INSERT INTO agents (id,last_seen,healthy) VALUES ('a',?,1)", now)
	s.exec("INSERT INTO target_checks (target_id,agent_id,failures,outcome,last_checked_at) VALUES ('target','a',3,0,?)", iso(fromSeconds(now)))
	refreshProbeState(s, now)
	assertCachedProbeStatus(t, s, "excluded")
	if n := s.one("SELECT previous_status,status FROM notification_outbox"); n["previous_status"] != "healthy" || n["status"] != "excluded" {
		t.Fatalf("missing durable exclusion notification: %v", n)
	}
	if since := s.one("SELECT blocked_since FROM replacement_bindings")["blocked_since"]; num(since) != now {
		t.Fatalf("replacement timer started at %v, want %v", since, now)
	}
	for heartbeat := now + 60; heartbeat < now+replacementDelay.Seconds(); heartbeat += 60 {
		s.exec("UPDATE agents SET last_seen=? WHERE id='a'", heartbeat)
		refreshProbeState(s, heartbeat)
	}
	if j := s.one("SELECT id FROM replacement_jobs"); j != nil {
		t.Fatal("replacement started before its deadline")
	}
	refreshProbeState(s, now+replacementDelay.Seconds())
	if j := s.one("SELECT stage FROM replacement_jobs"); j["stage"] != "preflight" {
		t.Fatalf("replacement did not start on its deadline: %v", j)
	}
	refreshProbeState(s, now+replacementDelay.Seconds()+1)
	if got := num(s.one("SELECT COUNT(*) n FROM notification_outbox")["n"]); got != 1 {
		t.Fatalf("outbox contains %v messages, want 1", got)
	}
}

func TestProbeScheduleTracksNewAndResetTargets(t *testing.T) {
	s := probeRefreshStore(t, 60)
	a := &App{s: s}
	poll := func(agent string) []row {
		var jobs []row
		s.transaction(func() { jobs = a.pollChecker(Poll{AgentID: agent, Version: "1.4.0", ControlOK: true}) })
		return jobs
	}
	if jobs := poll("a"); len(jobs) != 0 {
		t.Fatalf("unexpected jobs without a target: %v", jobs)
	}

	s.exec("INSERT INTO targets (id,pool_id,ip) VALUES ('target','pool','1.1.1.1')")
	if jobs := poll("a"); len(jobs) != 1 || jobs[0]["target_id"] != "target" {
		t.Fatalf("new target jobs = %v", jobs)
	}
	if jobs := poll("a"); len(jobs) != 0 {
		t.Fatalf("duplicate jobs on idle poll: %v", jobs)
	}
	s.exec("UPDATE jobs SET consumed=1")
	s.exec("DELETE FROM target_checks WHERE target_id='target'")
	if jobs := poll("a"); len(jobs) != 1 || jobs[0]["target_id"] != "target" {
		t.Fatalf("reset target jobs = %v", jobs)
	}
	s.exec("DELETE FROM agents WHERE id='a'")
	if jobs := poll("a"); len(jobs) != 1 || jobs[0]["target_id"] != "target" {
		t.Fatalf("re-registered checker jobs = %v", jobs)
	}
	s.exec("DELETE FROM targets WHERE id='target'")
	if jobs := poll("a"); len(jobs) != 0 {
		t.Fatalf("removed target jobs = %v", jobs)
	}
}

func TestProbeRefreshRollsBackInvalidationWithMutation(t *testing.T) {
	s := probeRefreshStore(t, 60)
	now := nowSeconds()
	s.exec("INSERT INTO targets (id,pool_id,ip) VALUES ('target','pool','1.1.1.1')")
	refreshProbeState(s, now)
	func() {
		defer func() { _ = recover() }()
		s.transaction(func() {
			s.exec("UPDATE targets SET manual_enabled=0 WHERE id='target'")
			panic("rollback")
		})
	}()
	refreshProbeState(s, now+time.Second.Seconds())
	assertCachedProbeStatus(t, s, "unknown")
}
