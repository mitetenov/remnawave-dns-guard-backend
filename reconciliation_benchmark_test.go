package guard

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkReconcilerPendingEnrollments(b *testing.B) {
	a, err := New(testConfig(":memory:"), Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { a.Close() })
	a.reconciler.provider = func() (*Cloudflare, error) {
		b.Fatal("incomplete enrollment unexpectedly called the DNS provider")
		return nil, nil
	}
	s := a.s
	now := time.Now()
	checkedAt := iso(now)
	seen := float64(now.UnixNano()) / 1e9
	s.transaction(func() {
		for i := range 10 {
			poolID := fmt.Sprintf("pool-%d", i)
			s.exec("INSERT INTO pools(id,hostname,interval_seconds,failure_threshold,recovery_threshold,dns_next_check) VALUES (?,?,60,3,5,?)", poolID, poolID+".example.test", seen+3600)
		}
		s.exec("INSERT INTO agents(id,last_seen,healthy,version) VALUES ('a',?,1,'1.7.0'),('b',?,1,'1.7.0'),('c',?,1,'1.7.0')", seen, seen, seen)
		for i := range 1000 {
			targetID := fmt.Sprintf("target-%d", i)
			poolID := fmt.Sprintf("pool-%d", i%10)
			ip := fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
			var action any
			if i < 50 {
				action = "enroll"
			}
			s.exec("INSERT INTO targets(id,pool_id,ip,dns_action,dns_present) VALUES (?,?,?,?,?)", targetID, poolID, ip, action, action == nil)
			s.exec(`INSERT INTO target_checks(target_id,agent_id,successes,last_checked_at,outcome,route_results)
 SELECT ?,id,1,?,1,'{"direct":{"outcome":"success"}}' FROM agents`, targetID, checkedAt)
		}
	})
	b.ReportAllocs()
	for b.Loop() {
		a.reconciler.runOnce()
	}
}
