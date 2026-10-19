package guard

import (
	"log"
	"strings"
	"sync"
	"time"
)

const leaseSeconds = 180
const dnsCheckSeconds = 300
const retrySeconds = 30
const controlFreshSeconds = 90

type Reconciler struct {
	s                *Store
	provider         func() (*Cloudflare, error)
	dnsMu            sync.Mutex
	wake, stop, done chan struct{}
	once             sync.Once
	started          bool
}

func newReconciler(s *Store, provider func() (*Cloudflare, error)) *Reconciler {
	return &Reconciler{s: s, provider: provider, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
}
func (r *Reconciler) start() {
	r.started = true
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			default:
			}
			r.safeCycle()
			select {
			case <-r.stop:
				return
			case <-r.wake:
			case <-ticker.C:
			}
		}
	}()
}
func (r *Reconciler) close() {
	r.once.Do(func() { close(r.stop) })
	if r.started {
		<-r.done
	}
}
func (r *Reconciler) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}
func (r *Reconciler) safeCycle() {
	defer func() {
		if recover() != nil {
			log.Print("DNS reconciliation cycle failed")
		}
	}()
	r.runOnce()
}
func (r *Reconciler) stopped() bool {
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}
func observedStatus(t row, present, uncertain bool) string {
	if !truth(t["manual_enabled"]) {
		return "disabled"
	}
	if t["last_checked_at"] == nil {
		if present {
			return "unknown"
		}
		return "excluded"
	}
	if truth(t["successes"]) {
		if present && !uncertain {
			return "healthy"
		}
		return "recovering"
	}
	if truth(t["failures"]) {
		if present {
			return "suspect"
		}
		return "excluded"
	}
	if present {
		return "unknown"
	}
	return "excluded"
}

// queueLocked is called under the short database mutex, never the DNS mutex.
func (r *Reconciler) queueLocked(targetID, action string) {
	s := r.s
	s.transaction(func() {
		t := s.one("SELECT * FROM targets WHERE id=?", targetID)
		if t == nil {
			return
		}
		operation, previous := any(uid()), t["manual_enabled"]
		if t["dns_action"] == action {
			operation, previous = t["dns_operation_id"], t["dns_previous_enabled"]
		}
		p := s.one("SELECT revision FROM pools WHERE id=?", t["pool_id"])
		s.exec("UPDATE targets SET dns_action=?,dns_operation_id=?,dns_previous_enabled=?,dns_profile_revision=?,dns_uncertain=1,dns_next_retry=0 WHERE id=?", action, operation, previous, p["revision"], targetID)
		if !strings.HasPrefix(action, "auto_") {
			enabled := oneOf(action, "enroll", "enable")
			status := "disabled"
			if enabled {
				status = "unknown"
			}
			s.exec("UPDATE targets SET manual_enabled=?,status=?,failures=0,successes=0,next_due=0,last_checked_at=NULL,last_error=NULL WHERE id=?", enabled, status, targetID)
			s.exec("UPDATE jobs SET consumed=1 WHERE target_id=?", targetID)
		}
	})
	r.signal()
}
func (r *Reconciler) execute(targetID string, raise bool) error {
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()
	return r.executeLocked(targetID, raise)
}
func (r *Reconciler) executeLocked(targetID string, raise bool) error {
	s := r.s
	snapshot := func() (row, row, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		t := s.one("SELECT * FROM targets WHERE id=?", targetID)
		if t == nil || t["dns_action"] == nil {
			return nil, nil, false
		}
		p := s.one("SELECT * FROM pools WHERE id=?", t["pool_id"])
		action := str(t["dns_action"])
		if strings.HasPrefix(action, "auto_") {
			valid := truth(p["automation_enabled"]) && truth(t["manual_enabled"]) && num(p["revision"]) == num(t["dns_profile_revision"])
			if action == "auto_remove" {
				valid = valid && num(t["failures"]) >= num(p["failure_threshold"])
			} else {
				valid = valid && num(t["successes"]) >= num(p["recovery_threshold"])
			}
			if !valid {
				s.exec("UPDATE targets SET dns_action=NULL,dns_uncertain=CASE WHEN dns_error IS NULL THEN 0 ELSE dns_uncertain END WHERE id=?", targetID)
				return nil, nil, false
			}
			a := s.one("SELECT * FROM agents WHERE id=?", t["last_agent_id"])
			if a == nil || !truth(a["healthy"]) || nowSeconds()-num(a["last_seen"]) > controlFreshSeconds {
				s.exec("UPDATE targets SET dns_next_retry=? WHERE id=?", nowSeconds()+retrySeconds, targetID)
				return nil, nil, false
			}
		}
		return t, p, true
	}
	t, p, ok := snapshot()
	if !ok {
		return nil
	}
	action, operation := str(t["dns_action"]), t["dns_operation_id"]
	// Old pending deletions do not carry an explicit choice to remove DNS.
	// Only the new delete_dns intent may perform a provider mutation.
	if action == "delete" {
		s.mu.Lock()
		defer s.mu.Unlock()
		if current := s.one("SELECT * FROM targets WHERE id=?", targetID); current != nil && current["dns_operation_id"] == operation {
			s.forgetTarget(current)
		}
		return nil
	}
	present := oneOf(action, "enroll", "enable", "auto_restore")
	provider, e := r.provider()
	actual := false
	if e == nil {
		if action == "replace_ip" {
			actual, e = provider.replaceIP(p, str(t["ip"]), str(t["dns_new_ip"]), truth(t["dns_replace_present"]))
		} else {
			actual, e = provider.ensure(p, str(t["ip"]), present)
		}
	}
	if e != nil {
		ie, ok := e.(*IntegrationError)
		if !ok {
			ie = integration("Cloudflare API unavailable or request rejected")
		}
		func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			current := s.one("SELECT * FROM targets WHERE id=?", targetID)
			if current == nil || current["dns_operation_id"] != operation {
				return
			}
			if ie.Kind == "last_record" && action != "replace_ip" {
				enabled := current["manual_enabled"]
				if !strings.HasPrefix(action, "auto_") {
					enabled = current["dns_previous_enabled"]
				}
				if current["status"] != "protected" {
					s.event("warning", "dns", "Removal prevented: final actual A record preserved", p["id"], targetID)
				}
				status := "disabled"
				if truth(enabled) {
					status = "protected"
				}
				s.exec("UPDATE targets SET manual_enabled=?,dns_present=1,dns_uncertain=0,dns_action=NULL,dns_error=NULL,dns_checked_at=?,status=? WHERE id=?", enabled, iso(time.Now()), status, targetID)
				return
			}
			if current["dns_error"] != ie.Message {
				s.event("error", "dns", "DNS change pending: "+ie.Message, p["id"], targetID)
			}
			s.exec("UPDATE targets SET dns_error=?,dns_next_retry=? WHERE id=?", ie.Message, nowSeconds()+retrySeconds, targetID)
		}()
		if raise {
			if oneOf(ie.Kind, "last_record", "proxy") {
				return ie
			}
			return integration(ie.Message + ". Операция сохранена; DNS ожидает подтверждения и будет проверен повторно.")
		}
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transaction(func() {
		current := s.one("SELECT * FROM targets WHERE id=?", targetID)
		if current == nil || current["dns_operation_id"] != operation {
			return
		}
		s.exec("UPDATE pools SET dns_next_check=0 WHERE id=?", p["id"])
		if action == "delete_dns" {
			s.exec("DELETE FROM targets WHERE id=?", targetID)
			s.event("warning", "manual", "Target removed; exact A record absence verified", p["id"], targetID)
			return
		}
		if action == "replace_ip" {
			status := "disabled"
			if truth(current["manual_enabled"]) {
				status = "excluded"
				if actual {
					status = "unknown"
				}
			}
			s.exec("UPDATE targets SET ip=dns_new_ip,dns_new_ip=NULL,dns_replace_present=NULL,dns_present=?,dns_uncertain=0,dns_action=NULL,dns_error=NULL,dns_checked_at=?,dns_drift=0,status=?,failures=0,successes=0,next_due=0,last_checked_at=NULL,last_latency_ms=NULL,last_error=NULL,last_agent_id=NULL WHERE id=?", actual, iso(time.Now()), status, targetID)
			s.exec("UPDATE jobs SET consumed=1 WHERE target_id=?", targetID)
			s.event("info", "manual", "Target IP updated; DNS verified and probe counters reset", p["id"], targetID)
			return
		}
		status := observedStatus(current, actual, false)
		s.exec("UPDATE targets SET dns_present=?,dns_uncertain=0,dns_action=NULL,dns_error=NULL,dns_checked_at=?,dns_drift=0,status=? WHERE id=?", actual, iso(time.Now()), status, targetID)
		if actual != truth(t["dns_present"]) || !strings.HasPrefix(action, "auto_") {
			message, level, kind := "Exact A record absence verified", "warning", "manual"
			if actual {
				message, level = "Exact A record presence verified", "info"
			}
			if strings.HasPrefix(action, "auto_") {
				kind = "dns"
			}
			s.event(level, kind, message, p["id"], targetID)
		}
		if actual {
			s.exec("UPDATE targets SET status='suspect' WHERE pool_id=? AND id!=? AND status='protected'", p["id"], targetID)
		}
	})
	return nil
}
func (r *Reconciler) scanPool(poolID string, adopt bool) (int, error) {
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()
	s := r.s
	var p row
	func() { s.mu.Lock(); defer s.mu.Unlock(); p = s.one("SELECT * FROM pools WHERE id=?", poolID) }()
	if p == nil {
		return 0, nil
	}
	adapter, e := r.provider()
	var addresses []row
	if e == nil {
		addresses, e = adapter.addressRecords(p)
	}
	if e == nil {
		e = checkProxy(addresses)
	}
	if e != nil {
		ie, ok := e.(*IntegrationError)
		if !ok {
			ie = integration("Cloudflare API unavailable or request rejected")
		}
		func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if p["dns_error"] != ie.Message {
				s.event("error", "dns", "DNS verification failed: "+ie.Message, poolID, nil)
			}
			s.exec("UPDATE pools SET dns_error=?,dns_next_check=? WHERE id=?", ie.Message, nowSeconds()+retrySeconds, poolID)
			s.exec("UPDATE targets SET dns_uncertain=1 WHERE pool_id=?", poolID)
		}()
		if adopt {
			return 0, ie
		}
		return 0, nil
	}
	actual := map[string]bool{}
	for _, record := range addresses {
		if record["type"] == "A" {
			actual[str(record["content"])] = true
		}
	}
	added := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transaction(func() {
		if adopt {
			for ip := range actual {
				if publicIPv4(ip) && s.one("SELECT id FROM targets WHERE pool_id=? AND (ip=? OR dns_new_ip=?)", poolID, ip, ip) == nil {
					s.exec("INSERT INTO targets (id,pool_id,name,ip) VALUES (?,?,?,?)", uid(), poolID, ip, ip)
					added++
				}
			}
		}
		enrolled := s.all("SELECT * FROM targets WHERE pool_id=?", poolID)
		managed := map[string]bool{}
		for _, t := range enrolled {
			managed[str(t["ip"])] = true
			if ip := str(t["dns_new_ip"]); ip != "" {
				managed[ip] = true
			}
		}
		driftCount := 0
		for ip := range actual {
			if !managed[ip] {
				driftCount++
			}
		}
		for _, t := range enrolled {
			if t["dns_action"] != nil {
				continue
			}
			present := actual[str(t["ip"])]
			changed := present != truth(t["dns_present"])
			drift := (changed || truth(t["dns_drift"])) && !adopt || present && !truth(t["manual_enabled"])
			if drift {
				driftCount++
			}
			status := observedStatus(t, present, false)
			if changed {
				if !truth(t["dns_drift"]) {
					state := "absent"
					if present {
						state = "present"
					}
					s.event("warning", "dns", "External DNS change detected; actual A record "+state, poolID, t["id"])
				}
				s.exec("UPDATE targets SET failures=0,successes=0 WHERE id=?", t["id"])
				if !truth(t["manual_enabled"]) {
					status = "disabled"
				} else if present {
					status = "unknown"
				} else {
					status = "excluded"
				}
			} else if t["status"] == "protected" && len(actual) == 1 {
				status = "protected"
			}
			s.exec("UPDATE targets SET dns_present=?,dns_uncertain=0,dns_checked_at=?,dns_drift=?,status=? WHERE id=?", present, iso(time.Now()), drift, status, t["id"])
		}
		if driftCount > 0 && float64(driftCount) != num(p["dns_drift_count"]) {
			s.event("warning", "dns", fmtDrift(driftCount), poolID, nil)
		}
		s.exec("UPDATE pools SET dns_checked_at=?,dns_error=NULL,dns_next_check=?,dns_drift_count=? WHERE id=?", iso(time.Now()), nowSeconds()+dnsCheckSeconds, driftCount, poolID)
	})
	return added, nil
}
func (r *Reconciler) runOnce() {
	s := r.s
	var pending, pools []row
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		pending = s.all("SELECT id FROM targets WHERE dns_action IS NOT NULL AND dns_next_retry<=?", nowSeconds())
	}()
	for _, t := range pending {
		if r.stopped() {
			return
		}
		_ = r.execute(str(t["id"]), false)
	}
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		pools = s.all("SELECT id FROM pools WHERE dns_next_check<=?", nowSeconds())
	}()
	for _, p := range pools {
		if r.stopped() {
			return
		}
		_, _ = r.scanPool(str(p["id"]), false)
	}
}
