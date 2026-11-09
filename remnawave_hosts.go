package guard

// Missing/stale checks do not prove an outage or recovery. Keep the remote
// state until every monitored target has failed, or an address in DNS recovers.
func desiredHostDisabled(pool row, targets []row, summaries map[string]probeSummary) (disabled, known bool) {
	if !truth(pool["automation_enabled"]) {
		return false, false
	}
	monitored, allDown, available := 0, true, false
	for _, target := range targets {
		if !truth(target["manual_enabled"]) {
			continue
		}
		monitored++
		if !truth(pool["disable_host_when_all_down"]) {
			continue
		}
		if truth(target["dns_uncertain"]) || target["dns_action"] != nil {
			// Unconfirmed targets prevent declaring a total outage, but must
			// not veto recovery of a different, confirmed address.
			allDown = false
			continue
		}
		summary := summaries[str(target["id"])]
		if !summary.Remove || truth(target["dns_present"]) && target["status"] != "protected" {
			allDown = false
		}
		if summary.Restore && truth(target["dns_present"]) {
			available = true
		}
	}
	if monitored == 0 {
		return false, false
	}
	if !truth(pool["disable_host_when_all_down"]) || available {
		return false, true
	}
	return allDown, allDown
}

func (r *Reconciler) syncRemnawaveHosts() {
	if r.remnawave == nil {
		return
	}
	s := r.s
	var pools []row
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		pools = s.all("SELECT id FROM pools WHERE automation_enabled=1 AND remnawave_next_check<=?", nowSeconds())
	}()
	for _, pool := range pools {
		if r.stopped() {
			return
		}
		r.syncRemnawavePool(str(pool["id"]))
	}
}

func (r *Reconciler) syncRemnawavePool(poolID string) {
	// Serialize with DNS operations and pool setting edits, without holding the
	// database mutex during provider requests.
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()
	s := r.s
	var pool row
	var disabled, known bool
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		pool = s.one("SELECT * FROM pools WHERE id=?", poolID)
		if pool == nil {
			return
		}
		s.exec("UPDATE pools SET remnawave_next_check=? WHERE id=?", nowSeconds()+retrySeconds, poolID)
		if !truth(pool["disable_host_when_all_down"]) && (s.get("remnawave_url") == "" || s.get("remnawave_api_token") == "") {
			return
		}
		targets := s.all("SELECT * FROM targets WHERE pool_id=?", poolID)
		view := s.probeSnapshot()
		summaries := map[string]probeSummary{}
		for _, target := range targets {
			summaries[str(target["id"])] = view.summary(target)
		}
		disabled, known = desiredHostDisabled(pool, targets, summaries)
	}()
	if !known {
		return
	}
	provider, err := r.remnawave()
	if err == nil {
		err = provider.ensurePoolHosts(str(pool["hostname"]), disabled)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if pool["remnawave_error"] != err.Error() {
			s.event("error", "system", "Remnawave host update pending: "+err.Error(), poolID, nil)
		}
		s.exec("UPDATE pools SET remnawave_error=?,remnawave_next_check=? WHERE id=?", err.Error(), nowSeconds()+retrySeconds, poolID)
		return
	}
	s.exec("UPDATE pools SET remnawave_host_disabled=?,remnawave_error=NULL,remnawave_next_check=? WHERE id=?", disabled, nowSeconds()+retrySeconds, poolID)
	if pool["remnawave_host_disabled"] == nil || truth(pool["remnawave_host_disabled"]) != disabled {
		message := "Remnawave hosts enabled; final A record remains protected"
		if disabled {
			message = "Remnawave hosts disabled: all monitored nodes failed; final A record preserved"
		}
		s.event("info", "system", message, poolID, nil)
	}
}
