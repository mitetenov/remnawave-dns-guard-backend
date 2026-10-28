package guard

import (
	"encoding/json"
	"net/http"
	"time"
)

var poolFields = []string{"name", "hostname", "zone_id", "ttl", "interval_seconds", "failure_threshold", "recovery_threshold", "automation_enabled"}

func (a *App) poolRoutes() {
	a.managementRoutes()
	a.route("GET /api/pools", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			return a.poolList()
		})
	})
	a.route("POST /api/pools", "ui", func(w http.ResponseWriter, r *http.Request) any {
		data := defaultPool()
		bodyObject(w, r, &data, []string{"name", "hostname", "zone_id"})
		validatePool(&data)
		return a.withStore(func() any {
			if data.AutomationEnabled {
				fail(409, "Save profile and add targets before enabling automation")
			}
			id := uid()
			a.s.exec("INSERT INTO pools (id,name,hostname,zone_id,ttl,interval_seconds,failure_threshold,recovery_threshold,automation_enabled,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)", id, data.Name, data.Hostname, data.ZoneID, data.TTL, data.IntervalSeconds, data.FailureThreshold, data.RecoveryThreshold, 0, iso(time.Now()))
			a.s.exec("UPDATE pools SET dns_next_check=? WHERE id=?", nowSeconds()+dnsCheckSeconds, id)
			a.s.event("info", "manual", "Pool created", id, nil)
			return poolView(a.pool(id))
		})
	})
	a.route("PATCH /api/pools/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		dummy := defaultPool()
		fields := bodyObject(w, r, &dummy, nil, poolFields...)
		for _, v := range fields {
			if string(v) == "null" {
				fail(422, "Pool fields cannot be null")
			}
		}
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		return a.withStore(func() any {
			id := r.PathValue("id")
			old := a.pool(id)
			merged := map[string]json.RawMessage{}
			for _, key := range poolFields {
				b, _ := json.Marshal(old[key])
				merged[key] = b
			}
			auto, _ := json.Marshal(truth(old["automation_enabled"]))
			merged["automation_enabled"] = auto
			for k, v := range fields {
				merged[k] = v
			}
			b, _ := json.Marshal(merged)
			data := defaultPool()
			if e := json.Unmarshal(b, &data); e != nil {
				fail(422, "Invalid pool fields")
			}
			func() {
				defer func() {
					if p := recover(); p != nil {
						if e, ok := p.(*apiError); ok && e.status == 422 {
							fail(422, "Invalid pool fields")
						}
						panic(p)
					}
				}()
				validatePool(&data)
			}()
			if (data.Hostname != old["hostname"] || data.ZoneID != old["zone_id"]) && a.s.one("SELECT id FROM targets WHERE pool_id=?", id) != nil {
				fail(409, "Hostname and zone cannot change while targets are enrolled")
			}
			if data.AutomationEnabled && (old["profile"] == nil || a.s.one("SELECT id FROM targets WHERE pool_id=? AND manual_enabled=1", id) == nil) {
				fail(409, "Save profile and add enabled targets before enabling automation")
			}
			a.s.transaction(func() {
				for key, value := range data.values() {
					a.s.exec("UPDATE pools SET "+key+"=? WHERE id=?", value, id)
				}
				a.s.event("info", "manual", "Pool settings updated", id, nil)
			})
			return poolView(a.pool(id))
		})
	})
	a.route("PUT /api/pools/{id}/profile", "ui", func(w http.ResponseWriter, r *http.Request) any {
		data := defaultProfile()
		bodyObject(w, r, &data, []string{"port", "uuid", "transport", "security", "server_name"})
		validateProfile(&data)
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		return a.withStore(func() any {
			id := r.PathValue("id")
			a.pool(id)
			a.s.transaction(func() {
				a.s.exec("UPDATE pools SET profile=?,revision=revision+1 WHERE id=?", a.s.encrypt(data), id)
				a.s.exec("UPDATE jobs SET consumed=1 WHERE target_id IN (SELECT id FROM targets WHERE pool_id=?)", id)
				a.s.exec("DELETE FROM target_checks WHERE target_id IN (SELECT id FROM targets WHERE pool_id=?)", id)
				a.s.exec("UPDATE targets SET failures=0,successes=0,next_due=0,last_checked_at=NULL,last_latency_ms=NULL,last_error=NULL,last_agent_id=NULL,status=CASE WHEN manual_enabled=0 THEN 'disabled' WHEN dns_present=0 THEN 'excluded' ELSE 'unknown' END WHERE pool_id=?", id)
				a.s.event("info", "manual", "Probe profile updated; pending jobs invalidated", id, nil)
			})
			return row{"ok": true}
		})
	})
	a.route("GET /api/pools/{id}/targets", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			id := r.PathValue("id")
			a.pool(id)
			return a.targetViews(a.s.all("SELECT * FROM targets WHERE pool_id=? ORDER BY name", id))
		})
	})
	a.route("POST /api/pools/{id}/targets", "ui", func(w http.ResponseWriter, r *http.Request) any {
		data := TargetInput{}
		bodyObject(w, r, &data, []string{"name", "ip"}, "remnawave_uuid")
		if !textLength(data.Name, 1, 100) {
			invalid("name")
		}
		if !publicIPv4(data.IP) {
			invalid("ip")
		}
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		id := r.PathValue("id")
		var p, existing row
		a.withStore(func() any {
			p = a.pool(id)
			existing = a.s.one("SELECT * FROM targets WHERE pool_id=? AND (ip=? OR dns_new_ip=?)", id, data.IP, data.IP)
			return nil
		})
		tid := ""
		if existing != nil {
			if existing["dns_action"] != "enroll" {
				fail(409, "Target IP already enrolled")
			}
			tid = str(existing["id"])
		} else {
			adapter := a.cloudflare()
			addresses, e := adapter.addressRecords(p)
			mustErr(e)
			mustErr(checkProxy(addresses))
			a.withStore(func() any {
				a.s.transaction(func() {
					tid = uid()
					a.s.exec("INSERT INTO targets (id,pool_id,name,ip,remnawave_uuid,dns_present) VALUES (?,?,?,?,?,0)", tid, id, data.Name, data.IP, data.RemnawaveUUID)
					a.reconciler.queueLocked(tid, "enroll")
				})
				return nil
			})
		}
		return a.manualDNSLocked(tid, "enroll")
	})
	a.route("POST /api/targets/{id}/disable", "ui", func(w http.ResponseWriter, r *http.Request) any { return a.manualDNS(r.PathValue("id"), "disable") })
	a.route("POST /api/targets/{id}/enable", "ui", func(w http.ResponseWriter, r *http.Request) any { return a.manualDNS(r.PathValue("id"), "enable") })
	a.route("POST /api/pools/{id}/sync", "ui", func(w http.ResponseWriter, r *http.Request) any {
		id := r.PathValue("id")
		a.withStore(func() any { a.pool(id); return nil })
		added, e := a.reconciler.scanPool(id, true)
		mustErr(e)
		a.withStore(func() any { a.s.event("info", "manual", fmtSync(added), id, nil); return nil })
		return row{"added": added, "message": "Exact A records adopted; excluded targets retained"}
	})
	a.route("POST /api/pools/{id}/check", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			id := r.PathValue("id")
			p := a.pool(id)
			if p["profile"] == nil {
				fail(409, "Сначала сохраните VLESS-профиль для проверки узлов")
			}
			if a.s.one("SELECT id FROM targets WHERE pool_id=? AND manual_enabled=1", id) == nil {
				fail(409, "Добавьте или включите хотя бы один узел для проверки")
			}
			a.s.exec("UPDATE target_checks SET next_due=0 WHERE target_id IN (SELECT id FROM targets WHERE pool_id=? AND manual_enabled=1)", id)
			return row{"ok": true}
		})
	})
}
