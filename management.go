package guard

import (
	"fmt"
	"net/http"
	"strings"
)

func (a *App) managementRoutes() {
	a.route("DELETE /api/pools/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		return a.withStore(func() any {
			id := r.PathValue("id")
			p := a.pool(id)
			a.s.transaction(func() {
				a.s.exec("DELETE FROM targets WHERE pool_id=?", id)
				a.s.exec("DELETE FROM pools WHERE id=?", id)
				a.s.event("warning", "manual", fmt.Sprintf("Pool removed: %s (%s); Cloudflare DNS records retained", p["name"], p["hostname"]), id, nil)
			})
			return row{"ok": true}
		})
	})
	a.route("DELETE /api/targets/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		deleteDNS := false
		if values, present := r.URL.Query()["delete_dns"]; present {
			if len(values) != 1 || !oneOf(values[0], "true", "false") {
				invalid("delete_dns")
			}
			deleteDNS = values[0] == "true"
		}
		if deleteDNS {
			return a.manualDNS(r.PathValue("id"), "delete_dns")
		}
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		return a.withStore(func() any {
			a.s.forgetTarget(a.target(r.PathValue("id")))
			return row{"ok": true}
		})
	})
	a.route("PATCH /api/targets/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data TargetInput
		fields := bodyObject(w, r, &data, nil, "name", "ip")
		for key, value := range fields {
			if string(value) == "null" {
				invalid(key)
			}
		}
		data.Name = strings.TrimSpace(data.Name)
		data.IP = strings.TrimSpace(data.IP)
		if _, ok := fields["name"]; ok && !textLength(data.Name, 1, 100) {
			invalid("name")
		}
		if _, ok := fields["ip"]; ok && !publicIPv4(data.IP) {
			invalid("ip")
		}
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		id := r.PathValue("id")
		var target, pool row
		a.withStore(func() any {
			target = a.target(id)
			pool = a.pool(str(target["pool_id"]))
			if _, ok := fields["name"]; !ok {
				data.Name = str(target["name"])
			}
			if _, ok := fields["ip"]; !ok {
				data.IP = str(target["ip"])
			}
			if target["dns_action"] == "replace_ip" {
				if data.IP != target["dns_new_ip"] || data.Name != target["name"] {
					fail(409, "Дождитесь завершения смены IP узла перед следующим изменением")
				}
			} else if data.IP != target["ip"] {
				if target["dns_action"] != nil {
					fail(409, "Дождитесь завершения текущей операции DNS перед сменой IP")
				}
				if a.s.one("SELECT id FROM targets WHERE pool_id=? AND id!=? AND (ip=? OR dns_new_ip=?)", pool["id"], id, data.IP, data.IP) != nil {
					fail(409, "Этот IP уже используется другим узлом пула")
				}
			}
			return nil
		})
		if data.IP != target["ip"] && target["dns_action"] != "replace_ip" {
			addresses, err := a.cloudflare().addressRecords(pool)
			mustErr(err)
			mustErr(checkProxy(addresses))
			oldPresent, newPresent := false, false
			for _, record := range addresses {
				if record["type"] == "A" {
					oldPresent = oldPresent || record["content"] == target["ip"]
					newPresent = newPresent || record["content"] == data.IP
				}
			}
			present := truth(target["manual_enabled"]) && oldPresent
			if !present && newPresent {
				fail(409, "Новый IP уже есть в DNS. Выберите другой адрес или импортируйте запись из Cloudflare")
			}
			a.withStore(func() any {
				a.s.transaction(func() {
					a.s.exec("UPDATE targets SET name=?,dns_new_ip=?,dns_replace_present=?,dns_action='replace_ip',dns_operation_id=?,dns_uncertain=1,dns_error=NULL,dns_next_retry=0 WHERE id=?", data.Name, data.IP, present, uid(), id)
					a.s.exec("UPDATE jobs SET consumed=1 WHERE target_id=?", id)
					a.s.event("info", "manual", "Target IP replacement requested", pool["id"], id)
				})
				return nil
			})
			a.reconciler.signal()
		} else if target["dns_action"] != "replace_ip" {
			return a.withStore(func() any {
				a.s.transaction(func() {
					a.s.exec("UPDATE targets SET name=? WHERE id=?", data.Name, id)
					if data.Name != target["name"] {
						a.s.event("info", "manual", "Target name updated", pool["id"], id)
					}
				})
				return a.targetView(a.target(id))
			})
		}
		mustErr(a.reconciler.executeLocked(id, true))
		return a.withStore(func() any { return a.targetView(a.target(id)) })
	})
}

// Caller holds the store mutex and the reconciler DNS mutex. Removing a target
// also removes its jobs and pending DNS intent without contacting Cloudflare.
func (s *Store) forgetTarget(target row) {
	s.transaction(func() {
		s.exec("DELETE FROM targets WHERE id=?", target["id"])
		s.event("warning", "manual", fmt.Sprintf("Target removed: %s (%s); Cloudflare DNS records retained", target["name"], target["ip"]), target["pool_id"], target["id"])
	})
}
