package guard

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// RFC 8709 wire encoding: string "ssh-ed25519" followed by one 32-byte public key.
func enrolledEd25519(key string) bool {
	if len(key) > 128 || !strings.HasPrefix(key, "ssh-ed25519 ") {
		return false
	}
	body, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(key, "ssh-ed25519 "))
	return err == nil && len(body) == 51 && string(body[:19]) == "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" &&
		key == "ssh-ed25519 "+base64.StdEncoding.EncodeToString(body)
}

func serverOrderError(err error) {
	if err != nil {
		var integrationErr *IntegrationError
		if errors.As(err, &integrationErr) {
			fail(502, err.Error())
		}
		fail(409, err.Error())
	}
}

func (a *App) orderRoutes() {
	a.route("GET /api/server-orders", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			jobs := a.s.all(`SELECT id,domain,stage,error,zone,plan,created_at,updated_at,ip,pool_hostname,group_name,profile_name,create_attempted,can_retry_create
 FROM server_orders WHERE ` + orderActive + ` OR id IN (SELECT id FROM server_orders ORDER BY created_at DESC LIMIT 200) ORDER BY created_at DESC`)
			for _, j := range jobs {
				j["can_cancel"] = orderStageCancellable(j)
				j["can_retry_create"] = truth(j["can_retry_create"])
				delete(j, "create_attempted")
			}
			pools := a.s.all(`SELECT p.id,p.name,p.hostname,COALESCE(t.domain_template,'') AS domain_template FROM pools p LEFT JOIN server_order_templates t ON p.id=t.pool_id ORDER BY p.name,p.hostname`)
			return row{"orders": jobs, "pools": pools, "stages": orderStages}
		})
	})
	a.route("GET /api/server-orders/options", "ui", func(w http.ResponseWriter, r *http.Request) any {
		query := r.URL.Query()
		choices, err := a.orders.options(r.Context(), query.Get("kind"), query.Get("zone"), query.Get("pool_id"), query.Get("group"))
		serverOrderError(err)
		return row{"choices": choices}
	})
	a.route("PUT /api/server-orders/pools/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data struct {
			Template string `json:"domain_template"`
		}
		bodyObject(w, r, &data, []string{"domain_template"})
		pattern := strings.ToLower(strings.TrimSpace(data.Template))
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		id := r.PathValue("id")
		var p row
		a.withStore(func() any { p = a.pool(id); return nil })
		if pattern != "" {
			if len(pattern) > 253 {
				invalid("domain_template")
			}
			domain, err := renderOrderDomain(pattern, "de", str(p["hostname"]), 1)
			serverOrderError(err)
			serverOrderError(a.orders.checkDomainZone(row{"domain": domain, "zone_id": p["zone_id"]}))
		}
		return a.withStore(func() any {
			if pattern == "" {
				a.s.exec("DELETE FROM server_order_templates WHERE pool_id=?", id)
			} else {
				a.s.exec("INSERT INTO server_order_templates(pool_id,domain_template) VALUES(?,?) ON CONFLICT(pool_id) DO UPDATE SET domain_template=excluded.domain_template", id, pattern)
			}
			return row{"ok": true}
		})
	})
	a.route("POST /api/server-orders", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data struct {
			Request string `json:"request_id"`
			Zone    string `json:"zone"`
			Plan    string `json:"plan"`
			Pool    string `json:"pool_id"`
			Group   string `json:"group"`
			Profile string `json:"profile_id"`
		}
		bodyObject(w, r, &data, []string{"request_id", "zone", "plan", "pool_id", "group", "profile_id"})
		id, err := a.orders.queue(r.Context(), data.Request, orderSelection{data.Zone, data.Plan, data.Pool, data.Group, data.Profile})
		serverOrderError(err)
		return row{"id": id}
	})
	a.route("POST /api/server-orders/{id}/cancel", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			id := r.PathValue("id")
			res := a.s.exec("UPDATE server_orders SET stage='cancelled',updated_at=?,snapshot=NULL,enroll_digest=NULL,error=NULL WHERE id=? AND stage IN ('preflight','provision') AND create_attempted=0", iso(time.Now()), id)
			n, _ := res.RowsAffected()
			if n == 0 {
				fail(409, "Этот заказ уже нельзя отменить")
			}
			return row{"ok": true}
		})
	})
	a.route("POST /api/server-orders/{id}/retry-create", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data struct {
			Confirmed bool `json:"confirmed_absent"`
		}
		bodyObject(w, r, &data, []string{"confirmed_absent"})
		if !data.Confirmed {
			invalid("confirmed_absent")
		}
		return a.withStore(func() any {
			res := a.s.exec(`UPDATE server_orders SET create_attempted=0,can_retry_create=0,error=NULL,updated_at=?,next_retry=0
 WHERE id=? AND stage='provision' AND can_retry_create=1 AND host_key IS NULL AND server_uuid IS NULL`, iso(time.Now()), r.PathValue("id"))
			n, _ := res.RowsAffected()
			if n == 0 {
				fail(409, "Повторное создание недоступно для этого заказа")
			}
			return row{"ok": true}
		})
	})
	a.route("POST /api/server-orders/{id}/enroll", "", func(w http.ResponseWriter, r *http.Request) any {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || len(token) != 43 {
			fail(401, "Invalid enrollment credential")
		}
		var data struct {
			Key string `json:"host_key"`
		}
		bodyObject(w, r, &data, []string{"host_key"})
		if !enrolledEd25519(data.Key) {
			invalid("host_key")
		}
		return a.withStore(func() any {
			j := a.s.one("SELECT id,stage,create_attempted,enroll_digest,host_key FROM server_orders WHERE id=?", r.PathValue("id"))
			if !truth(j["create_attempted"]) || !constantEqual(str(j["enroll_digest"]), digest(token)) {
				fail(401, "Invalid enrollment credential")
			}
			if key := str(j["host_key"]); key != "" {
				if !constantEqual(key, data.Key) {
					fail(409, "Server public key already enrolled")
				}
			} else {
				if !oneOf(str(j["stage"]), "provision", "enrollment") {
					fail(409, "Enrollment is closed")
				}
				a.s.exec("UPDATE server_orders SET host_key=?,next_retry=0,can_retry_create=0 WHERE id=?", data.Key, j["id"])
			}
			return row{"ok": true}
		})
	})
}
