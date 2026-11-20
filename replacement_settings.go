package guard

import (
	"net/http"
	"slices"
	"strings"
	"time"
)

// History outlives its target. A partial unique index also makes creating work
// idempotent when fresh probe results and the periodic observer overlap.
const replacementActive = "stage NOT IN ('complete','cancelled')"

func (s *Store) initializeReplacements() {
	s.exec(`CREATE TABLE IF NOT EXISTS replacement_bindings (
 target_id TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
 provider TEXT NOT NULL, server_uuid TEXT NOT NULL, node_uuid TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL, blocked_since REAL, UNIQUE(provider,server_uuid));
 CREATE TABLE IF NOT EXISTS replacement_jobs (
 id TEXT PRIMARY KEY, target_id TEXT NOT NULL, pool_id TEXT NOT NULL, name TEXT NOT NULL,
 provider TEXT NOT NULL, server_uuid TEXT NOT NULL, node_uuid TEXT NOT NULL, old_ip TEXT NOT NULL,
 new_server_uuid TEXT, new_ip TEXT, snapshot TEXT, create_attempted INTEGER NOT NULL DEFAULT 0,
 can_retry_create INTEGER NOT NULL DEFAULT 0, release_after REAL NOT NULL DEFAULT 0, old_record_ttl INTEGER NOT NULL DEFAULT 0,
 stage TEXT NOT NULL, error TEXT, next_retry REAL NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS replacement_active_target ON replacement_jobs(target_id) WHERE ` + replacementActive + `;
 CREATE TRIGGER IF NOT EXISTS replacement_reset_pool AFTER UPDATE OF automation_enabled,revision,failure_threshold ON pools
 WHEN NEW.automation_enabled!=OLD.automation_enabled OR NEW.revision!=OLD.revision OR NEW.failure_threshold!=OLD.failure_threshold
 BEGIN UPDATE replacement_bindings SET blocked_since=NULL WHERE target_id IN (SELECT id FROM targets WHERE pool_id=NEW.id); END;
 CREATE TRIGGER IF NOT EXISTS replacement_reset_target AFTER UPDATE OF ip,manual_enabled,last_checked_at ON targets
 WHEN NEW.ip!=OLD.ip OR NEW.manual_enabled!=OLD.manual_enabled OR NEW.last_checked_at IS NULL
 BEGIN UPDATE replacement_bindings SET blocked_since=NULL WHERE target_id=NEW.id; END;`)
	columns := s.all("PRAGMA table_info(replacement_bindings)")
	for _, name := range []string{"virtua_zone", "virtua_quote", "virtua_group", "virtua_domain"} {
		if !slices.ContainsFunc(columns, func(column row) bool { return column["name"] == name }) {
			s.exec("ALTER TABLE replacement_bindings ADD COLUMN " + name + " TEXT NOT NULL DEFAULT ''")
		}
	}
	columns = s.all("PRAGMA table_info(replacement_jobs)")
	for _, name := range []string{"enroll_digest", "host_key"} {
		if !slices.ContainsFunc(columns, func(column row) bool { return column["name"] == name }) {
			s.exec("ALTER TABLE replacement_jobs ADD COLUMN " + name + " TEXT")
		}
	}
	// No probes were observed while the backend was down. Already committed
	// retirements resume from their saved stage.
	s.exec("UPDATE replacement_bindings SET blocked_since=NULL WHERE blocked_since IS NOT NULL")
}

func (s *Store) activeReplacement(targetID any) row {
	return s.one("SELECT id,stage,pool_id,target_id FROM replacement_jobs WHERE target_id=? AND "+replacementActive, targetID)
}

func (s *Store) requireIdleReplacement(targetID any) {
	if s.one("SELECT id FROM server_orders WHERE target_id=? AND "+orderActive, targetID) != nil {
		fail(409, "Дождитесь завершения заказа сервера")
	}
	if s.activeReplacement(targetID) != nil {
		fail(409, "Для узла выполняется автозамена. Дождитесь её завершения.")
	}
}

func (s *Store) reservedReplacementIP(ip string) bool {
	return s.one("SELECT id FROM replacement_jobs WHERE (old_ip=? OR new_ip=?) AND "+replacementActive, ip, ip) != nil || s.one("SELECT id FROM server_orders WHERE ip=? AND "+orderActive, ip) != nil
}

func (a *App) replacementRoutes() {
	a.route("GET /api/replacements", "ui", func(w http.ResponseWriter, r *http.Request) any {
		readyErr := a.replacements.ansible.Ready()
		message := ""
		if readyErr != nil {
			message = readyErr.Error()
		}
		orderErr := a.orders.installer.checkOrderConfiguration(r.Context())
		orderMessage := ""
		if orderErr != nil {
			orderMessage = orderErr.Error()
		}
		return a.withStore(func() any {
			targets := a.s.all(`SELECT t.id,t.name,t.ip,p.name AS pool_name,p.automation_enabled AS pool_enabled,
 t.manual_enabled,COALESCE(b.node_uuid,t.remnawave_uuid) AS remnawave_uuid,
 COALESCE(b.provider,o.provider) AS provider,COALESCE(b.server_uuid,o.server_uuid) AS server_uuid,b.enabled,b.blocked_since,
 COALESCE(NULLIF(b.virtua_zone,''),o.zone,'') AS virtua_zone,COALESCE(NULLIF(b.virtua_quote,''),o.quote,'') AS virtua_quote,
 COALESCE(NULLIF(b.virtua_group,''),o.group_name,'') AS virtua_group,COALESCE(NULLIF(b.virtua_domain,''),o.domain,'') AS virtua_domain,
 o.id IS NOT NULL AS order_managed
 FROM targets t JOIN pools p ON p.id=t.pool_id LEFT JOIN replacement_bindings b ON b.target_id=t.id
 LEFT JOIN server_orders o ON o.target_id=t.id AND o.node_uuid=COALESCE(b.node_uuid,t.remnawave_uuid) AND o.stage='complete'
 ORDER BY p.name,t.name,t.id`)
			for _, t := range targets {
				for _, key := range []string{"enabled", "pool_enabled", "manual_enabled", "order_managed"} {
					t[key] = truth(t[key])
				}
				if t["blocked_since"] != nil {
					t["blocked_since"] = iso(fromSeconds(num(t["blocked_since"])))
				}
			}
			jobs := a.s.all(`SELECT id,target_id,name,provider,stage,old_ip,new_ip,error,created_at,updated_at,can_retry_create,release_after FROM replacement_jobs
 WHERE ` + replacementActive + ` OR id IN (SELECT id FROM replacement_jobs WHERE stage IN ('complete','cancelled') ORDER BY created_at DESC LIMIT 200)
 ORDER BY CASE WHEN ` + replacementActive + ` THEN 0 ELSE 1 END,created_at DESC`)
			for _, job := range jobs {
				job["can_retry_create"] = truth(job["can_retry_create"])
				if job["stage"] == "cleanup" && num(job["release_after"]) > 0 {
					job["release_after"] = iso(fromSeconds(num(job["release_after"])))
				} else {
					delete(job, "release_after")
				}
			}
			return row{
				"upcloud_configured": a.s.get("upcloud_token") != "", "ansible_ready": readyErr == nil, "ansible_error": message,
				"virtua_configured":   a.s.get("virtua_token") != "",
				"order_ansible_ready": orderErr == nil, "order_ansible_error": orderMessage, "targets": targets, "jobs": jobs,
			}
		})
	})
	a.route("POST /api/replacements/jobs/{id}/retry-create", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data struct {
			Confirmed bool `json:"confirmed_absent"`
		}
		bodyObject(w, r, &data, []string{"confirmed_absent"})
		if !data.Confirmed {
			invalid("confirmed_absent")
		}
		return a.withStore(func() any {
			job := a.s.one("SELECT * FROM replacement_jobs WHERE id=?", r.PathValue("id"))
			if job == nil {
				fail(404, "Замена не найдена")
			}
			if job["stage"] != "provision" || !truth(job["can_retry_create"]) ||
				(job["provider"] == virtuaOrderProvider && (job["new_server_uuid"] != nil || job["host_key"] != nil)) {
				fail(409, "Для этой замены повторное создание недоступно")
			}
			a.s.transaction(func() {
				a.s.exec("UPDATE replacement_jobs SET create_attempted=0,can_retry_create=0,error=NULL,next_retry=0,updated_at=? WHERE id=?", iso(time.Now()), job["id"])
				a.s.event("warning", "manual", "Администратор подтвердил отсутствие сервера и разрешил повторное создание", job["pool_id"], job["target_id"])
			})
			return row{"ok": true}
		})
	})
	a.route("PUT /api/replacements/settings", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data struct {
			Token string `json:"upcloud_token"`
		}
		bodyObject(w, r, &data, []string{"upcloud_token"})
		token := strings.TrimSpace(data.Token)
		if !textLength(token, 1, 4096) || strings.ContainsAny(token, "\r\n") {
			invalid("upcloud_token")
		}
		return a.withStore(func() any { a.s.set("upcloud_token", token); return row{"ok": true} })
	})
	a.route("PUT /api/replacements/targets/{id}", "ui", func(w http.ResponseWriter, r *http.Request) any {
		var data struct {
			Provider string `json:"provider"`
			Server   string `json:"server_uuid"`
			Node     string `json:"remnawave_uuid"`
			Enabled  bool   `json:"enabled"`
			Zone     string `json:"virtua_zone"`
			Quote    string `json:"virtua_quote"`
			Group    string `json:"virtua_group"`
			Domain   string `json:"virtua_domain"`
		}
		bodyObject(w, r, &data, []string{"provider", "server_uuid", "remnawave_uuid", "enabled"})
		adapter, ok := a.replacements.providers[data.Provider]
		if !ok && data.Provider != virtuaOrderProvider {
			invalid("provider")
		}
		parseServer := canonicalUUID
		if adapter.serverID != nil {
			parseServer = adapter.serverID
		}
		server, ok := parseServer(data.Server)
		if !ok {
			invalid("server_uuid")
		}
		node, ok := canonicalUUID(data.Node)
		if !ok {
			invalid("remnawave_uuid")
		}
		id := r.PathValue("id")
		return a.withStore(func() any {
			t := a.target(id)
			if a.s.one("SELECT id FROM server_orders WHERE target_id=? AND "+orderActive, id) != nil {
				fail(409, "Дождитесь завершения заказа сервера")
			}
			b := a.s.one("SELECT * FROM replacement_bindings WHERE target_id=?", id)
			order := a.s.one("SELECT * FROM server_orders WHERE target_id=? AND stage='complete'", id)
			if order != nil && (data.Provider == virtuaOrderProvider || order["provider"] == virtuaOrderProvider) &&
				(order["provider"] != data.Provider || order["node_uuid"] != node) {
				fail(409, "Для заказанного узла используются его провайдер и нода Remnawave")
			}
			if data.Provider == virtuaOrderProvider {
				if !validOrderZone(data.Provider, data.Zone) {
					invalid("virtua_zone")
				}
				if !textLength(data.Quote, 1, 272) {
					invalid("virtua_quote")
				}
				if order != nil {
					data.Group, data.Domain = str(order["group_name"]), str(order["domain"])
				}
				if !oneOf(data.Group, "nodes", "nodes_wl") {
					invalid("virtua_group")
				}
				data.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(data.Domain), "."))
				if !validReplacementOrderDomain(data.Domain) {
					invalid("virtua_domain")
				}
				if order == nil && a.s.replacementDomainUsed(id, data.Domain) {
					fail(409, "Этот домен уже используется в DNS Guard")
				}
			} else {
				data.Zone, data.Quote, data.Group, data.Domain = "", "", "", ""
			}
			same := b != nil && b["provider"] == data.Provider && b["server_uuid"] == server && b["node_uuid"] == node &&
				b["virtua_zone"] == data.Zone && b["virtua_quote"] == data.Quote && b["virtua_group"] == data.Group && b["virtua_domain"] == data.Domain
			if same && truth(b["enabled"]) == data.Enabled {
				return row{"ok": true}
			}
			job := a.s.activeReplacement(id)
			if job != nil && job["stage"] != "preflight" && !same {
				fail(409, "Привязку можно изменить после завершения автозамены")
			}
			if a.s.one("SELECT id FROM replacement_jobs WHERE target_id!=? AND provider=? AND new_server_uuid=? AND "+replacementActive, id, data.Provider, server) != nil {
				fail(409, "Этот сервер уже создан для другой замены")
			}
			if a.s.one("SELECT target_id FROM replacement_bindings WHERE target_id!=? AND ((provider=? AND server_uuid=?) OR node_uuid=?)", id, data.Provider, server, node) != nil {
				fail(409, "Сервер или нода уже привязаны к другой цели")
			}
			if data.Provider == virtuaOrderProvider && a.s.one("SELECT id FROM server_orders WHERE provider=? AND server_uuid=? AND (target_id IS NULL OR target_id!=?) AND stage NOT IN ('cancelled','rejected')", data.Provider, server, id) != nil {
				fail(409, "Этот сервер уже связан с другим заказом")
			}
			a.s.transaction(func() {
				if job != nil && job["stage"] == "preflight" {
					a.s.setReplacementStage(job, "cancelled")
				}
				a.s.exec(`INSERT INTO replacement_bindings(target_id,provider,server_uuid,node_uuid,enabled,virtua_zone,virtua_quote,virtua_group,virtua_domain) VALUES(?,?,?,?,?,?,?,?,?)
 ON CONFLICT(target_id) DO UPDATE SET provider=excluded.provider,server_uuid=excluded.server_uuid,node_uuid=excluded.node_uuid,
 enabled=excluded.enabled,blocked_since=NULL,virtua_zone=excluded.virtua_zone,virtua_quote=excluded.virtua_quote,
 virtua_group=excluded.virtua_group,virtua_domain=excluded.virtua_domain`, id, data.Provider, server, node, data.Enabled, data.Zone, data.Quote, data.Group, data.Domain)
				a.s.exec("UPDATE targets SET remnawave_uuid=? WHERE id=?", node, id)
				a.s.event("info", "system", "Настройки автозамены узла изменены", t["pool_id"], id)
			})
			return row{"ok": true}
		})
	})
}

func (s *Store) replacementDomainUsed(targetID any, domain string) bool {
	return s.one(`SELECT 1 FROM pools WHERE hostname=?
 UNION ALL SELECT 1 FROM server_orders WHERE domain=?
 UNION ALL SELECT 1 FROM replacement_bindings WHERE virtua_domain=? AND target_id!=? LIMIT 1`, domain, domain, domain, targetID) != nil
}

func (s *Store) nodeDomainReserved(domain string) bool {
	return s.one(`SELECT 1 FROM server_orders WHERE domain=?
 UNION ALL SELECT 1 FROM replacement_bindings WHERE virtua_domain=? LIMIT 1`, domain, domain) != nil
}

func (s *Store) setReplacementStage(job row, stage string) {
	s.exec("UPDATE replacement_jobs SET stage=?,error=NULL,can_retry_create=0,next_retry=0,updated_at=? WHERE id=?", stage, iso(time.Now()), job["id"])
	s.event("info", "system", "Автозамена: "+stage, job["pool_id"], job["target_id"])
}
