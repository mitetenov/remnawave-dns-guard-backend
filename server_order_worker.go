package guard

import (
	"encoding/json"
	"errors"
	"net/url"
	"time"
)

func (m *orderManager) runOnce() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var jobs []row
	m.a.withStore(func() any {
		jobs = m.a.s.all("SELECT * FROM server_orders WHERE "+orderActive+" AND next_retry<=? ORDER BY created_at", nowSeconds())
		return nil
	})
	for _, j := range jobs {
		if m.ctx.Err() != nil {
			return
		}
		if err := m.step(j); err != nil && m.ctx.Err() == nil {
			delay := float64(retrySeconds)
			var detail any = err.Error()
			if errors.Is(err, errOrderQuoteChanged) && !truth(j["create_attempted"]) {
				m.stopUnplaced(j, "cancelled", err)
				continue
			}
			if errors.Is(err, errReplacementPending) {
				delay = 5
				detail = nil
			}
			m.a.withStore(func() any {
				m.a.s.exec("UPDATE server_orders SET error=?,next_retry=?,can_retry_create=CASE WHEN host_key IS NULL AND server_uuid IS NULL THEN ? ELSE 0 END,updated_at=? WHERE id=? AND stage=?",
					detail, nowSeconds()+delay, errors.Is(err, errReplacementCreateUnconfirmed), iso(time.Now()), j["id"], j["stage"])
				return nil
			})
		}
	}
}

// A cancelled order cannot advance, even when a provider read started before cancellation.
func (m *orderManager) advance(j row, stage string, fn func()) {
	s := m.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.one("SELECT stage FROM server_orders WHERE id=?", j["id"]); cur["stage"] != j["stage"] {
		return
	}
	s.transaction(func() {
		if fn != nil {
			fn()
		}
		s.exec("UPDATE server_orders SET stage=?,next_retry=0,error=NULL,can_retry_create=0,updated_at=? WHERE id=?", stage, iso(time.Now()), j["id"])
	})
}

func orderInbounds(j row) ([]string, error) {
	var ids []string
	if err := json.Unmarshal([]byte(str(j["inbounds"])), &ids); err != nil || len(ids) == 0 {
		return nil, errors.New("Не удалось прочитать настройки профиля заказа")
	}
	return ids, nil
}

func (m *orderManager) preflight(j row) error {
	ctx, s := m.ctx, m.a.s
	base, err := url.Parse(m.a.config.PublicOrigin)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return errors.New("Укажите доступный по HTTPS PUBLIC_ORIGIN для регистрации SSH-ключа сервера")
	}
	if err = m.installer.ReadyForOrder(orderNode(j)); err != nil {
		return err
	}
	key, err := m.installer.loginPublicKey(ctx)
	if err != nil {
		return err
	}
	dns, err := m.a.dnsProvider()
	if err != nil {
		return err
	}
	if _, err = dns.checkOrderOrigin(j, "", "", false); err != nil {
		return err
	}
	pool := row{"hostname": j["pool_hostname"], "zone_id": j["zone_id"], "ttl": j["ttl"]}
	records, err := dns.addressRecords(pool)
	if err != nil {
		return err
	}
	if err = checkProxy(records); err != nil {
		return err
	}
	panel, err := m.a.remnawaveProvider()
	if err != nil {
		return err
	}
	ids, err := orderInbounds(j)
	if err != nil {
		return err
	}
	if err = panel.checkOrderProfile(ctx, str(j["profile_id"]), ids); err != nil {
		return err
	}
	if _, err = panel.orderNodeSecret(ctx); err != nil {
		return err
	}
	if err = panel.checkOrderHosts(ctx, str(j["pool_hostname"]), ids); err != nil {
		return err
	}
	c, err := m.cloud()
	if err != nil {
		return err
	}
	token := enrollmentToken()
	snapshot, _, zone, err := c.PrepareOrder(ctx, orderCloudRequest{OperationID: str(j["id"]), Zone: str(j["zone"]), Country: str(j["country"]), Plan: str(j["plan"]), Quote: str(j["quote"]),
		Hostname: str(j["alias"]), Title: str(j["domain"]), SSHUser: m.sshUser, SSHKey: key, EnrollToken: token, EnrollURL: base.String() + "/api/server-orders/" + str(j["id"]) + "/enroll"})
	if err != nil {
		return err
	}
	if zone != j["zone"] {
		return errors.New("UpCloud вернул другую локацию для заказа")
	}
	m.advance(j, "provision", func() {
		s.exec("UPDATE server_orders SET snapshot=?,enroll_digest=? WHERE id=?", s.cipher.encrypt(snapshot), digest(token), j["id"])
	})
	return nil
}

func (m *orderManager) provision(j row) error {
	s := m.a.s
	c, err := m.cloud()
	if err != nil {
		return err
	}
	raw, err := s.cipher.decrypt(str(j["snapshot"]))
	if err != nil {
		return errors.New("Не удалось прочитать сохранённый заказ UpCloud")
	}
	if !truth(j["create_attempted"]) {
		if _, err = m.selectedPlan(m.ctx, str(j["zone"]), str(j["quote"])); err != nil {
			return err
		}
	}
	claim := func() (bool, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		res := s.exec("UPDATE server_orders SET create_attempted=1,can_retry_create=0 WHERE id=? AND stage='provision' AND create_attempted=0 AND server_uuid IS NULL AND host_key IS NULL", j["id"])
		n, err := res.RowsAffected()
		return n == 1, err
	}
	server, ip, err := c.ProvisionOrder(m.ctx, raw, str(j["id"]), claim)
	if server != "" {
		if _, ok := canonicalUUID(server); !ok || (j["server_uuid"] != nil && j["server_uuid"] != server) {
			return errors.New("Идентификатор сервера UpCloud не совпадает с сохранённым заказом")
		}
		m.a.withStore(func() any {
			s.exec("UPDATE server_orders SET server_uuid=?,can_retry_create=0 WHERE id=? AND stage='provision' AND create_attempted=1 AND (server_uuid IS NULL OR server_uuid=?)", server, j["id"], server)
			return nil
		})
	}
	if errors.Is(err, errReplacementCreateRejected) {
		// A definite rejection requires a new operator confirmation to place another order.
		m.stopUnplaced(j, "rejected", err)
		return nil
	}
	if err != nil {
		return err
	}
	if _, ok := canonicalUUID(server); !ok || !publicIPv4(ip) {
		return errors.New("UpCloud не подтвердил UUID сервера и публичный IPv4")
	}
	m.advance(j, "enrollment", func() {
		s.exec("UPDATE server_orders SET server_uuid=?,ip=?,snapshot=NULL WHERE id=?", server, ip, j["id"])
	})
	return nil
}

func (m *orderManager) stopUnplaced(j row, stage string, reason error) {
	s := m.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exec(`UPDATE server_orders SET stage=?,updated_at=?,error=?,enroll_digest=NULL,snapshot=NULL,can_retry_create=0
 WHERE id=? AND stage=? AND server_uuid IS NULL AND host_key IS NULL AND (create_attempted=0 OR ?='rejected')`, stage, iso(time.Now()), reason.Error(), j["id"], j["stage"], stage)
}

func (m *orderManager) step(j row) error {
	a, s := m.a, m.a.s
	ctx := m.ctx
	switch j["stage"] {
	case "preflight":
		return m.preflight(j)
	case "provision":
		return m.provision(j)
	case "enrollment":
		if !truth(j["host_key"]) {
			return errReplacementPending
		}
		m.advance(j, "origin", nil)
	case "origin":
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		dns, err := a.dnsProvider()
		if err != nil {
			return err
		}
		if _, err = dns.checkOrderOrigin(j, "", str(j["ip"]), true); err != nil {
			return err
		}
		m.advance(j, "panel", nil)
	case "panel":
		panel, err := a.remnawaveProvider()
		if err != nil {
			return err
		}
		ids, err := orderInbounds(j)
		if err != nil {
			return err
		}
		country := str(j["country"])
		if country == "UK" {
			country = "GB"
		}
		id, err := panel.ensureOrderNode(ctx, str(j["id"]), str(j["alias"]), str(j["ip"]), country, str(j["profile_id"]), ids)
		if err != nil {
			return err
		}
		m.advance(j, "ansible", func() { s.exec("UPDATE server_orders SET node_uuid=? WHERE id=?", id, j["id"]) })
	case "ansible":
		if err := m.install(ctx, j, str(j["ip"]), str(j["node_uuid"])); err != nil {
			return err
		}
		m.advance(j, "target", nil)
	case "target":
		return m.enrollTarget(j)
	case "verify":
		return m.finish(j)
	}
	return nil
}

func (m *orderManager) enrollTarget(j row) error {
	s := m.a.s
	m.a.reconciler.dnsMu.Lock()
	defer m.a.reconciler.dnsMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.one("SELECT id FROM targets WHERE ip=? OR dns_new_ip=? OR lower(remnawave_uuid)=?", j["ip"], j["ip"], j["node_uuid"]) != nil ||
		s.one("SELECT target_id FROM replacement_bindings WHERE provider='upcloud' AND server_uuid=?", j["server_uuid"]) != nil {
		return errors.New("Сервер, IP или нода уже привязаны к другой цели")
	}
	id := uid()
	s.transaction(func() {
		s.exec("INSERT INTO targets(id,pool_id,name,ip,remnawave_uuid,dns_present) VALUES(?,?,?,?,?,0)", id, j["pool_id"], j["alias"], j["ip"], j["node_uuid"])
		m.a.reconciler.queueLocked(id, "enroll")
		s.exec("UPDATE server_orders SET target_id=?,stage='verify',error=NULL,updated_at=?,next_retry=0 WHERE id=?", id, iso(time.Now()), j["id"])
	})
	return nil
}

func (m *orderManager) finish(j row) error {
	a, s := m.a, m.a.s
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	var ready bool
	a.withStore(func() any {
		t := s.one("SELECT * FROM targets WHERE id=?", j["target_id"])
		ready = t != nil && t["ip"] == j["ip"] && t["dns_action"] == nil && !truth(t["dns_uncertain"]) && truth(t["manual_enabled"]) && truth(t["dns_present"]) && s.probeSnapshot().summary(t).Restore
		return nil
	})
	if !ready {
		return errReplacementPending
	}
	p, err := a.remnawaveProvider()
	if err != nil {
		return err
	}
	ids, err := orderInbounds(j)
	if err != nil {
		return err
	}
	if err = p.attachOrderHosts(m.ctx, str(j["pool_hostname"]), str(j["node_uuid"]), ids...); err != nil {
		return err
	}
	m.advance(j, "complete", func() {
		s.exec("INSERT INTO replacement_bindings(target_id,provider,server_uuid,node_uuid,enabled) VALUES(?,'upcloud',?,?,1)", j["target_id"], j["server_uuid"], j["node_uuid"])
		s.event("info", "system", "Сервер UpCloud развёрнут и включён в пул", j["pool_id"], j["target_id"])
	})
	return nil
}

func (s *Store) orderForPool(pool any) bool {
	return s.one("SELECT id FROM server_orders WHERE pool_id=? AND "+orderActive, pool) != nil
}

func orderStageCancellable(j row) bool {
	return oneOf(str(j["stage"]), "preflight", "provision") && !truth(j["create_attempted"])
}

func (m *orderManager) checkDomainZone(j row) error {
	c, err := m.a.dnsProvider()
	if err != nil {
		return err
	}
	return c.checkOrderOriginZone(str(j["domain"]), str(j["zone_id"]))
}
