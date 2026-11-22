package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (w *replacementWorker) replacementOrder(j row) row {
	order := w.managedOrder(j)
	if order != nil || j["provider"] != virtuaOrderProvider {
		return order
	}
	return w.a.withStore(func() any {
		b := w.a.s.one("SELECT virtua_group,virtua_domain FROM replacement_bindings WHERE target_id=?", j["target_id"])
		pool := w.a.pool(str(j["pool_id"]))
		domain := str(b["virtua_domain"])
		alias, _, _ := strings.Cut(domain, ".")
		return row{"id": j["target_id"], "manual_origin": true, "alias": alias, "group_name": b["virtua_group"],
			"domain": domain, "zone_id": pool["zone_id"], "ttl": max(60, num(pool["ttl"]))}
	}).(row)
}

func checkReplacementOrigin(dns *Cloudflare, order row, oldIP, newIP string, mutate bool) (float64, error) {
	if truth(order["manual_origin"]) {
		return dns.checkNodeOrigin(order, "dns-guard-replacement:"+str(order["id"]), oldIP, newIP, mutate, true)
	}
	return dns.checkOrderOrigin(order, oldIP, newIP, mutate)
}

func (w *replacementWorker) stepVirtua(j row) error {
	cloud, err := w.a.orders.cloudFor(virtuaOrderProvider)
	if err != nil {
		return err
	}
	c := cloud.(*virtuaOrder)
	switch j["stage"] {
	case "preflight":
		return w.preflight(j, func() (json.RawMessage, string, error) { return w.prepareVirtua(j, c) })
	case "provision":
		return w.provisionVirtua(j, c)
	case "enrollment":
		return w.finishVirtuaEnrollment(j, c)
	case "cleanup":
		return w.cleanup(j, func() error { return w.retireVirtua(j, c) })
	}
	return errors.New("неизвестный этап автозамены Virtua.Cloud")
}

func (w *replacementWorker) virtuaPlan(j row, c *virtuaOrder) (orderCloudPlan, string, string, error) {
	b := w.a.withStore(func() any {
		return w.a.s.one("SELECT virtua_zone,virtua_quote FROM replacement_bindings WHERE target_id=?", j["target_id"])
	}).(row)
	zone, quote := str(b["virtua_zone"]), str(b["virtua_quote"])
	if !validOrderZone(virtuaOrderProvider, zone) {
		return orderCloudPlan{}, "", "", errors.New("выберите локацию Virtua.Cloud в привязке узла")
	}
	plans, err := c.zonePlans(w.ctx, zone, true)
	if err != nil {
		return orderCloudPlan{}, "", "", err
	}
	plan, err := matchOrderQuote(zone, quote, plans)
	if errors.Is(err, errOrderQuoteChanged) {
		err = fmt.Errorf("обновите тариф Virtua.Cloud в привязке узла: %w", err)
	}
	return plan, zone, quote, err
}

func (w *replacementWorker) prepareVirtua(j row, c *virtuaOrder) (json.RawMessage, string, error) {
	m := w.a.orders
	base, err := m.enrollmentOrigin()
	if err != nil {
		return nil, "", err
	}
	key, err := m.installer.loginPublicKey(w.ctx)
	if err != nil {
		return nil, "", err
	}
	if err = c.checkReplacementServer(w.ctx, str(j["server_uuid"]), str(j["old_ip"])); err != nil {
		return nil, "", err
	}
	plan, zone, quote, err := w.virtuaPlan(j, c)
	if err != nil {
		return nil, "", err
	}
	token, id := enrollmentToken(), str(j["id"])
	data, _, _, err := c.PrepareOrder(w.ctx, orderCloudRequest{OperationID: id, Zone: zone, Country: plan.Country,
		Plan: plan.Code, Quote: quote, SSHUser: m.sshUser, SSHKey: key, EnrollToken: token,
		EnrollURL: base.String() + "/api/server-orders/" + id + "/enroll"})
	return data, digest(token), err
}

func (w *replacementWorker) provisionVirtua(j row, c *virtuaOrder) error {
	a, s := w.a, w.a.s
	raw, err := s.cipher.decrypt(str(j["snapshot"]))
	if err != nil {
		return errors.New("не удалось прочитать сохранённую конфигурацию Virtua.Cloud")
	}
	snapshot, err := readVirtuaSnapshot(raw, str(j["id"]))
	if err != nil {
		return err
	}
	claim := func() (bool, error) {
		if truth(j["create_attempted"]) {
			return false, nil
		}
		// Read the current price only when actually attempting a purchase.
		if _, _, _, err := w.virtuaPlan(j, c); err != nil {
			return false, err
		}
		if err := c.checkReplacementServer(w.ctx, str(j["server_uuid"]), str(j["old_ip"])); err != nil {
			return false, err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		current := s.one(`SELECT j.create_attempted,j.new_server_uuid,j.host_key,b.enabled,p.automation_enabled
 FROM replacement_jobs j JOIN replacement_bindings b ON b.target_id=j.target_id JOIN pools p ON p.id=j.pool_id
 WHERE j.id=? AND j.stage='provision'`, j["id"])
		if !truth(current["enabled"]) || !truth(current["automation_enabled"]) {
			return false, errReplacementPending
		}
		if truth(current["create_attempted"]) || current["new_server_uuid"] != nil || current["host_key"] != nil {
			return false, nil
		}
		s.exec("UPDATE replacement_jobs SET create_attempted=1,can_retry_create=0 WHERE id=?", j["id"])
		return true, nil
	}
	server, ip, err := c.ProvisionOrder(w.ctx, raw, str(j["id"]), str(j["new_server_uuid"]), claim)
	switch {
	case errors.Is(err, errOrderQuoteChanged):
		// No create request was accepted. The binding can be edited again.
		if cleanupErr := c.cleanupScript(w.ctx, snapshot); cleanupErr != nil {
			return cleanupErr
		}
		w.commit(j, "cancelled", func() {
			s.exec("UPDATE replacement_jobs SET snapshot=NULL,enroll_digest=NULL WHERE id=?", j["id"])
			s.event("warning", "system", err.Error(), j["pool_id"], j["target_id"])
		})
		return nil
	case errors.Is(err, errReplacementCreateRejected):
		a.withStore(func() any {
			s.exec("UPDATE replacement_jobs SET create_attempted=0 WHERE id=? AND stage='provision' AND new_server_uuid IS NULL AND host_key IS NULL", j["id"])
			return nil
		})
		return err
	}
	if server != "" {
		if id, ok := canonicalUUID(server); !ok || id != server || server == j["server_uuid"] {
			return errors.New("Virtua.Cloud не подтвердил UUID нового сервера")
		}
		conflict := a.withStore(func() any {
			if s.one(`SELECT id FROM replacement_jobs WHERE id=? AND create_attempted=1 AND (new_server_uuid IS NULL OR new_server_uuid=?)`, j["id"], server) == nil ||
				s.one("SELECT target_id FROM replacement_bindings WHERE provider='virtua' AND server_uuid=?", server) != nil ||
				s.one("SELECT id FROM replacement_jobs WHERE id!=? AND provider='virtua' AND new_server_uuid=? AND "+replacementActive, j["id"], server) != nil ||
				s.one("SELECT id FROM server_orders WHERE provider='virtua' AND server_uuid=? AND stage NOT IN ('cancelled','rejected')", server) != nil {
				return true
			}
			s.exec("UPDATE replacement_jobs SET new_server_uuid=?,can_retry_create=0 WHERE id=?", server, j["id"])
			return false
		}).(bool)
		if conflict {
			return errors.New("новый сервер Virtua.Cloud уже связан с другой операцией")
		}
	}
	if err != nil {
		return err
	}
	if server == "" || !publicIPv4(ip) || ip == j["old_ip"] {
		return errors.New("Virtua.Cloud не подтвердил новый публичный IPv4")
	}
	w.commit(j, "enrollment", func() {
		s.exec("UPDATE replacement_jobs SET new_ip=? WHERE id=?", ip, j["id"])
	})
	return nil
}

func (w *replacementWorker) finishVirtuaEnrollment(j row, c *virtuaOrder) error {
	if !enrolledEd25519(str(j["host_key"])) {
		return errReplacementPending
	}
	s := w.a.s
	raw, err := s.cipher.decrypt(str(j["snapshot"]))
	if err != nil {
		return errors.New("не удалось прочитать сохранённую конфигурацию Virtua.Cloud")
	}
	snapshot, err := readVirtuaSnapshot(raw, str(j["id"]))
	if err != nil {
		return err
	}
	if err = c.cleanupScript(w.ctx, snapshot); err != nil {
		return err
	}
	w.commit(j, "ansible", func() {
		s.exec("UPDATE replacement_jobs SET snapshot=NULL,enroll_digest=NULL WHERE id=?", j["id"])
	})
	return nil
}

func (w *replacementWorker) retireVirtua(j row, c *virtuaOrder) error {
	if !w.recovered(j) {
		return errReplacementPending
	}
	panel, err := w.a.remnawaveProvider()
	if err != nil {
		return err
	}
	if err = panel.checkVirtuaCutover(j); err != nil {
		return err
	}
	newID := str(j["new_server_uuid"])
	newIP, err := c.readyAddress(w.ctx, newID)
	if err != nil {
		return err
	}
	if newIP != j["new_ip"] {
		return errors.New("новый сервер Virtua.Cloud сменил IPv4")
	}
	return c.retireReplacementServer(w.ctx, str(j["server_uuid"]), str(j["old_ip"]), newID)
}

func (c *virtuaOrder) retireReplacementServer(ctx context.Context, oldID, oldIP, newID string) error {
	err := c.deleteReplacementServer(ctx, oldID, oldIP)
	var apiErr *virtuaAPIError
	if !errors.As(err, &apiErr) || apiErr.status != http.StatusForbidden || apiErr.operation != "GET /v1/cloud-server/"+oldID {
		return err
	}

	// The new VPS must also be visible in the account inventory used to confirm absence.
	servers, listErr := c.listServers(ctx)
	if listErr != nil {
		return fmt.Errorf("%w. Не удалось проверить список серверов: %w", err, listErr)
	}
	newListed := false
	for _, server := range servers {
		id, ok := canonicalUUID(server.ID)
		if !ok {
			return fmt.Errorf("%w. Virtua.Cloud вернул некорректный UUID в списке серверов", err)
		}
		if id == oldID {
			return fmt.Errorf("%w. Старый VPS по-прежнему в списке серверов Virtua.Cloud", err)
		}
		newListed = newListed || id == newID
	}
	if !newListed {
		return fmt.Errorf("%w. Новый VPS отсутствует в списке серверов Virtua.Cloud", err)
	}
	return nil
}

func (c *virtuaOrder) checkReplacementServer(ctx context.Context, id, expectedIP string) error {
	if canonical, ok := canonicalUUID(id); !ok || canonical != id {
		return errors.New("некорректный UUID сервера Virtua.Cloud")
	}
	server, err := c.server(ctx, id)
	if err != nil {
		return err
	}
	if server.Processing == nil || *server.Processing {
		return errReplacementPending
	}
	ip, err := c.publicAddress(ctx, id)
	if err != nil {
		return err
	}
	if ip == "" || ip != expectedIP {
		return errors.New("публичный IPv4 сервера Virtua.Cloud не совпадает с IP привязанного узла")
	}
	return nil
}

func (c *virtuaOrder) deleteReplacementServer(ctx context.Context, id, oldIP string) error {
	if err := c.checkReplacementServer(ctx, id, oldIP); err != nil {
		var apiErr *virtuaAPIError
		if errors.As(err, &apiErr) && (apiErr.status == http.StatusNotFound || apiErr.code == "cloud_server_not_found") {
			// The networking endpoint may return 404 for a server that still exists.
			_, err = c.server(ctx, id)
			if errors.As(err, &apiErr) && (apiErr.status == http.StatusNotFound || apiErr.code == "cloud_server_not_found") {
				return nil
			}
			if err == nil {
				return errors.New("не удалось подтвердить старый IPv4 перед удалением Virtua.Cloud")
			}
		}
		return err
	}
	if _, err := c.request(ctx, http.MethodDelete, "/cloud-server/"+id, nil, nil); err != nil {
		return err
	}
	return errReplacementPending
}
