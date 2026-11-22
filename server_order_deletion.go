package guard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	orderDeleteHosting = 1 << iota
	orderDeleteRemnawave
	orderDeleteDNS
	orderDeleteAll = orderDeleteHosting | orderDeleteRemnawave | orderDeleteDNS
)

type orderDeletionOptions struct {
	Hosting   bool `json:"hosting"`
	Remnawave bool `json:"remnawave"`
	DNS       bool `json:"dns"`
}

func (o orderDeletionOptions) mask() int {
	var selected int
	if o.Hosting {
		selected |= orderDeleteHosting
	}
	if o.Remnawave {
		selected |= orderDeleteRemnawave
	}
	if o.DNS {
		selected |= orderDeleteDNS
	}
	return selected
}

func (m *orderManager) queueDeletion(id string, selected int) {
	a, s := m.a, m.a.s
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	a.withStore(func() any {
		j := s.one("SELECT * FROM server_orders WHERE id=?", id)
		if j == nil {
			fail(404, "Заказ не найден")
		}
		selected &^= int(num(j["deleted_resources"]))
		if j["stage"] == "deleted" || selected == 0 {
			return nil
		}
		if j["stage"] == "deleting" && int(num(j["delete_pending"])) == selected {
			return nil
		}
		if j["stage"] != "complete" {
			fail(409, "Дождитесь завершения текущей операции с сервером")
		}
		if s.activeReplacement(j["target_id"]) != nil {
			fail(409, "Для узла выполняется автозамена. Дождитесь её завершения.")
		}

		// After autoremplacement the order still holds the original server identity.
		serverID, ip := j["server_uuid"], j["ip"]
		if replacement := s.one(`SELECT new_server_uuid,new_ip FROM replacement_jobs
 WHERE target_id=? AND provider=? AND node_uuid=? AND stage='complete' ORDER BY rowid DESC LIMIT 1`,
			j["target_id"], j["provider"], j["node_uuid"]); replacement != nil {
			serverID, ip = replacement["new_server_uuid"], replacement["new_ip"]
		}
		if selected&orderDeleteDNS != 0 {
			target := s.one("SELECT ip,dns_action FROM targets WHERE id=?", j["target_id"])
			if target != nil && (target["ip"] != ip || target["dns_action"] == "replace_ip") {
				fail(409, "IP цели меняется или не совпадает с IP сервера. Проверьте привязку перед удалением DNS.")
			}
		}
		s.exec(`UPDATE server_orders SET stage='deleting',delete_pending=?,server_uuid=?,ip=?,next_retry=0,error=NULL,updated_at=? WHERE id=?`,
			selected, serverID, ip, iso(time.Now()), id)
		return nil
	})
}

func (m *orderManager) deleteOrderResources(j row) error {
	pending := int(num(j["delete_pending"]))
	var done int
	var err error
	switch {
	case pending&orderDeleteDNS != 0:
		return m.deleteOrderDNS(j)
	case pending&orderDeleteRemnawave != 0:
		done = orderDeleteRemnawave
		panel, openErr := m.a.remnawaveProvider()
		if openErr != nil {
			return openErr
		}
		err = panel.deleteOrderNode(m.ctx, j)
	case pending&orderDeleteHosting != 0:
		done = orderDeleteHosting
		err = m.deleteOrderServer(j)
	}
	if err != nil {
		return err
	}
	m.finishOrderDeletionStep(j, done)
	return nil
}

// The DNS lock covers record removal and the local target deletion so that
// reconciliation cannot publish the address again between those steps.
func (m *orderManager) deleteOrderDNS(j row) error {
	a, s := m.a, m.a.s
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	pool := row{"hostname": j["pool_hostname"], "zone_id": j["zone_id"]}
	var conflict bool
	a.withStore(func() any {
		target := s.one("SELECT * FROM targets WHERE id=?", j["target_id"])
		conflict = target != nil && (target["ip"] != j["ip"] || target["pool_id"] != j["pool_id"] || target["dns_action"] == "replace_ip")
		conflict = conflict || s.one(`SELECT t.id FROM targets t JOIN pools p ON p.id=t.pool_id
 WHERE p.hostname=? AND p.zone_id=? AND t.id!=COALESCE(?, '') AND (t.ip=? OR t.dns_new_ip=?)`,
			pool["hostname"], pool["zone_id"], j["target_id"], j["ip"], j["ip"]) != nil
		return nil
	})
	if conflict {
		return errors.New("IP или DNS-пул изменился после развёртывания. Проверьте привязку сервера перед удалением DNS")
	}
	dns, err := a.dnsProvider()
	if err != nil {
		return err
	}
	err = dns.removeOrderDNS(j, pool)
	var integrationErr *IntegrationError
	if errors.As(err, &integrationErr) && integrationErr.Kind == "last_record" {
		a.withStore(func() any {
			s.exec("UPDATE server_orders SET stage='complete',delete_pending=0,error=?,updated_at=? WHERE id=?",
				"Последняя A-запись пула защищена. Добавьте другой IP или снимите галочку удаления из DNS и DNS Guard.", iso(time.Now()), j["id"])
			return nil
		})
		return nil
	}
	if err == nil {
		m.finishOrderDeletionStep(j, orderDeleteDNS)
	}
	return err
}

func (m *orderManager) finishOrderDeletionStep(j row, done int) {
	s := m.a.s
	pending := int(num(j["delete_pending"])) &^ done
	deleted := int(num(j["deleted_resources"])) | done
	stage := "deleting"
	if deleted == orderDeleteAll {
		stage = "deleted"
	} else if pending == 0 {
		stage = "complete"
	}
	m.advance(j, stage, func() {
		s.exec("UPDATE server_orders SET delete_pending=?,deleted_resources=? WHERE id=?", pending, deleted, j["id"])
		switch done {
		case orderDeleteDNS:
			s.exec("DELETE FROM targets WHERE id=?", j["target_id"])
			s.exec("UPDATE pools SET dns_next_check=0,remnawave_next_check=0 WHERE id=?", j["pool_id"])
			s.event("warning", "manual", "Сервер удалён из DNS и DNS Guard", j["pool_id"], j["target_id"])
		case orderDeleteHosting, orderDeleteRemnawave:
			s.exec("UPDATE replacement_bindings SET enabled=0,blocked_since=NULL WHERE target_id=?", j["target_id"])
		}
	})
}

func (c *Cloudflare) removeOrderDNS(j, pool row) error {
	orderID, valid := canonicalUUID(str(j["id"]))
	domain, ip, zone := str(j["domain"]), str(j["ip"]), str(j["zone_id"])
	if !valid || !publicIPv4(ip) || !validHost(domain) || !validHost(str(pool["hostname"])) || domain == pool["hostname"] || zone == "" {
		return errors.New("некорректные параметры DNS заказанного сервера")
	}
	origin, err := c.nodeOriginRecord(zone, domain, "dns-guard-order:"+orderID, false)
	if err != nil {
		return err
	}
	if origin != nil && origin["content"] != ip {
		return integration("A-запись домена сервера указывает на другой IP")
	}
	if _, err = c.ensure(pool, ip, false); err != nil {
		return err
	}
	if origin != nil {
		return c.deleteDNSRecord(zone, str(origin["id"]))
	}
	return nil
}

func (c *Cloudflare) deleteDNSRecord(zone, id string) error {
	_, err := c.request(http.MethodDelete, "/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(id), nil, nil)
	return err
}

func (r *Remnawave) deleteOrderNode(ctx context.Context, order row) error {
	id, valid := canonicalUUID(str(order["node_uuid"]))
	if !valid {
		return errors.New("некорректный UUID ноды Remnawave")
	}
	nodes, err := orderRemnawaveList[orderRemnawaveNode](ctx, r, "nodes")
	if err != nil {
		return err
	}
	for _, node := range nodes {
		nodeID, valid := canonicalUUID(node.UUID)
		if !valid {
			return integration("Remnawave вернул некорректный UUID ноды")
		}
		if nodeID != id {
			continue
		}
		if node.Address != order["ip"] && !strings.EqualFold(strings.TrimSuffix(node.Address, "."), str(order["domain"])) {
			return integration("Адрес ноды Remnawave не совпадает с IP или доменом сервера")
		}
		if err := r.deleteTaggedOrderHost(ctx, order); err != nil {
			return err
		}
		if err := r.orderRequest(ctx, http.MethodDelete, "nodes/"+id, nil, nil); err != nil {
			return err
		}
		return errReplacementPending
	}
	return r.deleteTaggedOrderHost(ctx, order)
}

func (m *orderManager) deleteOrderServer(j row) error {
	id, valid := canonicalUUID(str(j["server_uuid"]))
	ip := str(j["ip"])
	if !valid || !publicIPv4(ip) {
		return errors.New("некорректный UUID или IP заказанного сервера")
	}
	cloud, err := m.cloudFor(str(j["provider"]))
	if err != nil {
		return err
	}
	switch c := cloud.(type) {
	case *virtuaOrder:
		return c.deleteReplacementServer(m.ctx, id, ip)
	case *upCloudOrder:
		return c.deleteServer(m.ctx, id, ip)
	}
	return fmt.Errorf("удаление сервера у хостинга %s недоступно", orderProviderName(str(j["provider"])))
}

func (c *upCloudOrder) deleteServer(ctx context.Context, id, ip string) error {
	server, err := c.server(ctx, id)
	if upCloudStatus(err, http.StatusNotFound, "SERVER_NOT_FOUND") {
		return nil
	}
	if err != nil {
		return err
	}
	if oneOf(server.State, "maintenance", "pending_delete") {
		return errReplacementPending
	}
	var matches bool
	for _, nic := range server.Networking.Interfaces.Items {
		for _, address := range nic.IPs.Items {
			matches = matches || nic.Type == "public" && address.Family == "IPv4" && address.Address == ip
		}
	}
	if !matches {
		return errors.New("публичный IPv4 сервера UpCloud не совпадает с сохранённым IP")
	}
	path := "/server/" + id
	switch server.State {
	case "started":
		err = c.request(ctx, http.MethodPost, path+"/stop", row{"stop_server": row{"stop_type": "soft"}}, nil)
	case "stopped":
		err = c.request(ctx, http.MethodDelete, path+"?storages=1&backups=keep", nil, nil)
	default:
		return errors.New("проверьте состояние сервера в UpCloud перед удалением")
	}
	if err != nil {
		return err
	}
	return errReplacementPending
}
