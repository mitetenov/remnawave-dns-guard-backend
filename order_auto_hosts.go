package guard

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

const orderAutoHostCount = 10
const defaultOrderAutoHostTag = "AUTO_CHEAP_NODE"

func (a *App) orderAutoSlotTag() string {
	if a.config.OrderAutoHostTag != "" {
		return a.config.OrderAutoHostTag
	}
	return defaultOrderAutoHostTag
}

func (s *Store) initializeOrderAutoHosts() {
	s.exec(`CREATE TABLE IF NOT EXISTS server_order_auto_hosts (
 country TEXT NOT NULL, slot INTEGER NOT NULL, pool_id TEXT NOT NULL REFERENCES pools(id) ON DELETE CASCADE,
 hostname TEXT NOT NULL UNIQUE, zone_id TEXT NOT NULL, source_uuid TEXT NOT NULL, host_uuid TEXT NOT NULL UNIQUE,
 profile_id TEXT NOT NULL, inbound_id TEXT NOT NULL, port INTEGER NOT NULL,
 order_id TEXT UNIQUE REFERENCES server_orders(id), PRIMARY KEY(country,slot))`)
}

func orderAutoHostName(country string, slot int) string {
	return fmt.Sprintf("dns-guard-auto-%s-%02d", strings.ToLower(country), slot)
}

// A slot stays reserved while an order is running or its target still exists.
// A cancelled order or a removed target leaves its slot available for reuse.
const orderAutoHostOccupancy = `EXISTS (SELECT 1 FROM server_orders o WHERE o.id=h.order_id AND
 (o.` + orderActive + ` OR
 (o.stage='complete' AND EXISTS (SELECT 1 FROM targets t WHERE t.id=o.target_id))))`

func (s *Store) freeOrderAutoHost(pool, country string, profile string) (row, error) {
	first := s.one("SELECT profile_id FROM server_order_auto_hosts WHERE pool_id=? AND country=? LIMIT 1", pool, country)
	if first == nil {
		return nil, nil
	}
	if first["profile_id"] != profile {
		return nil, errors.New("для автохостов этой страны выберите профиль Remnawave исходного хоста")
	}
	host := s.one(`SELECT h.* FROM server_order_auto_hosts h WHERE pool_id=? AND country=? AND NOT `+orderAutoHostOccupancy+` ORDER BY slot LIMIT 1`, pool, country)
	if host == nil {
		return nil, errors.New("все 10 автохостов этой страны заняты. Для смены IP используйте автозамену существующего сервера")
	}
	return host, nil
}

func orderAutoHostAddress(value any) string {
	return strings.ToLower(strings.TrimSuffix(str(value), "."))
}

func (a *App) setupOrderAutoHosts(ctx context.Context, country, poolID, sourceID string) error {
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	s := a.s
	var pool row
	var saved []row
	a.withStore(func() any {
		pool = a.pool(poolID)
		saved = s.all("SELECT * FROM server_order_auto_hosts WHERE country=? ORDER BY slot", country)
		return nil
	})
	if len(saved) != 0 && (saved[0]["pool_id"] != poolID || saved[0]["source_uuid"] != sourceID || saved[0]["zone_id"] != pool["zone_id"]) {
		return errors.New("для этой страны уже настроены постоянные DNS-имена автохостов")
	}
	if len(saved) != 0 && len(saved) != orderAutoHostCount {
		return errors.New("в базе данных сохранён неполный набор автохостов")
	}
	panel, err := a.remnawaveProvider()
	if err != nil {
		return err
	}
	dns, err := a.dnsProvider()
	if err != nil {
		return err
	}
	hosts, err := orderRemnawaveList[row](ctx, panel, "hosts")
	if err != nil {
		return err
	}
	var source row
	for _, h := range hosts {
		if strings.EqualFold(str(h["uuid"]), sourceID) {
			source = h
			break
		}
	}
	inbound, _ := source["inbound"].(map[string]any)
	profileID, validProfile := canonicalUUID(str(inbound["configProfileUuid"]))
	inboundID, validInbound := canonicalUUID(str(inbound["configProfileInboundUuid"]))
	port := num(source["port"])
	if orderAutoHostAddress(source["address"]) != pool["hostname"] || !validProfile || !validInbound || port < 1 || port > 65535 || port != float64(int(port)) || truth(source["xrayJsonTemplateUuid"]) {
		return errors.New("выберите хост Remnawave с адресом выбранного DNS-пула и настроенным inbound")
	}
	exclusions, _ := source["excludeFromSubscriptionTypes"].([]any)
	for _, excluded := range exclusions {
		if excluded == "XRAY_JSON" {
			return errors.New("исходный хост исключён из подписок XRAY_JSON")
		}
	}
	if len(saved) > 0 && (saved[0]["profile_id"] != profileID || saved[0]["inbound_id"] != inboundID || num(saved[0]["port"]) != port) {
		return errors.New("в исходном хосте изменился inbound или порт. Для автохостов нужны прежние параметры подключения")
	}
	base := orderAutoHostPayload(source, profileID, inboundID, port)
	zoneID := str(pool["zone_id"])
	domains := make([]string, orderAutoHostCount)
	for i := range domains {
		domains[i] = orderAutoHostName(country, i+1) + "." + str(pool["hostname"])
		if len(saved) > 0 && saved[i]["hostname"] != domains[i] {
			return errors.New("имя DNS-пула изменилось после настройки автохостов")
		}
		if !validHost(domains[i]) {
			return errors.New("домен DNS-пула слишком длинный для автохостов")
		}
	}
	if len(saved) == 0 {
		conflict := a.withStore(func() any {
			for _, domain := range domains {
				if s.replacementDomainUsed("", domain) {
					return domain
				}
			}
			return ""
		}).(string)
		if conflict != "" {
			return fmt.Errorf("DNS-имя %s уже используется в DNS Guard", conflict)
		}
	}
	if err = dns.checkOrderOriginZones(zoneID, domains...); err != nil {
		return err
	}
	type slot struct {
		hostID  string
		payload row
		current row
	}
	slots := make([]slot, len(domains))
	for i, domain := range domains {
		name := orderAutoHostName(country, i+1)
		payload := row{"remark": name, "address": domain}
		for field, value := range base {
			payload[field] = value
		}
		current, err := findOrderAutoHost(hosts, payload)
		if err != nil {
			return err
		}
		hostID, _ := canonicalUUID(str(current["uuid"]))
		if len(saved) > 0 && hostID != str(saved[i]["host_uuid"]) {
			return fmt.Errorf("сохранённый автохост %s отсутствует или был пересоздан в Remnawave", name)
		}
		if _, err = dns.orderAutoHostRecord(zoneID, domain, hostID); err != nil {
			return err
		}
		slots[i] = slot{hostID: hostID, payload: payload, current: current}
	}
	tag := a.orderAutoSlotTag()
	for i := range slots {
		slot := &slots[i]
		if slot.hostID == "" {
			payload := maps.Clone(slot.payload)
			payload["tags"] = []string{tag}
			var created row
			createErr := panel.orderRequest(ctx, http.MethodPost, "hosts", payload, &created)
			candidates := []row{created}
			if createErr != nil {
				// A request can take effect even when its response is lost.
				candidates, err = orderRemnawaveList[row](ctx, panel, "hosts")
				if err != nil {
					return err
				}
			}
			slot.current, err = findOrderAutoHost(candidates, slot.payload)
			if err != nil {
				return err
			}
			slot.hostID, _ = canonicalUUID(str(slot.current["uuid"]))
			if slot.hostID == "" {
				return taggedOrderHostError("Remnawave не подтвердил создание автохоста", createErr)
			}
		}
		if err = panel.ensureOrderAutoSlotTag(ctx, slot.hostID, slot.current, tag); err != nil {
			return err
		}
	}
	if len(saved) == 0 {
		a.withStore(func() any {
			// Orders can be queued while the external requests are in flight.
			for _, domain := range domains {
				if s.replacementDomainUsed("", domain) {
					fail(409, fmt.Sprintf("DNS-имя %s уже используется в DNS Guard", domain))
				}
			}
			s.transaction(func() {
				for i, slot := range slots {
					s.exec(`INSERT INTO server_order_auto_hosts(country,slot,pool_id,hostname,zone_id,source_uuid,host_uuid,profile_id,inbound_id,port)
 VALUES(?,?,?,?,?,?,?,?,?,?)`, country, i+1, poolID, domains[i], zoneID, sourceID, slot.hostID, profileID, inboundID, port)
				}
			})
			return nil
		})
	}
	return nil
}

func orderAutoHostPayload(source row, profileID, inboundID string, port float64) row {
	payload := row{
		"inbound": map[string]any{"configProfileUuid": profileID, "configProfileInboundUuid": inboundID},
		"port":    port, "isHidden": true, "isDisabled": false,
	}
	for _, key := range []string{"path", "sni", "host", "alpn", "fingerprint", "securityLayer", "keepSniBlank", "excludedInternalSquads", "excludeFromSubscriptionTypes",
		"xhttpExtraParams", "xHttpExtraParams", "muxParams", "sockoptParams", "finalMask", "vlessRouteId", "pinnedPeerCertSha256", "verifyPeerCertByName"} {
		if value := source[key]; value != nil {
			payload[key] = value
		}
	}
	// An alias changes the dial address. Keep the SNI used by the source host.
	if truth(source["overrideSniFromAddress"]) {
		payload["sni"] = source["address"]
	}
	return payload
}

func findOrderAutoHost(hosts []row, expected row) (row, error) {
	var found row
	for _, h := range hosts {
		if h["remark"] != expected["remark"] && orderAutoHostAddress(h["address"]) != expected["address"] {
			continue
		}
		_, valid := canonicalUUID(str(h["uuid"]))
		if found != nil || !valid || orderAutoHostAddress(h["address"]) != expected["address"] || truth(h["overrideSniFromAddress"]) || truth(h["xrayJsonTemplateUuid"]) {
			return nil, fmt.Errorf("конфликт автохоста Remnawave %s", expected["remark"])
		}
		for key, value := range expected {
			if key == "isDisabled" && h[key] == nil {
				continue // Older panels may omit the false default.
			}
			if key != "address" && !reflect.DeepEqual(h[key], value) {
				return nil, fmt.Errorf("параметры автохоста Remnawave %s отличаются от исходного хоста", expected["remark"])
			}
		}
		found = h
	}
	return found, nil
}

func (c *Cloudflare) orderAutoHostRecord(zone, domain, hostID string) (row, error) {
	path := "/zones/" + url.PathEscape(zone) + "/dns_records"
	records, err := c.pages(path, url.Values{"name": {domain}})
	if err != nil {
		return nil, err
	}
	var owned row
	for _, record := range records {
		if !stringFields(record, "name", "type") {
			return nil, integration("Cloudflare вернул некорректную DNS-запись")
		}
		if orderAutoHostAddress(record["name"]) != domain || !oneOf(str(record["type"]), "A", "AAAA", "CNAME", "NS") {
			continue
		}
		if owned != nil || hostID == "" || record["type"] != "CNAME" || record["comment"] != "dns-guard-auto:"+hostID || record["proxied"] != false ||
			str(record["id"]) == "" || !validHost(orderAutoHostAddress(record["content"])) {
			return nil, fmt.Errorf("DNS-имя автохоста %s уже занято другой записью Cloudflare", domain)
		}
		owned = record
	}
	return owned, nil
}

func (c *Cloudflare) pointOrderAutoHost(host, order row) error {
	zone, domain, hostID := str(host["zone_id"]), str(host["hostname"]), str(host["host_uuid"])
	origin := str(order["domain"])
	if !validHost(origin) || domain == origin {
		return integration("Некорректный домен ноды для автохоста")
	}
	current, err := c.orderAutoHostRecord(zone, domain, hostID)
	if err != nil || orderAutoHostAddress(current["content"]) == origin {
		return err
	}
	path := "/zones/" + url.PathEscape(zone) + "/dns_records"
	if current == nil {
		_, err = c.request(http.MethodPost, path, nil, row{"type": "CNAME", "name": domain, "content": origin,
			"ttl": order["ttl"], "proxied": false, "comment": "dns-guard-auto:" + hostID})
	} else {
		_, err = c.request(http.MethodPatch, path+"/"+url.PathEscape(str(current["id"])), nil, row{"content": origin})
	}
	confirmed, readErr := c.orderAutoHostRecord(zone, domain, hostID)
	if readErr != nil {
		return readErr
	}
	if orderAutoHostAddress(confirmed["content"]) == origin {
		return nil
	}
	if err != nil {
		return err
	}
	return integration("Cloudflare не подтвердил адрес автохоста")
}

func (r *Remnawave) orderAutoHost(ctx context.Context, host row) (row, error) {
	var current row
	if err := r.orderRequest(ctx, http.MethodGet, "hosts/"+str(host["host_uuid"]), nil, &current); err != nil {
		return nil, err
	}
	expected := row{
		"remark": orderAutoHostName(str(host["country"]), int(num(host["slot"]))), "address": host["hostname"],
		"inbound": map[string]any{"configProfileUuid": host["profile_id"], "configProfileInboundUuid": host["inbound_id"]},
		"port":    num(host["port"]), "isHidden": true, "isDisabled": false,
	}
	current, err := findOrderAutoHost([]row{current}, expected)
	if err != nil {
		return nil, err
	}
	id, _ := canonicalUUID(str(current["uuid"]))
	if id != host["host_uuid"] {
		return nil, integration("Постоянный автохост не найден в Remnawave")
	}
	return current, nil
}

func (r *Remnawave) ensureOrderAutoSlotTag(ctx context.Context, id string, host row, tag string) error {
	tags, ok := host["tags"].([]any)
	if !ok && host["tags"] != nil {
		return integration("Remnawave вернул некорректные теги автохоста")
	}
	if slices.Contains(tags, any(tag)) {
		return nil
	}
	patchErr := r.orderRequest(ctx, http.MethodPatch, "hosts", row{"uuid": id, "tags": append(slices.Clone(tags), tag)}, nil)
	var current row
	if err := r.orderRequest(ctx, http.MethodGet, "hosts/"+id, nil, &current); err != nil {
		return err
	}
	currentID, _ := canonicalUUID(str(current["uuid"]))
	updated, _ := current["tags"].([]any)
	if currentID != id || !slices.Contains(updated, any(tag)) {
		return taggedOrderHostError("Remnawave не подтвердил сохранение тега автохоста", patchErr)
	}
	return nil
}
