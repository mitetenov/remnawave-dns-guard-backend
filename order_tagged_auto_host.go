package guard

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

var remnawaveOrderAutoHostTag = regexp.MustCompile(`^[A-Z0-9_:]{1,36}$`)

func taggedOrderHostRemark(orderID string) string { return "dns-guard-auto-" + orderID }

func remnawaveHostAddress(value any) string {
	return strings.ToLower(strings.TrimSuffix(str(value), "."))
}

func taggedOrderHostSource(hosts []row, order row, inbounds []string) (row, error) {
	var source row
	for _, host := range hosts {
		inbound, _ := host["inbound"].(map[string]any)
		excludedTypes, _ := host["excludeFromSubscriptionTypes"].([]any)
		port := num(host["port"])
		if remnawaveHostAddress(host["address"]) != remnawaveHostAddress(order["pool_hostname"]) ||
			truth(host["isHidden"]) || truth(host["isDisabled"]) || truth(host["xrayJsonTemplateUuid"]) ||
			!strings.EqualFold(str(inbound["configProfileUuid"]), str(order["profile_id"])) ||
			!slices.Contains(inbounds, str(inbound["configProfileInboundUuid"])) || slices.Contains(excludedTypes, any("XRAY_JSON")) ||
			port < 1 || port > 65535 || port != float64(int(port)) {
			continue
		}
		if source != nil {
			return nil, integration("Для «Авто» нужен один включённый видимый хост Remnawave с адресом пула и выбранным inbound")
		}
		source = host
	}
	if source == nil {
		return nil, integration("Для «Авто» не найден включённый видимый хост Remnawave с адресом пула и выбранным inbound")
	}
	return source, nil
}

func (r *Remnawave) checkTaggedOrderHost(ctx context.Context, order row, inbounds []string) error {
	hosts, err := orderRemnawaveList[row](ctx, r, "hosts")
	if err != nil {
		return err
	}
	_, err = taggedOrderHostSource(hosts, order, inbounds)
	return err
}

func taggedOrderHostPayload(source row, orderID, address, nodeID, tag string) row {
	payload := row{
		"remark": taggedOrderHostRemark(orderID), "address": address, "inbound": source["inbound"], "port": source["port"],
		"nodes": []any{nodeID}, "tags": []any{tag}, "isHidden": true, "isDisabled": true,
	}
	for _, field := range []string{
		"path", "sni", "host", "alpn", "fingerprint", "securityLayer", "keepSniBlank", "serverDescription",
		"internalSquads", "excludedInternalSquads", "excludeFromSubscriptionTypes", "xhttpExtraParams", "muxParams",
		"sockoptParams", "finalMask", "vlessRouteId", "pinnedPeerCertSha256", "verifyPeerCertByName",
	} {
		if source[field] != nil {
			payload[field] = source[field]
		}
	}
	if truth(source["overrideSniFromAddress"]) {
		payload["sni"] = source["address"]
	}
	return payload
}

func findTaggedOrderHost(hosts []row, expected row) (row, error) {
	var found row
	for _, host := range hosts {
		if host["remark"] != expected["remark"] {
			continue
		}
		if _, valid := canonicalUUID(str(host["uuid"])); !valid || found != nil {
			return nil, integration("Remnawave вернул конфликтующие хосты «Авто» для заказа")
		}
		for key, value := range expected {
			if key != "isDisabled" && !reflect.DeepEqual(value, host[key]) {
				return nil, integration("Настройки хоста «Авто» в Remnawave не совпадают с настройками заказа")
			}
		}
		if _, valid := host["isDisabled"].(bool); !valid || truth(host["overrideSniFromAddress"]) || truth(host["xrayJsonTemplateUuid"]) {
			return nil, integration("Не удалось подтвердить настройки хоста «Авто» в Remnawave")
		}
		found = host
	}
	return found, nil
}

func (r *Remnawave) ensureTaggedOrderHost(ctx context.Context, order row, inbounds []string, tag string) (string, error) {
	orderID, validOrder := canonicalUUID(str(order["id"]))
	nodeID, validNode := canonicalUUID(str(order["node_uuid"]))
	address := remnawaveHostAddress(order["domain"])
	if !validOrder || !validNode || !validHost(address) {
		return "", integration("Не удалось определить домен или ноду хоста «Авто»")
	}
	hosts, err := orderRemnawaveList[row](ctx, r, "hosts")
	if err != nil {
		return "", err
	}
	source, err := taggedOrderHostSource(hosts, order, inbounds)
	if err != nil {
		return "", err
	}
	payload := taggedOrderHostPayload(source, orderID, address, nodeID, tag)
	host, err := findTaggedOrderHost(hosts, payload)
	if err != nil {
		return "", err
	}
	if host == nil {
		createErr := r.orderRequest(ctx, http.MethodPost, "hosts", payload, nil)
		hosts, err = orderRemnawaveList[row](ctx, r, "hosts")
		if err != nil {
			return "", err
		}
		host, err = findTaggedOrderHost(hosts, payload)
		if err != nil {
			return "", err
		}
		if host == nil {
			return "", taggedOrderHostError("Remnawave не подтвердил создание хоста «Авто»", createErr)
		}
	}
	id, _ := canonicalUUID(str(host["uuid"]))
	if !truth(host["isDisabled"]) {
		return id, nil
	}
	patchErr := r.orderRequest(ctx, http.MethodPatch, "hosts", row{"uuid": id, "isDisabled": false}, nil)
	var current row
	if err := r.orderRequest(ctx, http.MethodGet, "hosts/"+id, nil, &current); err != nil {
		return "", err
	}
	host, err = findTaggedOrderHost([]row{current}, payload)
	if err != nil {
		return "", err
	}
	if host == nil || !strings.EqualFold(str(host["uuid"]), id) || truth(host["isDisabled"]) {
		return "", taggedOrderHostError("Remnawave не подтвердил включение хоста «Авто»", patchErr)
	}
	return id, nil
}

func taggedOrderHostError(message string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", message, err)
	}
	return integration(message)
}

func (r *Remnawave) deleteTaggedOrderHost(ctx context.Context, order row) error {
	if str(order["auto_host_uuid"]) == "" {
		return nil
	}
	id, valid := canonicalUUID(str(order["auto_host_uuid"]))
	if !valid {
		return integration("Некорректный UUID хоста «Авто» в заказе")
	}
	hosts, err := orderRemnawaveList[row](ctx, r, "hosts")
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if !strings.EqualFold(str(host["uuid"]), id) {
			continue
		}
		if host["remark"] != taggedOrderHostRemark(str(order["id"])) || !truth(host["isHidden"]) ||
			remnawaveHostAddress(host["address"]) != remnawaveHostAddress(order["domain"]) {
			return integration("Хост «Авто» в Remnawave не совпадает с сохранённым заказом")
		}
		return r.orderRequest(ctx, http.MethodDelete, "hosts/"+id, nil, nil)
	}
	return nil
}
