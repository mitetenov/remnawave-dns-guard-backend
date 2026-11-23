package guard

import (
	"errors"
	"strings"
)

func (r *Remnawave) checkVirtuaCutover(job row) error {
	nodes, err := r.nodes()
	if err != nil {
		return err
	}
	boundAddress := ""
	for _, node := range nodes {
		if node["address"] == job["old_ip"] {
			return errors.New("прежний IP всё ещё используется нодой Remnawave")
		}
		if strings.EqualFold(str(node["uuid"]), str(job["node_uuid"])) {
			boundAddress = str(node["address"])
		} else if replacementUsesOrigin(job, node["address"]) {
			return errors.New("домен используется другой нодой Remnawave")
		}
	}
	if boundAddress != job["new_ip"] && !replacementUsesOrigin(job, boundAddress) {
		return errors.New("не подтверждён новый адрес привязанной ноды Remnawave")
	}
	hosts, err := r.hosts()
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if host["address"] == job["old_ip"] {
			return errors.New("прежний IP всё ещё используется хостом Remnawave")
		}
	}
	return nil
}

func replacementUsesOrigin(job row, address any) bool {
	origin := str(job["node_domain"])
	return origin != "" && strings.EqualFold(strings.TrimSuffix(str(address), "."), origin)
}

func (r *Remnawave) checkReplacementNode(job row, update bool) error {
	nodes, err := r.nodes()
	if err != nil {
		return err
	}
	var bound row
	for _, node := range nodes {
		if !strings.EqualFold(str(node["uuid"]), str(job["node_uuid"])) {
			if node["address"] == job["old_ip"] || node["address"] == job["new_ip"] || replacementUsesOrigin(job, node["address"]) {
				return errors.New("этот адрес используется другой нодой Remnawave")
			}
			continue
		}
		bound = node
		if replacementUsesOrigin(job, node["address"]) {
			continue
		}
		if update && node["address"] == job["new_ip"] {
			continue
		}
		if node["address"] != job["old_ip"] {
			return errors.New("IPv4 привязанной ноды Remnawave не совпадает с прежним IP цели")
		}
	}
	if bound == nil {
		return errors.New("привязанная нода не найдена в Remnawave")
	}
	if !update {
		return nil
	}
	pluginID := str(job["plugin_uuid"])
	addressMatches := func(node row) bool {
		return node["address"] == job["new_ip"] || replacementUsesOrigin(job, node["address"])
	}
	pluginMatches := func(node row) bool {
		return pluginID == "" || strings.EqualFold(str(node["active_plugin_uuid"]), pluginID)
	}
	patch := row{"uuid": job["node_uuid"]}
	if !addressMatches(bound) {
		patch["address"] = job["new_ip"]
	}
	if !pluginMatches(bound) {
		patch["activePluginUuid"] = pluginID
	}
	if len(patch) == 1 {
		return nil
	}
	if err = r.patch("nodes", patch); err != nil {
		return err
	}
	nodes, err = r.nodes()
	if err != nil {
		return err
	}
	for _, current := range nodes {
		if strings.EqualFold(str(current["uuid"]), str(job["node_uuid"])) && addressMatches(current) {
			if !pluginMatches(current) {
				return errors.New("Remnawave ещё не подтвердил плагин ноды")
			}
			return nil
		}
	}
	return errors.New("Remnawave ещё не подтвердил адрес ноды")
}

// Hostnames continue to follow DNS. A host with an explicit IP can be changed
// only if its sole assigned node matches the enrolled node.
func (r *Remnawave) replacementHosts(job row, update bool) error {
	hosts, err := r.hosts()
	if err != nil {
		return err
	}
	var ids []string
	for _, host := range hosts {
		if host["address"] != job["old_ip"] {
			continue
		}
		nodes := host["node_uuids"].([]any)
		if len(nodes) != 1 || !strings.EqualFold(str(nodes[0]), str(job["node_uuid"])) {
			return errors.New("хост Remnawave с прежним IP не имеет однозначной привязки к этой ноде")
		}
		ids = append(ids, str(host["uuid"]))
	}
	if !update || len(ids) == 0 {
		return nil
	}
	for _, id := range ids {
		if err = r.patch("hosts", row{"uuid": id, "address": job["new_ip"]}); err != nil {
			return err
		}
	}
	hosts, err = r.hosts()
	if err != nil {
		return err
	}
	confirmed := map[string]bool{}
	for _, host := range hosts {
		if host["address"] == job["new_ip"] {
			confirmed[str(host["uuid"])] = true
		}
	}
	for _, id := range ids {
		if !confirmed[id] {
			return errors.New("Remnawave ещё не подтвердил новый адрес хоста")
		}
	}
	return nil
}
