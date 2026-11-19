package guard

import (
	"errors"
	"strings"
)

func (r *Remnawave) checkReplacementNode(job row, update bool) error {
	nodes, err := r.nodes()
	if err != nil {
		return err
	}
	found := false
	for _, node := range nodes {
		if !strings.EqualFold(str(node["uuid"]), str(job["node_uuid"])) {
			if node["address"] == job["old_ip"] || node["address"] == job["new_ip"] {
				return errors.New("этот адрес используется другой нодой Remnawave")
			}
			continue
		}
		found = true
		if update && node["address"] == job["new_ip"] {
			continue
		}
		if node["address"] != job["old_ip"] {
			return errors.New("IPv4 привязанной ноды Remnawave не совпадает с прежним IP цели")
		}
	}
	if !found {
		return errors.New("привязанная нода не найдена в Remnawave")
	}
	if !update {
		return nil
	}
	for _, node := range nodes {
		if strings.EqualFold(str(node["uuid"]), str(job["node_uuid"])) && node["address"] != job["new_ip"] {
			if err = r.patch("nodes", row{"uuid": job["node_uuid"], "address": job["new_ip"]}); err != nil {
				return err
			}
			nodes, err = r.nodes()
			if err != nil {
				return err
			}
			for _, current := range nodes {
				if strings.EqualFold(str(current["uuid"]), str(job["node_uuid"])) && current["address"] == job["new_ip"] {
					return nil
				}
			}
			return errors.New("Remnawave ещё не подтвердил адрес ноды")
		}
	}
	return nil
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
