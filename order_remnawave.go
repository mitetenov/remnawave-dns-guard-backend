package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"
)

type orderRemnawaveInbound struct {
	UUID        string `json:"uuid"`
	ProfileUUID string `json:"profileUuid"`
	Tag         string `json:"tag"`
}

type orderPanelProfile struct {
	ID       string                    `json:"id"`
	Name     string                    `json:"name"`
	Inbounds []orderPanelInboundChoice `json:"inbounds"`
}

type orderPanelInboundChoice struct {
	ID  string `json:"id"`
	Tag string `json:"tag"`
}

type orderRemnawaveNode struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Country       string `json:"countryCode"`
	Note          string `json:"note"`
	PluginUUID    string `json:"activePluginUuid"`
	ConfigProfile struct {
		UUID     string                  `json:"activeConfigProfileUuid"`
		Inbounds []orderRemnawaveInbound `json:"activeInbounds"`
	} `json:"configProfile"`
}

type orderRemnawaveHost struct {
	UUID    string                    `json:"uuid"`
	Address string                    `json:"address"`
	Nodes   []string                  `json:"nodes"`
	Inbound orderRemnawaveHostInbound `json:"inbound"`
}

type orderRemnawaveHostInbound struct {
	UUID string `json:"configProfileInboundUuid"`
}

var orderRemnawaveSecretPattern = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)

// Match the Ansible node's control API port. It is separate from client inbounds.
const orderRemnawaveNodePort = 2222

func (r *Remnawave) orderNodeSecret(ctx context.Context) (string, error) {
	var key struct {
		Secret string `json:"secretKey"`
	}
	if err := r.orderRequest(ctx, http.MethodGet, "keygen", nil, &key); err != nil {
		return "", err
	}
	// The panel's credential is an encoded payload written as a single
	// environment value by the deployment playbook.
	if len(key.Secret) > 128<<10 || !orderRemnawaveSecretPattern.MatchString(key.Secret) {
		return "", integration("Remnawave returned an invalid node secret")
	}
	return key.Secret, nil
}

func (r *Remnawave) orderProfiles(ctx context.Context) ([]orderPanelProfile, error) {
	var response struct {
		Profiles []struct {
			UUID     string                  `json:"uuid"`
			Name     string                  `json:"name"`
			Inbounds []orderRemnawaveInbound `json:"inbounds"`
		} `json:"configProfiles"`
	}
	if err := r.orderRequest(ctx, http.MethodGet, "config-profiles", nil, &response); err != nil {
		return nil, err
	}
	if response.Profiles == nil {
		return nil, integration("Remnawave returned an invalid configuration profile list")
	}
	profiles := make([]orderPanelProfile, 0, len(response.Profiles))
	seen := make(map[string]bool, len(response.Profiles))
	for _, profile := range response.Profiles {
		id, valid := canonicalUUID(profile.UUID)
		if !valid || strings.TrimSpace(profile.Name) == "" || seen[id] {
			return nil, integration("Remnawave returned an invalid configuration profile list")
		}
		seen[id] = true
		inbounds, err := orderProfileInboundChoices(id, profile.Inbounds)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, orderPanelProfile{ID: id, Name: profile.Name, Inbounds: inbounds})
	}
	return profiles, nil
}

func (r *Remnawave) orderPlugins(ctx context.Context) ([]orderChoice, error) {
	var response struct {
		Plugins []struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
		} `json:"nodePlugins"`
	}
	if err := r.orderRequest(ctx, http.MethodGet, "node-plugins", nil, &response); err != nil {
		return nil, err
	}
	if response.Plugins == nil {
		return nil, integration("Remnawave returned an invalid node plugin list")
	}
	choices := make([]orderChoice, 0, len(response.Plugins))
	seen := make(map[string]bool, len(response.Plugins))
	for _, plugin := range response.Plugins {
		id, valid := canonicalUUID(plugin.UUID)
		if !valid || strings.TrimSpace(plugin.Name) == "" || seen[id] {
			return nil, integration("Remnawave returned an invalid node plugin list")
		}
		seen[id] = true
		choices = append(choices, orderChoice{ID: id, Label: plugin.Name})
	}
	return choices, nil
}

func (r *Remnawave) orderPluginName(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	plugins, err := r.orderPlugins(ctx)
	if err != nil {
		return "", err
	}
	for _, plugin := range plugins {
		if plugin.ID == id {
			return plugin.Label, nil
		}
	}
	return "", errors.New("выбранный плагин ноды не найден в Remnawave")
}

func (r *Remnawave) checkOrderProfile(ctx context.Context, profileID string, inbounds []string) error {
	profileID, requested, err := orderRemnawaveProfile(profileID, inbounds)
	if err != nil {
		return err
	}
	var profile struct {
		Inbounds []orderRemnawaveInbound `json:"inbounds"`
	}
	if err := r.orderRequest(ctx, http.MethodGet, "config-profiles/"+profileID+"/inbounds", nil, &profile); err != nil {
		return err
	}
	available, err := orderProfileInboundChoices(profileID, profile.Inbounds)
	if err != nil {
		return err
	}
	for _, id := range requested {
		if !slices.ContainsFunc(available, func(inbound orderPanelInboundChoice) bool { return inbound.ID == id }) {
			return integration("A selected inbound does not belong to the Remnawave configuration profile")
		}
	}
	return nil
}

func orderProfileInboundChoices(profileID string, inbounds []orderRemnawaveInbound) ([]orderPanelInboundChoice, error) {
	if inbounds == nil {
		return nil, integration("Remnawave returned an invalid configuration profile response")
	}
	choices := make([]orderPanelInboundChoice, 0, len(inbounds))
	seen := make(map[string]bool, len(inbounds))
	for _, inbound := range inbounds {
		id, valid := canonicalUUID(inbound.UUID)
		owner, validOwner := canonicalUUID(inbound.ProfileUUID)
		if !valid || !validOwner || owner != profileID || seen[id] {
			return nil, integration("Remnawave returned an invalid configuration profile response")
		}
		seen[id] = true
		choices = append(choices, orderPanelInboundChoice{ID: id, Tag: inbound.Tag})
	}
	return choices, nil
}

func orderRemnawaveProfile(profileID string, inbounds []string) (string, []string, error) {
	profile, valid := canonicalUUID(profileID)
	if !valid || len(inbounds) == 0 {
		return "", nil, integration("A Remnawave configuration profile and at least one inbound are required")
	}
	ids := make([]string, 0, len(inbounds))
	seen := make(map[string]bool, len(inbounds))
	for _, inbound := range inbounds {
		id, valid := canonicalUUID(inbound)
		if !valid || seen[id] {
			return "", nil, integration("The Remnawave inbound selection is invalid")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return profile, ids, nil
}

func (r *Remnawave) ensureOrderNode(ctx context.Context, orderID, name, ip, country, profileID string, inbounds []string, pluginID string) (string, error) {
	orderID, valid := canonicalUUID(orderID)
	name = strings.TrimSpace(name)
	country = strings.ToUpper(country)
	nameLength := len(utf16.Encode([]rune(name)))
	if !valid || !publicIPv4(ip) || nameLength < 3 || nameLength > 30 ||
		len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return "", integration("The Remnawave node order identity is invalid")
	}
	profileID, inbounds, err := orderRemnawaveProfile(profileID, inbounds)
	if err != nil {
		return "", err
	}
	note := "dns-guard-order:" + orderID
	find := func() (string, error) {
		nodes, err := orderRemnawaveList[orderRemnawaveNode](ctx, r, "nodes")
		if err != nil {
			return "", err
		}
		var found string
		for _, n := range nodes {
			if n.Name == "" || n.Address == "" {
				return "", integration("Remnawave returned an invalid node response")
			}
			if n.Note != note {
				if n.Name == name || n.Address == ip {
					return "", integration("The ordered node name or address is already used by another Remnawave node")
				}
				continue
			}
			id, valid := canonicalUUID(n.UUID)
			if found != "" || !valid || n.Name != name || n.Address != ip || n.Port != orderRemnawaveNodePort || n.Country != country ||
				!strings.EqualFold(n.ConfigProfile.UUID, profileID) ||
				!hasOrderRemnawaveInbounds(n.ConfigProfile.Inbounds, inbounds) ||
				(pluginID != "" && !strings.EqualFold(n.PluginUUID, pluginID)) {
				return "", integration("The Remnawave node marked for this order does not match its saved configuration")
			}
			found = id
		}
		return found, nil
	}
	if existing, err := find(); err != nil || existing != "" {
		return existing, err
	}
	create := row{
		"name":        name,
		"address":     ip,
		"port":        orderRemnawaveNodePort,
		"countryCode": country,
		"note":        note,
		"configProfile": row{
			"activeConfigProfileUuid": profileID,
			"activeInbounds":          inbounds,
		},
	}
	if pluginID != "" {
		create["activePluginUuid"] = pluginID
	}
	createErr := r.orderRequest(ctx, http.MethodPost, "nodes", create, nil)
	// The panel enforces unique name and address. Even if a retry raced a
	// pending POST, the readback adopts only the node marked for this order.
	id, err := find()
	if err != nil || id != "" {
		return id, err
	}
	if createErr != nil {
		return "", createErr
	}
	return "", integration("Remnawave has not confirmed the new node")
}

func hasOrderRemnawaveInbounds(active []orderRemnawaveInbound, requested []string) bool {
	if len(active) != len(requested) {
		return false
	}
	seen := make(map[string]bool, len(active))
	for _, inbound := range active {
		id, valid := canonicalUUID(inbound.UUID)
		if !valid || seen[id] || !slices.Contains(requested, id) {
			return false
		}
		seen[id] = true
	}
	return true
}

func (r *Remnawave) checkOrderHosts(ctx context.Context, hostname string, inboundIDs []string) error {
	_, err := r.orderHostIDs(ctx, strings.TrimRight(hostname, "."), inboundIDs)
	return err
}

func (r *Remnawave) attachOrderHosts(ctx context.Context, hostname, nodeID string, inboundIDs ...string) error {
	hostname = strings.TrimRight(hostname, ".")
	nodeID, valid := canonicalUUID(nodeID)
	if !valid {
		return integration("The Remnawave node identity is invalid")
	}
	ids, err := r.orderHostIDs(ctx, hostname, inboundIDs)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := r.attachOrderHost(ctx, id, hostname, nodeID, inboundIDs); err != nil {
			return err
		}
	}
	return nil
}

func (r *Remnawave) orderHostIDs(ctx context.Context, hostname string, inboundIDs []string) ([]string, error) {
	if !validHost(hostname) || len(inboundIDs) == 0 {
		return nil, integration("The Remnawave pool hostname or inbound selection is invalid")
	}
	for _, inbound := range inboundIDs {
		if _, valid := canonicalUUID(inbound); !valid {
			return nil, integration("The Remnawave inbound selection is invalid")
		}
	}
	hosts, err := orderRemnawaveList[orderRemnawaveHost](ctx, r, "hosts")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if !orderRemnawaveHostMatches(host, hostname, inboundIDs) {
			continue
		}
		id, valid := canonicalUUID(host.UUID)
		if !valid || slices.Contains(ids, id) {
			return nil, integration("Remnawave returned an invalid pool host identity")
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, integration("No Remnawave hosts match the pool hostname and selected inbounds")
	}
	return ids, nil
}

func orderRemnawaveHostMatches(host orderRemnawaveHost, hostname string, inboundIDs []string) bool {
	if !strings.EqualFold(strings.TrimRight(host.Address, "."), hostname) {
		return false
	}
	inbound, valid := canonicalUUID(host.Inbound.UUID)
	return valid && slices.ContainsFunc(inboundIDs, func(id string) bool {
		match, _ := canonicalUUID(id)
		return match == inbound
	})
}

func (r *Remnawave) attachOrderHost(ctx context.Context, id, hostname, nodeID string, inboundIDs []string) error {
	read := func() ([]string, error) {
		var host orderRemnawaveHost
		if err := r.orderRequest(ctx, http.MethodGet, "hosts/"+id, nil, &host); err != nil {
			return nil, err
		}
		if !strings.EqualFold(host.UUID, id) || !orderRemnawaveHostMatches(host, hostname, inboundIDs) || host.Nodes == nil {
			return nil, integration("The Remnawave pool host identity or assignment list could not be confirmed")
		}
		for i, node := range host.Nodes {
			uuid, valid := canonicalUUID(node)
			if !valid {
				return nil, integration("Remnawave returned an invalid pool host node assignment")
			}
			host.Nodes[i] = uuid
		}
		return host.Nodes, nil
	}
	nodes, err := read()
	if err != nil {
		return err
	}
	// An empty list leaves the host governed by its inbound and DNS. Only
	// add explicit links to hosts which already use explicit assignments.
	if len(nodes) == 0 || slices.Contains(nodes, nodeID) {
		return nil
	}
	desired := append(nodes, nodeID)
	patchErr := r.orderRequest(ctx, http.MethodPatch, "hosts", row{"uuid": id, "nodes": desired}, nil)
	current, err := read()
	if err != nil {
		return err
	}
	for _, assigned := range desired {
		if !slices.Contains(current, assigned) {
			if patchErr != nil {
				return patchErr
			}
			return integration("Remnawave has not confirmed the pool host node assignments")
		}
	}
	return nil
}

func orderRemnawaveList[T any](ctx context.Context, r *Remnawave, resource string) ([]T, error) {
	var response json.RawMessage
	if err := r.orderRequest(ctx, http.MethodGet, resource, nil, &response); err != nil {
		return nil, err
	}
	if raw := bytes.TrimSpace(response); len(raw) > 0 && raw[0] == '{' {
		var wrapped map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return nil, integration("Remnawave returned an invalid list")
		}
		response = wrapped[resource]
	}
	var list []T
	if err := json.Unmarshal(response, &list); err != nil || list == nil {
		return nil, integration("Remnawave returned an invalid list")
	}
	return list, nil
}

func (r *Remnawave) orderRequest(ctx context.Context, method, resource string, input, result any) error {
	var inputReader io.Reader
	if input != nil {
		body, err := json.Marshal(input)
		if err != nil {
			return integration("Could not prepare the Remnawave order request")
		}
		inputReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.url+"/api/"+resource, inputReader)
	if err != nil {
		return integration("Could not prepare the Remnawave order request")
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := r.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return integration("Remnawave ordering API unavailable or request rejected")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return integration("Remnawave ordering API unavailable or request rejected")
	}
	if result == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		return nil
	}
	var envelope struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&envelope); err != nil ||
		len(envelope.Response) == 0 || bytes.Equal(envelope.Response, []byte("null")) ||
		json.Unmarshal(envelope.Response, result) != nil {
		return integration("Remnawave returned an invalid order response")
	}
	return nil
}
