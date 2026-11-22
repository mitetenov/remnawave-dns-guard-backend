package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const upCloudReplacementLabel = "dns-guard-replacement"

var upCloudErrorCode = regexp.MustCompile("^[A-Z0-9_]{1,96}$")

type upCloudReplacement struct {
	client *http.Client
	token  string
}

func newUpCloudReplacement(client *http.Client, token string) replacementProvider {
	return &upCloudReplacement{client: providerClient(client), token: token}
}

type upCloudAPIError struct {
	status int
	code   string
}

func (e *upCloudAPIError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("UpCloud API returned HTTP %d", e.status)
	}
	return fmt.Sprintf("UpCloud API returned HTTP %d (%s)", e.status, e.code)
}

func upCloudStatus(err error, status int, code string) bool {
	var apiErr *upCloudAPIError
	return errors.As(err, &apiErr) && apiErr.status == status && apiErr.code == code
}

func (c *upCloudReplacement) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode UpCloud request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.upcloud.com/1.3"+path, body)
	if err != nil {
		return errors.New("could not prepare UpCloud request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.client.Do(req)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.New("UpCloud API request failed")
	}
	defer res.Body.Close()
	dec := json.NewDecoder(io.LimitReader(res.Body, 2<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var reply struct {
			Error struct {
				Code string `json:"error_code"`
			} `json:"error"`
		}
		apiErr := &upCloudAPIError{status: res.StatusCode}
		if dec.Decode(&reply) == nil && upCloudErrorCode.MatchString(reply.Error.Code) {
			apiErr.code = reply.Error.Code
		}
		return apiErr
	}
	if output != nil && dec.Decode(output) != nil {
		return errors.New("UpCloud API returned invalid JSON")
	}
	return nil
}

type upCloudLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type upCloudConfig struct {
	CoreNumber   json.Number `json:"core_number"`
	MemoryAmount json.Number `json:"memory_amount"`
	Hostname     string      `json:"hostname"`
	Title        string      `json:"title"`
	Zone         string      `json:"zone"`
	Plan         string      `json:"plan"`
	BootOrder    string      `json:"boot_order"`
	Firewall     string      `json:"firewall"`
	NICModel     string      `json:"nic_model"`
	Metadata     string      `json:"metadata"`
	Timezone     string      `json:"timezone,omitempty"`
	VideoModel   string      `json:"video_model,omitempty"`
	SimpleBackup string      `json:"simple_backup"`
	ServerGroup  string      `json:"server_group,omitempty"`
}

type upCloudDisk struct {
	ID       string      `json:"storage"`
	Type     string      `json:"type"`
	Address  string      `json:"address"`
	BootDisk json.Number `json:"boot_disk,omitempty"`
}

type upCloudIP struct {
	Address       string      `json:"address"`
	Family        string      `json:"family"`
	Access        string      `json:"access"`
	Zone          string      `json:"zone"`
	Server        string      `json:"server"`
	MAC           string      `json:"mac"`
	PTR           string      `json:"ptr_record"`
	Floating      string      `json:"floating"`
	ReleasePolicy string      `json:"release_policy"`
	DHCPProvided  string      `json:"dhcp_provided"`
	IsDelegated   string      `json:"is_delegated"`
	AccountID     json.Number `json:"account_id,omitempty"`
	DelegatedTo   json.Number `json:"delegated_to_account_id,omitempty"`
}

type upCloudInterface struct {
	Index             int    `json:"index"`
	Type              string `json:"type"`
	MAC               string `json:"mac"`
	Bootable          string `json:"bootable"`
	SourceIPFiltering string `json:"source_ip_filtering"`
	IPs               struct {
		Items []upCloudIP `json:"ip_address"`
	} `json:"ip_addresses"`
}

type upCloudNetworking struct {
	Interfaces struct {
		Items []upCloudInterface `json:"interface"`
	} `json:"interfaces"`
}

type upCloudTags []string

func (tags *upCloudTags) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '{' {
		var wrapped struct {
			Items []string `json:"tag"`
		}
		if err := json.Unmarshal(data, &wrapped); err != nil {
			return err
		}
		*tags = wrapped.Items
		return nil
	}
	return json.Unmarshal(data, (*[]string)(tags))
}

type upCloudServer struct {
	upCloudConfig
	ID                    string      `json:"uuid"`
	State                 string      `json:"state"`
	RemoteAccessEnabled   string      `json:"remote_access_enabled"`
	FirewallPrivate       string      `json:"firewall_private"`
	FirewallPublicIngress string      `json:"firewall_public_default_incoming_action"`
	FirewallPublicEgress  string      `json:"firewall_public_default_outgoing_action"`
	Host                  json.Number `json:"host"`
	License               json.Number `json:"license"`
	Disks                 struct {
		Items []upCloudDisk `json:"storage_device"`
	} `json:"storage_devices"`
	Labels struct {
		Items []upCloudLabel `json:"label"`
	} `json:"labels"`
	Tags    upCloudTags `json:"tags"`
	Devices struct {
		Items []json.RawMessage `json:"device"`
	} `json:"devices"`
	Networking upCloudNetworking `json:"networking"`
}

type upCloudNICSpec struct {
	Index  int    `json:"index"`
	Type   string `json:"type"`
	Family string `json:"family"`
}

type upCloudSnapshot struct {
	ServerID          string           `json:"server_id"`
	OperationID       string           `json:"operation_id"`
	OldIP             upCloudIP        `json:"old_ip"`
	Config            upCloudConfig    `json:"config"`
	Disks             []upCloudDisk    `json:"disks"`
	Labels            []upCloudLabel   `json:"labels"`
	NICs              []upCloudNICSpec `json:"nics"`
	Firewall          upCloudFirewall  `json:"firewall"`
	ReleaseWithServer bool             `json:"release_with_server,omitempty"` // Older snapshots reserve the original address.
}

type upCloudFirewall struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

func (s upCloudServer) hasLabel(key, value string) bool {
	for _, label := range s.Labels.Items {
		if strings.EqualFold(label.Key, key) && label.Value == value {
			return true
		}
	}
	return false
}

func (s upCloudServer) networkSpecs() ([]upCloudNICSpec, upCloudInterface, error) {
	nics := slices.Clone(s.Networking.Interfaces.Items)
	slices.SortFunc(nics, func(a, b upCloudInterface) int { return a.Index - b.Index })
	var specs []upCloudNICSpec
	var publicV4 upCloudInterface
	families := map[string]bool{}
	for i, nic := range nics {
		if nic.Index != i+1 || nic.MAC == "" || !oneOf(nic.Type, "public", "utility") ||
			nic.Bootable == "yes" || nic.SourceIPFiltering == "no" || len(nic.IPs.Items) != 1 {
			return nil, upCloudInterface{}, errors.New("UpCloud server has an unsupported network interface layout")
		}
		ip := nic.IPs.Items[0]
		addr, err := netip.ParseAddr(ip.Address)
		key := nic.Type + ip.Family
		if err != nil || families[key] || ip.Floating == "yes" ||
			!oneOf(key, "publicIPv4", "publicIPv6", "utilityIPv4") ||
			(addr.Is4() && ip.Family != "IPv4") || (!addr.Is4() && (!addr.Is6() || addr.Is4In6() || ip.Family != "IPv6")) {
			return nil, upCloudInterface{}, errors.New("UpCloud server has an unsupported IP address layout")
		}
		families[key] = true
		specs = append(specs, upCloudNICSpec{Index: nic.Index, Type: nic.Type, Family: ip.Family})
		if key == "publicIPv4" {
			if !publicIPv4(ip.Address) || ip.DHCPProvided != "yes" {
				return nil, upCloudInterface{}, errors.New("UpCloud server must use a public IPv4 address provided by DHCP")
			}
			publicV4 = nic
		} else if !oneOf(ip.ReleasePolicy, "", "release") || ip.DHCPProvided == "no" {
			return nil, upCloudInterface{}, errors.New("UpCloud server has an additional address with an unsupported allocation policy")
		}
	}
	if publicV4.Index == 0 {
		return nil, upCloudInterface{}, errors.New("UpCloud server has no public IPv4 address")
	}
	return specs, publicV4, nil
}

func (c *upCloudReplacement) createSpec(ctx context.Context, s upCloudServer, operationID string) (upCloudSnapshot, error) {
	cores, _ := s.CoreNumber.Int64()
	memory, _ := s.MemoryAmount.Int64()
	if s.Hostname == "" || s.Zone == "" || s.Plan == "" || cores <= 0 || memory <= 0 {
		return upCloudSnapshot{}, errors.New("UpCloud server details are missing required settings")
	}
	switch {
	case !oneOf(s.BootOrder, "disk", "disk,cdrom", "disk,cdrom,network"):
		return upCloudSnapshot{}, errors.New("UpCloud server has an unsupported boot order (boot_order)")
	case !oneOf(s.Firewall, "on", "off"):
		return upCloudSnapshot{}, errors.New("UpCloud server has an unsupported public firewall setting (firewall)")
	case !oneOf(s.RemoteAccessEnabled, "", "no"):
		return upCloudSnapshot{}, errors.New("UpCloud replacement cannot preserve remote console access (remote_access_enabled)")
	case !oneOf(s.FirewallPrivate, "", "off"):
		return upCloudSnapshot{}, errors.New("UpCloud replacement cannot preserve the private firewall (firewall_private)")
	case !oneOf(s.License.String(), "", "0"):
		return upCloudSnapshot{}, errors.New("UpCloud replacement cannot preserve the server license (license)")
	case len(s.Tags) != 0:
		return upCloudSnapshot{}, errors.New("UpCloud replacement cannot preserve server tags (tags)")
	case len(s.Devices.Items) != 0:
		return upCloudSnapshot{}, errors.New("UpCloud replacement cannot preserve attached devices (devices)")
	case strings.HasPrefix(strings.ToUpper(s.Plan), "GPU"):
		return upCloudSnapshot{}, errors.New("UpCloud replacement does not support GPU plans (plan)")
	}
	if err := c.checkHostPlacement(ctx, s); err != nil {
		return upCloudSnapshot{}, err
	}
	nics, publicV4, err := s.networkSpecs()
	if err != nil {
		return upCloudSnapshot{}, err
	}
	disks := slices.Clone(s.Disks.Items)
	if len(disks) == 0 || len(disks) > 16 {
		return upCloudSnapshot{}, errors.New("UpCloud server has an unsupported number of disks")
	}
	slices.SortFunc(disks, func(a, b upCloudDisk) int { return strings.Compare(a.Address, b.Address) })
	foundDisks, foundAddresses := map[string]bool{}, map[string]bool{}
	for i, disk := range disks {
		id, valid := canonicalUUID(disk.ID)
		if !valid || id != disk.ID || disk.Type != "disk" || disk.Address == "" ||
			foundDisks[disk.ID] || foundAddresses[disk.Address] || !oneOf(disk.BootDisk.String(), "", "0", "1") {
			return upCloudSnapshot{}, errors.New("UpCloud server has an unsupported disk layout")
		}
		foundDisks[disk.ID], foundAddresses[disk.Address] = true, true
		if disk.BootDisk == "" {
			disks[i].BootDisk = "0"
		}
	}
	var labels []upCloudLabel
	for _, label := range s.Labels.Items {
		if strings.HasPrefix(label.Key, "_") {
			return upCloudSnapshot{}, errors.New("UpCloud server has a managed service label")
		}
		if !strings.EqualFold(label.Key, upCloudReplacementLabel) {
			labels = append(labels, label)
		}
	}
	if len(labels) >= 255 {
		return upCloudSnapshot{}, errors.New("UpCloud server has no space for the replacement operation label")
	}
	slices.SortFunc(labels, func(a, b upCloudLabel) int { return strings.Compare(a.Key, b.Key) })
	config := s.upCloudConfig
	if config.SimpleBackup == "" {
		config.SimpleBackup = "no"
	}
	if config.Metadata == "" {
		config.Metadata = "no"
	}
	if config.NICModel == "" {
		config.NICModel = "virtio"
	}
	ip := publicV4.IPs.Items[0]
	ip.MAC = publicV4.MAC
	return upCloudSnapshot{ServerID: s.ID, OperationID: operationID, OldIP: ip, Config: config, Disks: disks, Labels: labels, NICs: nics}, nil
}

type upCloudZone struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Public      string `json:"public"`
}

func (c *upCloudReplacement) zones(ctx context.Context) ([]upCloudZone, error) {
	var reply struct {
		Zones *struct {
			Items []upCloudZone `json:"zone"`
		} `json:"zones"`
	}
	if err := c.request(ctx, http.MethodGet, "/zone", nil, &reply); err != nil {
		return nil, err
	}
	if reply.Zones == nil {
		return nil, errors.New("UpCloud returned an invalid zone list")
	}
	return reply.Zones.Items, nil
}

func (c *upCloudReplacement) checkHostPlacement(ctx context.Context, server upCloudServer) error {
	if oneOf(server.Host.String(), "", "0") {
		return nil
	}
	if host, err := server.Host.Int64(); err != nil || host <= 0 {
		return errors.New("UpCloud server has an invalid host ID (host)")
	}
	// UpCloud can report the current compute host in server details. Only
	// private cloud zones allow selecting a specific host when creating a VM.
	zones, err := c.zones(ctx)
	if err != nil {
		return fmt.Errorf("verify UpCloud host placement (host): %w", err)
	}
	for _, zone := range zones {
		if zone.ID != server.Zone {
			continue
		}
		switch zone.Public {
		case "yes":
			return nil
		case "no":
			return errors.New("UpCloud replacement cannot preserve private cloud host placement (host)")
		}
	}
	return errors.New("UpCloud could not verify public zone for the reported host (host)")
}

func (c *upCloudReplacement) server(ctx context.Context, id string) (upCloudServer, error) {
	var reply struct {
		Server upCloudServer `json:"server"`
	}
	err := c.request(ctx, http.MethodGet, "/server/"+id, nil, &reply)
	if err != nil {
		return upCloudServer{}, err
	}
	if reply.Server.ID != id {
		return upCloudServer{}, errors.New("UpCloud returned details for a different server")
	}
	server := reply.Server
	if server.Networking.Interfaces.Items == nil {
		var reply struct {
			Networking upCloudNetworking `json:"networking"`
		}
		if err := c.request(ctx, http.MethodGet, "/server/"+id+"/networking", nil, &reply); err != nil {
			return upCloudServer{}, err
		}
		server.Networking = reply.Networking
	}
	return server, nil
}

func (c *upCloudReplacement) address(ctx context.Context, ip string) (upCloudIP, error) {
	var reply struct {
		IP upCloudIP `json:"ip_address"`
	}
	err := c.request(ctx, http.MethodGet, "/ip_address/"+ip, nil, &reply)
	if err == nil && reply.IP.Address != ip {
		err = errors.New("UpCloud returned details for a different IP address")
	}
	return reply.IP, err
}

func (c *upCloudReplacement) checkPlan(ctx context.Context, config upCloudConfig) error {
	if config.Plan == "custom" {
		return nil
	}
	var reply struct {
		Plans struct {
			Items []struct {
				Name            string      `json:"name"`
				CoreNumber      json.Number `json:"core_number"`
				MemoryAmount    json.Number `json:"memory_amount"`
				CurrentOffering string      `json:"current_offering"`
			} `json:"plan"`
		} `json:"plans"`
	}
	if err := c.request(ctx, http.MethodGet, "/plan", nil, &reply); err != nil {
		return err
	}
	for _, plan := range reply.Plans.Items {
		if plan.Name == config.Plan && plan.CoreNumber == config.CoreNumber &&
			plan.MemoryAmount == config.MemoryAmount && plan.CurrentOffering != "no" {
			return nil
		}
	}
	return errors.New("UpCloud no longer offers the original plan with the original CPU and memory")
}

func (c *upCloudReplacement) checkDisks(ctx context.Context, snap upCloudSnapshot, owner string) error {
	for _, disk := range snap.Disks {
		var reply struct {
			Storage struct {
				ID      string `json:"uuid"`
				Zone    string `json:"zone"`
				Type    string `json:"type"`
				Access  string `json:"access"`
				State   string `json:"state"`
				Tier    string `json:"tier"`
				Servers *struct {
					Items []string `json:"server"`
				} `json:"servers"`
			} `json:"storage"`
		}
		if err := c.request(ctx, http.MethodGet, "/storage/"+disk.ID, nil, &reply); err != nil {
			return err
		}
		d := reply.Storage
		if d.ID != disk.ID || d.Zone != snap.Config.Zone || d.Type != "normal" || d.Access != "private" ||
			d.State != "online" || !oneOf(d.Tier, "", "maxiops", "standard", "hdd") || d.Servers == nil {
			return errors.New("UpCloud disk cannot be safely reattached")
		}
		if (owner == "" && len(d.Servers.Items) != 0) || (owner != "" && !slices.Equal(d.Servers.Items, []string{owner})) {
			return errors.New("UpCloud disk attachments changed or are still being updated")
		}
	}
	return nil
}

func (c *upCloudReplacement) firewallDefaults(ctx context.Context, server upCloudServer) (upCloudFirewall, error) {
	var reply struct {
		Rules *struct {
			Items []row `json:"firewall_rule"`
		} `json:"firewall_rules"`
	}
	if err := c.request(ctx, http.MethodGet, "/server/"+server.ID+"/firewall_rule", nil, &reply); err != nil {
		return upCloudFirewall{}, err
	}
	unsupported := errors.New("UpCloud server has cloud firewall rules this replacement cannot preserve")
	if reply.Rules == nil || len(reply.Rules.Items) > 2 {
		return upCloudFirewall{}, unsupported
	}
	in, out := server.FirewallPublicIngress, server.FirewallPublicEgress
	if !oneOf(in, "", "accept", "drop") || !oneOf(out, "", "accept", "drop") {
		return upCloudFirewall{}, unsupported
	}
	directions := map[string]*string{"in": &in, "out": &out}
	seen := map[string]bool{}
	for _, rule := range reply.Rules.Items {
		dir, action := str(rule["direction"]), str(rule["action"])
		policy := directions[dir]
		if policy == nil || seen[dir] || !oneOf(action, "accept", "drop") || (*policy != "" && *policy != action) {
			return upCloudFirewall{}, unsupported
		}
		for key, value := range rule {
			if !oneOf(key, "position", "direction", "action") && value != nil && value != "" {
				return upCloudFirewall{}, unsupported
			}
		}
		*policy, seen[dir] = action, true
	}
	return upCloudFirewall{In: in, Out: out}, nil
}

func (c *upCloudReplacement) confirmReplacementFirewall(ctx context.Context, server upCloudServer, expected upCloudFirewall, restore bool) error {
	actual, err := c.firewallDefaults(ctx, server)
	if err != nil {
		return err
	}
	equivalent := func() bool {
		// Disabled filters permit traffic even when the provider reports its
		// implicit accept policy as an explicit rule.
		return actual == expected || (server.Firewall == "off" &&
			(expected.In == actual.In || (expected.In == "" && actual.In == "accept")) &&
			(expected.Out == actual.Out || (expected.Out == "" && actual.Out == "accept")))
	}
	if equivalent() {
		return nil
	}
	if !restore || (expected.In == "" && expected.Out == "") {
		return errors.New("UpCloud replacement cloud firewall defaults do not match the original server")
	}
	var rules []row
	if expected.In != "" {
		rules = append(rules, row{"direction": "in", "action": expected.In})
	}
	if expected.Out != "" {
		rules = append(rules, row{"direction": "out", "action": expected.Out})
	}
	input := row{"firewall_rules": row{"firewall_rule": rules}}
	if err := c.request(ctx, http.MethodPut, "/server/"+server.ID+"/firewall_rule", input, nil); err != nil {
		return err
	}
	server, err = c.server(ctx, server.ID)
	if err != nil {
		return err
	}
	actual, err = c.firewallDefaults(ctx, server)
	if err != nil {
		return err
	}
	if !equivalent() {
		return errors.New("UpCloud has not confirmed the restored firewall defaults")
	}
	return nil
}

func (c *upCloudReplacement) Snapshot(ctx context.Context, serverID, oldIP, operationID string) (json.RawMessage, error) {
	id, valid := canonicalUUID(serverID)
	if !valid || !publicIPv4(oldIP) || operationID == "" || len(operationID) > 255 {
		return nil, errors.New("invalid UpCloud server UUID, public IPv4, or operation ID")
	}
	server, err := c.server(ctx, id)
	if err != nil {
		return nil, err
	}
	if !oneOf(server.State, "started", "stopped") {
		return nil, errors.New("UpCloud server must be running or stopped before replacement")
	}
	snap, err := c.createSpec(ctx, server, operationID)
	if err != nil {
		return nil, err
	}
	if snap.OldIP.Address != oldIP {
		return nil, errors.New("UpCloud server UUID does not have the target's public IPv4 address")
	}
	if !snap.OldIP.releasedWithServer() {
		return nil, errors.New("UpCloud target IPv4 must be non-floating and released when the server is deleted")
	}
	snap.ReleaseWithServer = true
	if err := c.checkDisks(ctx, snap, id); err != nil {
		return nil, err
	}
	snap.Firewall, err = c.firewallDefaults(ctx, server)
	if err != nil {
		return nil, err
	}
	if server.Firewall == "on" && (snap.Firewall.In == "drop" || snap.Firewall.Out == "drop") {
		return nil, errors.New("UpCloud server has active restrictive cloud firewall defaults")
	}
	if err := c.checkPlan(ctx, snap.Config); err != nil {
		return nil, err
	}
	return json.Marshal(snap)
}

func decodeUpCloudSnapshot(data json.RawMessage, oldIP string) (upCloudSnapshot, error) {
	var snap upCloudSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return upCloudSnapshot{}, errors.New("invalid UpCloud replacement snapshot")
	}
	id, ok := canonicalUUID(snap.ServerID)
	if !ok || id != snap.ServerID || !publicIPv4(oldIP) || snap.OldIP.Address != oldIP ||
		snap.OperationID == "" || len(snap.Disks) == 0 || snap.OldIP.Family != "IPv4" || !snap.OldIP.releasedWithServer() {
		return upCloudSnapshot{}, errors.New("UpCloud replacement snapshot does not match the original server and public IPv4")
	}
	if snap.ReleaseWithServer {
		if snap.OldIP.MAC == "" || snap.OldIP.DHCPProvided != "yes" {
			return upCloudSnapshot{}, errors.New("UpCloud replacement snapshot is missing the original public IPv4 interface")
		}
	} else if snap.OldIP.Server != snap.ServerID || snap.OldIP.Zone != snap.Config.Zone || snap.OldIP.Access != "public" {
		return upCloudSnapshot{}, errors.New("UpCloud replacement snapshot does not match the original server and public IPv4")
	}
	return snap, nil
}

func (s upCloudSnapshot) matchesAddress(ip upCloudIP) bool {
	return ip.Address == s.OldIP.Address && ip.Access == s.OldIP.Access && ip.Family == s.OldIP.Family &&
		ip.Zone == s.OldIP.Zone && ip.AccountID == s.OldIP.AccountID && ip.PTR == s.OldIP.PTR && !ip.delegated()
}

func (ip upCloudIP) delegated() bool {
	return ip.IsDelegated == "yes" || !oneOf(ip.DelegatedTo.String(), "", "0")
}

func (ip upCloudIP) releasedWithServer() bool {
	return ip.Floating == "no" && ip.ReleasePolicy == "release" && !ip.delegated()
}

func (s upCloudSnapshot) holdsAddress(ip upCloudIP) bool {
	return s.matchesAddress(ip) && ip.Floating == "yes" && ip.ReleasePolicy == "keep" && ip.Server == "" && ip.MAC == ""
}

func (c *upCloudReplacement) confirmHeld(ctx context.Context, snap upCloudSnapshot) error {
	ip, err := c.address(ctx, snap.OldIP.Address)
	if err != nil {
		return fmt.Errorf("verify reserved UpCloud IPv4: %w", err)
	}
	if !snap.holdsAddress(ip) {
		return errors.New("UpCloud has not confirmed the original IPv4 as detached and reserved")
	}
	return nil
}

func (c *upCloudReplacement) Retire(ctx context.Context, serverID, oldIP string, data json.RawMessage) error {
	snap, err := decodeUpCloudSnapshot(data, oldIP)
	id, valid := canonicalUUID(serverID)
	if err != nil || !valid || id != snap.ServerID {
		return errors.New("UpCloud retirement does not match the original server UUID and IPv4")
	}
	server, err := c.server(ctx, id)
	if upCloudStatus(err, http.StatusNotFound, "SERVER_NOT_FOUND") {
		if snap.ReleaseWithServer {
			return nil
		}
		return c.confirmHeld(ctx, snap)
	}
	if err != nil {
		return err
	}
	if oneOf(server.State, "maintenance", "pending_delete") {
		return fmt.Errorf("%w: waiting for the original UpCloud server to finish its current operation", errReplacementPending)
	}
	if !oneOf(server.State, "started", "stopped") {
		return errors.New("the original UpCloud server is in an unexpected state; check its status in UpCloud")
	}
	actual, err := c.createSpec(ctx, server, snap.OperationID)
	if err != nil {
		return err
	}
	if actual.OldIP.Address != oldIP || actual.OldIP.MAC != snap.OldIP.MAC || actual.Config != snap.Config ||
		!slices.Equal(actual.Disks, snap.Disks) || !slices.Equal(actual.NICs, snap.NICs) || !slices.Equal(actual.Labels, snap.Labels) {
		return errors.New("UpCloud server settings changed after the replacement was requested")
	}
	if err := c.checkDisks(ctx, snap, id); err != nil {
		return err
	}
	firewall, err := c.firewallDefaults(ctx, server)
	if err != nil {
		return err
	}
	if firewall != snap.Firewall {
		return errors.New("UpCloud server firewall changed after the replacement was requested")
	}
	if snap.ReleaseWithServer {
		if !actual.OldIP.releasedWithServer() {
			return errors.New("UpCloud target IPv4 release settings changed after the replacement was requested")
		}
	} else if err := c.reserveOldIP(ctx, snap); err != nil {
		return err
	}
	if server.State == "started" {
		input := row{"stop_server": row{"stop_type": "soft"}}
		if err := c.request(ctx, http.MethodPost, "/server/"+id+"/stop", input, nil); err != nil {
			return err
		}
		return fmt.Errorf("%w: waiting for the original UpCloud server to shut down gracefully", errReplacementPending)
	}
	// Delete the VM only. The attached disks are reused when creating its replacement.
	if err := c.request(ctx, http.MethodDelete, "/server/"+id, nil, nil); err != nil && !upCloudStatus(err, http.StatusNotFound, "SERVER_NOT_FOUND") {
		return err
	}
	if snap.ReleaseWithServer {
		return fmt.Errorf("%w: waiting for UpCloud to confirm deletion of the original server", errReplacementPending)
	}
	return c.confirmHeld(ctx, snap)
}

func (c *upCloudReplacement) reserveOldIP(ctx context.Context, snap upCloudSnapshot) error {
	path := "/ip_address/" + snap.OldIP.Address
	ip, err := c.address(ctx, snap.OldIP.Address)
	if err != nil {
		return err
	}
	if !snap.matchesAddress(ip) || ip.Server != snap.ServerID || ip.MAC != snap.OldIP.MAC || ip.Floating != "no" ||
		!oneOf(ip.ReleasePolicy, "release", "keep") {
		return errors.New("the original UpCloud IPv4 no longer matches the replacement snapshot")
	}
	if ip.ReleasePolicy == "keep" {
		return nil
	}
	input := row{"ip_address": row{"release_policy": "keep"}}
	if err := c.request(ctx, http.MethodPatch, path, input, nil); err != nil {
		return err
	}
	ip, err = c.address(ctx, snap.OldIP.Address)
	if err != nil {
		return err
	}
	if !snap.matchesAddress(ip) || ip.Server != snap.ServerID || ip.MAC != snap.OldIP.MAC || ip.Floating != "no" || ip.ReleasePolicy != "keep" {
		return errors.New("UpCloud has not confirmed the hold on the original IPv4")
	}
	return nil
}

func (s upCloudSnapshot) createRequest() row {
	disks := make([]row, 0, len(s.Disks))
	for _, d := range s.Disks {
		disk := row{"action": "attach", "storage": d.ID, "address": d.Address, "type": d.Type}
		if d.BootDisk == "1" {
			disk["boot_disk"] = 1
		}
		disks = append(disks, disk)
	}
	nics := make([]row, 0, len(s.NICs))
	for _, nic := range s.NICs {
		nics = append(nics, row{
			"type": nic.Type, "index": nic.Index,
			"ip_addresses": row{"ip_address": []row{{"family": nic.Family}}},
		})
	}
	labels := append(slices.Clone(s.Labels), upCloudLabel{Key: upCloudReplacementLabel, Value: s.OperationID})
	type settings struct {
		upCloudConfig
		Disks               row    `json:"storage_devices"`
		Networking          row    `json:"networking"`
		Labels              row    `json:"labels"`
		PasswordDelivery    string `json:"password_delivery"`
		RemoteAccessEnabled string `json:"remote_access_enabled"`
	}
	return row{"server": settings{
		upCloudConfig:       s.Config,
		Disks:               row{"storage_device": disks},
		Networking:          row{"interfaces": row{"interface": nics}},
		Labels:              row{"label": labels},
		PasswordDelivery:    "none",
		RemoteAccessEnabled: "no",
	}}
}

func (c *upCloudReplacement) findOperationServer(ctx context.Context, label, operationID string) (string, error) {
	query := url.Values{"label": {label + "=" + operationID}, "limit": {"2"}}
	var reply struct {
		Servers *struct {
			Items []upCloudServer `json:"server"`
		} `json:"servers"`
	}
	if err := c.request(ctx, http.MethodGet, "/server?"+query.Encode(), nil, &reply); err != nil {
		return "", err
	}
	if reply.Servers == nil {
		return "", errors.New("UpCloud returned an invalid server list")
	}
	if len(reply.Servers.Items) == 0 {
		return "", nil
	}
	if len(reply.Servers.Items) != 1 {
		return "", fmt.Errorf("multiple UpCloud servers match %s=%s", label, operationID)
	}
	server := reply.Servers.Items[0]
	id, valid := canonicalUUID(server.ID)
	if !valid || id != server.ID || !server.hasLabel(label, operationID) {
		return "", errors.New("UpCloud operation lookup returned an unrelated server")
	}
	return id, nil
}

func (c *upCloudReplacement) verifyReplacement(ctx context.Context, snap upCloudSnapshot, id string, restoreFirewall bool) (string, error) {
	if id == snap.ServerID {
		return "", errors.New("UpCloud returned the original server UUID for the replacement")
	}
	server, err := c.server(ctx, id)
	if err != nil {
		return "", err
	}
	if !server.hasLabel(upCloudReplacementLabel, snap.OperationID) {
		return "", errors.New("UpCloud server is missing the replacement operation label")
	}
	if server.State == "maintenance" {
		return "", fmt.Errorf("%w: waiting for UpCloud replacement %s to start", errReplacementPending, id)
	}
	if server.State != "started" {
		return "", fmt.Errorf("UpCloud replacement %s is not running yet; check its status in UpCloud", id)
	}
	actual, err := c.createSpec(ctx, server, snap.OperationID)
	if err != nil {
		return "", err
	}
	if actual.Config != snap.Config || !slices.Equal(actual.Disks, snap.Disks) ||
		!slices.Equal(actual.NICs, snap.NICs) || !slices.Equal(actual.Labels, snap.Labels) {
		return "", errors.New("UpCloud replacement configuration does not match the original server")
	}
	ip := actual.OldIP.Address
	if ip == snap.OldIP.Address {
		return "", errors.New("UpCloud assigned the original IPv4 to the replacement")
	}
	if err := c.checkDisks(ctx, snap, id); err != nil {
		return "", err
	}
	if err := c.confirmReplacementFirewall(ctx, server, snap.Firewall, restoreFirewall); err != nil {
		return "", err
	}
	return ip, nil
}

func (c *upCloudReplacement) Provision(ctx context.Context, data json.RawMessage, operationID, oldIP string, claimCreate func() (bool, error)) (string, string, error) {
	snap, err := decodeUpCloudSnapshot(data, oldIP)
	if err != nil {
		return "", "", err
	}
	if snap.OperationID != operationID || claimCreate == nil {
		return "", "", errors.New("UpCloud provisioning does not match the replacement operation")
	}
	if !snap.ReleaseWithServer {
		if err := c.confirmHeld(ctx, snap); err != nil {
			return "", "", err
		}
	}
	id, err := c.findOperationServer(ctx, upCloudReplacementLabel, operationID)
	if err != nil {
		return "", "", err
	}
	if id != "" {
		ip, err := c.verifyReplacement(ctx, snap, id, true)
		return id, ip, err
	}
	if err := c.checkDisks(ctx, snap, ""); err != nil {
		return "", "", fmt.Errorf("%w; check for the server label %s=%s", err, upCloudReplacementLabel, operationID)
	}
	id, err = c.createOperationServer(ctx, upCloudReplacementLabel, operationID, snap.createRequest(), claimCreate)
	if err != nil {
		return "", "", err
	}
	ip, err := c.verifyReplacement(ctx, snap, id, true)
	return id, ip, err
}

func (c *upCloudReplacement) createOperationServer(ctx context.Context, label, operationID string, input any, claimCreate func() (bool, error)) (string, error) {
	claimed, err := claimCreate()
	if err != nil {
		return "", err
	}
	lookup := fmt.Sprintf("check for the server label %s=%s", label, operationID)
	if !claimed {
		return "", fmt.Errorf("%w: %s", errReplacementCreateUnconfirmed, lookup)
	}
	uncertain := fmt.Errorf("UpCloud create outcome is unconfirmed; %s", lookup)
	var reply struct {
		Server upCloudServer `json:"server"`
	}
	if err := c.request(ctx, http.MethodPost, "/server", input, &reply); err != nil {
		var apiErr *upCloudAPIError
		if errors.As(err, &apiErr) && apiErr.code != "" && slices.Contains([]int{400, 401, 402, 403, 404, 409, 422, 429}, apiErr.status) {
			return "", fmt.Errorf("%w: %w", errReplacementCreateRejected, err)
		}
		return "", fmt.Errorf("%w: %w", uncertain, err)
	}
	id, valid := canonicalUUID(reply.Server.ID)
	if !valid || id != reply.Server.ID {
		return "", uncertain
	}
	return id, nil
}

func (c *upCloudReplacement) ReleaseOldIP(ctx context.Context, data json.RawMessage, serverID, newIP, oldIP string) error {
	snap, err := decodeUpCloudSnapshot(data, oldIP)
	if err != nil {
		return err
	}
	id, valid := canonicalUUID(serverID)
	if !valid || id != serverID || !publicIPv4(newIP) || newIP == oldIP {
		return errors.New("invalid replacement UpCloud server UUID or IPv4 for cleanup")
	}
	actualIP, err := c.verifyReplacement(ctx, snap, id, false)
	if err != nil {
		return err
	}
	if actualIP != newIP {
		return errors.New("UpCloud replacement IPv4 changed before the operation could be completed")
	}
	if snap.ReleaseWithServer {
		return nil
	}
	ip, err := c.address(ctx, oldIP)
	if upCloudStatus(err, http.StatusNotFound, "IP_ADDRESS_NOT_FOUND") || upCloudStatus(err, http.StatusForbidden, "IP_ADDRESS_FORBIDDEN") {
		// A lost response from the release can leave the address unallocated or
		// already issued to a different account.
		return nil
	}
	if err != nil {
		return err
	}
	if !snap.holdsAddress(ip) {
		return errors.New("UpCloud cleanup cannot verify the reserved, detached original IPv4")
	}
	err = c.request(ctx, http.MethodDelete, "/ip_address/"+oldIP, nil, nil)
	if upCloudStatus(err, http.StatusNotFound, "IP_ADDRESS_NOT_FOUND") || upCloudStatus(err, http.StatusForbidden, "IP_ADDRESS_FORBIDDEN") {
		return nil
	}
	return err
}
