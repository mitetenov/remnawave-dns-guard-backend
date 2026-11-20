package guard

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	upCloudOrderLabel      = "dns-guard-order"
	upCloudOrderImageLabel = "dns-guard-order-image"
	upCloudOrderDebian13   = "01000000-0000-4000-8000-000020080100"
)

type orderCloudCountry struct {
	Code  string   `json:"code"`
	Name  string   `json:"name"`
	Zones []string `json:"zones"`
}

type orderCloudRequest struct {
	OperationID, Country, Zone, Hostname, Title, Plan, Quote, TemplateID, SSHUser, SSHKey string
	EnrollURL, EnrollToken                                                                string
}

type orderCloudProvider interface {
	Countries(context.Context) ([]orderCloudCountry, error)
	Plans(ctx context.Context, zone string) ([]orderCloudPlan, error)
	PrepareOrder(context.Context, orderCloudRequest) (snapshot json.RawMessage, hostKey, zone string, err error)
	ProvisionOrder(ctx context.Context, snapshot json.RawMessage, operationID, existingServer string, claimCreate func() (bool, error)) (serverID, ip string, err error)
}

type upCloudOrder struct {
	*upCloudReplacement
}

func newUpCloudOrder(client *http.Client, token string) orderCloudProvider {
	return &upCloudOrder{&upCloudReplacement{client: providerClient(client), token: token}}
}

var (
	upCloudOrderZonePattern = regexp.MustCompile(`^[a-z]{2}-[a-z0-9][a-z0-9-]{0,11}$`)
	upCloudOrderIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	upCloudOrderHostLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	upCloudEnrollmentToken  = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

// Zone prefixes come from the live API. This table only supplies names for
// providers that return city-only descriptions and for location labels.
var upCloudOrderCountryNames = map[string]string{
	"AU": "Australia", "DE": "Germany", "DK": "Denmark", "ES": "Spain",
	"FI": "Finland", "NL": "Netherlands", "NO": "Norway", "PL": "Poland",
	"SE": "Sweden", "SG": "Singapore", "UK": "United Kingdom", "US": "United States",
}

func (c *upCloudOrder) Countries(ctx context.Context) ([]orderCloudCountry, error) {
	var reply struct {
		Zones *struct {
			Items []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
				Public      string `json:"public"`
			} `json:"zone"`
		} `json:"zones"`
	}
	if err := c.request(ctx, http.MethodGet, "/zone", nil, &reply); err != nil {
		return nil, err
	}
	if reply.Zones == nil {
		return nil, errors.New("UpCloud returned an invalid zone list")
	}
	var countries []orderCloudCountry
	grouped := map[string][]string{}
	descriptions := map[string]string{}
	for _, entry := range reply.Zones.Items {
		if entry.Public != "yes" || !upCloudOrderZonePattern.MatchString(entry.ID) {
			continue
		}
		code := strings.ToUpper(entry.ID[:2])
		grouped[code] = append(grouped[code], entry.ID)
		if country, _, found := strings.Cut(entry.Description, ","); found && descriptions[code] == "" {
			descriptions[code] = strings.TrimSpace(country)
		}
	}
	for code, zones := range grouped {
		slices.Sort(zones)
		name := upCloudOrderCountryNames[code]
		if name == "" {
			name = descriptions[code]
			if name == "" {
				name = code
			}
		}
		countries = append(countries, orderCloudCountry{Code: code, Name: name, Zones: slices.Compact(zones)})
	}
	slices.SortFunc(countries, func(a, b orderCloudCountry) int { return strings.Compare(a.Code, b.Code) })
	return countries, nil
}

type orderCloudPlan struct {
	Code         string  `json:"code"`
	Family       string  `json:"-"` // Catalog metadata, excluded from order snapshots and quotes.
	CPU          int     `json:"cpu"`
	MemoryMB     int     `json:"memory_mb"`
	StorageGB    int     `json:"storage_gb"`
	StorageTier  string  `json:"storage_tier"`
	Price        float64 `json:"price"`
	MonthlyPrice float64 `json:"-"` // Display estimate. Orders charge the hourly rate.
	Currency     string  `json:"currency"`
	Name         string  `json:"name,omitempty"`
	Country      string  `json:"country,omitempty"`
}

func (c *upCloudOrder) Plans(ctx context.Context, zone string) ([]orderCloudPlan, error) {
	countries, err := c.Countries(ctx)
	if err != nil {
		return nil, err
	}
	for _, country := range countries {
		if slices.Contains(country.Zones, zone) {
			return c.zonePlans(ctx, zone)
		}
	}
	return nil, errors.New("UpCloud does not currently list the selected public zone")
}

func (c *upCloudOrder) zonePlans(ctx context.Context, zone string) ([]orderCloudPlan, error) {
	var reply struct {
		Plans struct {
			Items []struct {
				Name      string      `json:"name"`
				Family    string      `json:"family"`
				Cores     json.Number `json:"core_number"`
				Memory    json.Number `json:"memory_amount"`
				Size      json.Number `json:"storage_size"`
				Tier      string      `json:"storage_tier"`
				GPUs      json.Number `json:"gpu_amount"`
				Available string      `json:"current_offering"`
			} `json:"plan"`
		} `json:"plans"`
	}
	if err := c.request(ctx, http.MethodGet, "/plan", nil, &reply); err != nil {
		return nil, err
	}
	prices, currency, err := c.zonePrices(ctx, zone)
	if err != nil {
		return nil, err
	}
	imageSize, err := c.debian13Size(ctx)
	if err != nil {
		return nil, err
	}
	plans := []orderCloudPlan{}
	for _, plan := range reply.Plans.Items {
		cores, _ := plan.Cores.Int64()
		memory, _ := plan.Memory.Int64()
		size, _ := plan.Size.Int64()
		name := strings.ToUpper(plan.Name)
		price, offered := prices[plan.Name]
		if !offered || plan.Available == "no" || !oneOf(plan.GPUs.String(), "", "0") ||
			strings.HasPrefix(name, "GPU") || strings.Contains(name, "SPOT") ||
			cores <= 0 || memory <= 0 || size < max(10, imageSize) || size > 1024 || !oneOf(plan.Tier, "standard", "maxiops", "hdd") {
			continue
		}
		plans = append(plans, orderCloudPlan{
			Code: plan.Name, Family: plan.Family, CPU: int(cores), MemoryMB: int(memory), StorageGB: int(size),
			StorageTier: plan.Tier, Price: price, Currency: currency,
		})
	}
	slices.SortFunc(plans, func(a, b orderCloudPlan) int {
		if a.Price < b.Price {
			return -1
		}
		if a.Price > b.Price {
			return 1
		}
		return strings.Compare(a.Code, b.Code)
	})
	return plans, nil
}

func (c *upCloudOrder) zonePrices(ctx context.Context, zone string) (map[string]float64, string, error) {
	var reply struct {
		Prices struct {
			Currency string                       `json:"currency"`
			Zones    []map[string]json.RawMessage `json:"zone"`
		} `json:"prices"`
	}
	query := url.Values{"zone": {zone}}
	if err := c.request(ctx, http.MethodGet, "/price?"+query.Encode(), nil, &reply); err != nil {
		return nil, "", err
	}
	var items map[string]json.RawMessage
	for _, candidate := range reply.Prices.Zones {
		var name string
		if json.Unmarshal(candidate["name"], &name) == nil && name == zone {
			items = candidate
			break
		}
	}
	if items == nil {
		return nil, "", errors.New("UpCloud did not provide pricing for the selected public zone")
	}
	currency := reply.Prices.Currency
	if currency == "" {
		var account struct {
			Account struct {
				Currency string `json:"currency"`
			} `json:"account"`
		}
		if err := c.request(ctx, http.MethodGet, "/account", nil, &account); err != nil {
			return nil, "", err
		}
		currency = account.Account.Currency
	}
	if len(currency) != 3 || strings.ContainsFunc(currency, func(r rune) bool { return r < 'A' || r > 'Z' }) {
		return nil, "", errors.New("UpCloud returned an invalid account currency")
	}
	prices := map[string]float64{}
	for key, raw := range items {
		name, ok := strings.CutPrefix(key, "server_plan_")
		if !ok || name == "" {
			continue
		}
		var quote struct {
			Amount json.Number `json:"amount"`
			Price  json.Number `json:"price"`
		}
		if json.Unmarshal(raw, &quote) != nil || quote.Amount != "1" {
			continue
		}
		credits, err := quote.Price.Float64()
		if err == nil && credits >= 0 {
			prices[name] = credits / 100
		}
	}
	return prices, currency, nil
}

func (c *upCloudOrder) debian13Size(ctx context.Context) (int64, error) {
	var reply struct {
		Storages struct {
			Items []struct {
				ID           string      `json:"uuid"`
				Title        string      `json:"title"`
				Access       string      `json:"access"`
				Type         string      `json:"type"`
				TemplateType string      `json:"template_type"`
				State        string      `json:"state"`
				Size         json.Number `json:"size"`
				License      json.Number `json:"license"`
			} `json:"storage"`
		} `json:"storages"`
	}
	if err := c.request(ctx, http.MethodGet, "/storage/template", nil, &reply); err != nil {
		return 0, err
	}
	for _, template := range reply.Storages.Items {
		if template.ID != upCloudOrderDebian13 {
			continue
		}
		release, ok := strings.CutPrefix(template.Title, "Debian GNU/Linux 13")
		debian13 := ok && (release == "" || strings.ContainsRune(" .(", rune(release[0])))
		if template.Access != "public" || template.Type != "template" || template.State != "online" ||
			template.TemplateType != "cloud-init" || !oneOf(template.License.String(), "", "0") || !debian13 {
			return 0, errors.New("UpCloud did not return the public Debian 13 cloud-init template")
		}
		size, _ := template.Size.Int64()
		if size <= 0 {
			return 0, errors.New("UpCloud returned an invalid size for the Debian 13 template")
		}
		return size, nil
	}
	return 0, errors.New("UpCloud does not offer the Debian 13 public image")
}

type upCloudOrderSnapshot struct {
	OperationID string         `json:"operation_id"`
	Zone        string         `json:"zone"`
	Hostname    string         `json:"hostname"`
	Title       string         `json:"title"`
	Plan        orderCloudPlan `json:"plan"`
	TemplateID  string         `json:"template_id"`
	SSHUser     string         `json:"ssh_user"`
	SSHKey      string         `json:"ssh_key"`
	UserData    string         `json:"user_data"`
}

func validOrderCloudHostname(host string) bool {
	if len(host) == 0 || len(host) > 128 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !upCloudOrderHostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func cleanOrderLoginKey(value string) (string, bool) {
	if len(value) > 8192 || strings.ContainsAny(strings.TrimSpace(value), "\r\n") {
		return "", false
	}
	fields := strings.Fields(value)
	if len(fields) < 2 || !oneOf(fields[0], "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521") {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	prefixLength := len(fields[0]) + 4
	if err != nil || len(key) <= prefixLength || binary.BigEndian.Uint32(key[:4]) != uint32(len(fields[0])) ||
		string(key[4:prefixLength]) != fields[0] {
		return "", false
	}
	return strings.Join(fields[:2], " "), true
}

func (c *upCloudOrder) PrepareOrder(ctx context.Context, req orderCloudRequest) (json.RawMessage, string, string, error) {
	template := upCloudOrderDebian13
	if req.TemplateID != "" {
		selected, valid := canonicalUUID(req.TemplateID)
		if !valid || selected != template {
			return nil, "", "", errors.New("UpCloud orders require the official Debian 13 template")
		}
	}
	loginKey, validKey := cleanOrderLoginKey(req.SSHKey)
	countryCode := strings.ToUpper(strings.TrimSpace(req.Country))
	if !upCloudOrderIDPattern.MatchString(req.OperationID) || !upCloudOrderZonePattern.MatchString(req.Zone) || !validOrderCloudHostname(req.Hostname) ||
		req.Title == "" || utf8.RuneCountInString(req.Title) > 255 || strings.ContainsFunc(req.Title, unicode.IsControl) || !utf8.ValidString(req.Title) ||
		req.Plan == "" || len(req.Plan) > 255 || !replacementSSHUser.MatchString(req.SSHUser) || !validKey {
		return nil, "", "", errors.New("invalid parameters for the new UpCloud server")
	}
	enrollURL, err := url.Parse(req.EnrollURL)
	if err != nil || enrollURL.Scheme != "https" || enrollURL.Hostname() == "" || enrollURL.User != nil ||
		enrollURL.Path == "" || enrollURL.RawQuery != "" || enrollURL.ForceQuery || enrollURL.Fragment != "" ||
		!upCloudEnrollmentToken.MatchString(req.EnrollToken) {
		return nil, "", "", errors.New("the UpCloud order requires an HTTPS enrollment URL and a one-time token")
	}
	countries, err := c.Countries(ctx)
	if err != nil {
		return nil, "", "", err
	}
	var zone string
	for _, country := range countries {
		if country.Code == countryCode && slices.Contains(country.Zones, req.Zone) {
			zone = req.Zone
			break
		}
	}
	if zone == "" {
		return nil, "", "", errors.New("UpCloud does not offer the selected public zone in this country")
	}
	plans, err := c.zonePlans(ctx, zone)
	if err != nil {
		return nil, "", "", err
	}
	planIndex := slices.IndexFunc(plans, func(plan orderCloudPlan) bool { return plan.Code == req.Plan })
	if planIndex < 0 {
		if req.Quote != "" {
			return nil, "", "", errOrderQuoteChanged
		}
		return nil, "", "", errors.New("UpCloud does not offer the selected plan in this public zone")
	}
	plan := plans[planIndex]
	if req.Quote != "" && orderPlanChoice(zone, plan).ID != req.Quote {
		return nil, "", "", errOrderQuoteChanged
	}
	userData, err := orderCloudInit(req.EnrollURL, req.EnrollToken, req.SSHUser)
	if err != nil {
		return nil, "", "", err
	}
	snap := upCloudOrderSnapshot{
		OperationID: req.OperationID, Zone: zone, Hostname: req.Hostname, Title: req.Title, Plan: plan,
		TemplateID: template, SSHUser: req.SSHUser, SSHKey: loginKey, UserData: userData,
	}
	payload, err := json.Marshal(snap)
	return payload, "", zone, err
}

func (s upCloudOrderSnapshot) createRequest() row {
	network := []row{
		{"type": "public", "ip_addresses": row{"ip_address": []row{{"family": "IPv4"}}}},
		{"type": "utility", "ip_addresses": row{"ip_address": []row{{"family": "IPv4"}}}},
	}
	disk := row{
		"action": "clone", "storage": s.TemplateID, "size": s.Plan.StorageGB, "tier": s.Plan.StorageTier,
		"title": s.Hostname + " OS", "encrypted": "yes", "type": "disk",
		"labels": []upCloudLabel{{Key: upCloudOrderLabel, Value: s.OperationID}, {Key: upCloudOrderImageLabel, Value: s.TemplateID}},
	}
	return row{"server": row{
		"zone": s.Zone, "plan": s.Plan.Code, "hostname": s.Hostname, "title": s.Title,
		"metadata": "yes", "password_delivery": "none", "remote_access_enabled": "no", "firewall": "off", "simple_backup": "no",
		"user_data": s.UserData, "labels": row{"label": []upCloudLabel{{Key: upCloudOrderLabel, Value: s.OperationID}}},
		"storage_devices": row{"storage_device": []row{disk}}, "networking": row{"interfaces": row{"interface": network}},
		"login_user": row{"username": s.SSHUser, "create_password": "no", "ssh_keys": row{"ssh_key": []string{s.SSHKey}}},
	}}
}

func (c *upCloudOrder) verifyDisk(ctx context.Context, snap upCloudOrderSnapshot, serverID, diskID string) error {
	id, valid := canonicalUUID(diskID)
	if !valid || id != diskID || id == snap.TemplateID {
		return errors.New("UpCloud order does not have a separate cloned disk")
	}
	var reply struct {
		Storage struct {
			ID        string         `json:"uuid"`
			Type      string         `json:"type"`
			Access    string         `json:"access"`
			State     string         `json:"state"`
			Zone      string         `json:"zone"`
			Tier      string         `json:"tier"`
			Size      json.Number    `json:"size"`
			Encrypted string         `json:"encrypted"`
			Labels    []upCloudLabel `json:"labels"`
			Servers   struct {
				Items []string `json:"server"`
			} `json:"servers"`
		} `json:"storage"`
	}
	if err := c.request(ctx, http.MethodGet, "/storage/"+id, nil, &reply); err != nil {
		return err
	}
	disk := reply.Storage
	size, _ := disk.Size.Int64()
	if disk.ID != id || disk.Type != "normal" || disk.Access != "private" || disk.Zone != snap.Zone ||
		size != int64(snap.Plan.StorageGB) || disk.Tier != snap.Plan.StorageTier || disk.Encrypted != "yes" ||
		!slices.Equal(disk.Servers.Items, []string{serverID}) ||
		!slices.Contains(disk.Labels, upCloudLabel{Key: upCloudOrderLabel, Value: snap.OperationID}) ||
		!slices.Contains(disk.Labels, upCloudLabel{Key: upCloudOrderImageLabel, Value: snap.TemplateID}) {
		return errors.New("UpCloud order disk does not match the requested image and plan")
	}
	if disk.State == "maintenance" {
		return fmt.Errorf("%w: waiting for the ordered UpCloud storage to finish cloning", errReplacementPending)
	}
	if disk.State != "online" {
		return errors.New("UpCloud order disk is not ready")
	}
	return nil
}

func (c *upCloudOrder) verifyOrder(ctx context.Context, s upCloudOrderSnapshot, id string) (string, error) {
	server, err := c.server(ctx, id)
	if upCloudStatus(err, http.StatusNotFound, "SERVER_NOT_FOUND") {
		return "", fmt.Errorf("%w: waiting for UpCloud to return the ordered server", errReplacementPending)
	}
	if err != nil {
		return "", err
	}
	cores, _ := server.CoreNumber.Int64()
	memory, _ := server.MemoryAmount.Int64()
	if !server.hasLabel(upCloudOrderLabel, s.OperationID) || server.Zone != s.Zone || server.Plan != s.Plan.Code ||
		server.Hostname != s.Hostname || server.Title != s.Title || cores != int64(s.Plan.CPU) || memory != int64(s.Plan.MemoryMB) {
		return "", errors.New("UpCloud returned a VM that does not match the order")
	}
	if server.State == "maintenance" {
		return "", fmt.Errorf("%w: waiting for the ordered UpCloud server to start", errReplacementPending)
	}
	if server.State != "started" {
		return "", errors.New("the ordered UpCloud VM is not running; check its status in UpCloud")
	}
	if len(server.Disks.Items) != 1 || server.Disks.Items[0].Type != "disk" {
		return "", errors.New("the ordered UpCloud VM does not have one cloned disk")
	}
	if err := c.verifyDisk(ctx, s, id, server.Disks.Items[0].ID); err != nil {
		return "", err
	}
	nics, nic, err := server.networkSpecs()
	if err != nil || !slices.Equal(nics, []upCloudNICSpec{{Index: 1, Type: "public", Family: "IPv4"}, {Index: 2, Type: "utility", Family: "IPv4"}}) {
		return "", errors.New("the ordered UpCloud VM does not have the requested IPv4 networking")
	}
	ip, err := c.address(ctx, nic.IPs.Items[0].Address)
	if err != nil {
		return "", err
	}
	if ip.Server != id || ip.Zone != s.Zone || ip.Access != "public" || ip.Family != "IPv4" || ip.MAC != nic.MAC ||
		ip.Floating != "no" || ip.delegated() {
		return "", errors.New("UpCloud has not confirmed the ordered VM's public IPv4")
	}
	if server.Metadata != "yes" || server.RemoteAccessEnabled == "yes" {
		return "", errors.New("UpCloud has not confirmed metadata and remote-access settings for the order")
	}
	if !oneOf(server.SimpleBackup, "", "no") {
		return "", errors.New("UpCloud enabled a backup add-on that was not included in the order")
	}
	return ip.Address, nil
}

func (c *upCloudOrder) ProvisionOrder(ctx context.Context, data json.RawMessage, operationID, _ string, claimCreate func() (bool, error)) (string, string, error) {
	var snap upCloudOrderSnapshot
	if err := json.Unmarshal(data, &snap); err != nil || snap.OperationID != operationID || claimCreate == nil ||
		!upCloudOrderIDPattern.MatchString(operationID) || !upCloudOrderZonePattern.MatchString(snap.Zone) ||
		snap.TemplateID != upCloudOrderDebian13 || !strings.HasPrefix(snap.UserData, "#cloud-config\n") {
		return "", "", errors.New("invalid saved UpCloud order")
	}
	id, err := c.findOperationServer(ctx, upCloudOrderLabel, operationID)
	if err != nil {
		return "", "", err
	}
	if id == "" {
		id, err = c.createOperationServer(ctx, upCloudOrderLabel, operationID, snap.createRequest(), claimCreate)
		if err != nil {
			return "", "", err
		}
	}
	ip, err := c.verifyOrder(ctx, snap, id)
	return id, ip, err
}
