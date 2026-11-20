package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const virtuaAPIBase = "https://api.virtua.cloud/v1"

var (
	virtuaZonePattern    = regexp.MustCompile("^[a-z0-9][a-z0-9-]{0,23}$")
	virtuaCountryPattern = regexp.MustCompile("^[A-Z]{2}$")
	virtuaIDPattern      = regexp.MustCompile("^[A-Za-z0-9._-]{1,255}$")
	virtuaErrorPattern   = regexp.MustCompile("^[a-z0-9_]{1,80}$")
)

type virtuaOrder struct {
	client *http.Client
	token  string
	cache  *virtuaCatalogCache
}

type virtuaAPIError struct {
	status int
	code   string
	detail string
}

func (e *virtuaAPIError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("Virtua.Cloud API: HTTP %d", e.status)
	}
	if e.detail != "" {
		return fmt.Sprintf("Virtua.Cloud API: %s (%s)", e.code, e.detail)
	}
	return "Virtua.Cloud API: " + e.code
}

func validVirtuaOffer(id string) bool {
	return id != "" && len(id) <= 255 && !strings.ContainsFunc(id, unicode.IsControl)
}

func validVirtuaToken(token string) bool {
	return token != "" && len(token) <= 4096 && !strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r >= 127 })
}

func (c *virtuaOrder) request(ctx context.Context, method, path string, input url.Values, output any) (http.Header, error) {
	var body io.Reader
	if input != nil {
		body = strings.NewReader(input.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, virtuaAPIBase+path, body)
	if err != nil {
		return nil, integration("не удалось подготовить запрос Virtua.Cloud")
	}
	req.Header.Set("Accept", "application/json")
	if path != "/offers" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, integration("нет ответа от API Virtua.Cloud")
	}
	defer resp.Body.Close()
	const maxReply = 8 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if err != nil || len(data) > maxReply {
		return nil, integration("не удалось прочитать ответ API Virtua.Cloud")
	}
	var result struct {
		Success *bool  `json:"success"`
		Error   string `json:"error"`
		Code    string `json:"error_code"`
	}
	parseErr := json.Unmarshal(data, &result)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || (result.Success != nil && !*result.Success) {
		apiErr := &virtuaAPIError{status: resp.StatusCode}
		if parseErr == nil && virtuaErrorPattern.MatchString(result.Error) {
			apiErr.code = result.Error
			if virtuaErrorPattern.MatchString(result.Code) {
				apiErr.detail = result.Code
			}
		}
		return nil, apiErr
	}
	// /account is documented without a success flag.
	if parseErr != nil || (result.Success == nil && path != "/account") ||
		(output != nil && json.Unmarshal(data, output) != nil) {
		return nil, integration("некорректный ответ API Virtua.Cloud")
	}
	return resp.Header, nil
}

func (c *virtuaOrder) checkAccount(ctx context.Context) error {
	var account struct {
		Balance  string `json:"balance"`
		Currency string `json:"currency"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/account", nil, &account); err != nil {
		return err
	}
	if account.Balance == "" || account.Currency == "" {
		return integration("Virtua.Cloud не вернул данные аккаунта")
	}
	return nil
}

type virtuaCatalogZone struct {
	Code    string `json:"code"`
	Country string `json:"country"`
	City    string `json:"city"`
	State   string `json:"state"`
}

type virtuaCatalogPlan struct {
	Name     string `json:"name"`
	OS       string `json:"os_family"`
	CPUModel string `json:"cpu_family"`
	CPU      int    `json:"vcpus"`
	RAM      int    `json:"memory_mb"`
	Disk     int    `json:"disk_gb"`
	DiskType string `json:"disk_type"`
	Hourly   string `json:"price_hour"`
	Zones    []struct {
		Code  string `json:"code"`
		Offer string `json:"offer_id"`
	} `json:"zones"`
}

type virtuaCatalog struct {
	Currency string              `json:"currency"`
	Zones    []virtuaCatalogZone `json:"zones"`
	Plans    []virtuaCatalogPlan `json:"plans"`
}

type virtuaCatalogCache struct {
	mu      sync.Mutex
	expires time.Time
	data    virtuaCatalog
}

func (c *virtuaOrder) catalog(ctx context.Context, refresh bool) (virtuaCatalog, error) {
	cache := c.cache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !refresh && time.Now().Before(cache.expires) {
		return cache.data, nil
	}
	var catalog virtuaCatalog
	headers, err := c.request(ctx, http.MethodGet, "/offers", nil, &catalog)
	if err != nil {
		return catalog, err
	}
	if catalog.Currency != "EUR" || catalog.Zones == nil || catalog.Plans == nil {
		return catalog, integration("Virtua.Cloud вернул неполный каталог тарифов")
	}
	cache.data = catalog
	cache.expires = time.Time{}
	for entry := range strings.SplitSeq(headers.Get("Cache-Control"), ",") {
		value, ok := strings.CutPrefix(strings.TrimSpace(entry), "max-age=")
		if seconds, err := strconv.Atoi(value); ok && err == nil && seconds > 0 && seconds <= 300 {
			cache.expires = time.Now().Add(time.Duration(seconds) * time.Second)
		}
	}
	return catalog, nil
}

func (cat virtuaCatalog) plansIn(zone virtuaCatalogZone) []orderCloudPlan {
	var out []orderCloudPlan
	if zone.State != "available" || !virtuaZonePattern.MatchString(zone.Code) || !virtuaCountryPattern.MatchString(zone.Country) {
		return out
	}
	seen := map[string]bool{}
	for _, p := range cat.Plans {
		hour, err := strconv.ParseFloat(p.Hourly, 64)
		if p.OS != "linux" || p.Name == "" || p.CPU <= 0 || p.RAM <= 0 || p.Disk <= 0 ||
			err != nil || hour <= 0 || math.IsNaN(hour) || math.IsInf(hour, 0) {
			continue
		}
		for _, entry := range p.Zones {
			if entry.Code != zone.Code || !validVirtuaOffer(entry.Offer) || seen[entry.Offer] {
				continue
			}
			seen[entry.Offer] = true
			out = append(out, orderCloudPlan{
				Code: entry.Offer, Name: strings.TrimSpace(p.Name + " " + p.CPUModel), Country: zone.Country,
				CPU: p.CPU, MemoryMB: p.RAM, StorageGB: p.Disk, StorageTier: p.DiskType, Price: hour, Currency: cat.Currency,
			})
		}
	}
	return out
}

func (c *virtuaOrder) Countries(ctx context.Context) ([]orderCloudCountry, error) {
	cat, err := c.catalog(ctx, false)
	if err != nil {
		return nil, err
	}
	var countries []orderCloudCountry
	for _, z := range cat.Zones {
		if len(cat.plansIn(z)) > 0 {
			countries = append(countries, orderCloudCountry{Code: z.Country, Name: z.City + " · " + z.Country, Zones: []string{z.Code}})
		}
	}
	return countries, nil
}

func (c *virtuaOrder) Plans(ctx context.Context, zone string) ([]orderCloudPlan, error) {
	return c.zonePlans(ctx, zone, false)
}

func (c *virtuaOrder) zonePlans(ctx context.Context, zone string, refresh bool) ([]orderCloudPlan, error) {
	cat, err := c.catalog(ctx, refresh)
	if err != nil {
		return nil, err
	}
	for _, z := range cat.Zones {
		if z.Code == zone {
			return cat.plansIn(z), nil
		}
	}
	return nil, nil
}

func (c *virtuaOrder) image(ctx context.Context, diskGB int) (string, error) {
	var list struct {
		Systems []struct {
			ID           string          `json:"uuid"`
			Distribution string          `json:"distribution"`
			Version      string          `json:"version"`
			Category     string          `json:"category"`
			Windows      json.RawMessage `json:"is_windows"`
			MinDisk      int             `json:"min_disk_space"`
		} `json:"systems"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud/systems", nil, &list); err != nil {
		return "", err
	}
	for _, image := range list.Systems {
		major, _, _ := strings.Cut(image.Version, ".")
		if image.Category == "linux" && image.Distribution == "debian" && major == "13" &&
			oneOf(string(image.Windows), `"0"`, "0", "false") && image.MinDisk > 0 && image.MinDisk <= diskGB &&
			virtuaIDPattern.MatchString(image.ID) {
			return image.ID, nil
		}
	}
	return "", errors.New("Virtua.Cloud не предлагает Debian 13 для выбранного размера диска")
}

type virtuaOrderSnapshot struct {
	OperationID string `json:"operation_id"`
	Zone        string `json:"zone"`
	Offer       string `json:"offer"`
	System      string `json:"system"`
	Script      string `json:"script"`
}

func (c *virtuaOrder) PrepareOrder(ctx context.Context, req orderCloudRequest) (json.RawMessage, string, string, error) {
	if id, ok := canonicalUUID(req.OperationID); !ok || id != req.OperationID || !virtuaZonePattern.MatchString(req.Zone) {
		return nil, "", "", errors.New("некорректные параметры заказа Virtua.Cloud")
	}
	script, err := virtuaBootstrap(req)
	if err != nil {
		return nil, "", "", err
	}
	plans, err := c.Plans(ctx, req.Zone)
	if err != nil {
		return nil, "", "", err
	}
	for _, plan := range plans {
		if plan.Code == req.Plan && plan.Country == req.Country && orderPlanChoice(req.Zone, plan).ID == req.Quote {
			image, err := c.image(ctx, plan.StorageGB)
			if err != nil {
				return nil, "", "", err
			}
			snap, err := json.Marshal(virtuaOrderSnapshot{OperationID: req.OperationID, Zone: req.Zone, Offer: plan.Code, System: image, Script: script})
			return snap, "", req.Zone, err
		}
	}
	return nil, "", "", errOrderQuoteChanged
}

func readVirtuaSnapshot(data json.RawMessage, id string) (virtuaOrderSnapshot, error) {
	var snap virtuaOrderSnapshot
	orderID, valid := canonicalUUID(id)
	if err := json.Unmarshal(data, &snap); err != nil || !valid || orderID != id || snap.OperationID != id ||
		!virtuaZonePattern.MatchString(snap.Zone) || !validVirtuaOffer(snap.Offer) ||
		!virtuaIDPattern.MatchString(snap.System) || !strings.HasPrefix(snap.Script, "#!/bin/bash\n") {
		return snap, errors.New("некорректный сохранённый заказ Virtua.Cloud")
	}
	return snap, nil
}

func (s virtuaOrderSnapshot) name() string { return "dns-guard-" + s.OperationID }

func (c *virtuaOrder) scriptIDs(ctx context.Context, snap virtuaOrderSnapshot) ([]string, error) {
	var scripts struct {
		Scripts []struct {
			ID      string `json:"uuid"`
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"scripts"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/script", nil, &scripts); err != nil {
		return nil, err
	}
	if scripts.Scripts == nil {
		return nil, integration("Virtua.Cloud не вернул список скриптов")
	}
	var ids []string
	for _, script := range scripts.Scripts {
		if script.Name != snap.name() {
			continue
		}
		id, valid := canonicalUUID(script.ID)
		if !valid || script.Content != snap.Script {
			return nil, errors.New("найден скрипт Virtua.Cloud с именем заказа и другим содержимым")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (c *virtuaOrder) ensureScript(ctx context.Context, snap virtuaOrderSnapshot) (string, error) {
	ids, err := c.scriptIDs(ctx, snap)
	if err != nil {
		return "", err
	}
	if len(ids) > 0 {
		return ids[0], nil
	}
	_, err = c.request(ctx, http.MethodPost, "/script", url.Values{"name": {snap.name()}, "content": {snap.Script}}, nil)
	if err != nil {
		return "", err
	}
	ids, err = c.scriptIDs(ctx, snap)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", errors.New("Virtua.Cloud не подтвердил создание скрипта настройки")
	}
	return ids[0], nil
}

func (c *virtuaOrder) cleanupScript(ctx context.Context, snap virtuaOrderSnapshot) error {
	ids, err := c.scriptIDs(ctx, snap)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = c.request(ctx, http.MethodDelete, "/script", url.Values{"uuid": {id}}, nil); err != nil {
			return err
		}
	}
	return nil
}

type virtuaServer struct {
	ID         string `json:"uuid"`
	Name       string `json:"name"`
	Label      string `json:"label"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	Setup      *bool  `json:"is_setup"`
	Processing *bool  `json:"is_processing"`
}

func (c *virtuaOrder) findServer(ctx context.Context, name string) (string, error) {
	var list struct {
		Servers []virtuaServer `json:"cloud_servers"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud-server", nil, &list); err != nil {
		return "", err
	}
	if list.Servers == nil {
		return "", integration("Virtua.Cloud не вернул список серверов")
	}
	var found string
	for _, server := range list.Servers {
		if server.Name != name && server.Label != name && server.Hostname != name {
			continue
		}
		id, ok := canonicalUUID(server.ID)
		if !ok || (found != "" && found != id) {
			return "", errors.New("Virtua.Cloud вернул неоднозначный сервер для заказа " + name)
		}
		found = id
	}
	return found, nil
}

func (c *virtuaOrder) readyAddress(ctx context.Context, id string) (string, error) {
	var details struct {
		Server virtuaServer `json:"cloud_server"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud-server/"+id, nil, &details); err != nil {
		return "", err
	}
	server := details.Server
	if returned, ok := canonicalUUID(server.ID); !ok || returned != id || server.Setup == nil || server.Processing == nil {
		return "", integration("Virtua.Cloud вернул неполные сведения о сервере")
	}
	if !*server.Setup || *server.Processing || server.Status != "running" {
		return "", errReplacementPending
	}
	var addresses struct {
		IPs []struct {
			Address string `json:"address"`
			Version int    `json:"version"`
		} `json:"ip_addresses"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/network/cloud-server/"+id+"/show", nil, &addresses); err != nil {
		return "", err
	}
	var ip string
	for _, address := range addresses.IPs {
		if address.Version == 4 && publicIPv4(address.Address) {
			if ip != "" && ip != address.Address {
				return "", errors.New("Virtua.Cloud вернул несколько публичных IPv4 для нового сервера")
			}
			ip = address.Address
		}
	}
	if ip == "" {
		return "", errReplacementPending
	}
	return ip, nil
}

func (c *virtuaOrder) createServer(ctx context.Context, snap virtuaOrderSnapshot, script string) (string, error) {
	var reply struct {
		ID       string       `json:"uuid"`
		ServerID string       `json:"cloud_server_uuid"`
		Server   virtuaServer `json:"cloud_server"`
	}
	_, err := c.request(ctx, http.MethodPost, "/cloud/order", url.Values{
		"offer": {snap.Offer}, "system": {snap.System}, "hostname": {snap.name()}, "script": {script}, "billing_period": {"0"},
	}, &reply)
	if err != nil {
		var refusal *virtuaAPIError
		if errors.As(err, &refusal) && refusal.status < 500 && oneOf(refusal.code,
			"missing_offer", "invalid_offer", "cloud_zone_not_available", "cloud_zone_sold_out",
			"ip_address_v4_available_too_low", "cloud_offer_is_out_of_stock", "system_not_available_in_zone",
			"windows", "system_disk_too_small", "cloud_server_limits_reached", "balance_too_low") {
			return "", fmt.Errorf("%w: %s", errReplacementCreateRejected, refusal)
		}
		return "", err // An ambiguous outcome is reconciled without repeating the charge.
	}
	for _, candidate := range []string{reply.Server.ID, reply.ServerID, reply.ID} {
		if id, valid := canonicalUUID(candidate); valid {
			return id, nil
		}
	}
	return "", errReplacementPending
}

func (c *virtuaOrder) ProvisionOrder(ctx context.Context, data json.RawMessage, operationID, existingServer string, claimCreate func() (bool, error)) (string, string, error) {
	snap, err := readVirtuaSnapshot(data, operationID)
	if err != nil {
		return "", "", err
	}
	id := existingServer
	if id != "" {
		if checked, ok := canonicalUUID(id); !ok || checked != id {
			return "", "", errors.New("некорректный UUID сохранённого сервера Virtua.Cloud")
		}
	} else {
		id, err = c.findServer(ctx, snap.name())
		if err != nil {
			return "", "", err
		}
	}
	if id == "" {
		script, err := c.ensureScript(ctx, snap)
		if err != nil {
			return "", "", err
		}
		claimed, err := claimCreate()
		if err != nil {
			return "", "", err
		}
		if !claimed {
			return "", "", fmt.Errorf("%w: %s", errReplacementCreateUnconfirmed, snap.name())
		}
		id, err = c.createServer(ctx, snap, script)
		if err != nil {
			return "", "", err
		}
	}
	ip, err := c.readyAddress(ctx, id)
	return id, ip, err
}
