package guard

import (
	"cmp"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type virtuaCatalogZone struct {
	Code    string `json:"code"`
	Country string `json:"country"`
	City    string `json:"city"`
	State   string `json:"state"`
}

type virtuaPublicCatalog struct {
	Currency string              `json:"currency"`
	Zones    []virtuaCatalogZone `json:"zones"`
	Plans    []struct {
		OS       string      `json:"os_family"`
		CPUModel string      `json:"cpu_family"`
		DiskType string      `json:"disk_type"`
		Hourly   json.Number `json:"price_hour"`
		Monthly  json.Number `json:"price_month"`
		Zones    []struct {
			Code  string `json:"code"`
			Offer string `json:"offer_id"`
		} `json:"zones"`
	} `json:"plans"`
}

type virtuaAccountOffer struct {
	ID              string          `json:"uuid"`
	Name            string          `json:"name"`
	Category        string          `json:"category"`
	WindowsIncluded json.RawMessage `json:"is_windows_included"`
	CPUModel        string          `json:"cpu_family"`
	CPU             json.Number     `json:"vcpus"`
	Memory          json.Number     `json:"memory"`
	MemorySize      json.Number     `json:"memory_size"`
	Disk            json.Number     `json:"disk"`
	RootSpace       json.Number     `json:"root_space"`
	DiskType        string          `json:"root_disk_type"`
	Hourly          json.Number     `json:"price_hour"`
	Monthly         json.Number     `json:"price_month"`
	Currency        string          `json:"currency"`
	Zone            struct {
		Code    string `json:"code"`
		Country string `json:"country_code"`
		City    string `json:"city_name"`
	} `json:"cloud_zone"`
}

type virtuaCatalog struct {
	zones []virtuaCatalogZone
	plans map[string][]orderCloudPlan
}

type virtuaCatalogCache struct {
	mu          sync.Mutex
	expires     time.Time
	tokenDigest string
	data        virtuaCatalog
}

func (c *virtuaOrder) catalog(ctx context.Context, refresh bool) (virtuaCatalog, error) {
	cache := c.cache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	key := digest(c.token)
	if !refresh && cache.tokenDigest == key && time.Now().Before(cache.expires) {
		return cache.data, nil
	}
	catalog, err := c.fetchCatalog(ctx)
	if err != nil {
		return virtuaCatalog{}, err
	}
	cache.data = catalog
	cache.tokenDigest = key
	cache.expires = time.Now().Add(time.Minute)
	return catalog, nil
}

func (c *virtuaOrder) fetchCatalog(ctx context.Context) (virtuaCatalog, error) {
	// The public endpoint supplies zone availability and metadata for overlapping
	// plans. Account offers supply the actual order IDs, hardware and hourly rates.
	var public virtuaPublicCatalog
	if _, err := c.request(ctx, http.MethodGet, "/offers", nil, &public); err != nil {
		return virtuaCatalog{}, err
	}
	if public.Currency == "" || public.Zones == nil || public.Plans == nil {
		return virtuaCatalog{}, integration("Virtua.Cloud вернул неполный публичный каталог")
	}
	var account struct {
		Offers []virtuaAccountOffer `json:"offers"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud/offers", nil, &account); err != nil {
		return virtuaCatalog{}, err
	}
	if account.Offers == nil {
		return virtuaCatalog{}, integration("Virtua.Cloud не вернул тарифы аккаунта")
	}
	return public.accountCatalog(account.Offers), nil
}

func (public virtuaPublicCatalog) accountCatalog(offers []virtuaAccountOffer) virtuaCatalog {
	catalog := virtuaCatalog{plans: make(map[string][]orderCloudPlan)}
	zones := make(map[string]virtuaCatalogZone)
	for _, zone := range public.Zones {
		if !virtuaZonePattern.MatchString(zone.Code) || !virtuaCountryPattern.MatchString(zone.Country) {
			continue
		}
		zones[zone.Code] = zone
		if zone.State == "available" {
			catalog.zones = append(catalog.zones, zone)
		}
	}
	type planMetadata struct {
		zone, cpuModel, diskType string
		hourly, monthly          float64
		linux                    bool
	}
	metadata := make(map[string]planMetadata)
	for _, plan := range public.Plans {
		for _, entry := range plan.Zones {
			metadata[entry.Offer] = planMetadata{entry.Code, plan.CPUModel, plan.DiskType, virtuaPrice(plan.Hourly), virtuaPrice(plan.Monthly), plan.OS == "linux"}
		}
	}
	seen := make(map[string]bool)
	for _, offer := range offers {
		if !validVirtuaOffer(offer.ID) || strings.TrimSpace(offer.Name) == "" || seen[offer.ID] {
			continue
		}
		meta := metadata[offer.ID]
		if !offer.isLinux(meta.linux) {
			continue
		}
		zone := offer.resolveZone(zones, meta.zone)
		if zone.State != "available" {
			continue
		}
		cpu := virtuaSize(offer.CPU)
		ram := virtuaSize(offer.Memory, offer.MemorySize)
		disk := virtuaSize(offer.Disk, offer.RootSpace)
		hourly := virtuaPrice(offer.Hourly)
		if cpu == 0 || ram == 0 || disk == 0 || hourly == 0 {
			continue
		}
		currency := strings.ToUpper(strings.TrimSpace(offer.Currency))
		if currency == "" {
			currency = public.Currency
		}
		monthly := virtuaPrice(offer.Monthly)
		if monthly == 0 && currency == public.Currency && hourly == meta.hourly {
			monthly = meta.monthly
		}
		seen[offer.ID] = true
		catalog.plans[zone.Code] = append(catalog.plans[zone.Code], orderCloudPlan{
			Code: offer.ID, Name: strings.TrimSpace(offer.Name + " " + cmp.Or(offer.CPUModel, meta.cpuModel)),
			Country: zone.Country, CPU: cpu, MemoryMB: ram, StorageGB: disk, StorageTier: cmp.Or(offer.DiskType, meta.diskType),
			Price: hourly, MonthlyPrice: monthly, Currency: currency,
		})
	}
	return catalog
}

func (offer virtuaAccountOffer) isLinux(publicLinux bool) bool {
	switch string(offer.WindowsIncluded) {
	case `"0"`, "0", "false":
		return true
	case "", "null":
		return publicLinux || offer.Category == "vcs"
	default:
		return false
	}
}

func (offer virtuaAccountOffer) resolveZone(zones map[string]virtuaCatalogZone, knownCode string) virtuaCatalogZone {
	if zone, ok := zones[offer.Zone.Code]; ok {
		return zone
	}
	if zone, ok := zones[knownCode]; ok {
		return zone
	}
	if dot := strings.LastIndexByte(offer.ID, '.'); dot >= 0 {
		if zone, found := zones[offer.ID[dot+1:]]; found {
			return zone
		}
	}
	if offer.Zone.Country == "" || offer.Zone.City == "" {
		return virtuaCatalogZone{}
	}
	var match virtuaCatalogZone
	for _, zone := range zones {
		if strings.EqualFold(offer.Zone.Country, zone.Country) && strings.EqualFold(offer.Zone.City, zone.City) {
			if match.Code != "" {
				return virtuaCatalogZone{}
			}
			match = zone
		}
	}
	return match
}

func virtuaSize(values ...json.Number) int {
	for _, value := range values {
		if n, err := strconv.Atoi(string(value)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func virtuaPrice(value json.Number) float64 {
	price, err := value.Float64()
	if err != nil || price <= 0 || math.IsNaN(price) || math.IsInf(price, 0) {
		return 0
	}
	return price
}

func (c *virtuaOrder) Countries(ctx context.Context) ([]orderCloudCountry, error) {
	cat, err := c.catalog(ctx, false)
	if err != nil {
		return nil, err
	}
	var countries []orderCloudCountry
	for _, zone := range cat.zones {
		if len(cat.plans[zone.Code]) > 0 {
			countries = append(countries, orderCloudCountry{Code: zone.Country, Name: zone.City + " · " + zone.Country, Zones: []string{zone.Code}})
		}
	}
	return countries, nil
}

func (c *virtuaOrder) Plans(ctx context.Context, zone string) ([]orderCloudPlan, error) {
	return c.zonePlans(ctx, zone, false)
}

func (c *virtuaOrder) zonePlans(ctx context.Context, zone string, refresh bool) ([]orderCloudPlan, error) {
	cat, err := c.catalog(ctx, refresh)
	return cat.plans[zone], err
}
