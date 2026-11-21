package guard

import (
	"math"
	"net/http"
	"net/url"
	"strings"
)

func (c *Cloudflare) checkOrderOriginZone(domain, zoneID string) error {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !validHost(domain) || zoneID == "" {
		return integration("The ordered node origin zone configuration is invalid")
	}
	zones, err := c.pages("/zones", nil)
	if err != nil {
		return err
	}
	var zoneName string
	for _, zone := range zones {
		if !stringFields(zone, "id", "name") {
			return integration("Cloudflare returned an invalid zone response")
		}
		if zone["id"] == zoneID {
			if status := str(zone["status"]); status != "" && status != "active" {
				return integration("The selected Cloudflare zone is not active")
			}
			zoneName = strings.ToLower(strings.TrimSuffix(str(zone["name"]), "."))
		}
	}
	if !validHost(zoneName) || !strings.HasSuffix(domain, "."+zoneName) {
		return integration("The ordered node domain must be a subdomain of the selected Cloudflare zone")
	}
	for _, zone := range zones {
		name := strings.ToLower(strings.TrimSuffix(str(zone["name"]), "."))
		if len(name) > len(zoneName) && (domain == name || strings.HasSuffix(domain, "."+name)) &&
			(str(zone["status"]) == "" || zone["status"] == "active") {
			return integration("The ordered node domain belongs to a more specific Cloudflare zone")
		}
	}
	return nil
}

// An ordered node's origin has one dedicated DNS-only A record, separate from
// the pool hostname. The order marker controls adoption and future changes.
func (c *Cloudflare) checkOrderOrigin(j row, oldIP, newIP string, mutate bool) (float64, error) {
	orderID, valid := canonicalUUID(str(j["id"]))
	if !valid {
		return 0, integration("The ordered node origin record configuration is invalid")
	}
	return c.checkNodeOrigin(j, "dns-guard-order:"+orderID, oldIP, newIP, mutate, false)
}

func (c *Cloudflare) checkNodeOrigin(j row, marker, oldIP, newIP string, mutate, manual bool) (float64, error) {
	domain := strings.ToLower(strings.TrimSuffix(str(j["domain"]), "."))
	zoneID := str(j["zone_id"])
	if oldIP != "" && !publicIPv4(oldIP) || newIP != "" && !publicIPv4(newIP) || mutate && newIP == "" {
		return 0, integration("The ordered node origin record configuration is invalid")
	}
	if err := c.checkOrderOriginZone(domain, zoneID); err != nil {
		return 0, err
	}
	read := func() (row, error) {
		return c.nodeOriginRecord(zoneID, domain, marker, manual)
	}
	record, err := read()
	if err != nil {
		return 0, err
	}
	if oldIP == "" && newIP == "" {
		if record != nil {
			return 0, integration("The ordered node domain already has a Cloudflare address record")
		}
		return 0, nil
	}
	configuredTTL := num(j["ttl"])
	ttl := func(r row) float64 {
		return replacementRecordTTL([]row{r}, str(r["content"]), configuredTTL)
	}
	currentIP := str(record["content"])
	if record != nil && currentIP == newIP && newIP != "" {
		return ttl(record), nil
	}
	if record != nil && (oldIP == "" || currentIP != oldIP) {
		return 0, integration("The ordered node origin points to an unexpected IPv4 address")
	}
	if record == nil && ((!manual && (oldIP != "" || !mutate)) || (manual && oldIP == "" && !mutate)) {
		return 0, integration("The ordered node's owned Cloudflare A record could not be found")
	}
	if !mutate {
		return ttl(record), nil
	}

	var mutationErr error
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	if record == nil {
		if configuredTTL != math.Trunc(configuredTTL) || configuredTTL < 60 || configuredTTL > 86400 {
			return 0, integration("The ordered node origin TTL is invalid")
		}
		_, mutationErr = c.request(http.MethodPost, path, nil, row{
			"type": "A", "name": domain, "content": newIP, "ttl": configuredTTL, "proxied": false, "comment": marker,
		})
	} else {
		// Keep the record's comment, TTL and DNS-only status.
		_, mutationErr = c.request(http.MethodPatch, path+"/"+url.PathEscape(str(record["id"])), nil, row{"content": newIP})
	}
	confirmed, err := read()
	if err != nil {
		return 0, err
	}
	if confirmed["content"] != newIP {
		if mutationErr != nil {
			return 0, mutationErr
		}
		return 0, integration("Cloudflare has not confirmed the ordered node origin address")
	}
	return max(ttl(record), ttl(confirmed)), nil
}

func (c *Cloudflare) nodeOriginRecord(zoneID, domain, marker string, manual bool) (row, error) {
	records, err := c.pages("/zones/"+url.PathEscape(zoneID)+"/dns_records", url.Values{"name": {domain}})
	if err != nil {
		return nil, err
	}
	var owned row
	for _, record := range records {
		if !stringFields(record, "name", "type") {
			return nil, integration("Cloudflare returned an invalid origin record response")
		}
		if !strings.EqualFold(strings.TrimSuffix(str(record["name"]), "."), domain) {
			continue
		}
		switch record["type"] {
		case "A":
			comment := str(record["comment"])
			ownedByOther := strings.HasPrefix(comment, "dns-guard-order:") || strings.HasPrefix(comment, "dns-guard-replacement:")
			if owned != nil || (comment != marker && (!manual || ownedByOther)) || record["proxied"] != false ||
				!stringFields(record, "id", "content") || str(record["id"]) == "" {
				return nil, integration("The ordered node domain has a conflicting Cloudflare A record")
			}
			owned = record
		case "AAAA", "CNAME", "NS":
			return nil, integration("The ordered node domain has a conflicting Cloudflare record")
		}
	}
	return owned, nil
}
