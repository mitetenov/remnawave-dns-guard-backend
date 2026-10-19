package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type IntegrationError struct{ Message, Kind string }

func (e *IntegrationError) Error() string          { return e.Message }
func integration(message string) *IntegrationError { return &IntegrationError{Message: message} }
func providerClient(client *http.Client) *http.Client {
	if client != nil {
		copy := *client
		if copy.Timeout == 0 {
			copy.Timeout = 20 * time.Second
		}
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &copy
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type Cloudflare struct {
	token  string
	client *http.Client
}

func (c *Cloudflare) request(method, path string, params url.Values, payload any) (row, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	endpoint := "https://api.cloudflare.com/client/v4" + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	req, e := http.NewRequest(method, endpoint, body)
	if e != nil {
		return nil, integration("Cloudflare API unavailable or request rejected")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, e := c.client.Do(req)
	if e != nil {
		return nil, integration("Cloudflare API unavailable or request rejected")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, integration("Cloudflare API unavailable or request rejected")
	}
	var out row
	dec := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	if e = dec.Decode(&out); e != nil {
		return nil, integration("Cloudflare API unavailable or request rejected")
	}
	if out == nil || out["success"] != true {
		return nil, integration("Cloudflare rejected the operation; verify token permissions and zone")
	}
	if _, ok := out["result"]; !ok {
		return nil, integration("Cloudflare rejected the operation; verify token permissions and zone")
	}
	return out, nil
}
func (c *Cloudflare) pages(path string, params url.Values) ([]row, error) {
	out := []row{}
	if params == nil {
		params = url.Values{}
	}
	for page := 1; page <= 1000; page++ {
		params.Set("page", strconv.Itoa(page))
		params.Set("per_page", "100")
		body, e := c.request(http.MethodGet, path, params, nil)
		if e != nil {
			return nil, e
		}
		rows, ok := body["result"].([]any)
		if !ok {
			return nil, integration("Cloudflare returned an invalid response")
		}
		for _, r := range rows {
			v, ok := r.(map[string]any)
			if !ok {
				return nil, integration("Cloudflare returned an invalid response")
			}
			out = append(out, row(v))
		}
		total := 1
		if info, ok := body["result_info"]; ok && info != nil {
			if m, ok := info.(map[string]any); ok {
				if n, ok := m["total_pages"]; ok {
					f, valid := n.(float64)
					if !valid || f < 1 || f != float64(int(f)) {
						return nil, integration("Cloudflare returned invalid pagination metadata")
					}
					total = int(f)
				}
			} else {
				return nil, integration("Cloudflare returned invalid pagination metadata")
			}
		}
		if page >= total {
			return out, nil
		}
	}
	return nil, integration("Cloudflare response exceeds the record limit")
}
func (c *Cloudflare) zones() ([]row, error) {
	rows, e := c.pages("/zones", nil)
	if e != nil {
		return nil, e
	}
	out := []row{}
	for _, z := range rows {
		if !stringFields(z, "id", "name") {
			return nil, integration("Cloudflare returned an invalid zone response")
		}
		out = append(out, row{"id": z["id"], "name": z["name"]})
	}
	return out, nil
}
func stringFields(r row, keys ...string) bool {
	for _, key := range keys {
		if _, ok := r[key].(string); !ok {
			return false
		}
	}
	return true
}
func (c *Cloudflare) addressRecords(p row) ([]row, error) {
	rows, e := c.pages("/zones/"+url.PathEscape(str(p["zone_id"]))+"/dns_records", url.Values{"name": {str(p["hostname"])}})
	if e != nil {
		return nil, e
	}
	out := []row{}
	for _, r := range rows {
		if !stringFields(r, "id", "type", "name", "content") {
			return nil, integration("Cloudflare returned an invalid record response")
		}
		if oneOf(str(r["type"]), "A", "AAAA") && strings.ToLower(strings.TrimRight(str(r["name"]), ".")) == str(p["hostname"]) {
			out = append(out, r)
		}
	}
	return out, nil
}
func checkProxy(records []row) error {
	for _, r := range records {
		if truth(r["proxied"]) {
			return &IntegrationError{Message: "Disable Cloudflare proxy for all A/AAAA records at this exact hostname", Kind: "proxy"}
		}
	}
	return nil
}
func (c *Cloudflare) ensure(p row, ip string, present bool) (bool, error) {
	records, e := c.addressRecords(p)
	if e != nil {
		return false, e
	}
	if e = checkProxy(records); e != nil {
		return false, e
	}
	a := []row{}
	matching := []row{}
	for _, r := range records {
		if r["type"] == "A" {
			a = append(a, r)
			if r["content"] == ip {
				matching = append(matching, r)
			}
		}
	}
	path := "/zones/" + url.PathEscape(str(p["zone_id"])) + "/dns_records"
	if present {
		if len(matching) == 0 {
			_, e = c.request(http.MethodPost, path, nil, row{"type": "A", "name": p["hostname"], "content": ip, "ttl": p["ttl"], "proxied": false})
			if e != nil {
				return false, e
			}
		}
	} else {
		if len(matching) > 0 && len(a) <= len(matching) {
			return false, &IntegrationError{Message: "The final actual A record must be preserved", Kind: "last_record"}
		}
		for _, r := range matching {
			if _, e = c.request(http.MethodDelete, path+"/"+url.PathEscape(str(r["id"])), nil, nil); e != nil {
				return false, e
			}
		}
	}
	verified, e := c.addressRecords(p)
	if e != nil {
		return false, e
	}
	if e = checkProxy(verified); e != nil {
		return false, e
	}
	exists := false
	for _, r := range verified {
		if r["type"] == "A" && r["content"] == ip {
			exists = true
		}
	}
	if exists != present {
		return false, integration("Cloudflare DNS change could not be verified; retry later")
	}
	return exists, nil
}

// Confirm the replacement before removing the old IP, including when it is the
// pool's final A record. Repeating either step after a timeout is idempotent.
func (c *Cloudflare) replaceIP(p row, oldIP, newIP string, present bool) (bool, error) {
	if present {
		if _, err := c.ensure(p, newIP, true); err != nil {
			return false, err
		}
	}
	if _, err := c.ensure(p, oldIP, false); err != nil {
		return false, err
	}
	records, err := c.addressRecords(p)
	if err != nil {
		return false, err
	}
	if err = checkProxy(records); err != nil {
		return false, err
	}
	actual := false
	for _, record := range records {
		if record["type"] == "A" && record["content"] == newIP {
			actual = true
		}
	}
	if actual != present {
		return false, integration("Cloudflare DNS replacement could not be verified; retry later")
	}
	return actual, nil
}

type Remnawave struct {
	url, token string
	client     *http.Client
}

func newRemnawave(endpoint, token string, client *http.Client) (*Remnawave, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, integration("Remnawave URL must be an HTTPS base URL without credentials")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	endpoint = strings.TrimSuffix(endpoint, "/api")
	return &Remnawave{endpoint, token, client}, nil
}
func (r *Remnawave) get(resource string) ([]row, error) {
	req, e := http.NewRequest(http.MethodGet, r.url+"/api/"+resource, nil)
	if e != nil {
		return nil, integration("Remnawave API unavailable or request rejected")
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	response, e := r.client.Do(req)
	if e != nil {
		return nil, integration("Remnawave API unavailable or request rejected")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, integration("Remnawave API unavailable or request rejected")
	}
	var body row
	if e = json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&body); e != nil {
		return nil, integration("Remnawave API unavailable or request rejected")
	}
	data := body["response"]
	if nested, ok := data.(map[string]any); ok {
		data = nested[resource]
		if data == nil {
			data = []any{}
		}
	}
	items, ok := data.([]any)
	if !ok {
		return nil, integration("Remnawave API unavailable or request rejected")
	}
	out := []row{}
	for _, item := range items {
		v, ok := item.(map[string]any)
		if !ok {
			return nil, integration("Remnawave API unavailable or request rejected")
		}
		out = append(out, row(v))
	}
	return out, nil
}
func (r *Remnawave) nodes() ([]row, error) {
	rows, e := r.get("nodes")
	if e != nil {
		return nil, e
	}
	out := []row{}
	for _, n := range rows {
		if !stringFields(n, "uuid", "name", "address") {
			return nil, integration("Remnawave returned an invalid node response")
		}
		var profile any
		if n["configProfile"] != nil {
			p, ok := n["configProfile"].(map[string]any)
			if !ok {
				return nil, integration("Remnawave returned an invalid node response")
			}
			profile = p["activeConfigProfileUuid"]
		}
		out = append(out, row{"uuid": n["uuid"], "name": n["name"], "address": n["address"], "is_connected": truth(n["isConnected"]), "config_profile_uuid": profile})
	}
	return out, nil
}
func (r *Remnawave) hosts() ([]row, error) {
	rows, e := r.get("hosts")
	if e != nil {
		return nil, e
	}
	out := []row{}
	for _, h := range rows {
		port, ok := h["port"].(float64)
		if !stringFields(h, "uuid", "address") || !ok || port != float64(int(port)) {
			return nil, integration("Remnawave returned an invalid host response")
		}
		nodes := []any{}
		if n, exists := h["nodes"]; exists {
			nodes, ok = n.([]any)
			if !ok {
				return nil, integration("Remnawave returned an invalid host response")
			}
		}
		for _, n := range nodes {
			if _, ok = n.(string); !ok {
				return nil, integration("Remnawave returned an invalid host response")
			}
		}
		remark := h["remark"]
		if remark == nil {
			remark = ""
		}
		out = append(out, row{"uuid": h["uuid"], "remark": remark, "address": h["address"], "port": int(port), "node_uuids": nodes})
	}
	return out, nil
}
