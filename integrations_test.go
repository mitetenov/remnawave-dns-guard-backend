package guard

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustURL(value string) *url.URL { u, _ := url.Parse(value); return u }

func TestCloudflareMalformedRepliesDoNotLeakProviderBody(t *testing.T) {
	for _, body := range []any{[]any{}, row{"success": false, "errors": []any{"secret"}}, row{"success": true, "result": []any{nil}}, row{"success": true, "result": []any{}, "result_info": row{"total_pages": "secret"}}, row{"success": true, "result": []any{row{"id": "zone"}}}} {
		c := &Cloudflare{"secret", providerClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(body, 200), nil })})}
		if _, err := c.zones(); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe malformed response error", err)
		}
	}
}

func TestCloudflarePaginationAndExactHostname(t *testing.T) {
	pages := []string{}
	c := &Cloudflare{"token", providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		pages = append(pages, req.URL.Query().Get("page"))
		if req.Header.Get("Authorization") != "Bearer token" || req.URL.Query().Get("name") != "vpn.example.com" {
			t.Fatal("missing scoped query or auth")
		}
		rows := []row{{"id": "other", "type": "A", "name": "other.example.com", "content": "1.1.1.1"}}
		if req.URL.Query().Get("page") == "2" {
			rows = []row{{"id": "exact", "type": "A", "name": "VPN.EXAMPLE.COM.", "content": "8.8.8.8"}, {"id": "txt", "type": "TXT", "name": "vpn.example.com", "content": "value"}}
		}
		return response(row{"success": true, "result": rows, "result_info": row{"total_pages": 2}}, 200), nil
	})})}
	rows, err := c.addressRecords(row{"zone_id": "zone", "hostname": "vpn.example.com"})
	if err != nil || len(rows) != 1 || rows[0]["id"] != "exact" || strings.Join(pages, ",") != "1,2" {
		t.Fatal(rows, pages, err)
	}
}

func TestRemnawaveCurrentReadOnlyShapesAndSanitizedErrors(t *testing.T) {
	client := providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" || req.Header.Get("Authorization") != "Bearer api-token" {
			t.Fatal("unsafe Remnawave request")
		}
		var rows []row
		if strings.HasSuffix(req.URL.Path, "/nodes") {
			rows = []row{{"uuid": "node", "name": "n", "address": "host.example.com", "isConnected": true, "configProfile": row{"activeConfigProfileUuid": "profile"}}}
		} else {
			rows = []row{{"uuid": "host", "remark": "h", "address": "1.1.1.1", "port": 443, "nodes": []string{"node"}}}
		}
		return response(row{"response": rows}, 200), nil
	})})
	r, err := newRemnawave("https://panel.example.com/api/", "api-token", client)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := r.nodes()
	if err != nil || nodes[0]["config_profile_uuid"] != "profile" || nodes[0]["address"] != "host.example.com" {
		t.Fatal(nodes, err)
	}
	hosts, err := r.hosts()
	if err != nil || str(hosts[0]["node_uuids"].([]any)[0]) != "node" {
		t.Fatal(hosts, err)
	}
	r.client = providerClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response("api-token", 403), nil })})
	if _, err = r.nodes(); err == nil || strings.Contains(err.Error(), "api-token") {
		t.Fatal("unsafe provider error", err)
	}
	for _, endpoint := range []string{"http://panel.example.com", "https://user:password@panel.example.com", "https://panel.example.com?token=secret", "https://panel.example.com/#secret"} {
		if _, err = newRemnawave(endpoint, "api-token", client); err == nil {
			t.Fatal("invalid Remnawave base URL accepted", endpoint)
		}
	}
}

func TestProviderRedirectNeverForwardsToken(t *testing.T) {
	calls := 0
	c := &Cloudflare{"secret", providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		r := response(row{"success": true, "result": []any{}}, 302)
		r.Header.Set("Location", "https://other.example.com/leak")
		return r, nil
	})})}
	if _, err := c.zones(); err == nil || calls != 1 {
		t.Fatal("redirect followed", calls, err)
	}
}
