package guard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

const (
	testVirtuaOrderID = "d295eb42-dbe3-4222-8f87-79ef3c0e5cfc"
	testVirtuaScript  = "4ad1df94-89af-4a2b-a385-d24851d02ccf"
)

func TestVirtuaOrderCatalogBootstrapAndLostResponse(t *testing.T) {
	ctx := t.Context()
	hostname := "dns-guard-" + testVirtuaOrderID
	const plusOffer = "vcs-2+-ryzen.par01fr"
	catalogRequests, accountRequests, scriptPosts, serverPosts := 0, 0, 0, 0
	claimed, exists, ready := false, false, false
	var script string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.virtua.cloud" {
			t.Fatalf("unexpected API host %q", r.URL.Host)
		}
		if r.URL.Path != "/v1/offers" && r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing API authentication for %s", r.URL.Path)
		}
		if r.URL.Path == "/v1/offers" && r.Header.Get("Authorization") != "" {
			t.Fatal("public catalog received the API token")
		}
		var fields url.Values
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			fields, _ = url.ParseQuery(string(body))
		}
		ok := func(v row) (*http.Response, error) { v["success"] = true; return response(v, 200), nil }
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/offers":
			catalogRequests++
			offer := row{"name": "vCS-2", "os_family": "linux", "cpu_family": "intel-xeon", "vcpus": 1, "memory_mb": 2048, "disk_gb": 40, "disk_type": "ssd", "price_hour": "0.0167",
				"zones": []row{{"code": "par01fr", "offer_id": "vcs-2.par01fr"}, {"code": "fmt02us", "offer_id": "vcs-2.fmt02us"}}}
			res, _ := ok(row{"currency": "EUR", "zones": []row{{"code": "par01fr", "country": "FR", "city": "Paris", "state": "available"}, {"code": "fmt02us", "country": "US", "city": "Fremont", "state": "sold_out"}}, "plans": []row{offer}})
			res.Header.Set("Cache-Control", "public, max-age=300")
			return res, nil
		case "GET /v1/cloud/offers":
			accountRequests++
			return ok(row{"offers": []row{
				{"uuid": "vcs-2.par01fr", "name": "vCS-2", "category": "vcs", "vcpus": 1, "memory": 2048, "disk": 40, "price_hour": "0.0167", "price_month": "12.00", "currency": "EUR"},
				{"uuid": plusOffer, "name": "vCS-2+", "is_windows_included": "0", "cpu_family": "amd-ryzen", "vcpus": "2", "memory_size": "2048", "root_space": "60", "root_disk_type": "nvme", "price_hour": "0.0292", "price_month": "21.00"},
				{"uuid": "vcs-2+-ryzen.fmt02us", "name": "vCS-2+", "category": "vcs", "vcpus": 2, "memory": 2048, "disk": 60, "price_hour": "0.0292"},
				{"uuid": "windows.par01fr", "name": "Windows", "is_windows_included": true, "vcpus": 2, "memory": 2048, "disk": 60, "price_hour": "0.04"},
			}})
		case "GET /v1/cloud/systems":
			return ok(row{"systems": []row{
				{"uuid": "debian-13-too-large", "category": "linux", "distribution": "debian", "version": "13", "is_windows": "0", "min_disk_space": 80},
				{"uuid": "debian-13", "category": "linux", "distribution": "debian", "version": "13.1", "is_windows": "0", "min_disk_space": 10},
			}})
		case "GET /v1/script":
			scripts := []row{}
			if script != "" {
				scripts = append(scripts, row{"uuid": testVirtuaScript, "name": hostname, "content": script})
			}
			return ok(row{"scripts": scripts})
		case "POST /v1/script":
			scriptPosts++
			if fields.Get("name") != hostname || !strings.Contains(fields.Get("content"), "dns-guard-enroll.service") {
				t.Fatal("wrong bootstrap script")
			}
			script = fields.Get("content")
			return ok(row{})
		case "DELETE /v1/script":
			if fields.Get("uuid") != testVirtuaScript {
				t.Fatal("incorrect cleanup script UUID")
			}
			script = ""
			return ok(row{})
		case "GET /v1/cloud-server":
			servers := []row{}
			if exists {
				servers = append(servers, row{"uuid": testOrderVM, "name": "vs01.vsys.cloud", "label": hostname})
			}
			return ok(row{"cloud_servers": servers})
		case "POST /v1/cloud/order":
			serverPosts++
			if !claimed || fields.Get("offer") != plusOffer || fields.Get("hostname") != hostname ||
				fields.Get("system") != "debian-13" || fields.Get("script") != testVirtuaScript || fields.Get("billing_period") != "0" {
				t.Fatalf("incorrect order form: %v", fields)
			}
			exists = true
			return nil, errors.New("lost response")
		case "GET /v1/cloud-server/" + testOrderVM:
			return ok(row{"cloud_server": row{"uuid": testOrderVM, "status": "running", "is_setup": ready, "is_processing": !ready}})
		case "GET /v1/network/cloud-server/" + testOrderVM + "/show":
			return ok(row{"ip_addresses": []row{{"address": "10.0.0.1", "version": 4}, {"address": "8.8.4.4", "version": 4}}})
		default:
			t.Fatalf("unexpected API request %s %s", r.Method, r.URL)
			return nil, nil
		}
	})}
	c := &virtuaOrder{client: providerClient(client), token: "test-token", cache: &virtuaCatalogCache{}}
	countries, err := c.Countries(ctx)
	if err != nil || len(countries) != 1 || countries[0].Code != "FR" {
		t.Fatalf("incorrect countries %+v: %v", countries, err)
	}
	plans, err := c.Plans(ctx, "par01fr")
	if err != nil || len(plans) != 2 || catalogRequests != 1 || accountRequests != 1 {
		t.Fatalf("incorrect plans %+v after %d public and %d account catalog requests: %v", plans, catalogRequests, accountRequests, err)
	}
	plan := plans[1]
	if plan.Code != plusOffer || plan.Country != "FR" || plan.CPU != 2 || plan.MemoryMB != 2048 || plan.StorageGB != 60 {
		t.Fatalf("missing account-only vCS-2+ plan: %+v", plan)
	}
	quote := orderPlanChoice("par01fr", plan)
	if !strings.Contains(quote.Label, "0.0292 EUR/ч · ≈ 21.00 EUR/мес. без НДС") {
		t.Fatalf("incorrect customer quote: %s", quote.Label)
	}
	plan.MonthlyPrice = 0
	if orderPlanChoice("par01fr", plan).ID != quote.ID {
		t.Fatal("changing the monthly estimate must not invalidate a previously confirmed hourly quote")
	}
	req := orderCloudRequest{
		OperationID: testVirtuaOrderID, Zone: "par01fr", Country: "FR", Plan: plan.Code, Quote: quote.ID,
		SSHUser: "root", SSHKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		EnrollURL: "https://guard.example.com/api/server-orders/" + testVirtuaOrderID + "/enroll", EnrollToken: strings.Repeat("a", 43),
	}
	data, _, zone, err := c.PrepareOrder(ctx, req)
	if err != nil || zone != "par01fr" {
		t.Fatalf("failed to prepare order: %v", err)
	}
	snap, err := readVirtuaSnapshot(data, testVirtuaOrderID)
	if err != nil || !strings.Contains(snap.Script, req.SSHKey) {
		t.Fatalf("failed to prepare bootstrap: %v", err)
	}
	command := exec.CommandContext(ctx, "bash", "-n")
	command.Stdin = strings.NewReader(snap.Script)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap syntax: %v %s", err, out)
	}
	claim := func() (bool, error) {
		if claimed {
			return false, nil
		}
		claimed = true
		return true, nil
	}
	if _, _, err := c.ProvisionOrder(ctx, data, testVirtuaOrderID, "", claim); err == nil {
		t.Fatal("expected lost response")
	}
	exists = false
	if _, _, err := c.ProvisionOrder(ctx, data, testVirtuaOrderID, "", claim); !errors.Is(err, errReplacementCreateUnconfirmed) {
		t.Fatalf("unexpected error while the server is absent: %v", err)
	}
	exists = true
	id, ip, err := c.ProvisionOrder(ctx, data, testVirtuaOrderID, "", claim)
	if id != testOrderVM || ip != "" || !errors.Is(err, errReplacementPending) {
		t.Fatalf("failed to recover pending server %q %q: %v", id, ip, err)
	}
	ready = true
	id, ip, err = c.ProvisionOrder(ctx, data, testVirtuaOrderID, id, claim)
	if err != nil || id != testOrderVM || ip != "8.8.4.4" || serverPosts != 1 || scriptPosts != 1 {
		t.Fatalf("wrong server %q %q after %d server and %d script requests: %v", id, ip, serverPosts, scriptPosts, err)
	}
	if err = c.cleanupScript(ctx, snap); err != nil || script != "" {
		t.Fatalf("bootstrap script cleanup failed: %v", err)
	}
}

func TestVirtuaOrderImageVersion(t *testing.T) {
	for _, version := range []string{`13`, `13.1`, `"13"`, `"13.1.2"`} {
		t.Run(version, func(t *testing.T) {
			systems := []row{
				{"uuid": "debian-testing", "category": "linux", "distribution": "debian", "version": "testing", "is_windows": false, "min_disk_space": 10},
				{"uuid": "debian-12", "category": "linux", "distribution": "debian", "version": 12, "is_windows": false, "min_disk_space": 10},
				{"uuid": "debian-13", "category": "linux", "distribution": "debian", "version": json.RawMessage(version), "is_windows": false, "min_disk_space": 10},
			}
			c := &virtuaOrder{client: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return response(row{"success": true, "systems": systems}, 200), nil
			})}}
			id, err := c.image(t.Context(), 40)
			if err != nil || id != "debian-13" {
				t.Fatalf("image() = %q, %v", id, err)
			}
		})
	}
}

func TestVirtuaOrderResponseDiagnostics(t *testing.T) {
	for _, tc := range []struct{ reply, want string }{
		{`{"success":true,"systems":[{"version":{"private":"provider-secret"}}]}`, "поле systems.0.version: тип object, ожидается string или number"},
		{`{"systems":[],"private":"provider-secret"}`, "отсутствует обязательный признак success"},
		{`<html>provider-secret`, "некорректный JSON"},
	} {
		c := &virtuaOrder{token: "auth-secret", client: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.reply))}, nil
		})}}
		_, err := c.image(t.Context(), 40)
		if err == nil || !strings.Contains(err.Error(), "GET /v1/cloud/systems (HTTP 200)") ||
			!strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret") {
			t.Errorf("unexpected diagnostic: %v", err)
		}
	}
}

func TestVirtuaOrderRecognizesOnlyDocumentedRefusals(t *testing.T) {
	for _, tc := range []struct {
		status   int
		code     string
		rejected bool
	}{
		{200, "balance_too_low", true},
		{200, "system_not_available_in_zone", true},
		{502, "balance_too_low", false},
		{429, "", false},
		{200, "unknown_error", false},
	} {
		c := &virtuaOrder{client: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return response(row{"success": false, "error": tc.code, "messages": []row{{"content": "sensitive provider message"}}}, tc.status), nil
		})}}
		_, err := c.createServer(t.Context(), virtuaOrderSnapshot{}, testVirtuaScript)
		if err == nil || errors.Is(err, errReplacementCreateRejected) != tc.rejected || strings.Contains(err.Error(), "sensitive provider message") {
			t.Errorf("unexpected error from status %d code %s: %v", tc.status, tc.code, err)
		}
	}
}

func TestUpCloudOrderSelectionDigestIsBackwardCompatible(t *testing.T) {
	sel := orderSelection{Zone: "fi-hel1", Plan: "plan", PoolID: "pool", Group: "nodes", ProfileID: "profile"}
	legacy, _ := json.Marshal(sel)
	sel.Provider = upCloudOrderProvider
	if selectionDigest(sel) != digest(string(legacy)) {
		t.Fatal("existing UpCloud order would not recognize its request ID")
	}
	sel.Provider = virtuaOrderProvider
	if selectionDigest(sel) == digest(string(legacy)) {
		t.Fatal("the Virtua.Cloud provider is missing from request identity")
	}
}
