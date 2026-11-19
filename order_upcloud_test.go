package guard

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const (
	testOrderTemplate = upCloudOrderDebian13
	testOrderDisk     = "019d64ef-31d1-4684-a26b-c86c955cbf46"
	testOrderVM       = "0053cd80-5945-4105-9081-11192806a8f7"
	testOrderIP       = "94.237.0.208"
	testOrderID       = "order-1"
	testOrderToken    = "fake-enrollment-token_0123456789ABCDEF"
	testOrderURL      = "https://guard.example.com/api/orders/order-1/enroll"
)

type testOrderUpCloud struct {
	t              *testing.T
	serverExists   bool
	providerStatus string
	loseCreate     bool
	badDisk        bool
	wrongIPOwner   bool
	closedPlan     bool
	nativeImage    bool
	templateSize   int
	planPrice      float64
	createAttempts int
	calls          []string
}

func fakeOrderUpCloud(t *testing.T) (*testOrderUpCloud, orderCloudProvider) {
	t.Helper()
	f := &testOrderUpCloud{t: t, providerStatus: "started", templateSize: 10, planPrice: 3.5}
	return f, newUpCloudOrder(&http.Client{Transport: roundTripFunc(f.request)}, "test-token")
}

func exampleUpCloudOrder() orderCloudRequest {
	// Encode a deterministic OpenSSH public key without generating a
	// working private key or requiring OpenSSH in the test harness.
	var key [51]byte
	binary.BigEndian.PutUint32(key[0:4], 11)
	copy(key[4:15], "ssh-ed25519")
	binary.BigEndian.PutUint32(key[15:19], 32)
	return orderCloudRequest{
		OperationID: testOrderID, Country: "DE", Zone: "de-fra1", Hostname: "de-vless-01", Title: "Germany VLESS 01",
		Plan: "PREMIUM-2xCPU-4GB", SSHUser: "deploy",
		SSHKey:    "ssh-ed25519 " + base64.StdEncoding.EncodeToString(key[:]) + " local-comment",
		EnrollURL: testOrderURL, EnrollToken: testOrderToken,
	}
}

func (f *testOrderUpCloud) request(req *http.Request) (*http.Response, error) {
	f.t.Helper()
	if req.URL.Scheme != "https" || req.URL.Host != "api.upcloud.com" || req.Header.Get("Authorization") != "Bearer test-token" {
		f.t.Fatalf("unexpected UpCloud request %v", req.URL)
	}
	path := req.Method + " " + strings.TrimPrefix(req.URL.Path, "/1.3")
	f.calls = append(f.calls, path)
	switch path {
	case "GET /zone":
		return response(row{"zones": row{"zone": []row{
			{"id": "de-fra2", "description": "Frankfurt #2", "public": "yes"},
			{"id": "de-private", "description": "Managed server room", "public": "no"},
			{"id": "uk-lon1", "description": "London #1", "public": "yes"},
			{"id": "de-fra1", "description": "Germany, Frankfurt", "public": "yes"},
			{"id": "de-fra1", "description": "Frankfurt #1", "public": "yes"},
			{"id": "fr-par1", "description": "France, Paris", "public": "yes"},
		}}}, 200), nil
	case "GET /plan":
		available := "yes"
		if f.closedPlan {
			available = "no"
		}
		return response(row{"plans": row{"plan": []row{
			{"name": "PREMIUM-2xCPU-4GB", "family": "premium", "core_number": 2, "memory_amount": 4096, "current_offering": available, "storage_size": 50, "storage_tier": "maxiops"},
			{"name": "16xCPU-32GB", "core_number": 16, "memory_amount": 32768, "current_offering": "yes", "storage_size": 200, "storage_tier": "maxiops"},
		}}}, 200), nil
	case "GET /price":
		if req.URL.Query().Get("zone") != "de-fra1" {
			f.t.Fatalf("expected the selected price-list zone, got %s", req.URL)
		}
		return response(row{"prices": row{"zone": []row{
			{"name": "de-fra2", "server_plan_PREMIUM-2xCPU-4GB": row{"amount": 1, "price": 50}, "server_plan_16xCPU-32GB": row{"amount": 1, "price": 60}},
			{"name": "de-fra1", "server_plan_PREMIUM-2xCPU-4GB": row{"amount": 1, "price": f.planPrice}},
		}}}, 200), nil
	case "GET /account":
		return response(row{"account": row{"currency": "EUR"}}, 200), nil
	case "GET /storage/template":
		kind := "cloud-init"
		if f.nativeImage {
			kind = "native"
		}
		return response(row{"storages": row{"storage": []row{
			{"uuid": testOrderTemplate, "title": "Debian GNU/Linux 13 (Trixie)", "access": "public", "type": "template",
				"state": "online", "template_type": kind, "license": 0, "size": f.templateSize},
		}}}, 200), nil
	case "GET /server":
		if got := req.URL.Query().Get("label"); got != upCloudOrderLabel+"="+testOrderID {
			f.t.Fatalf("unexpected order label filter %q", got)
		}
		servers := []row{}
		if f.serverExists {
			servers = append(servers, row{"uuid": testOrderVM, "labels": row{"label": []upCloudLabel{{upCloudOrderLabel, testOrderID}}}})
		}
		return response(row{"servers": row{"server": servers}}, 200), nil
	case "POST /server":
		f.createAttempts++
		var body struct {
			Server struct {
				upCloudConfig
				Labels struct {
					Items []upCloudLabel `json:"label"`
				} `json:"labels"`
				Disks struct {
					Items []row `json:"storage_device"`
				} `json:"storage_devices"`
				Login    row    `json:"login_user"`
				UserData string `json:"user_data"`
			} `json:"server"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			f.t.Fatal(err)
		}
		proposal := body.Server
		if proposal.Zone != "de-fra1" || proposal.Plan != "PREMIUM-2xCPU-4GB" || proposal.Metadata != "yes" ||
			proposal.SimpleBackup != "no" ||
			proposal.Hostname != "de-vless-01" || proposal.Title != "Germany VLESS 01" ||
			!slices.Contains(proposal.Labels.Items, upCloudLabel{upCloudOrderLabel, testOrderID}) ||
			proposal.Login["username"] != "deploy" || proposal.Login["create_password"] != "no" ||
			!strings.Contains(proposal.UserData, testOrderToken) {
			f.t.Fatal("new server request did not contain the selected country, plan, or enrollment setup")
		}
		if len(proposal.Disks.Items) != 1 {
			f.t.Fatal("new VM should have one boot disk")
		}
		disk := proposal.Disks.Items[0]
		if disk["action"] != "clone" || disk["storage"] != testOrderTemplate || disk["size"] != float64(50) ||
			disk["tier"] != "maxiops" || disk["encrypted"] != "yes" {
			f.t.Fatal("new VM disk did not use the plan's exact included size and selected template")
		}
		f.serverExists = true
		if f.loseCreate {
			return nil, errors.New("simulated response loss with sensitive text")
		}
		return response(row{"server": row{"uuid": testOrderVM}}, 202), nil
	case "GET /server/" + testOrderVM:
		spec := exampleUpCloudOrder()
		return response(row{"server": row{
			"uuid": testOrderVM, "hostname": spec.Hostname, "title": spec.Title, "state": f.providerStatus,
			"zone": "de-fra1", "plan": spec.Plan, "metadata": "yes", "remote_access_enabled": "no",
			"core_number": "2", "memory_amount": "4096",
			"labels":          row{"label": []upCloudLabel{{upCloudOrderLabel, testOrderID}}},
			"storage_devices": row{"storage_device": []row{{"storage": testOrderDisk, "type": "disk"}}},
			"networking": row{"interfaces": row{"interface": []row{
				{"type": "public", "index": 1, "mac": "de:ff:aa:bb:cc:11", "ip_addresses": row{"ip_address": []row{
					{"address": testOrderIP, "family": "IPv4", "dhcp_provided": "yes", "floating": "no"},
				}}},
				{"type": "utility", "index": 2, "mac": "de:ff:aa:bb:cc:22", "ip_addresses": row{"ip_address": []row{
					{"address": "10.1.0.12", "family": "IPv4", "dhcp_provided": "yes"},
				}}},
			}}},
		}}, 200), nil
	case "GET /storage/" + testOrderDisk:
		operation := testOrderID
		if f.badDisk {
			operation = "different-order"
		}
		return response(row{"storage": row{
			"uuid": testOrderDisk, "access": "private", "type": "normal", "zone": "de-fra1", "size": 50,
			"tier": "maxiops", "encrypted": "yes", "state": "online", "servers": row{"server": []string{testOrderVM}},
			"labels": []upCloudLabel{{upCloudOrderLabel, operation}, {upCloudOrderImageLabel, testOrderTemplate}},
		}}, 200), nil
	case "GET /ip_address/" + testOrderIP:
		owner := testOrderVM
		if f.wrongIPOwner {
			owner = "0016dadf-eba4-4331-bd34-b4ad841f23e2"
		}
		return response(row{"ip_address": row{
			"address": testOrderIP, "server": owner, "zone": "de-fra1", "access": "public",
			"family": "IPv4", "mac": "de:ff:aa:bb:cc:11", "floating": "no",
		}}, 200), nil
	default:
		f.t.Fatalf("unexpected UpCloud request %s", path)
		return nil, nil
	}
}

func TestUpCloudOrderPreparationUsesLivePublicCountriesAndPlan(t *testing.T) {
	f, upcloud := fakeOrderUpCloud(t)
	ctx := context.Background()
	countries, err := upcloud.Countries(ctx)
	if err != nil || len(countries) != 3 || countries[0].Code != "DE" || countries[0].Name != "Germany" ||
		!slices.Equal(countries[0].Zones, []string{"de-fra1", "de-fra2"}) || countries[1].Name != "France" ||
		countries[2].Code != "UK" {
		t.Fatalf("unexpected public country choices %+v (%v)", countries, err)
	}
	plans, err := upcloud.Plans(ctx, "de-fra1")
	wantPlan := orderCloudPlan{Code: "PREMIUM-2xCPU-4GB", Family: "premium", CPU: 2, MemoryMB: 4096, StorageGB: 50, StorageTier: "maxiops", Price: 0.035, Currency: "EUR"}
	if err != nil || !slices.Equal(plans, []orderCloudPlan{wantPlan}) {
		t.Fatalf("unexpected tariff catalog %+v (%v)", plans, err)
	}
	selected := exampleUpCloudOrder()
	selected.Quote = orderPlanChoice(selected.Zone, wantPlan).ID
	snapshot, hostKey, zone, err := upcloud.PrepareOrder(ctx, selected)
	if err != nil || zone != "de-fra1" || hostKey != "" {
		t.Fatalf("expected a fixed public zone and no host key before cloud-init, got %q %q (%v)", zone, hostKey, err)
	}
	var prepared upCloudOrderSnapshot
	if err := json.Unmarshal(snapshot, &prepared); err != nil {
		t.Fatal(err)
	}
	snapshotPlan := wantPlan
	snapshotPlan.Family = ""
	if prepared.Plan != snapshotPlan || prepared.TemplateID != testOrderTemplate || prepared.SSHKey != strings.TrimSuffix(exampleUpCloudOrder().SSHKey, " local-comment") {
		t.Fatal("prepared order did not preserve exactly the plan's included size and the login key")
	}
	var config struct {
		Generate []string `json:"ssh_genkeytypes"`
		Files    []struct {
			Path        string `json:"path"`
			Permissions string `json:"permissions"`
			Content     string `json:"content"`
		} `json:"write_files"`
	}
	userData, ok := strings.CutPrefix(prepared.UserData, "#cloud-config\n")
	if !ok || json.Unmarshal([]byte(userData), &config) != nil || !slices.Equal(config.Generate, []string{"ed25519"}) ||
		len(config.Files) != 4 || !strings.Contains(config.Files[0].Content, "ssh_deletekeys: false") ||
		config.Files[1].Permissions != "0600" || strings.Contains(userData, "PRIVATE KEY") {
		t.Fatal("invalid cloud-init enrollment or host-key persistence settings")
	}
	var credentials row
	if err := json.Unmarshal([]byte(config.Files[1].Content), &credentials); err != nil ||
		credentials["url"] != testOrderURL || credentials["token"] != testOrderToken {
		t.Fatal("enrollment configuration must separate the HTTPS URL from its one-time token")
	}
	f.planPrice = 4
	if _, _, _, err := upcloud.PrepareOrder(ctx, selected); !errors.Is(err, errOrderQuoteChanged) {
		t.Fatalf("did not reject a changed approved price: %v", err)
	}
	f.planPrice, f.closedPlan = 3.5, true
	if _, _, _, err := upcloud.PrepareOrder(ctx, exampleUpCloudOrder()); err == nil {
		t.Fatal("ordered a plan that is no longer offered")
	}
	f.closedPlan, f.nativeImage = false, true
	if _, _, _, err := upcloud.PrepareOrder(ctx, exampleUpCloudOrder()); err == nil {
		t.Fatal("ordered a template without cloud-init")
	}
	f.nativeImage, f.templateSize = false, 60
	if options, err := upcloud.Plans(ctx, "de-fra1"); err != nil || len(options) != 0 {
		t.Fatalf("offered a tariff smaller than the live image size: %+v (%v)", options, err)
	}
	f.templateSize = 10
	req := exampleUpCloudOrder()
	req.Zone = "uk-lon1"
	if _, _, _, err := upcloud.PrepareOrder(ctx, req); err == nil {
		t.Fatal("ordered a VM in a zone outside the selected country")
	}
	req.Zone, req.Plan = "de-fra1", "16xCPU-32GB"
	if _, _, _, err := upcloud.PrepareOrder(ctx, req); err == nil {
		t.Fatal("ordered a VM using a tariff missing from the zone's price list")
	}
	req.Plan, req.TemplateID = wantPlan.Code, "01000000-0000-4000-8000-000030240400"
	if _, _, _, err := upcloud.PrepareOrder(ctx, req); err == nil {
		t.Fatal("ordered a VM with an image other than Debian 13")
	}
	for _, path := range f.calls {
		if !strings.HasPrefix(path, "GET ") {
			t.Fatalf("prepare issued unexpected mutation %q", path)
		}
	}
}

func TestUpCloudOrderRecoversCreateAndVerifiesDiskAndIPv4(t *testing.T) {
	f, upcloud := fakeOrderUpCloud(t)
	ctx := context.Background()
	snapshot, _, _, err := upcloud.PrepareOrder(ctx, exampleUpCloudOrder())
	if err != nil {
		t.Fatal(err)
	}
	var claimed bool
	claim := func() (bool, error) {
		if claimed {
			return false, nil
		}
		claimed = true
		return true, nil
	}
	f.loseCreate = true
	if _, _, err := upcloud.ProvisionOrder(ctx, snapshot, testOrderID, claim); err == nil ||
		errors.Is(err, errReplacementCreateUnconfirmed) || strings.Contains(err.Error(), "sensitive text") {
		t.Fatalf("unexpected error after uncertain create: %v", err)
	}
	// Recover from only the durable claim and snapshot. A missing label with
	// an outstanding claim must never issue a new POST automatically.
	upcloud = newUpCloudOrder(&http.Client{Transport: roundTripFunc(f.request)}, "test-token")
	f.serverExists = false
	if _, _, err := upcloud.ProvisionOrder(ctx, snapshot, testOrderID, claim); !errors.Is(err, errReplacementCreateUnconfirmed) {
		t.Fatalf("expected an explicitly unconfirmed create, got %v", err)
	}
	f.serverExists, f.providerStatus = true, "maintenance"
	if _, _, err := upcloud.ProvisionOrder(ctx, snapshot, testOrderID, claim); !errors.Is(err, errReplacementPending) {
		t.Fatalf("expected maintenance state to retry, got %v", err)
	}
	f.providerStatus, f.badDisk = "started", true
	if _, _, err := upcloud.ProvisionOrder(ctx, snapshot, testOrderID, claim); err == nil {
		t.Fatal("adopted a server with a disk from a different order")
	}
	f.badDisk, f.wrongIPOwner = false, true
	if _, _, err := upcloud.ProvisionOrder(ctx, snapshot, testOrderID, claim); err == nil {
		t.Fatal("adopted a server with a public IP owned by another VM")
	}
	f.wrongIPOwner = false
	id, ip, err := upcloud.ProvisionOrder(ctx, snapshot, testOrderID, claim)
	if err != nil || id != testOrderVM || ip != testOrderIP || f.createAttempts != 1 {
		t.Fatalf("recovered (%s, %s, %v), submitted %d create requests", id, ip, err, f.createAttempts)
	}
}
