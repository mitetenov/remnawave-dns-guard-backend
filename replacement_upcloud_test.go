package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const (
	testUpCloudOldServer = "00798b85-efdc-41ca-8021-f6ef457b8531"
	testUpCloudNewServer = "0053cd80-5945-4105-9081-11192806a8f7"
	testUpCloudDisk      = "012580a1-32a1-466e-a323-689ca16f2d43"
	testUpCloudOldIP     = "94.237.0.207"
	testUpCloudNewIP     = "94.237.0.208"
	testUpCloudOperation = "test-operation"
)

type fakeReplacementUpCloud struct {
	t           *testing.T
	old         upCloudServer
	next        upCloudServer
	addr        upCloudIP
	owner       string
	createError string
	hideLabel   bool
	loseCleanup bool
	oldFirewall []row
	newFirewall []row
	calls       []string
}

func newFakeReplacementUpCloud(t *testing.T) (*fakeReplacementUpCloud, replacementProvider) {
	t.Helper()
	const details = `{
		"boot_order":"disk", "core_number":"2", "memory_amount":"2048", "firewall":"off",
		"hostname":"node.example.com", "title":"Node", "metadata":"yes",
		"nic_model":"virtio", "plan":"2xCPU-2GB", "simple_backup":"no", "state":"started",
		"timezone":"UTC", "video_model":"cirrus", "zone":"fi-hel1",
		"labels":{"label":[{"key":"env","value":"prod"}]},
		"tags":[],
		"networking":{"interfaces":{"interface":[
			{"index":1,"type":"public","mac":"de:ff:ff:ff:66:89","ip_addresses":{"ip_address":[
				{"address":"94.237.0.207","dhcp_provided":"yes","family":"IPv4","floating":"no","release_policy":"release"}
			]}},
			{"index":2,"type":"utility","mac":"de:ff:ff:ff:66:90","ip_addresses":{"ip_address":[
				{"address":"10.2.0.2","dhcp_provided":"yes","family":"IPv4"}
			]}},
			{"index":3,"type":"public","mac":"de:ff:ff:ff:66:91","ip_addresses":{"ip_address":[
				{"address":"2a04:3544:1000:1510::1","dhcp_provided":"yes","family":"IPv6"}
			]}}
		]}},
		"storage_devices":{"storage_device":[{"address":"virtio:0","type":"disk","boot_disk":"1"}]}
	}`
	fake := &fakeReplacementUpCloud{t: t, owner: testUpCloudOldServer}
	if err := json.Unmarshal([]byte(details), &fake.old); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(details), &fake.next); err != nil {
		t.Fatal(err)
	}
	fake.old.ID = testUpCloudOldServer
	fake.next.ID = testUpCloudNewServer
	fake.next.Networking.Interfaces.Items[0].MAC = "de:ff:ff:ff:66:92"
	fake.next.Networking.Interfaces.Items[0].IPs.Items[0].Address = testUpCloudNewIP
	fake.next.Labels.Items = append(fake.next.Labels.Items, upCloudLabel{Key: upCloudReplacementLabel, Value: testUpCloudOperation})
	fake.old.Disks.Items[0].ID = testUpCloudDisk
	fake.next.Disks.Items[0].ID = testUpCloudDisk
	fake.addr = upCloudIP{
		Address: testUpCloudOldIP, Family: "IPv4", Access: "public", Zone: "fi-hel1", Server: testUpCloudOldServer,
		MAC: fake.old.Networking.Interfaces.Items[0].MAC, PTR: "94-237-0-207.fi-hel1.upcloud.host",
		Floating: "no", ReleasePolicy: "release", AccountID: "552",
	}
	client := &http.Client{Transport: roundTripFunc(fake.request)}
	return fake, newUpCloudReplacement(client, "test-token")
}

func (f *fakeReplacementUpCloud) request(req *http.Request) (*http.Response, error) {
	f.t.Helper()
	if req.URL.Scheme != "https" || req.URL.Host != "api.upcloud.com" || req.Header.Get("Authorization") != "Bearer test-token" {
		f.t.Fatalf("unexpected UpCloud request %v", req.URL)
	}
	call := req.Method + " " + strings.TrimPrefix(req.URL.Path, "/1.3")
	f.calls = append(f.calls, call)
	switch call {
	case "GET /server/" + testUpCloudOldServer:
		if f.old.State == "deleted" {
			return upCloudTestError(404, "SERVER_NOT_FOUND"), nil
		}
		return response(row{"server": f.old}, 200), nil
	case "GET /server/" + testUpCloudNewServer:
		return response(row{"server": f.next}, 200), nil
	case "GET /server/" + testUpCloudOldServer + "/firewall_rule":
		return response(row{"firewall_rules": row{"firewall_rule": f.oldFirewall}}, 200), nil
	case "GET /server/" + testUpCloudNewServer + "/firewall_rule":
		return response(row{"firewall_rules": row{"firewall_rule": f.newFirewall}}, 200), nil
	case "PUT /server/" + testUpCloudNewServer + "/firewall_rule":
		var body struct {
			Rules struct {
				Items []row `json:"firewall_rule"`
			} `json:"firewall_rules"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			f.t.Fatal(err)
		}
		f.newFirewall = body.Rules.Items
		return response(row{}, 204), nil
	case "GET /storage/" + testUpCloudDisk:
		servers := []string{}
		if f.owner != "" {
			servers = append(servers, f.owner)
		}
		return response(row{"storage": row{
			"uuid": testUpCloudDisk, "zone": "fi-hel1", "type": "normal", "access": "private", "state": "online",
			"servers": row{"server": servers},
		}}, 200), nil
	case "GET /plan":
		return response(row{"plans": row{"plan": []row{
			{"name": "2xCPU-2GB", "core_number": 2, "memory_amount": 2048, "current_offering": "yes"},
		}}}, 200), nil
	case "GET /ip_address/" + testUpCloudOldIP:
		if f.addr.Address == "" {
			return upCloudTestError(404, "IP_ADDRESS_NOT_FOUND"), nil
		}
		return response(row{"ip_address": f.addr}, 200), nil
	case "PATCH /ip_address/" + testUpCloudOldIP:
		var body struct {
			IP struct {
				ReleasePolicy string `json:"release_policy"`
			} `json:"ip_address"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.IP.ReleasePolicy != "keep" {
			f.t.Fatalf("expected release-policy hold, got %+v (%v)", body, err)
		}
		f.addr.ReleasePolicy = "keep"
		return response(row{"ip_addresses": []row{}}, 202), nil
	case "POST /server/" + testUpCloudOldServer + "/stop":
		var body struct {
			Stop struct {
				Type    string `json:"stop_type"`
				Timeout string `json:"timeout"`
			} `json:"stop_server"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Stop.Type != "soft" || body.Stop.Timeout != "" {
			f.t.Fatalf("expected graceful shutdown, got %+v (%v)", body, err)
		}
		f.old.State = "stopped"
		return response(row{}, 202), nil
	case "DELETE /server/" + testUpCloudOldServer:
		if f.old.State != "stopped" || f.addr.ReleasePolicy != "keep" || req.URL.RawQuery != "" {
			f.t.Fatalf("server deletion requested before shutdown/IP hold or with storage flags: %v", req.URL)
		}
		f.old.State = "deleted"
		f.owner = ""
		f.addr.Server, f.addr.MAC, f.addr.Floating = "", "", "yes"
		return response(row{}, 204), nil
	case "GET /server":
		if q := req.URL.Query().Get("label"); q != upCloudReplacementLabel+"="+testUpCloudOperation {
			f.t.Fatalf("unexpected operation filter %q", q)
		}
		matches := []upCloudServer{}
		if f.owner == testUpCloudNewServer && !f.hideLabel {
			matches = append(matches, f.next)
		}
		return response(row{"servers": row{"server": matches}}, 200), nil
	case "POST /server":
		if f.owner != "" || f.addr.Floating != "yes" || f.addr.ReleasePolicy != "keep" {
			f.t.Fatal("create attempted before original disk was detached and address reserved")
		}
		var body struct {
			Server struct {
				upCloudServer
				PasswordDelivery string `json:"password_delivery"`
				Disks            struct {
					Items []struct {
						upCloudDisk
						Action string `json:"action"`
					} `json:"storage_device"`
				} `json:"storage_devices"`
			} `json:"server"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			f.t.Fatal(err)
		}
		settings := body.Server
		if settings.upCloudConfig != f.old.upCloudConfig || settings.PasswordDelivery != "none" ||
			!settings.hasLabel(upCloudReplacementLabel, testUpCloudOperation) || !settings.hasLabel("env", "prod") ||
			len(settings.Disks.Items) != 1 || settings.Disks.Items[0].ID != testUpCloudDisk ||
			settings.Disks.Items[0].Action != "attach" || settings.Disks.Items[0].BootDisk != "1" ||
			len(settings.Networking.Interfaces.Items) != 3 {
			f.t.Fatalf("create request lost original settings or provenance: %+v", settings)
		}
		for i, nic := range settings.Networking.Interfaces.Items {
			if nic.Index != i+1 || nic.Type != f.old.Networking.Interfaces.Items[i].Type ||
				len(nic.IPs.Items) != 1 || nic.IPs.Items[0].Address != "" || nic.IPs.Items[0].Family != f.old.Networking.Interfaces.Items[i].IPs.Items[0].Family {
				f.t.Fatalf("unexpected create NIC %+v", nic)
			}
		}
		if f.createError == "rejected" {
			return upCloudTestError(402, "INSUFFICIENT_CREDITS"), nil
		}
		if f.createError != "lost-before" {
			f.owner = testUpCloudNewServer
		}
		if f.createError != "" {
			return nil, errors.New("test connection lost")
		}
		return response(row{"server": f.next}, 202), nil
	case "DELETE /ip_address/" + testUpCloudOldIP:
		if f.owner != testUpCloudNewServer || f.addr.Server != "" || f.addr.Floating != "yes" {
			f.t.Fatal("cleanup requested before provision, or for an attached address")
		}
		f.addr = upCloudIP{}
		if f.loseCleanup {
			return nil, errors.New("test cleanup connection lost")
		}
		return response(row{}, 204), nil
	default:
		f.t.Fatalf("unexpected API call %q", call)
		return nil, nil
	}
}

func upCloudTestError(status int, code string) *http.Response {
	return response(row{"error": row{"error_code": code}}, status)
}

func retireFakeUpCloud(t *testing.T, provider replacementProvider) json.RawMessage {
	t.Helper()
	ctx := context.Background()
	snap, err := provider.Snapshot(ctx, testUpCloudOldServer, testUpCloudOldIP, testUpCloudOperation)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Retire(ctx, testUpCloudOldServer, testUpCloudOldIP, snap); !errors.Is(err, errReplacementPending) || !strings.Contains(err.Error(), "shut down gracefully") {
		t.Fatalf("expected a graceful stop before deletion, got %v", err)
	}
	for range 2 {
		if err := provider.Retire(ctx, testUpCloudOldServer, testUpCloudOldIP, snap); err != nil {
			t.Fatal(err)
		}
	}
	return snap
}

func TestUpCloudReplacementRecoversLostCreateAndCleanupResponses(t *testing.T) {
	fake, provider := newFakeReplacementUpCloud(t)
	fake.createError = "lost-after"
	fake.loseCleanup = true
	snap := retireFakeUpCloud(t, provider)
	ctx := context.Background()
	var claimed bool
	claimCreate := func() (bool, error) {
		if claimed {
			return false, nil
		}
		claimed = true
		return true, nil
	}
	if _, _, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, claimCreate); err == nil || errors.Is(err, errReplacementCreateRejected) || errors.Is(err, errReplacementCreateUnconfirmed) {
		t.Fatalf("lost response must leave the create claim held, got %v", err)
	}
	// Use a fresh adapter to recover using only the persisted snapshot and UpCloud.
	provider = newUpCloudReplacement(&http.Client{Transport: roundTripFunc(fake.request)}, "test-token")
	fake.hideLabel = true
	if _, _, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, claimCreate); err == nil || !strings.Contains(err.Error(), upCloudReplacementLabel+"="+testUpCloudOperation) {
		t.Fatalf("expected recovery lookup hint before the label appears, got %v", err)
	}
	fake.hideLabel = false
	id, ip, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, claimCreate)
	if err != nil || id != testUpCloudNewServer || ip != testUpCloudNewIP {
		t.Fatalf("recovering replacement yielded (%s, %s, %v)", id, ip, err)
	}
	if fake.addr.Address != testUpCloudOldIP || fake.addr.ReleasePolicy != "keep" {
		t.Fatal("old IPv4 was released before explicit cleanup")
	}
	if err := provider.ReleaseOldIP(ctx, snap, id, ip, testUpCloudOldIP); err == nil {
		t.Fatal("expected the simulated lost cleanup response")
	}
	if err := provider.ReleaseOldIP(ctx, snap, id, ip, testUpCloudOldIP); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	var mutations []string
	for _, call := range fake.calls {
		if !strings.HasPrefix(call, "GET ") {
			mutations = append(mutations, call)
		}
	}
	want := []string{
		"PATCH /ip_address/" + testUpCloudOldIP, "POST /server/" + testUpCloudOldServer + "/stop",
		"DELETE /server/" + testUpCloudOldServer, "POST /server", "DELETE /ip_address/" + testUpCloudOldIP,
	}
	if !slices.Equal(mutations, want) {
		t.Fatalf("mutations %v do not match %v", mutations, want)
	}
}

func TestUpCloudReplacementHoldsAmbiguousCreateClaim(t *testing.T) {
	fake, provider := newFakeReplacementUpCloud(t)
	fake.createError = "lost-before"
	snap := retireFakeUpCloud(t, provider)
	ctx := context.Background()
	var claimed bool
	for attempt := range 3 {
		_, _, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, func() (bool, error) {
			defer func() { claimed = true }()
			return !claimed, nil
		})
		if err == nil || errors.Is(err, errReplacementCreateRejected) || !strings.Contains(err.Error(), upCloudReplacementLabel+"="+testUpCloudOperation) {
			t.Fatalf("expected an actionable ambiguous create error, got %v", err)
		}
		if errors.Is(err, errReplacementCreateUnconfirmed) != (attempt > 0) {
			t.Fatalf("operator retry availability on attempt %d: %v", attempt, err)
		}
	}
	count := 0
	for _, call := range fake.calls {
		if call == "POST /server" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("submitted %d create requests", count)
	}
}

func TestUpCloudReplacementPreservesExplicitFirewallDefaults(t *testing.T) {
	fake, provider := newFakeReplacementUpCloud(t)
	fake.old.Firewall, fake.next.Firewall = "on", "on"
	fake.oldFirewall = []row{
		{"direction": "in", "action": "accept", "position": "1", "comment": "", "protocol": "", "family": ""},
		{"direction": "out", "action": "accept", "position": "2", "comment": "", "protocol": "", "family": ""},
	}
	fake.newFirewall = []row{{"direction": "in", "action": "drop", "position": "1"}}
	snap := retireFakeUpCloud(t, provider)
	id, ip, err := provider.Provision(context.Background(), snap, testUpCloudOperation, testUpCloudOldIP, func() (bool, error) {
		return true, nil
	})
	if err != nil || id != testUpCloudNewServer || ip != testUpCloudNewIP {
		t.Fatalf("provision with accept defaults yielded (%s, %s, %v)", id, ip, err)
	}
	if !slices.Contains(fake.calls, "PUT /server/"+testUpCloudNewServer+"/firewall_rule") {
		t.Fatal("replacement firewall defaults were not restored")
	}
}

func TestUpCloudReplacementRefusesCustomFirewallAndAncillaryAddress(t *testing.T) {
	for _, scenario := range []string{"custom-firewall", "retained-IPv6", "explicit-utility"} {
		t.Run(scenario, func(t *testing.T) {
			fake, provider := newFakeReplacementUpCloud(t)
			switch scenario {
			case "custom-firewall":
				fake.oldFirewall = []row{{"direction": "in", "action": "accept", "position": "1", "destination_port_start": "22"}}
			case "retained-IPv6":
				fake.old.Networking.Interfaces.Items[2].IPs.Items[0].ReleasePolicy = "keep"
			case "explicit-utility":
				fake.old.Networking.Interfaces.Items[1].IPs.Items[0].DHCPProvided = "no"
			}
			if _, err := provider.Snapshot(context.Background(), testUpCloudOldServer, testUpCloudOldIP, testUpCloudOperation); err == nil {
				t.Fatal("snapshot accepted an unsupported layout")
			}
			for _, call := range fake.calls {
				if !strings.HasPrefix(call, "GET ") {
					t.Fatalf("unsupported source mutated with %s", call)
				}
			}
		})
	}
}

func TestUpCloudReplacementCanRetryDefiniteCreateRejection(t *testing.T) {
	fake, provider := newFakeReplacementUpCloud(t)
	fake.createError = "rejected"
	snap := retireFakeUpCloud(t, provider)
	ctx := context.Background()
	claim := func() (bool, error) { return true, nil }
	if _, _, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, claim); !errors.Is(err, errReplacementCreateRejected) {
		t.Fatalf("create rejection not classified: %v", err)
	}
	fake.createError = ""
	if _, _, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, claim); err != nil {
		t.Fatal(err)
	}
}

func TestUpCloudReplacementRefusesUnsafeSourceChanges(t *testing.T) {
	fake, provider := newFakeReplacementUpCloud(t)
	ctx := context.Background()
	if _, err := provider.Snapshot(ctx, testUpCloudOldServer, testUpCloudNewIP, testUpCloudOperation); err == nil {
		t.Fatal("snapshot accepted a server with a different IPv4")
	}
	snap, err := provider.Snapshot(ctx, testUpCloudOldServer, testUpCloudOldIP, testUpCloudOperation)
	if err != nil {
		t.Fatal(err)
	}
	fake.old.Networking.Interfaces.Items[1].Type = "private"
	if err := provider.Retire(ctx, testUpCloudOldServer, testUpCloudOldIP, snap); err == nil {
		t.Fatal("retire accepted a server with a changed network layout")
	}
	for _, call := range fake.calls {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatalf("unsafe source mutated with %s", call)
		}
	}
}

func TestUpCloudReplacementRefusesMismatchedRecovery(t *testing.T) {
	fake, provider := newFakeReplacementUpCloud(t)
	snap := retireFakeUpCloud(t, provider)
	ctx := context.Background()
	fake.owner = testUpCloudNewServer
	fake.next.Networking.Interfaces.Items[0].IPs.Items[0].Address = testUpCloudOldIP
	_, _, err := provider.Provision(ctx, snap, testUpCloudOperation, testUpCloudOldIP, func() (bool, error) {
		t.Fatal("unexpected new create claim")
		return false, nil
	})
	if err == nil || !strings.Contains(err.Error(), "assigned the original IPv4") {
		t.Fatalf("expected original IPv4 to be rejected, got %v", err)
	}
	fake.next.Networking.Interfaces.Items[0].IPs.Items[0].Address = testUpCloudNewIP
	fake.next.Disks.Items[0].ID = "019d64ef-31d1-4684-a26b-c86c955cbf46"
	if err := provider.ReleaseOldIP(ctx, snap, testUpCloudNewServer, testUpCloudNewIP, testUpCloudOldIP); err == nil {
		t.Fatal("released original address for a VM with different disks")
	}
	if fake.addr.Address != testUpCloudOldIP {
		t.Fatal("cleanup removed the original IPv4")
	}
}
