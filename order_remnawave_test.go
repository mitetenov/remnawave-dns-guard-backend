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
	orderPanelID        = "123e4567-e89b-42d3-a456-426614174000"
	orderPanelNode      = "123e4567-e89b-42d3-a456-426614174001"
	orderPanelProfileID = "123e4567-e89b-42d3-a456-426614174002"
	orderPanelInbound   = "123e4567-e89b-42d3-a456-426614174003"
	orderPanelOldNode   = "123e4567-e89b-42d3-a456-426614174004"
	orderPanelHost      = "123e4567-e89b-42d3-a456-426614174005"
	orderPanelEmpty     = "123e4567-e89b-42d3-a456-426614174006"
	orderPanelOther     = "123e4567-e89b-42d3-a456-426614174007"
	orderPanelPlugin    = "123e4567-e89b-42d3-a456-426614174008"
)

func orderPanelClient(t *testing.T, handler roundTripFunc) *Remnawave {
	t.Helper()
	client := providerClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "order-panel.example.com" || req.Header.Get("Authorization") != "Bearer panel-token" {
			t.Fatal("unexpected request authority or authorization")
		}
		return handler(req)
	})})
	panel, err := newRemnawave("https://order-panel.example.com/api/", "panel-token", client)
	if err != nil {
		t.Fatal(err)
	}
	return panel
}

func TestRemnawaveOrderKeyAndProfileScopes(t *testing.T) {
	secret := "opaque-encoded-key"
	status := http.StatusOK
	profile := orderPanelProfileID
	panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatal("unexpected mutation")
		}
		switch req.URL.Path {
		case "/api/keygen":
			return response(row{"response": row{"secretKey": secret}}, status), nil
		case "/api/config-profiles/" + orderPanelProfileID + "/inbounds":
			return response(row{"response": row{"inbounds": []row{{"uuid": orderPanelInbound, "profileUuid": profile}}}}, 200), nil
		default:
			t.Fatal("unexpected provider endpoint")
			return nil, nil
		}
	})
	ctx := context.Background()
	if got, err := panel.orderNodeSecret(ctx); got != secret || err != nil {
		t.Fatal("valid credential was not returned")
	}
	if err := panel.checkOrderProfile(ctx, orderPanelProfileID, []string{orderPanelInbound}); err != nil {
		t.Fatal(err)
	}
	if err := panel.checkOrderProfile(ctx, orderPanelProfileID, []string{orderPanelOther}); err == nil {
		t.Fatal("accepted missing inbound")
	}
	profile = orderPanelOther
	if err := panel.checkOrderProfile(ctx, orderPanelProfileID, []string{orderPanelInbound}); err == nil {
		t.Fatal("accepted inbound owned by another profile")
	}
	secret = "hidden-payload\nOTHER=value"
	if got, err := panel.orderNodeSecret(ctx); got != "" || err == nil || strings.Contains(err.Error(), "hidden-payload") {
		t.Fatal("unsafe malformed credential response")
	}
	status = http.StatusForbidden
	if got, err := panel.orderNodeSecret(ctx); got != "" || err == nil || strings.Contains(err.Error(), "hidden-payload") {
		t.Fatal("unsafe credential error")
	}
}

func TestRemnawaveOrderProfilesReturnOnlySelectableMetadata(t *testing.T) {
	panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/api/config-profiles" {
			t.Fatal("unexpected request for panel profile choices")
		}
		return response(row{"response": row{"configProfiles": []row{
			{
				"uuid": orderPanelProfileID, "name": "Standard", "config": row{"privateKey": "private-profile-configuration"},
				"inbounds": []row{{"uuid": orderPanelInbound, "profileUuid": orderPanelProfileID, "tag": "vless"}},
			},
			{"uuid": orderPanelOther, "name": "Unused", "inbounds": []row{}},
		}}}, 200), nil
	})
	profiles, err := panel.orderProfiles(context.Background())
	if err != nil || len(profiles) != 2 {
		t.Fatal("profile choices were not returned", err)
	}
	if profiles[0].ID != orderPanelProfileID || profiles[0].Name != "Standard" ||
		!slices.Equal(profiles[0].Inbounds, []orderPanelInboundChoice{{ID: orderPanelInbound, Tag: "vless"}}) ||
		profiles[1].Inbounds == nil || len(profiles[1].Inbounds) != 0 {
		t.Fatal("profile choices did not preserve names and available inbounds")
	}
	jsonChoices, err := json.Marshal(profiles)
	if err != nil || strings.Contains(string(jsonChoices), "private") {
		t.Fatal("profile choices include panel configuration")
	}
}

func TestRemnawaveOrderPluginChoices(t *testing.T) {
	reads := 0
	panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/api/node-plugins" {
			t.Fatal("unexpected request for panel plugin choices")
		}
		reads++
		return response(row{"response": row{"total": 1, "nodePlugins": []row{
			{"uuid": orderPanelPlugin, "name": "Node filters", "config": row{"configuration": "private"}},
		}}}, 200), nil
	})
	ctx := context.Background()
	if name, err := panel.orderPluginName(ctx, ""); name != "" || err != nil || reads != 0 {
		t.Fatal("an optional selection must not require the plugin API", name, err)
	}
	if choices, err := panel.orderPlugins(ctx); err != nil || !slices.Equal(choices, []orderChoice{{ID: orderPanelPlugin, Label: "Node filters"}}) {
		t.Fatal("unexpected plugin choices", choices, err)
	}
	if name, err := panel.orderPluginName(ctx, orderPanelPlugin); name != "Node filters" || err != nil {
		t.Fatal("the selected plugin was not found", name, err)
	}
	if _, err := panel.orderPluginName(ctx, orderPanelOther); err == nil {
		t.Fatal("accepted a missing plugin")
	}
}

func TestRemnawaveOrderNodeReadbackAfterLostCreateReply(t *testing.T) {
	const ip = "8.8.4.4"
	const name = "fin-new-01"
	created := []row{}
	creates := 0
	panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/api/nodes" {
			t.Fatal("unexpected provider endpoint")
		}
		switch req.Method {
		case http.MethodGet:
			return response(row{"response": created}, 200), nil
		case http.MethodPost:
			creates++
			var body struct {
				Name, Address, CountryCode, Note string
				ActivePluginUUID                 string
				Port                             int
				ConfigProfile                    struct {
					ActiveConfigProfileUUID string
					ActiveInbounds          []string
				}
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil ||
				body.Name != name || body.Address != ip || body.CountryCode != "FI" || body.Port != 2222 ||
				body.Note != "dns-guard-order:"+orderPanelID ||
				body.ActivePluginUUID != orderPanelPlugin ||
				body.ConfigProfile.ActiveConfigProfileUUID != orderPanelProfileID ||
				!slices.Equal(body.ConfigProfile.ActiveInbounds, []string{orderPanelInbound}) {
				t.Fatal("unexpected create request", body, err)
			}
			created = append(created, row{
				"uuid": orderPanelNode, "name": body.Name, "address": body.Address, "port": body.Port, "countryCode": body.CountryCode, "note": body.Note,
				"configProfile": row{"activeConfigProfileUuid": orderPanelProfileID, "activeInbounds": []row{{"uuid": orderPanelInbound}}}, "activePluginUuid": body.ActivePluginUUID,
			})
			return nil, errors.New("upstream sent a sensitive error after creating the node")
		default:
			t.Fatal("unexpected provider method")
			return nil, nil
		}
	})
	for range 2 {
		id, err := panel.ensureOrderNode(context.Background(), orderPanelID, name, ip, "fi", orderPanelProfileID, []string{orderPanelInbound}, orderPanelPlugin)
		if id != orderPanelNode || err != nil {
			t.Fatal(id, err)
		}
	}
	if creates != 1 {
		t.Fatalf("sent %d create requests", creates)
	}
}

func TestRemnawaveOrderNodeRefusesConflictingOrChangedNodes(t *testing.T) {
	const ip = "8.8.4.4"
	const name = "fin-new-01"
	for _, mode := range []string{"unrelated address", "unrelated name", "changed port", "changed profile", "changed inbounds", "duplicate order mark"} {
		t.Run(mode, func(t *testing.T) {
			n := row{
				"uuid": orderPanelNode, "name": name, "address": ip, "port": 2222, "countryCode": "FI", "note": "dns-guard-order:" + orderPanelID,
				"configProfile": row{"activeConfigProfileUuid": orderPanelProfileID, "activeInbounds": []row{{"uuid": orderPanelInbound}}},
			}
			nodes := []row{n}
			switch mode {
			case "unrelated address":
				n["name"], n["note"] = "other", "unrelated"
			case "unrelated name":
				n["address"], n["note"] = "8.8.8.8", "unrelated"
			case "changed port":
				n["port"] = 443
			case "changed profile":
				n["configProfile"].(row)["activeConfigProfileUuid"] = orderPanelOther
			case "changed inbounds":
				n["configProfile"].(row)["activeInbounds"] = []row{{"uuid": orderPanelOther}}
			case "duplicate order mark":
				nodes = append(nodes, n)
			}
			panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.Path != "/api/nodes" {
					t.Fatal("unsafe mutation for conflicting node")
				}
				return response(row{"response": nodes}, 200), nil
			})
			if id, err := panel.ensureOrderNode(context.Background(), orderPanelID, name, ip, "FI", orderPanelProfileID, []string{orderPanelInbound}, ""); id != "" || err == nil {
				t.Fatal("accepted conflicting node", id, err)
			}
		})
	}
}

func TestRemnawaveOrderHostAttachmentPreservesExplicitAndEmptyLists(t *testing.T) {
	hosts := []orderRemnawaveHost{
		{UUID: orderPanelHost, Address: "VPN.EXAMPLE.COM.", Nodes: []string{orderPanelOldNode}, Inbound: orderRemnawaveHostInbound{UUID: orderPanelInbound}},
		{UUID: orderPanelEmpty, Address: "vpn.example.com", Nodes: []string{}, Inbound: orderRemnawaveHostInbound{UUID: orderPanelInbound}},
		{UUID: orderPanelOther, Address: "child.vpn.example.com", Nodes: []string{orderPanelOldNode}, Inbound: orderRemnawaveHostInbound{UUID: orderPanelInbound}},
		{UUID: orderPanelProfileID, Address: "vpn.example.com", Nodes: []string{orderPanelOldNode}, Inbound: orderRemnawaveHostInbound{UUID: orderPanelOther}},
	}
	patches := 0
	panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method + " " + req.URL.Path {
		case "GET /api/hosts":
			return response(row{"response": hosts}, 200), nil
		case "GET /api/hosts/" + orderPanelHost:
			return response(row{"response": hosts[0]}, 200), nil
		case "GET /api/hosts/" + orderPanelEmpty:
			return response(row{"response": hosts[1]}, 200), nil
		case "PATCH /api/hosts":
			var body row
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body) != 2 || body["uuid"] != orderPanelHost {
				t.Fatal("only the matched nonempty assignment may be changed", body, err)
			}
			if got, ok := body["nodes"].([]any); !ok || !slices.Equal(got, []any{orderPanelOldNode, orderPanelNode}) {
				t.Fatal("existing assignments were not preserved", body)
			}
			hosts[0].Nodes = []string{orderPanelOldNode, orderPanelNode}
			patches++
			return nil, errors.New("lost response after persisting assignment")
		default:
			t.Fatal("unexpected request for host outside the exact pool")
			return nil, nil
		}
	})
	if err := panel.checkOrderHosts(context.Background(), "VPN.EXAMPLE.COM.", []string{orderPanelInbound}); err != nil {
		t.Fatal(err)
	}
	if err := panel.checkOrderHosts(context.Background(), "vpn.example.com", []string{orderPanelNode}); err == nil {
		t.Fatal("pool hosts with another inbound passed preflight")
	}
	for range 2 {
		if err := panel.attachOrderHosts(context.Background(), "vpn.example.com", orderPanelNode, orderPanelInbound); err != nil {
			t.Fatal(err)
		}
	}
	if patches != 1 || len(hosts[1].Nodes) != 0 || len(hosts[2].Nodes) != 1 || len(hosts[3].Nodes) != 1 {
		t.Fatal("attachment was not scoped and repeatable")
	}
}

func TestRemnawaveOrderHostAddressChangedBeforeMutation(t *testing.T) {
	panel := orderPanelClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method + " " + req.URL.Path {
		case "GET /api/hosts":
			return response(row{"response": []orderRemnawaveHost{{
				UUID: orderPanelHost, Address: "vpn.example.com", Nodes: []string{orderPanelOldNode}, Inbound: orderRemnawaveHostInbound{UUID: orderPanelInbound},
			}}}, 200), nil
		case "GET /api/hosts/" + orderPanelHost:
			return response(row{"response": orderRemnawaveHost{
				UUID: orderPanelHost, Address: "different.example.com", Nodes: []string{orderPanelOldNode}, Inbound: orderRemnawaveHostInbound{UUID: orderPanelInbound},
			}}, 200), nil
		default:
			t.Fatal("changed host was mutated")
			return nil, nil
		}
	})
	if err := panel.attachOrderHosts(context.Background(), "vpn.example.com", orderPanelNode, orderPanelInbound); err == nil {
		t.Fatal("address change did not prevent assignment")
	}
}
