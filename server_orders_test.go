package guard

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestOrderVerificationRetriesOnceAfterConfirmedTimeout(t *testing.T) {
	app, err := New(testConfig(filepath.Join(t.TempDir(), "orders.db")), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	s, m := app.s, app.orders
	s.exec("INSERT INTO pools(id,hostname,zone_id,interval_seconds,failure_threshold,recovery_threshold) VALUES('pool','vpn.example.com','zone',30,2,2)")
	s.exec(`INSERT INTO server_orders(id,request_id,selection_hash,pool_id,pool_hostname,zone_id,ttl,zone,country,plan,quote,group_name,
 profile_id,profile_name,inbounds,serial,alias,domain,created_at,updated_at,stage,server_uuid,node_uuid,ip,create_attempted)
 VALUES(?,?,'hash','pool','vpn.example.com','zone',120,'de-fra1','DE','plan','quote','nodes','profile','name','[]',1,'de-01',?,'time','time','target',?,?,?,1)`,
		orderOriginID, orderOriginID, orderOriginDNS, orderPanelID, orderPanelNode, orderOriginOld)
	s.exec(`INSERT INTO server_order_auto_hosts(country,slot,pool_id,hostname,zone_id,source_uuid,host_uuid,profile_id,inbound_id,port,order_id)
 VALUES('DE',1,'pool','auto.example.com','zone','source',?,'profile','inbound',443,?)`, orderPanelID, orderOriginID)
	order := func() row { return s.one("SELECT * FROM server_orders WHERE id=?", orderOriginID) }
	started := nowSeconds()
	if err := m.enrollTarget(order()); err != nil || num(order()["verify_deadline"]) < started+orderVerifyTimeout.Seconds() {
		t.Fatalf("expected a full verification window after enrollment: %v, %v", err, order())
	}
	targetID := order()["target_id"]
	s.exec("INSERT INTO agents(id,last_seen,healthy) VALUES('checker',?,1)", nowSeconds())
	s.exec("INSERT INTO target_checks(target_id,agent_id,failures,last_checked_at,outcome) VALUES(?,'checker',2,?,0)", targetID, iso(fromSeconds(nowSeconds())))
	wait := func(j row) {
		t.Helper()
		if err := m.finish(j); !errors.Is(err, errReplacementPending) || order()["stage"] != "verify" {
			t.Fatalf("expected to keep verifying: %v, %v", err, order())
		}
	}
	wait(order())
	s.exec("UPDATE server_orders SET verify_deadline=? WHERE id=?", nowSeconds()-1, orderOriginID)
	s.exec("UPDATE agents SET last_seen=0")
	wait(order())
	s.exec("UPDATE agents SET last_seen=?", nowSeconds())
	s.exec("INSERT INTO agents(id,last_seen,healthy) VALUES('unchecked',?,1)", nowSeconds())
	wait(order())
	s.exec("DELETE FROM agents WHERE id='unchecked'")
	loaded := order()
	app.recordProbe(s.one("SELECT * FROM targets WHERE id=?", targetID), s.one("SELECT * FROM pools WHERE id='pool'"),
		s.one("SELECT * FROM agents WHERE id='checker'"), Result{OK: true}, nowSeconds())
	s.exec("UPDATE target_checks SET failures=2,successes=0,outcome=0")
	wait(loaded)
	if order()["verify_deadline"] != nil {
		t.Fatal("one successful probe must disarm the deadline")
	}

	// Simulate the case with no success and acknowledge each cleanup step.
	s.exec("UPDATE server_orders SET verify_deadline=? WHERE id=?", nowSeconds()-1, orderOriginID)
	if err := m.finish(order()); err != nil || order()["stage"] != "deleting" || num(order()["delete_pending"]) != orderDeleteAll {
		t.Fatalf("expected a confirmed timeout to queue cleanup: %v, %v", err, order())
	}
	m.finishOrderDeletionStep(order(), orderDeleteDNS)
	m.finishOrderDeletionStep(order(), orderDeleteRemnawave)
	if order()["stage"] != "deleting" || orderOperationID(order()) != orderOriginID || m.autoHost(orderOriginID) == nil {
		t.Fatal("must wait for hosting deletion and keep the auto-host slot", order())
	}
	m.finishOrderDeletionStep(order(), orderDeleteHosting)
	retry := order()
	if retry["stage"] != "preflight" || orderOperationID(retry) == orderOriginID || retry["ip"] != nil || retry["target_id"] != nil ||
		truth(retry["create_attempted"]) || retry["domain"] != orderOriginDNS || retry["quote"] != "quote" || m.autoHost(orderOriginID) == nil {
		t.Fatal("expected the original order to restart with a new cloud identity", retry)
	}
	token := enrollmentToken()
	s.exec("UPDATE server_orders SET stage='enrollment',create_attempted=1,enroll_digest=? WHERE id=?", digest(token), orderOriginID)
	wire := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	body := `{"host_key":"ssh-ed25519 ` + base64.StdEncoding.EncodeToString(wire) + `"}`
	for id, want := range map[string]int{orderOriginID: http.StatusUnauthorized, orderOperationID(retry): http.StatusOK} {
		req := httptest.NewRequest(http.MethodPost, "/api/server-orders/"+id+"/enroll", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("enrollment for %s returned %d, want %d: %s", id, rec.Code, want, rec.Body.String())
		}
	}
	s.exec("UPDATE server_orders SET stage='target',server_uuid=?,node_uuid=?,ip=? WHERE id=?", orderPanelID, orderPanelNode, orderOriginNew, orderOriginID)
	if err := m.enrollTarget(order()); err != nil || order()["target_id"] == targetID || num(order()["verify_deadline"]) <= nowSeconds() {
		t.Fatalf("expected a new target and verification window: %v, %v", err, order())
	}
	s.exec("UPDATE server_orders SET verify_deadline=? WHERE id=?", nowSeconds()-1, orderOriginID)
	s.exec("INSERT INTO target_checks(target_id,agent_id,failures,last_checked_at,outcome) VALUES(?,'checker',2,?,0)", order()["target_id"], iso(fromSeconds(nowSeconds())))
	if err := m.finish(order()); err != nil || order()["stage"] != "deleting" {
		t.Fatalf("expected cleanup for the failed second server: %v, %v", err, order())
	}
	m.finishOrderDeletionStep(order(), orderDeleteDNS)
	m.finishOrderDeletionStep(order(), orderDeleteRemnawave)
	m.finishOrderDeletionStep(order(), orderDeleteHosting)
	if order()["stage"] != "unreachable" || num(order()["deleted_resources"]) != orderDeleteAll || m.autoHost(orderOriginID) != nil {
		t.Fatal("a second failed VPS must end the order and release the auto-host slot", order())
	}
}

type orderOptionsInstaller struct {
	orderInstaller
	configErr error
	preflight func(orderAnsibleNode) error
}

func (i orderOptionsInstaller) checkOrderConfiguration(context.Context) error {
	return i.configErr
}

func (i orderOptionsInstaller) ReadyForOrder(_ context.Context, node orderAnsibleNode) error {
	return i.preflight(node)
}

func TestOrderOptionsCheckSetupBeforeLookingUpChoices(t *testing.T) {
	configErr := errors.New("test SSH configuration error")
	groupErr := errors.New("test XHTTP configuration error")
	manager := &orderManager{
		a: &App{config: Config{PublicOrigin: "http://guard.example.test"}},
		installer: orderOptionsInstaller{configErr: configErr, preflight: func(node orderAnsibleNode) error {
			if node.Group != "nodes_wl" || !validReplacementOrderDomain(node.Domain) {
				t.Fatalf("unexpected preflight node %+v", node)
			}
			return groupErr
		}},
	}
	if choices, err := manager.options(t.Context(), "zone", "", "", "", ""); len(choices) != 0 ||
		!errors.Is(err, configErr) || !strings.Contains(err.Error(), "PUBLIC_ORIGIN") {
		t.Fatalf("expected both setup errors before location lookup, got %v, %v", choices, err)
	}
	if choices, err := manager.options(t.Context(), "profile", "", "", "nodes_wl", ""); len(choices) != 0 || !errors.Is(err, groupErr) {
		t.Fatalf("expected the group error before profile lookup, got %v, %v", choices, err)
	}
}

func TestOrderEnrollmentOriginRejectsEmptyQuery(t *testing.T) {
	manager := &orderManager{a: &App{config: Config{PublicOrigin: "https://guard.example.test?"}}}
	if base, err := manager.enrollmentOrigin(); base != nil || err == nil || !strings.Contains(err.Error(), "PUBLIC_ORIGIN") {
		t.Fatalf("expected an origin validation error, got %v, %v", base, err)
	}
}

func TestOrderQuoteTracksZonePriceAndConfiguration(t *testing.T) {
	plan := orderCloudPlan{Code: "STARTER-2xCPU-2GB", Family: "starter", CPU: 2, MemoryMB: 2048, StorageGB: 30, StorageTier: "standard", Price: 0.01, Currency: "EUR"}
	original := orderPlanChoice("fi-hel1", plan)
	if original.Family != "starter" {
		t.Errorf("wrong Starter family %q", original.Family)
	}
	for _, value := range []string{plan.Code, "2 vCPU", "2048", "30", "6.72 EUR/мес.", "0.01 EUR/ч"} {
		if !strings.Contains(original.Label, value) {
			t.Errorf("missing %q in %q", value, original.Label)
		}
	}
	if orderPlanChoice("fi-hel2", plan).ID == original.ID {
		t.Error("zone was not bound to quote")
	}
	withoutFamily := plan
	withoutFamily.Family = ""
	if orderPlanChoice("fi-hel1", withoutFamily).ID != original.ID {
		t.Error("catalog family should not change an existing quote")
	}
	for _, change := range []func(*orderCloudPlan){
		func(p *orderCloudPlan) { p.Price = 0.02 }, func(p *orderCloudPlan) { p.Currency = "USD" }, func(p *orderCloudPlan) { p.MemoryMB = 4096 },
		func(p *orderCloudPlan) { p.StorageGB = 40 }, func(p *orderCloudPlan) { p.StorageTier = "maxiops" }, func(p *orderCloudPlan) { p.CPU = 4 },
	} {
		changed := plan
		change(&changed)
		if orderPlanChoice("fi-hel1", changed).ID == original.ID {
			t.Error("material plan change kept the quoted ID")
		}
	}
}

func TestOrderPlanFamilyAndMonthlyPrice(t *testing.T) {
	plan := orderCloudPlan{Code: "PREMIUM-1xCPU-1GB", Family: "premium", Price: 0.0074404762, Currency: "USD"}
	choice := orderPlanChoice("fi-hel1", plan)
	if choice.Family != "premium" || !strings.Contains(choice.Label, "5.00 USD/мес.") {
		t.Errorf("unexpected Premium choice %+v", choice)
	}
	plan.Code, plan.Family = "1xCPU-1GB", "general_purpose"
	if choice := orderPlanChoice("fi-hel1", plan); choice.Family != "" {
		t.Errorf("legacy plan assigned to %q", choice.Family)
	}
}

func TestServerOrderDomain(t *testing.T) {
	for _, tc := range []struct{ template, want string }{
		{"{country}-{n}.{pool}", "de-01.eu.example.com"}, {"node{n}.example.com", "node01.example.com"},
		{"{country}.{pool}", ""}, {"{country}-{unknown}-{n}.{pool}", ""}, {"-{n}.{pool}", ""}, {strings.Repeat("s", 63) + "{n}.example.com", ""},
		{"{n}..example.com", ""},
	} {
		got, err := renderOrderDomain(tc.template, "DE", "eu.example.com", 1)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("template %q: got %q, error %v", tc.template, got, err)
		}
	}
}

func TestServerEnrollmentSSHKeyWireFormat(t *testing.T) {
	wire := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	encode := func(b []byte) string { return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b) }
	valid := encode(wire)
	if !enrolledEd25519(valid) {
		t.Fatal("valid public key rejected")
	}
	for _, key := range []string{valid + " comment", valid + "\n", "ssh-rsa " + strings.TrimPrefix(valid, "ssh-ed25519 "), encode(wire[:len(wire)-1]), encode(append(wire, 0))} {
		if enrolledEd25519(key) {
			t.Errorf("unexpected enrollment for %q", key)
		}
	}
	wire[18] = 31
	if enrolledEd25519(encode(wire)) {
		t.Error("mismatched encoded key length accepted")
	}
}
