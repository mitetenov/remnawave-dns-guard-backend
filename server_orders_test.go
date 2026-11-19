package guard

import (
	"encoding/base64"
	"strings"
	"testing"
)

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
