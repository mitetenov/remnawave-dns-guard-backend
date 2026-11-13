package guard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func hysteriaProfile() Profile {
	p := defaultProfile()
	p.Protocol, p.Port, p.Transport, p.Security, p.ServerName = "hysteria2", 8443, "udp", "tls", "edge.example.com"
	p.Password, p.Obfs, p.ObfsPassword, p.PinSHA256 = "user:secret", "salamander", "obfs-secret", strings.Repeat("ab", 32)
	return p
}

func TestHysteriaValidation(t *testing.T) {
	p := hysteriaProfile()
	validateProfile(&p)
	for name, mutate := range map[string]func(*Profile){
		"TCP":                   func(p *Profile) { p.Transport = "tcp" },
		"REALITY":               func(p *Profile) { p.Security = "reality" },
		"password control":      func(p *Profile) { p.Password = "secret\n" },
		"oversized password":    func(p *Profile) { p.Password = strings.Repeat("x", 2049) },
		"unknown obfs":          func(p *Profile) { p.Obfs = "gecko" },
		"missing obfs password": func(p *Profile) { p.ObfsPassword = "" },
		"invalid pin":           func(p *Profile) { p.PinSHA256 = "ab" },
		"wrong ALPN":            func(p *Profile) { p.ALPN = []string{"h2"} },
		"VLESS UUID":            func(p *Profile) { p.UUID = "550e8400-e29b-41d4-a716-446655440000" },
		"XHTTP extra":           func(p *Profile) { p.XHTTPExtra = json.RawMessage(`{}`) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if _, ok := recover().(*apiError); !ok {
					t.Fatal("invalid profile accepted")
				}
			}()
			p := hysteriaProfile()
			mutate(&p)
			validateProfile(&p)
		})
	}
}

func TestHysteriaWireProfileAndAgentCompatibility(t *testing.T) {
	p := hysteriaProfile()
	validateProfile(&p)
	cipher := newFernet(strings.Repeat("S", 32))
	raw, _ := json.Marshal(p)
	encrypted := cipher.encrypt(raw)
	decrypted, err := cipher.decrypt(encrypted)
	var decoded Profile
	if err != nil || json.Unmarshal(decrypted, &decoded) != nil || decoded.Password != p.Password || decoded.ObfsPassword != p.ObfsPassword || decoded.PinSHA256 != p.PinSHA256 || strings.Contains(encrypted, p.Password) {
		t.Fatal("Hysteria credentials not preserved by encrypted profile storage")
	}
	for _, version := range []string{"1.6.0", "1.6.1", "1.7.0", "2.0.0"} {
		if !supportsHysteria2(version) {
			t.Fatal("supported agent version rejected", version)
		}
	}
	for _, version := range []string{"", "1.5.0", "1.6.0-beta", "1.06.0"} {
		if supportsHysteria2(version) {
			t.Fatal("unsupported agent version accepted", version)
		}
	}
	legacy := defaultProfile()
	legacy.Protocol, legacy.Port, legacy.UUID, legacy.Transport, legacy.Security, legacy.ServerName = "vless", 443, "550e8400-e29b-41d4-a716-446655440000", "tcp", "tls", "edge.example.com"
	validateProfile(&legacy)
	legacyRaw, _ := json.Marshal(legacy)
	for _, field := range []string{"protocol", "password", "obfs", "obfs_password", "pin_sha256"} {
		if bytes.Contains(legacyRaw, []byte(`"`+field+`"`)) {
			t.Fatal("legacy strict decoder would reject field", field)
		}
	}
}

func TestMixedHysteriaSubscriptionFormats(t *testing.T) {
	text := subscriptionURI + "\nhysteria2://secret@edge.example.com:443?sni=edge.example.com\nhy2://secret@edge.example.com\nss://ignored\n"
	for _, input := range []string{text, base64.StdEncoding.EncodeToString([]byte(text))} {
		list, err := subscriptionURIs([]byte(input))
		if err != nil || len(list) != 3 {
			t.Fatal("mixed subscription lost Hysteria links", list, err)
		}
	}
}
