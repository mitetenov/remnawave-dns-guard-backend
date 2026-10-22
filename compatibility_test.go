package guard

import (
	"encoding/base64"

	"strings"
	"testing"
)

func TestPythonFernetAndUnicodeCredentialGolden(t *testing.T) {
	// Created by Python cryptography.Fernet using SHA256(APP_SECRET).
	const legacy = "gAAAAABq1eUDYpNeKrprfWZV4kC6SHkEpnY1IDTv1CO1lMUiwDcYusXEaSfr-JPMKbQBIbzjXN6TC4e-hqg5tL20NyNit44K9A=="
	cipher := newFernet(strings.Repeat("S", 32))
	plain, err := cipher.decrypt(legacy)
	if err != nil || string(plain) != "legacy-token" {
		t.Fatal(string(plain), err)
	}
	cfg := testConfig(":memory:")
	cfg.Username, cfg.Password = "админ😀", "секрет"
	if got := authRevision(cfg); got != "219a0c969efb4e258dce76c4c08c0de3be38e6ffb8ae4e8e8b197efde1c19997" {
		t.Fatal("Python JSON/HMAC compatibility changed", got)
	}
	for _, value := range []string{"", "invalid", legacy[:30], base64.URLEncoding.EncodeToString(make([]byte, 73))} {
		if _, err := cipher.decrypt(value); err == nil {
			t.Fatal("invalid Fernet token accepted")
		}
	}
	token, _ := base64.URLEncoding.DecodeString(legacy)
	token[28] ^= 1
	if _, err := cipher.decrypt(base64.URLEncoding.EncodeToString(token)); err == nil {
		t.Fatal("tampered Fernet token accepted")
	}
	if _, err := newFernet(strings.Repeat("X", 32)).decrypt(legacy); err == nil {
		t.Fatal("wrong APP_SECRET accepted")
	}
	for _, value := range []string{"", "Русский 😀", strings.Repeat("p", 32)} {
		plain, err := cipher.decrypt(cipher.encrypt([]byte(value)))
		if err != nil || string(plain) != value {
			t.Fatal("roundtrip failed", err)
		}
	}
}
