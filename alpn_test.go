package guard

import (
	"encoding/json"
	"os"

	"strings"
	"testing"
)

func TestALPNAgentVersion(t *testing.T) {
	for _, version := range []string{"1.2.0", "1.2.1", "1.3.0", "2.0.0"} {
		if !supportsALPN(version) {
			t.Error(version)
		}
	}
	for _, version := range []string{"", "1", "1.0.0", "1.1.0", "1.2.0-beta", "1.02.0"} {
		if supportsALPN(version) {
			t.Error(version)
		}
	}
}

func TestALPNValidation(t *testing.T) {
	data, err := os.ReadFile("testdata/profile-alpn.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, raw := range cases.Valid {
		var protocols []string
		if err := json.Unmarshal(raw, &protocols); err != nil || !validALPN(protocols, "tls") {
			t.Errorf("valid ALPN rejected: %s", raw)
		}
	}
	for _, raw := range cases.Invalid {
		// Null is rejected by the strict HTTP/job decoder before slice validation.
		if string(raw) == "null" {
			continue
		}
		var protocols []string
		if err := json.Unmarshal(raw, &protocols); err == nil && validALPN(protocols, "tls") {
			t.Errorf("invalid ALPN accepted: %s", raw)
		}
	}
	if validALPN([]string{"h2"}, "reality") || validALPN(make([]string, 17), "tls") || validALPN([]string{strings.Repeat("a", 256)}, "tls") {
		t.Error("context/length validation failed")
	}
	if !validALPN(nil, "reality") {
		t.Error("legacy profile rejected")
	}
}
