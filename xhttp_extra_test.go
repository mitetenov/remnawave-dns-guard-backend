package guard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestXHTTPExtraAgentVersion(t *testing.T) {
	for _, version := range []string{"1.1.0", "1.2.0", "2.0.0"} {
		if !supportsXHTTPExtra(version) {
			t.Error(version)
		}
	}
	for _, version := range []string{"", "1", "1.0.0", "0.9.0", "1.1.0-beta", "garbage", "+1.1.0", "1.01.0"} {
		if supportsXHTTPExtra(version) {
			t.Error(version)
		}
	}
}

func TestXHTTPExtraSchema(t *testing.T) {
	data, err := os.ReadFile("testdata/xhttp-extra.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, value := range cases.Valid {
		if !validXHTTPExtra(value, "xhttp", "stream-up") {
			t.Errorf("rejected valid extra: %s", value)
		}
		if validXHTTPExtra(value, "tcp", "auto") {
			t.Error("TCP extra accepted")
		}
	}
	for _, value := range cases.Invalid {
		if validXHTTPExtra(value, "xhttp", "stream-up") {
			t.Errorf("accepted invalid extra: %s", value)
		}
	}
	if validXHTTPExtra(json.RawMessage(`{"headers":{"X-Pad":"`+strings.Repeat("x", 16384)+`"}}`), "xhttp", "auto") {
		t.Error("oversized extra")
	}
	if validXHTTPExtra(json.RawMessage(`{"headers":{"X-Pad":"`+strings.Repeat("<", 3000)+`"}}`), "xhttp", "auto") {
		t.Error("HTML escaping exceeds wire size")
	}
	if !validXHTTPExtra(nil, "tcp", "auto") {
		t.Error("legacy profile rejected")
	}
	if !validXHTTPExtra(json.RawMessage(`{"uplinkHTTPMethod":"GET","uplinkDataPlacement":"cookie"}`), "xhttp", "packet-up") {
		t.Error("packet-up fields rejected")
	}
}
