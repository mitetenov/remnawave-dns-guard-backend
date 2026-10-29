package guard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProxyTestCorrelationAndExpiry(t *testing.T) {
	for _, test := range []struct {
		id       string
		age      float64
		result   string
		accepted bool
	}{
		{"test-1", 0, "", true}, {"other", 0, "", false}, {"test-1", 61, "", false}, {"test-1", 0, "passed", false}, {"test-1", 0, "failed", false}, {"", 0, "", false},
	} {
		agent := row{"proxy_test_id": "test-1", "proxy_test_requested": 100 - test.age, "proxy_test_result": test.result}
		if proxyTestMatches(agent, test.id, 100) != test.accepted {
			t.Fatalf("unexpected test acceptance: %+v", test)
		}
	}
	if supportsProxyPreview("1.4.0") || !supportsProxyPreview("1.5.0") || !supportsProxyPreview("2.0.0") {
		t.Fatal("incorrect capability gate")
	}
}

func TestProxyCredentialsVisibleOnlyInDetail(t *testing.T) {
	s := &Store{cipher: newFernet("test-secret")}
	value := "socks5://login:p%40ss@192.0.2.10:1080"
	agent := row{"version": "1.5.0", "proxy_url": s.cipher.encrypt([]byte(value))}
	fleet := s.checkerProxyView(agent, 100)
	if fleet["endpoint"] != "socks5://192.0.2.10:1080" {
		t.Fatal(fleet)
	}
	data, _ := json.Marshal(fleet)
	if strings.Contains(string(data), "login") || strings.Contains(string(data), "p%40ss") || fleet["url"] != nil {
		t.Fatal("fleet view contains credentials")
	}
	detail := s.checkerProxyDetail(agent, 100)
	if detail["url"] != value {
		t.Fatal("agent detail does not expose requested proxy settings")
	}
	if str(agent["proxy_url"]) == value {
		t.Fatal("storage is not encrypted")
	}
}
