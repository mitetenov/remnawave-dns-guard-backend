package guard

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const subscriptionURI = "vless://e764ae13-9e06-4e6d-a870-2898c984ca22@1.1.1.1:443?security=tls&sni=example.com#Test"
const hwidPlaceholder = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#App%20not%20supported"

func TestSubscriptionFormats(t *testing.T) {
	text := subscriptionURI + "\r\nss://ignored\r\n" + subscriptionURI + "\n" + strings.Replace(subscriptionURI, "#Test", "#Other", 1)
	inputs := []string{"\ufeff \n" + text + "\n"}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		value := encoding.EncodeToString([]byte(text))
		inputs = append(inputs, value[:20]+"\n"+value[20:])
	}
	for _, input := range inputs {
		uris, err := subscriptionURIs([]byte(input))
		if err != nil || len(uris) != 2 || uris[0] != subscriptionURI || !strings.HasSuffix(uris[1], "#Other") {
			t.Fatalf("format or deduplication failed: count=%d err=%v", len(uris), err)
		}
	}
	for _, value := range []string{"", "not base64", "<html>Subscription page</html>", `{"outbounds":[]}`, "ss://unsupported", "vless://" + strings.Repeat("x", 16384)} {
		if _, err := subscriptionURIs([]byte(value)); err == nil {
			t.Fatal("invalid subscription accepted")
		}
	}
	many := strings.Builder{}
	for i := 0; i < 501; i++ {
		many.WriteString(subscriptionURI + strings.Repeat("x", i) + "\n")
	}
	if _, err := subscriptionURIs([]byte(many.String())); err == nil {
		t.Fatal("server limit not enforced")
	}
}

func TestSubscriptionURLAndIPRestrictions(t *testing.T) {
	for _, value := range []string{"http://example.com/secret", "file:///secret", "https://user:secret@example.com", "https://example.com/#secret", "https://127.0.0.1", "https://10.0.0.1", "https://169.254.169.254/latest", "https://[::1]", "https://[::ffff:127.0.0.1]", "https://[fc00::1]", "https://[fe80::1]", "https://[2001:db8::1]", "https://[2002:7f00:1::1]", "https://[3fff::1]", "https://" + strings.Repeat("x", 8192)} {
		if _, err := subscriptionURL(value); err == nil {
			t.Fatalf("unsafe URL accepted: %s", value[:min(len(value), 80)])
		}
	}
	for _, value := range []string{"https://sub.example.com/token?format=base64", "https://1.1.1.1:8443/token", "https://[2606:4700:4700::1111]/token"} {
		if _, err := subscriptionURL(value); err != nil {
			t.Fatal("public URL rejected", err)
		}
	}
}

func TestSubscriptionDialPinsPublicDNSAnswers(t *testing.T) {
	for _, ips := range [][]netip.Addr{
		{netip.MustParseAddr("1.1.1.1")},
		{netip.MustParseAddr("2606:4700:4700::1111")},
		{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::ffff:10.0.0.1")},
		nil,
	} {
		lookups, dials := 0, 0
		d := subscriptionDialer{
			lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				lookups++
				if network != "ip" || host != "sub.example.com" {
					t.Fatal("unexpected DNS lookup")
				}
				return ips, nil
			},
			dial: func(_ context.Context, network, address string) (net.Conn, error) {
				dials++
				if network != "tcp" || address != net.JoinHostPort(ips[0].String(), "443") {
					t.Fatal("checked IP was not pinned")
				}
				return nil, errors.New("test connection failure")
			},
		}
		_, _ = d.DialContext(context.Background(), "tcp", "sub.example.com:443")
		wantDials := 0
		if len(ips) == 1 && publicSubscriptionIP(ips[0]) {
			wantDials = 1
		}
		if lookups != 1 || dials != wantDials {
			t.Fatalf("unsafe DNS handling: lookups=%d dials=%d want=%d", lookups, dials, wantDials)
		}
	}
	client := newSubscriptionClient()
	defer client.CloseIdleConnections()
	if client.Transport.(*http.Transport).Proxy != nil || client.Timeout == 0 {
		t.Fatal("subscriptions must bypass environment proxies and have a deadline")
	}
}

func TestSubscriptionFetchLimitsAndSanitizedErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		fail   bool
	}{
		{200, subscriptionURI, false},
		{403, "secret", true},
		{200, strings.Repeat("x", maxSubscriptionBytes+1), true},
		{200, "<html>secret</html>", true},
		{0, "", true},
	} {
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != "GET" || req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.Header.Get("User-Agent") != "DNSGuard/1.0" {
				t.Fatal("unexpected credentials or request headers")
			}
			if tc.status == 0 {
				return nil, errors.New("https://sub.example.com/secret provider error")
			}
			return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		_, err := fetchSubscription(context.Background(), client, "https://sub.example.com/secret", "")
		if (err != nil) != tc.fail || err != nil && strings.Contains(err.Error(), "secret") {
			t.Fatal("incorrect or unsafe subscription error", err)
		}
	}
	for _, target := range []string{"http://example.com", "https://127.0.0.1", "https://user:secret@example.com"} {
		if err := subscriptionRedirect(&http.Request{URL: mustURL(target)}, []*http.Request{{}}); err == nil {
			t.Fatal("unsafe redirect accepted")
		}
	}
	if subscriptionRedirect(&http.Request{URL: mustURL("https://example.com")}, make([]*http.Request, 4)) == nil {
		t.Fatal("redirect limit not enforced")
	}
}

func TestSubscriptionRedirectCannotReachPrivateServer(t *testing.T) {
	calls := 0
	client := &http.Client{CheckRedirect: subscriptionRedirect, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://127.0.0.1/private"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if _, err := fetchSubscription(context.Background(), client, "https://example.com/secret", ""); err == nil || calls != 1 {
		t.Fatal("private redirect reached upstream", calls, err)
	}
}

func TestSubscriptionPreviewOverTLSWithoutPersistence(t *testing.T) {
	e := newTestEnv(t)
	requests := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("panel credentials leaked to subscription server")
		}
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(subscriptionURI)))
	}))
	defer upstream.Close()
	client := upstream.Client()
	transport := client.Transport.(*http.Transport).Clone()
	dialer := subscriptionDialer{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "1.1.1.1:443" {
				t.Error("unvalidated destination used")
			}
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	transport.DialContext = dialer.DialContext
	client.Transport, client.CheckRedirect = transport, subscriptionRedirect
	e.app.subscriptionClient.CloseIdleConnections()
	e.app.subscriptionClient = client
	resp, err := e.request("POST", "/api/subscriptions/preview", row{"url": "https://example.com/secret"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(string(body), "vless://") || requests != 1 {
		t.Fatalf("preview failed: status=%d body=%s requests=%d", resp.StatusCode, body, requests)
	}
	for _, path := range []string{"/api/pools", "/api/events"} {
		if rows := asRows(e.do("GET", path, nil, 200)); len(rows) != 0 {
			t.Fatal("preview mutated stored state")
		}
	}
	e.do("POST", "/api/subscriptions/preview", row{"url": nil}, 422)
	e.do("POST", "/api/subscriptions/preview", row{"url": "https://127.0.0.1/secret"}, 422)
	req, _ := http.NewRequest("POST", e.server.URL+"/api/subscriptions/preview", strings.NewReader(`{"url":"https://example.com/secret"}`))
	req.Header.Set("Origin", "https://untrusted.example")
	rejected, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rejected.Body.Close()
	if rejected.StatusCode != 403 {
		t.Fatal("cross-origin preview was not rejected")
	}
	e.do("POST", "/api/auth/logout", nil, 200)
	e.do("POST", "/api/subscriptions/preview", row{"url": "https://example.com/secret"}, 401)
	if requests != 1 {
		t.Fatal("invalid or unauthenticated request reached upstream")
	}
}

func TestSubscriptionHwidErrorsDoNotBecomeServers(t *testing.T) {
	for _, tc := range []struct {
		headers http.Header
		want    string
	}{
		{http.Header{"X-Hwid-Not-Supported": {"true"}, "X-Hwid-Limit": {"true"}}, "Подписка требует HWID"},
		{http.Header{"X-Hwid-Max-Devices-Reached": {"true"}}, "лимит устройств"},
		{http.Header{"X-Hwid-Limit": {"true"}}, "лимит устройств"},
		{http.Header{}, "служебную заглушку"},
	} {
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Hwid") != "" {
				t.Fatal("a device was sent without operator opt-in")
			}
			return &http.Response{StatusCode: 200, Header: tc.headers, Body: io.NopCloser(strings.NewReader(base64.StdEncoding.EncodeToString([]byte(hwidPlaceholder))))}, nil
		})}
		uris, err := fetchSubscription(context.Background(), client, "https://example.com/secret", "")
		if err == nil || !strings.Contains(err.Error(), tc.want) || len(uris) != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatal("HWID rejection was not explained safely", err)
		}
	}
}

func TestSubscriptionDeviceIDIsStableScopedAndNeverTheSecret(t *testing.T) {
	secret := strings.Repeat("private", 8)
	id := func(value, key string) string {
		req, _ := http.NewRequest("GET", value, nil)
		setSubscriptionDevice(req, key)
		if req.Header.Get("X-Device-Model") != "DNS Guard" {
			t.Fatal("device should be recognizable in the provider's device list")
		}
		return req.Header.Get("X-Hwid")
	}
	first := id("https://sub.example.com/account-a", secret)
	if !regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`).MatchString(first) || first == secret || strings.Contains(first, "private") {
		t.Fatal("HWID format is invalid or leaks the application secret")
	}
	if first != id("https://SUB.EXAMPLE.COM:443/account-b?format=base64", secret) {
		t.Fatal("retries, other subscriptions and canonical origins must reuse the device")
	}
	if first == id("https://other.example.com/account-a", secret) || first == id("https://sub.example.com/account-a", secret+"other") {
		t.Fatal("device identity must be scoped to the installation and provider")
	}
}

func TestSubscriptionDeviceHeadersFollowRedirectsWithoutSharingIdentity(t *testing.T) {
	for _, target := range []string{"https://sub.example.com/final", "https://other.example.com/final"} {
		ids := []string{}
		client := &http.Client{CheckRedirect: subscriptionRedirect, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			ids = append(ids, req.Header.Get("X-Hwid"))
			if len(ids) == 1 {
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": {target}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(subscriptionURI))}, nil
		})}
		uris, err := fetchSubscription(context.Background(), client, "https://sub.example.com/secret", strings.Repeat("S", 32))
		if err != nil || len(uris) != 1 || len(ids) != 2 || ids[0] == "" || ids[1] == "" {
			t.Fatal("HWID disappeared after redirect", err)
		}
		sameProvider := strings.HasPrefix(target, "https://sub.example.com/")
		if (ids[0] == ids[1]) != sameProvider {
			t.Fatal("HWID must remain stable only for the same provider")
		}
	}
}

func TestSubscriptionHwidOptInOverTLSAndRestart(t *testing.T) {
	e := newTestEnv(t)
	var mu sync.Mutex
	devices := map[string]bool{}
	requests := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("panel credentials leaked")
		}
		hwid := r.Header.Get("X-Hwid")
		if hwid == "" {
			w.Header().Set("X-Hwid-Not-Supported", "true")
			w.Header().Set("X-Hwid-Limit", "true")
			_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(hwidPlaceholder)))
			return
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9=-]{10,64}$`).MatchString(hwid) || hwid == e.cfg.AppSecret || r.Header.Get("X-Device-Model") != "DNS Guard" {
			t.Error("invalid subscription device headers")
		}
		devices[hwid] = true
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(subscriptionURI)))
	}))
	defer upstream.Close()
	connect := func() {
		client := upstream.Client()
		transport := client.Transport.(*http.Transport).Clone()
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		}
		copy := *client
		copy.Transport, copy.CheckRedirect = transport, subscriptionRedirect
		e.app.subscriptionClient.CloseIdleConnections()
		e.app.subscriptionClient = &copy
	}
	connect()
	endpoint := "/api/subscriptions/preview"
	message := asRow(e.do("POST", endpoint, row{"url": "https://example.com/account-a"}, 422))
	if !strings.Contains(str(message["detail"]), "Подписка требует HWID") {
		t.Fatal("the operator was not told to opt in")
	}
	for _, account := range []string{"account-a", "account-b"} {
		data := asRow(e.do("POST", endpoint, row{"url": "https://example.com/" + account, "use_hwid": true}, 200))
		if len(data["uris"].([]any)) != 1 || data["uris"].([]any)[0] != subscriptionURI {
			t.Fatal("real servers were not imported with HWID")
		}
	}
	e.restart(false)
	connect()
	e.do("POST", endpoint, row{"url": "https://example.com/account-a", "use_hwid": true}, 200)
	e.do("POST", endpoint, row{"url": "https://example.com/account-a", "use_hwid": false}, 422)
	e.do("POST", endpoint, row{"url": "https://example.com/account-a", "use_hwid": nil}, 422)
	mu.Lock()
	defer mu.Unlock()
	if len(devices) != 1 || requests != 5 {
		t.Fatal("retry or restart consumed another device slot")
	}
	if len(asRows(e.do("GET", "/api/pools", nil, 200))) != 0 || len(asRows(e.do("GET", "/api/events", nil, 200))) != 0 {
		t.Fatal("subscription preview modified panel state")
	}
}
