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
	"strings"
	"testing"
)

const subscriptionURI = "vless://e764ae13-9e06-4e6d-a870-2898c984ca22@1.1.1.1:443?security=tls&sni=example.com#Test"

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
		_, err := fetchSubscription(context.Background(), client, "https://sub.example.com/secret")
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
	if _, err := fetchSubscription(context.Background(), client, "https://example.com/secret"); err == nil || calls != 1 {
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
