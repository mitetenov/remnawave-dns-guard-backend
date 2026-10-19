package guard

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxSubscriptionBytes = 2 << 20

func subscriptionURL(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || len(value) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("Укажите HTTPS-ссылку на подписку без логина, пароля и фрагмента.")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicSubscriptionIP(ip) {
		return nil, errors.New("Ссылка подписки должна вести на публичный сервер.")
	}
	return u, nil
}

func publicSubscriptionIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is4() {
		return publicIPv4(ip.String())
	}
	// Only native global IPv6; exclude documentation and transition ranges.
	return netip.MustParsePrefix("2000::/3").Contains(ip) &&
		!netip.MustParsePrefix("2001::/23").Contains(ip) &&
		!netip.MustParsePrefix("2001:db8::/32").Contains(ip) &&
		!netip.MustParsePrefix("2002::/16").Contains(ip) &&
		!netip.MustParsePrefix("3fff::/20").Contains(ip)
}

type subscriptionDialer struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func (d subscriptionDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid subscription address")
	}
	ips, err := d.lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("subscription DNS lookup failed")
	}
	for _, ip := range ips {
		if !publicSubscriptionIP(ip) {
			return nil, errors.New("subscription address is not public")
		}
	}
	for _, ip := range ips {
		// Connect to the checked address directly, avoiding a second DNS lookup.
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("subscription connection failed")
}

func newSubscriptionClient() *http.Client {
	dialer := subscriptionDialer{net.DefaultResolver.LookupNetIP, (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxResponseHeaderBytes = 32 << 10
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: subscriptionRedirect}
}

func subscriptionRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 3 {
		return errors.New("too many subscription redirects")
	}
	_, err := subscriptionURL(req.URL.String())
	return err
}

func subscriptionURIs(body []byte) ([]string, error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	// Plain URI lists and standard/URL-safe Base64, with or without padding.
	if !strings.Contains(text, "://") {
		compact := strings.Join(strings.Fields(text), "")
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := encoding.DecodeString(compact); err == nil {
				text = strings.TrimPrefix(string(decoded), "\ufeff")
				break
			}
		}
	}
	list, seen := []string{}, map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		uri := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(uri), "vless://") || seen[uri] {
			continue
		}
		if len(uri) > 16384 || len(list) >= 500 {
			return nil, errors.New("Подписка превышает лимит: до 500 серверов и 16 КБ на ссылку.")
		}
		seen[uri] = true
		list = append(list, uri)
	}
	if len(list) == 0 {
		return nil, errors.New("В подписке нет VLESS-ссылок. Нужен список ссылок в текстовом формате или Base64.")
	}
	return list, nil
}

func fetchSubscription(ctx context.Context, client *http.Client, value string) ([]string, error) {
	u, err := subscriptionURL(value)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("Не удалось прочитать ссылку подписки.")
	}
	req.Header.Set("User-Agent", "DNSGuard/1.0")
	req.Header.Set("Accept", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Не удалось загрузить подписку. Проверьте ссылку и доступность публичного HTTPS-сервера.")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Сервер подписки отклонил запрос. Проверьте ссылку, срок действия и ограничения подписки.")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
	if err != nil {
		return nil, errors.New("Не удалось прочитать ответ сервера подписки. Повторите загрузку.")
	}
	if len(body) > maxSubscriptionBytes {
		return nil, errors.New("Подписка слишком большая. Максимальный размер — 2 МБ.")
	}
	return subscriptionURIs(body)
}

func (a *App) subscriptionRoutes() {
	a.route("POST /api/subscriptions/preview", "ui", func(w http.ResponseWriter, r *http.Request) any {
		w.Header().Set("Cache-Control", "no-store")
		var data struct {
			URL string `json:"url"`
		}
		bodyObject(w, r, &data, []string{"url"})
		uris, err := fetchSubscription(r.Context(), a.subscriptionClient, data.URL)
		if err != nil {
			fail(422, err.Error())
		}
		// Preview only: never persist the URL, credentials or the downloaded list.
		return row{"uris": uris}
	})
}
