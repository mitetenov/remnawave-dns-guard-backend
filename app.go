package guard

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type apiError struct {
	status  int
	detail  string
	headers http.Header
}

func fail(status int, detail string) { panic(&apiError{status: status, detail: detail}) }
func invalid(field string)           { fail(422, "Invalid request fields: "+field) }
func constantEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
func fmtDrift(n int) string          { return fmt.Sprintf("DNS drift detected: %d discrepancies", n) }
func fmtSync(n int) string {
	return fmt.Sprintf("Exact hostname DNS sync complete; adopted %d targets", n)
}
func mustErr(e error) {
	if e != nil {
		panic(e)
	}
}
func ConfigFromEnv() Config { return configFromEnv() }

type Options struct {
	Client          *http.Client
	BackgroundTasks bool
}
type App struct {
	config             Config
	s                  *Store
	reconciler         *Reconciler
	client             *http.Client
	subscriptionClient *http.Client
	mux                *http.ServeMux
	loginFailures      []float64
	closeOnce          sync.Once
	closeErr           error
}

func New(c Config, options Options) (*App, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	s, e := openStore(c)
	if e != nil {
		return nil, e
	}
	a := &App{config: c, s: s, client: providerClient(options.Client), mux: http.NewServeMux(), loginFailures: []float64{}}
	a.subscriptionClient = newSubscriptionClient()
	a.reconciler = newReconciler(s, a.dnsProvider)
	a.routes()
	if options.BackgroundTasks {
		a.reconciler.start()
	}
	return a, nil
}
func (a *App) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := a.mux.Handler(r)
		if pattern == "" {
			methods := []string{}
			for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} {
				candidate := *r
				candidate.Method = method
				if _, p := a.mux.Handler(&candidate); p != "" {
					methods = append(methods, method)
				}
			}
			if len(methods) > 0 {
				w.Header().Set("Allow", strings.Join(methods, ", "))
				writeJSON(w, http.StatusMethodNotAllowed, row{"detail": "Method Not Allowed"})
			} else {
				writeJSON(w, http.StatusNotFound, row{"detail": "Not Found"})
			}
			return
		}
		a.mux.ServeHTTP(w, r)
	})
}
func (a *App) Close() error {
	a.closeOnce.Do(func() {
		a.reconciler.close()
		a.client.CloseIdleConnections()
		a.subscriptionClient.CloseIdleConnections()
		a.closeErr = a.s.db.Close()
	})
	return a.closeErr
}
func (a *App) RunOnce() { a.reconciler.runOnce() }
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (a *App) route(pattern, auth string, fn func(http.ResponseWriter, *http.Request) any) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				status, detail := 500, "Internal server error"
				switch e := p.(type) {
				case *apiError:
					status, detail = e.status, e.detail
					for k, values := range e.headers {
						for _, v := range values {
							w.Header().Add(k, v)
						}
					}
				case *IntegrationError:
					status, detail = 502, e.Message
					if oneOf(e.Kind, "proxy", "last_record") {
						status = 409
					}
				case interface{ Code() int }:
					if e.Code()&255 == 19 {
						status, detail = 409, "A pool hostname or target IP already exists"
					}
				}
				if status == 500 {
					log.Print("API request failed")
				}
				writeJSON(w, status, row{"detail": detail})
			}
		}()
		switch auth {
		case "ui":
			a.auth(r)
		case "origin":
			a.origin(r)
		case "agent":
			if !constantEqual(r.Header.Get("Authorization"), "Bearer "+a.config.AgentToken) {
				fail(401, "Invalid agent credentials")
			}
		}
		value := fn(w, r)
		writeJSON(w, 200, value)
	})
}
func (a *App) origin(r *http.Request) {
	v := r.Header.Get("Origin")
	if v != "" && v != a.config.PublicOrigin || v == "" && r.Header.Get("X-Requested-With") != "DNSGuard" {
		fail(403, "Invalid request origin")
	}
}
func (a *App) auth(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.origin(r)
	}
	token := ""
	if c, e := r.Cookie("dns_guard_session"); e == nil {
		token = c.Value
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	session := a.s.one("SELECT * FROM sessions WHERE token=? AND expires>?", digest(token), nowSeconds())
	if session == nil {
		fail(401, "Authentication required")
	}
	return str(session["username"])
}
func bodyObject(w http.ResponseWriter, r *http.Request, value any, required []string, nullable ...string) map[string]json.RawMessage {
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if e != nil {
		invalid("request")
	}
	fields := map[string]json.RawMessage{}
	if e = json.Unmarshal(raw, &fields); e != nil || fields == nil {
		invalid("request")
	}
	allowed := map[string]bool{}
	t := reflect.TypeOf(value).Elem()
	for i := 0; i < t.NumField(); i++ {
		allowed[strings.Split(t.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	nulls := map[string]bool{}
	for _, name := range nullable {
		nulls[name] = true
	}
	bad := []string{}
	for name, v := range fields {
		if !allowed[name] {
			bad = append(bad, "request")
		} else if string(v) == "null" && !nulls[name] {
			bad = append(bad, name)
		}
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		compact := []string{}
		for _, name := range bad {
			if len(compact) == 0 || compact[len(compact)-1] != name {
				compact = append(compact, name)
			}
		}
		fail(422, "Invalid request fields: "+strings.Join(compact, ", "))
	}
	if e = json.Unmarshal(raw, value); e != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(e, &typeErr) {
			name := strings.Split(typeErr.Field, ".")[0]
			if allowed[name] {
				invalid(name)
			}
		}
		invalid("request")
	}
	return fields
}
func (a *App) withStore(fn func() any) any { a.s.mu.Lock(); defer a.s.mu.Unlock(); return fn() }
func (a *App) pool(id string) row {
	p := a.s.one("SELECT * FROM pools WHERE id=?", id)
	if p == nil {
		fail(404, "Pool not found")
	}
	return p
}
func (a *App) target(id string) row {
	t := a.s.one("SELECT * FROM targets WHERE id=?", id)
	if t == nil {
		fail(404, "Target not found")
	}
	return t
}
func poolView(p row) row {
	value := row{}
	for k, v := range p {
		if !oneOf(k, "profile", "revision", "dns_next_check") {
			value[k] = v
		}
	}
	value["automation_enabled"], value["profile_configured"] = truth(p["automation_enabled"]), truth(p["profile"])
	return value
}
func (a *App) targetViews(rows []row) []row {
	intervals := map[string]float64{}
	for _, p := range a.s.all("SELECT id,interval_seconds FROM pools") {
		intervals[str(p["id"])] = num(p["interval_seconds"])
	}
	agents := map[string]row{}
	for _, v := range a.s.all("SELECT * FROM agents") {
		agents[str(v["id"])] = v
	}
	now := nowSeconds()
	out := []row{}
	for _, t := range rows {
		value := row{}
		for k, v := range t {
			if !oneOf(k, "next_due", "last_agent_id", "dns_operation_id", "dns_previous_enabled", "dns_profile_revision", "dns_next_retry", "dns_action", "dns_new_ip", "dns_replace_present") {
				value[k] = v
			}
		}
		for _, key := range []string{"manual_enabled", "dns_present", "dns_uncertain", "dns_drift"} {
			value[key] = truth(value[key])
		}
		value["dns_pending_action"] = t["dns_action"]
		fresh := false
		if stamp := str(t["last_checked_at"]); stamp != "" {
			if checked, e := time.Parse(time.RFC3339Nano, stamp); e == nil {
				window := max(float64(leaseSeconds), intervals[str(t["pool_id"])]*3)
				agent := agents[str(t["last_agent_id"])]
				fresh = fromSeconds(now).Before(checked.Add(time.Duration(window*float64(time.Second)))) && agent != nil && truth(agent["healthy"]) && now-num(agent["last_seen"]) <= controlFreshSeconds
			}
		}
		value["probe_fresh"], value["last_status"] = fresh, t["status"]
		if truth(t["manual_enabled"]) && t["last_checked_at"] != nil && !fresh {
			value["status"] = "stale"
		}
		out = append(out, value)
	}
	return out
}
func (a *App) targetView(t row) row { return a.targetViews([]row{t})[0] }
func (a *App) settingsView() row {
	s := a.s
	agent := s.one("SELECT * FROM agents ORDER BY last_seen DESC LIMIT 1")
	var seen any
	healthy := false
	if agent != nil {
		seen = iso(fromSeconds(num(agent["last_seen"])))
		healthy = truth(agent["healthy"]) && nowSeconds()-num(agent["last_seen"]) <= controlFreshSeconds
	}
	return row{"cloudflare_configured": s.get("cloudflare_api_token") != "", "remnawave_configured": s.get("remnawave_url") != "" && s.get("remnawave_api_token") != "", "remnawave_url": s.get("remnawave_url"), "agent_last_seen": seen, "agent_healthy": healthy}
}
func (a *App) cloudflare() *Cloudflare {
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	token := a.s.get("cloudflare_api_token")
	if token == "" {
		fail(400, "Configure Cloudflare first")
	}
	return &Cloudflare{token, a.client}
}
func (a *App) dnsProvider() (*Cloudflare, error) {
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	token := a.s.get("cloudflare_api_token")
	if token == "" {
		return nil, integration("Configure Cloudflare first")
	}
	return &Cloudflare{token, a.client}, nil
}
func (a *App) remnawave() *Remnawave {
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	endpoint, token := a.s.get("remnawave_url"), a.s.get("remnawave_api_token")
	if endpoint == "" || token == "" {
		fail(400, "Configure Remnawave first")
	}
	r, e := newRemnawave(endpoint, token, a.client)
	mustErr(e)
	return r
}
func (a *App) manualDNSLocked(id, action string) any {
	a.s.mu.Lock()
	func() {
		defer a.s.mu.Unlock()
		if a.target(id)["dns_action"] == "replace_ip" {
			fail(409, "Дождитесь завершения смены IP узла")
		}
		a.reconciler.queueLocked(id, action)
	}()
	mustErr(a.reconciler.executeLocked(id, true))
	return a.withStore(func() any {
		if action == "delete_dns" {
			return row{"ok": true}
		}
		return a.targetView(a.target(id))
	})
}
func (a *App) manualDNS(id, action string) any {
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	return a.manualDNSLocked(id, action)
}

func (a *App) routes() {
	a.route("GET /api/health", "", func(w http.ResponseWriter, r *http.Request) any { return row{"ok": true} })
	a.route("POST /api/auth/login", "origin", func(w http.ResponseWriter, r *http.Request) any {
		data := Login{}
		bodyObject(w, r, &data, []string{"username", "password"})
		if !textLength(data.Username, 0, 200) {
			invalid("username")
		}
		if !textLength(data.Password, 0, 1000) {
			invalid("password")
		}
		return a.withStore(func() any {
			now := nowSeconds()
			for len(a.loginFailures) > 0 && a.loginFailures[0] <= now-60 {
				a.loginFailures = a.loginFailures[1:]
			}
			if len(a.loginFailures) >= 10 {
				retry := max(1, int(61-(now-a.loginFailures[0])))
				panic(&apiError{429, "Too many login attempts; retry later", http.Header{"Retry-After": {strconv.Itoa(retry)}}})
			}
			if !constantEqual(data.Username, a.config.Username) || !constantEqual(data.Password, a.config.Password) {
				a.loginFailures = append(a.loginFailures, now)
				fail(401, "Invalid credentials")
			}
			random := make([]byte, 32)
			if _, e := rand.Read(random); e != nil {
				panic(e)
			}
			token := base64.RawURLEncoding.EncodeToString(random)
			a.s.exec("DELETE FROM sessions WHERE expires<?", now)
			a.s.exec("INSERT INTO sessions VALUES (?,?,?)", digest(token), a.config.Username, now+12*3600)
			http.SetCookie(w, &http.Cookie{Name: "dns_guard_session", Value: token, MaxAge: 12 * 3600, HttpOnly: true, Secure: a.config.CookieSecure, SameSite: http.SameSiteStrictMode, Path: "/api"})
			return row{"username": a.config.Username}
		})
	})
	a.route("GET /api/auth/me", "ui", func(w http.ResponseWriter, r *http.Request) any { return row{"username": a.auth(r)} })
	a.route("POST /api/auth/logout", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			token := ""
			if c, e := r.Cookie("dns_guard_session"); e == nil {
				token = c.Value
			}
			a.s.exec("DELETE FROM sessions WHERE token=?", digest(token))
			http.SetCookie(w, &http.Cookie{Name: "dns_guard_session", Value: "", MaxAge: -1, HttpOnly: true, Secure: a.config.CookieSecure, SameSite: http.SameSiteStrictMode, Path: "/api"})
			return row{"ok": true}
		})
	})
	a.route("GET /api/settings", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any { return a.settingsView() })
	})
	a.route("PUT /api/settings", "ui", func(w http.ResponseWriter, r *http.Request) any {
		data := Settings{}
		bodyObject(w, r, &data, nil, "cloudflare_api_token", "remnawave_url", "remnawave_api_token")
		for name, v := range map[string]*string{"cloudflare_api_token": data.CloudflareAPIToken, "remnawave_url": data.RemnawaveURL, "remnawave_api_token": data.RemnawaveAPIToken} {
			limit := 4096
			if name == "remnawave_url" {
				limit = 2048
			}
			if v != nil && !textLength(*v, 0, limit) {
				invalid(name)
			}
		}
		if data.RemnawaveURL != nil && *data.RemnawaveURL != "" {
			_, e := newRemnawave(*data.RemnawaveURL, "", a.client)
			mustErr(e)
		}
		return a.withStore(func() any {
			for key, value := range map[string]*string{"cloudflare_api_token": data.CloudflareAPIToken, "remnawave_url": data.RemnawaveURL, "remnawave_api_token": data.RemnawaveAPIToken} {
				if value != nil && *value != "" {
					v := *value
					if key == "remnawave_url" {
						v = strings.TrimRight(v, "/")
					}
					a.s.set(key, v)
				}
			}
			a.s.event("info", "system", "Integration settings updated", nil, nil)
			return a.settingsView()
		})
	})
	a.route("GET /api/overview", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any {
			result := a.settingsView()
			delete(result, "remnawave_url")
			views := a.targetViews(a.s.all("SELECT * FROM targets"))
			healthy, excluded, stale := 0, 0, 0
			for _, t := range views {
				if t["status"] == "healthy" && !truth(t["dns_uncertain"]) {
					healthy++
				}
				if truth(t["manual_enabled"]) && !truth(t["dns_present"]) && !truth(t["dns_uncertain"]) {
					excluded++
				}
				if t["status"] == "stale" {
					stale++
				}
			}
			result["pools"], result["targets"], result["healthy"], result["excluded"], result["stale"] = num(a.s.one("SELECT COUNT(*) n FROM pools")["n"]), len(views), healthy, excluded, stale
			return result
		})
	})
	a.route("POST /api/integrations/cloudflare/test", "ui", func(w http.ResponseWriter, r *http.Request) any {
		_, e := a.cloudflare().zones()
		mustErr(e)
		return row{"ok": true, "message": "Cloudflare zone access verified"}
	})
	a.route("POST /api/integrations/remnawave/test", "ui", func(w http.ResponseWriter, r *http.Request) any {
		_, e := a.remnawave().nodes()
		mustErr(e)
		return row{"ok": true, "message": "Remnawave read access verified"}
	})
	a.route("GET /api/cloudflare/zones", "ui", func(w http.ResponseWriter, r *http.Request) any {
		rows, e := a.cloudflare().zones()
		mustErr(e)
		return rows
	})
	a.route("GET /api/remnawave/nodes", "ui", func(w http.ResponseWriter, r *http.Request) any {
		rows, e := a.remnawave().nodes()
		mustErr(e)
		return rows
	})
	a.route("GET /api/remnawave/hosts", "ui", func(w http.ResponseWriter, r *http.Request) any {
		rows, e := a.remnawave().hosts()
		mustErr(e)
		return rows
	})
	a.poolRoutes()
	a.subscriptionRoutes()
	a.agentRoutes()
	a.route("GET /api/events", "ui", func(w http.ResponseWriter, r *http.Request) any {
		limit := 100
		if values, ok := r.URL.Query()["limit"]; ok {
			n, e := strconv.Atoi(values[0])
			if e != nil {
				invalid("request")
			}
			limit = max(1, min(n, 500))
		}
		return a.withStore(func() any {
			conditions := []string{}
			args := []any{}
			for _, key := range []string{"level", "type", "pool_id"} {
				if values, ok := r.URL.Query()[key]; ok {
					conditions = append(conditions, key+"=?")
					args = append(args, values[0])
				}
			}
			query := "SELECT * FROM events"
			if len(conditions) > 0 {
				query += " WHERE " + strings.Join(conditions, " AND ")
			}
			query += " ORDER BY created_at DESC LIMIT ?"
			args = append(args, limit)
			return a.s.all(query, args...)
		})
	})
}
