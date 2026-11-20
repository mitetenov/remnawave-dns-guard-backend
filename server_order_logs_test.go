package guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerOrderLogHistory(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "orders.db"))
	app, err := New(config, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if app != nil {
			_ = app.Close()
		}
	})
	s := app.s
	for serial, id := range []string{"old", "other"} {
		s.exec(`INSERT INTO server_orders(id,request_id,selection_hash,pool_id,pool_hostname,zone_id,ttl,zone,country,plan,quote,
 group_name,profile_id,profile_name,inbounds,serial,alias,domain,created_at,updated_at,snapshot,enroll_digest)
 VALUES(?,?,'hash','pool','pool.test','zone',120,'fra01de','DE','plan','quote','nodes','profile','name','[]',?,?,?,
 '2026-11-20T15:00:00Z','2026-11-20T15:00:00Z','private-snapshot','private-credential')`, id, id, serial, id, id+".test")
	}
	s.exec("UPDATE server_orders SET error='previous error' WHERE id='old'")
	// Simulate the existing order rows seen on an upgrade, before any journal existed.
	s.exec("DELETE FROM server_order_logs WHERE order_id='old'")
	s.initializeOrderLogs()
	s.initializeOrderLogs()
	s.exec("UPDATE server_orders SET error='new diagnostic',updated_at='2026-11-20T15:01:00Z' WHERE id='old'")
	s.exec("UPDATE server_orders SET error='new diagnostic',updated_at='2026-11-20T15:02:00Z' WHERE id='old'")
	s.exec("UPDATE server_orders SET error='other order error' WHERE id='other'")
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	app, err = New(config, Options{})
	if err != nil {
		t.Fatal(err)
	}
	app.s.exec("INSERT INTO sessions(token,username,expires) VALUES(?,'admin',?)", digest("admin-session"), nowSeconds()+300)
	request := func(method, path string, admin bool, status int) string {
		t.Helper()
		req := httptest.NewRequest(method, "/api/server-orders/"+path, nil)
		if admin {
			req.AddCookie(&http.Cookie{Name: "dns_guard_session", Value: "admin-session"})
			req.Header.Set("X-Requested-With", "DNSGuard")
		}
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s returned %d: %s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	request(http.MethodGet, "old/logs", false, http.StatusUnauthorized)
	request(http.MethodGet, "missing/logs", true, http.StatusNotFound)
	request(http.MethodPost, "old/cancel", true, http.StatusOK)
	reply := request(http.MethodGet, "old/logs", true, http.StatusOK)
	var logs []row
	if err := json.Unmarshal([]byte(reply), &logs); err != nil || len(logs) != 3 ||
		logs[0]["stage"] != "cancelled" || logs[1]["message"] != "new diagnostic" ||
		logs[1]["occurrences"] != float64(2) || logs[1]["recorded_at"] != "2026-11-20T15:02:00Z" ||
		logs[2]["message"] != "previous error" || strings.Contains(reply, "private") || strings.Contains(reply, "other order error") {
		t.Fatalf("unexpected history after restart and cancellation: %s", reply)
	}
}
