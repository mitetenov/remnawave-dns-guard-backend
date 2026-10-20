package guard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const telegramTestToken = "123456789:telegram_test_secret"

func configureTelegram(e *testEnv, chat string) {
	e.do("PUT", "/api/notifications/telegram", row{"enabled": true, "bot_token": telegramTestToken, "chat_id": chat}, 200)
}

func captureTelegram(e *testEnv) *[]row {
	messages := []row{}
	e.app.notifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.telegram.org" || r.URL.Path != "/bot"+telegramTestToken+"/sendMessage" || r.Method != "POST" {
			e.t.Errorf("unexpected Telegram request")
		}
		var body row
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			e.t.Error(err)
		}
		messages = append(messages, body)
		return response(row{"ok": true, "result": row{"message_id": 1}}, 200), nil
	})
	return &messages
}

func TestTelegramSettingsEncryptedPauseAndRestart(t *testing.T) {
	e := newTestEnv(t)
	initial := asRow(e.do("GET", "/api/notifications/telegram", nil, 200))
	if truth(initial["enabled"]) || truth(initial["bot_token_configured"]) {
		t.Fatal(initial)
	}
	configureTelegram(e, "-1001234567890")
	e.do("PUT", "/api/notifications/telegram", row{"enabled": false}, 200)
	e.restart(false)
	saved := asRow(e.do("GET", "/api/notifications/telegram", nil, 200))
	b, _ := json.Marshal(saved)
	if strings.Contains(string(b), telegramTestToken) || saved["enabled"] != false || saved["bot_token_configured"] != true || saved["chat_id"] != "-1001234567890" {
		t.Fatal(saved)
	}
	if str(e.one("SELECT value FROM settings WHERE key='telegram_bot_token'")["value"]) == telegramTestToken {
		t.Fatal("token stored in plaintext")
	}
	if str(e.one("SELECT value FROM settings WHERE key='telegram_chat_id'")["value"]) == "-1001234567890" {
		t.Fatal("chat stored in plaintext")
	}
	e.do("PUT", "/api/notifications/telegram", row{"enabled": true, "bot_token": ""}, 200)
	if !truth(asRow(e.do("GET", "/api/notifications/telegram", nil, 200))["enabled"]) {
		t.Fatal("resume failed")
	}
}

func TestTelegramTestUsesDraftWithoutSaving(t *testing.T) {
	e := newTestEnv(t)
	messages := captureTelegram(e)
	for _, chat := range []string{"123456789", "-1001234567890", "-123456789"} {
		e.do("POST", "/api/notifications/telegram/test", row{"bot_token": telegramTestToken, "chat_id": chat}, 200)
		if (*messages)[len(*messages)-1]["chat_id"] != chat {
			t.Fatal("chat ID changed")
		}
	}
	if truth(asRow(e.do("GET", "/api/notifications/telegram", nil, 200))["bot_token_configured"]) {
		t.Fatal("test saved draft")
	}
	configureTelegram(e, "123456789")
	e.do("PUT", "/api/notifications/telegram", row{"enabled": false}, 200)
	e.do("POST", "/api/notifications/telegram/test", row{"chat_id": "-1001234567890"}, 200)
	if asRow(e.do("GET", "/api/notifications/telegram", nil, 200))["chat_id"] != "123456789" {
		t.Fatal("test changed destination")
	}
}

func TestTelegramValidationAndAuthentication(t *testing.T) {
	e := newTestEnv(t)
	for _, chat := range []string{"0", "1.5", "123abc", "@group", "9223372036854775808"} {
		e.do("PUT", "/api/notifications/telegram", row{"bot_token": telegramTestToken, "chat_id": chat}, 422)
	}
	e.do("PUT", "/api/notifications/telegram", row{"enabled": true}, 422)
	e.do("POST", "/api/notifications/telegram/test", row{"bot_token": "123:../token", "chat_id": "123"}, 422)
	e.do("PUT", "/api/notifications/telegram", row{"enabled": nil}, 422)
	for _, method := range []string{"GET", "PUT", "POST"} {
		path := "/api/notifications/telegram"
		if method == "POST" {
			path += "/test"
		}
		req, _ := http.NewRequest(method, e.server.URL+path, strings.NewReader(`{}`))
		req.Header.Set("X-Requested-With", "DNSGuard")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("unauthenticated %s: %d", method, resp.StatusCode)
		}
	}
}

func TestTelegramStatusTransitionsNoRepeatsAndPause(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(1, false, 2, 2)
	messages := captureTelegram(e)
	configureTelegram(e, "-1001234567890")
	e.round(p, true, "")
	e.round(p, true, "")
	if len(*messages) != 1 || !strings.Contains(str((*messages)[0]["text"]), "Ожидает проверки → Доступен") {
		t.Fatal(*messages)
	}
	e.round(p, false, "connection_failed")
	e.round(p, false, "connection_failed")
	if len(*messages) != 2 || !strings.Contains(str((*messages)[1]["text"]), "Доступен → Под подозрением") {
		t.Fatal(*messages)
	}
	e.sql("UPDATE targets SET last_checked_at=? WHERE id=?", iso(time.Now().Add(-time.Hour)), targets[0]["id"])
	e.app.notifier.runOnce()
	e.app.notifier.runOnce()
	if len(*messages) != 3 || !strings.Contains(str((*messages)[2]["text"]), "Под подозрением → Нет свежих данных") {
		t.Fatal(*messages)
	}
	e.round(p, true, "")
	if len(*messages) != 4 || !strings.Contains(str((*messages)[3]["text"]), "Нет свежих данных → Доступен") {
		t.Fatal(*messages)
	}
	e.do("PUT", "/api/notifications/telegram", row{"enabled": false}, 200)
	e.round(p, false, "connection_failed")
	e.do("PUT", "/api/notifications/telegram", row{"enabled": true}, 200)
	e.app.notifier.runOnce()
	if len(*messages) != 4 {
		t.Fatal("pause replayed messages", *messages)
	}
	e.round(p, true, "")
	if len(*messages) != 5 {
		t.Fatal("resume did not deliver transition", *messages)
	}
}

func TestTelegramQueueAtomicRetryAndRestart(t *testing.T) {
	e := newTestEnv(t)
	_, targets := e.setup(1, false, 2, 2)
	configureTelegram(e, "123456789")
	func() {
		defer func() { _ = recover() }()
		e.app.withStore(func() any {
			e.app.s.transaction(func() {
				e.app.s.exec("UPDATE targets SET status='disabled' WHERE id=?", targets[0]["id"])
				panic("rollback")
			})
			return nil
		})
	}()
	if num(e.one("SELECT COUNT(*) n FROM notification_outbox")["n"]) != 0 {
		t.Fatal("notification escaped transaction")
	}
	e.sql("UPDATE targets SET status='disabled',manual_enabled=0 WHERE id=?", targets[0]["id"])
	e.restart(false)
	e.app.notifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, errors.New("secret URL: " + r.URL.String()) })
	e.app.notifier.runOnce()
	q := e.one("SELECT * FROM notification_outbox")
	if num(q["attempts"]) != 1 || num(q["next_retry"]) <= nowSeconds() {
		t.Fatal(q)
	}
	for _, event := range asRows(e.do("GET", "/api/events", nil, 200)) {
		if strings.Contains(str(event["message"]), telegramTestToken) {
			t.Fatal("token leaked")
		}
	}
	messages := captureTelegram(e)
	e.app.notifier.runOnce()
	if len(*messages) != 0 {
		t.Fatal("retry ignored backoff")
	}
	e.sql("UPDATE notification_outbox SET next_retry=0")
	e.app.notifier.runOnce()
	if len(*messages) != 1 || num(e.one("SELECT COUNT(*) n FROM notification_outbox")["n"]) != 0 {
		t.Fatal("retry failed")
	}
}

func TestTelegramFailureDoesNotHoldStoreLock(t *testing.T) {
	e := newTestEnv(t)
	_, targets := e.setup(1, false, 2, 2)
	configureTelegram(e, "123456789")
	e.sql("UPDATE targets SET status='disabled',manual_enabled=0 WHERE id=?", targets[0]["id"])
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	e.app.notifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return response(row{"ok": true}, 200), nil
	})
	done := make(chan struct{})
	go func() { defer close(done); e.app.notifier.runOnce() }()
	<-entered
	e.do("GET", "/api/notifications/telegram", nil, 200)
	e.do("PUT", "/api/notifications/telegram", row{"enabled": false}, 200)
	once.Do(func() { close(release) })
	<-done
	if num(e.one("SELECT COUNT(*) n FROM notification_outbox")["n"]) != 0 {
		t.Fatal("pause retained pending message")
	}
}

func TestTelegramErrorsAreSafe(t *testing.T) {
	e := newTestEnv(t)
	for _, status := range []int{400, 401, 403, 404, 429, 500} {
		e.app.notifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return response(row{"ok": false, "error_code": status, "description": telegramTestToken}, status), nil
		})
		out := e.do("POST", "/api/notifications/telegram/test", row{"bot_token": telegramTestToken, "chat_id": "123"}, 502)
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), telegramTestToken) {
			t.Fatal("error leaked token")
		}
	}
}

func TestTelegramAutomaticDNSTransitions(t *testing.T) {
	e := newTestEnv(t)
	p, targets := e.setup(2, true, 1, 1)
	messages := captureTelegram(e)
	configureTelegram(e, "-1001234567890")
	e.round(p, true, "")
	e.do("POST", "/api/pools/"+str(p["id"])+"/check", nil, 200)
	jobs := e.poll(true, "ru-1")
	for _, job := range jobs {
		if job["target_id"] == targets[0]["id"] {
			e.result(job, false, "ru-1", "connection_failed")
		}
	}
	e.app.notifier.runOnce()
	texts := ""
	for _, v := range *messages {
		texts += str(v["text"]) + "\n"
	}
	if !strings.Contains(texts, "Доступен → Под подозрением") || !strings.Contains(texts, "Под подозрением → Исключён") {
		t.Fatal(texts)
	}
	// Complete the other lease before requesting recovery.
	for _, job := range jobs {
		if job["target_id"] != targets[0]["id"] {
			e.result(job, true, "ru-1", "")
		}
	}
	e.round(p, true, "")
	e.app.notifier.runOnce()
	texts = ""
	for _, v := range *messages {
		texts += str(v["text"]) + "\n"
	}
	if !strings.Contains(texts, "Исключён → Восстанавливается") || !strings.Contains(texts, "Восстанавливается → Доступен") {
		t.Fatal(texts)
	}
}

func TestTelegramRespectsRateLimit(t *testing.T) {
	e := newTestEnv(t)
	_, targets := e.setup(1, false, 2, 2)
	configureTelegram(e, "123456789")
	e.sql("UPDATE targets SET status='disabled',manual_enabled=0 WHERE id=?", targets[0]["id"])
	e.app.notifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(row{"ok": false, "error_code": 429, "parameters": row{"retry_after": 120}}, 429), nil
	})
	start := nowSeconds()
	e.app.notifier.runOnce()
	if num(e.one("SELECT next_retry FROM notification_outbox")["next_retry"]) < start+120 {
		t.Fatal("ignored Telegram retry_after")
	}
}
