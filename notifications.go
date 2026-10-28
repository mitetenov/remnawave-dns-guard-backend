package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TelegramSettings struct {
	Enabled  *bool   `json:"enabled"`
	BotToken *string `json:"bot_token"`
	ChatID   *string `json:"chat_id"`
}

var telegramTokenPattern = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
var telegramChatPattern = regexp.MustCompile(`^-?[1-9][0-9]*$`)

func validateTelegram(token, chat string) {
	if !textLength(token, 3, 256) || !telegramTokenPattern.MatchString(token) {
		fail(422, "Введите корректный токен Telegram-бота в формате 123456:ABC…")
	}
	id, err := strconv.ParseInt(chat, 10, 64)
	if err != nil || id == 0 || !telegramChatPattern.MatchString(chat) {
		fail(422, "Chat ID должен быть числом: положительным для ЛС или отрицательным для группы, например -1001234567890")
	}
}

func (a *App) telegramView() row {
	return row{"enabled": truth(a.s.one("SELECT enabled FROM notification_control WHERE id=1")["enabled"]), "bot_token_configured": a.s.get("telegram_bot_token") != "", "chat_id": a.s.get("telegram_chat_id")}
}

// Empty token means keep the saved secret, including when testing an edited chat.
func (a *App) telegramCredentials(data TelegramSettings) (string, string) {
	token, chat := a.s.get("telegram_bot_token"), a.s.get("telegram_chat_id")
	if data.BotToken != nil && strings.TrimSpace(*data.BotToken) != "" {
		token = strings.TrimSpace(*data.BotToken)
	}
	if data.ChatID != nil {
		chat = strings.TrimSpace(*data.ChatID)
	}
	return token, chat
}

func (a *App) notificationRoutes() {
	a.route("GET /api/notifications/telegram", "ui", func(w http.ResponseWriter, r *http.Request) any {
		return a.withStore(func() any { return a.telegramView() })
	})
	a.route("PUT /api/notifications/telegram", "ui", func(w http.ResponseWriter, r *http.Request) any {
		data := TelegramSettings{}
		bodyObject(w, r, &data, nil)
		return a.withStore(func() any {
			token, chat := a.telegramCredentials(data)
			enabled := truth(a.s.one("SELECT enabled FROM notification_control WHERE id=1")["enabled"])
			if data.Enabled != nil {
				enabled = *data.Enabled
			}
			if enabled || token != "" || chat != "" {
				validateTelegram(token, chat)
			}
			a.s.transaction(func() {
				changed := enabled != truth(a.s.one("SELECT enabled FROM notification_control WHERE id=1")["enabled"]) || token != a.s.get("telegram_bot_token") || chat != a.s.get("telegram_chat_id")
				a.s.set("telegram_bot_token", token)
				a.s.set("telegram_chat_id", chat)
				if changed {
					// A pause or destination change discards pending messages. Resuming
					// starts from the current state instead of replaying old changes.
					a.s.exec("DELETE FROM notification_outbox")
					a.s.exec(notificationBaselineSQL)
				}
				a.s.exec("UPDATE notification_control SET enabled=? WHERE id=1", enabled)
				a.s.event("info", "system", "Telegram notification settings updated", nil, nil)
			})
			return a.telegramView()
		})
	})
	a.route("POST /api/notifications/telegram/test", "ui", func(w http.ResponseWriter, r *http.Request) any {
		data := TelegramSettings{}
		bodyObject(w, r, &data, nil)
		var token, chat string
		a.withStore(func() any { token, chat = a.telegramCredentials(data); return nil })
		validateTelegram(token, chat)
		if err := a.notifier.send(r.Context(), token, chat, "DNS Guard · Тестовое уведомление\nTelegram подключён. Сюда будут приходить изменения статусов хостов."); err != nil {
			fail(502, err.Error())
		}
		return row{"ok": true, "message": "Тестовое сообщение отправлено в Telegram."}
	})
}

// The worker refreshes the same Go projection as targetViews before reading
// this view, including transitions caused by checker heartbeat expiry.
func (s *Store) initializeNotifications() {
	s.exec(`CREATE TABLE IF NOT EXISTS notification_control (id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0);
 INSERT OR IGNORE INTO notification_control VALUES (1,0);
 CREATE TABLE IF NOT EXISTS notification_target_status (target_id TEXT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE, status TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS notification_outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, target_name TEXT, ip TEXT, pool_name TEXT, hostname TEXT, previous_status TEXT, status TEXT, created_at TEXT, attempts INTEGER DEFAULT 0, next_retry REAL DEFAULT 0);
 DROP TRIGGER IF EXISTS notification_target_insert;
 DROP TRIGGER IF EXISTS notification_target_update;
 DROP VIEW IF EXISTS notification_target_states;
 CREATE VIEW notification_target_states AS
 SELECT t.id,t.name AS target_name,t.ip,p.name AS pool_name,p.hostname,t.status
 FROM targets t JOIN pools p ON p.id=t.pool_id;`)
	s.exec(`INSERT INTO notification_target_status SELECT id,status FROM notification_target_states WHERE true ON CONFLICT(target_id) DO NOTHING`)
	s.exec(`CREATE TRIGGER IF NOT EXISTS notification_target_insert AFTER INSERT ON targets BEGIN
 INSERT INTO notification_target_status SELECT id,status FROM notification_target_states WHERE id=NEW.id;
 END;
 CREATE TRIGGER IF NOT EXISTS notification_target_update AFTER UPDATE OF status ON targets BEGIN
 ` + notificationEnqueueSQL + ` AND v.id=NEW.id;
 INSERT INTO notification_target_status SELECT id,status FROM notification_target_states WHERE id=NEW.id
 ON CONFLICT(target_id) DO UPDATE SET status=excluded.status;
 END;`)
}

const notificationBaselineSQL = `INSERT INTO notification_target_status SELECT id,status FROM notification_target_states WHERE true ON CONFLICT(target_id) DO UPDATE SET status=excluded.status WHERE notification_target_status.status!=excluded.status`
const notificationEnqueueSQL = `INSERT INTO notification_outbox (target_name,ip,pool_name,hostname,previous_status,status,created_at)
 SELECT v.target_name,v.ip,v.pool_name,v.hostname,n.status,v.status,strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM notification_target_states v JOIN notification_target_status n ON n.target_id=v.id
 WHERE v.status!=n.status AND (SELECT enabled FROM notification_control WHERE id=1)=1`

type Notifier struct {
	s       *Store
	client  *http.Client
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	started bool
}

func newNotifier(s *Store, client *http.Client) *Notifier {
	ctx, cancel := context.WithCancel(context.Background())
	copy := *client
	copy.Timeout = 10 * time.Second
	return &Notifier{s: s, client: &copy, ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

func (n *Notifier) start() {
	n.started = true
	go func() {
		defer close(n.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
				func() {
					defer func() {
						if recover() != nil {
							log.Print("Telegram notification cycle failed")
						}
					}()
					n.runOnce()
				}()
			}
		}
	}()
}

func (n *Notifier) close() {
	n.cancel()
	if n.started {
		<-n.done
	}
	n.client.CloseIdleConnections()
}

func (n *Notifier) runOnce() {
	n.mu.Lock()
	defer n.mu.Unlock()
	var pending row
	var token, chat string
	func() {
		n.s.mu.Lock()
		defer n.s.mu.Unlock()
		n.s.transaction(func() {
			n.s.refreshProbeTargets()
			n.s.exec(notificationEnqueueSQL)
			n.s.exec(notificationBaselineSQL)
		})
		if !truth(n.s.one("SELECT enabled FROM notification_control WHERE id=1")["enabled"]) {
			return
		}
		// Keep chronological order, and send at most one message per second.
		pending = n.s.one("SELECT * FROM notification_outbox ORDER BY id LIMIT 1")
		if pending == nil || num(pending["next_retry"]) > nowSeconds() {
			pending = nil
			return
		}
		token, chat = n.s.get("telegram_bot_token"), n.s.get("telegram_chat_id")
	}()
	if pending == nil {
		return
	}
	err := n.send(n.ctx, token, chat, notificationMessage(pending))
	if n.ctx.Err() != nil {
		return
	}
	n.s.mu.Lock()
	defer n.s.mu.Unlock()
	if n.s.one("SELECT id FROM notification_outbox WHERE id=?", pending["id"]) == nil {
		return
	}
	if err == nil {
		n.s.exec("DELETE FROM notification_outbox WHERE id=?", pending["id"])
	} else {
		attempts := int(num(pending["attempts"])) + 1
		delay := min(300, 5*(1<<min(attempts, 6)))
		if telegramErr, ok := err.(*telegramError); ok {
			delay = max(delay, telegramErr.retryAfter)
		}
		n.s.exec("UPDATE notification_outbox SET attempts=?,next_retry=? WHERE id=?", attempts, nowSeconds()+float64(delay), pending["id"])
		if attempts == 1 {
			n.s.event("warning", "system", "Telegram: "+err.Error()+" Доставка будет повторена.", nil, nil)
		}
	}
}

func notificationMessage(v row) string {
	names := map[string]string{"unknown": "Ожидает проверки", "healthy": "Доступен", "suspect": "Под подозрением", "excluded": "Исключён", "recovering": "Восстанавливается", "disabled": "Отключён вручную", "protected": "Последний A · защищён", "stale": "Нет свежих данных"}
	return fmt.Sprintf("DNS Guard · Изменение статуса хоста\nХост: %s (%s)\nПул: %s · %s\n%s → %s\nВремя: %s", v["target_name"], v["ip"], v["pool_name"], v["hostname"], names[str(v["previous_status"])], names[str(v["status"])], v["created_at"])
}

type telegramError struct {
	message    string
	retryAfter int
}

func (e *telegramError) Error() string { return e.message }

func (n *Notifier) send(ctx context.Context, token, chat, message string) error {
	body, _ := json.Marshal(row{"chat_id": chat, "text": message})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return integration("Не удалось отправить сообщение в Telegram.")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	// Transport errors include the token-bearing URL. Never expose them.
	if err != nil {
		return integration("Telegram недоступен. Проверьте соединение и повторите попытку.")
	}
	defer resp.Body.Close()
	var result struct {
		OK         bool `json:"ok"`
		ErrorCode  int  `json:"error_code"`
		Parameters struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil {
		return integration("Telegram вернул некорректный ответ.")
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && result.OK {
		return nil
	}
	code := result.ErrorCode
	if code == 0 {
		code = resp.StatusCode
	}
	switch code {
	case 401, 404:
		return integration("Telegram отклонил токен бота. Проверьте токен.")
	case 400:
		return integration("Telegram не принял сообщение. Проверьте Chat ID, запустите бота в ЛС или добавьте его в группу.")
	case 403:
		return integration("Бот не может писать в этот чат. Разблокируйте его или разрешите отправку сообщений в группе.")
	case 429:
		return &telegramError{message: "Telegram временно ограничил отправку. Повторите попытку позже.", retryAfter: max(0, result.Parameters.RetryAfter)}
	default:
		return integration("Не удалось отправить сообщение в Telegram. Повторите попытку позже.")
	}
}
