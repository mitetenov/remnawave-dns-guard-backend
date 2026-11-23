package guard

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestReplacementNotificationsFollowProviderStages(t *testing.T) {
	for _, tc := range []struct {
		provider, name string
		want           []string
	}{
		{"upcloud", "UpCloud", []string{"Автозамена запущена", "Старый сервер удалён", "Новый сервер заказан", "Новый сервер готов"}},
		{"virtua", "Virtua.Cloud", []string{"Автозамена запущена", "Новый сервер заказан", "Новый сервер готов", "Старый сервер удалён"}},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			s := probeRefreshStore(t, 60)
			insert := func(id string) {
				s.exec(`INSERT INTO replacement_jobs(id,target_id,pool_id,name,provider,server_uuid,node_uuid,old_ip,stage,created_at,updated_at)
 VALUES(?,?,'pool','Node',?,'old-server','node','8.8.8.8','preflight','now','now')`, id, id, tc.provider)
			}
			insert("paused")
			s.exec("UPDATE replacement_jobs SET stage='provision' WHERE id='paused'")
			s.exec("UPDATE replacement_jobs SET new_server_uuid='paused-server' WHERE id='paused'")
			s.exec("UPDATE notification_control SET enabled=1")
			s.set("telegram_bot_token", "123456:test-token")
			s.set("telegram_chat_id", "-10012345678")
			insert("replacement")
			advance := func(stage string) {
				s.setReplacementStage(row{"id": "replacement", "pool_id": "pool", "target_id": "replacement"}, stage)
			}
			if tc.provider == "upcloud" {
				advance("retire")
			}
			advance("provision")
			for range 2 {
				s.exec("UPDATE replacement_jobs SET new_server_uuid='new-server' WHERE id='replacement'")
			}
			s.exec("UPDATE replacement_jobs SET new_ip='1.1.1.1' WHERE id='replacement'")
			for _, stage := range []string{"ansible", "remnawave", "verify", "dns", "verify", "dns", "cleanup", "complete"} {
				advance(stage)
			}

			// Startup must preserve pending replacement messages and their order.
			s.initializeNotifications()
			var sent []string
			n := newNotifier(s, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body row
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["chat_id"] != "-10012345678" {
					t.Fatalf("unexpected Telegram payload: %v (%v)", body, err)
				}
				sent = append(sent, str(body["text"]))
				return response(row{"ok": true}, http.StatusOK), nil
			})})
			defer n.close()
			for range len(tc.want) + 1 {
				n.runOnce()
			}
			if len(sent) != len(tc.want) {
				t.Fatalf("expected %d messages; got %q", len(tc.want), sent)
			}
			for i, title := range tc.want {
				if !strings.HasPrefix(sent[i], "DNS Guard · "+title) || !strings.Contains(sent[i], "Провайдер: "+tc.name) ||
					!strings.Contains(sent[i], "Операция: replacement") || !strings.Contains(sent[i], "Старый IP: 8.8.8.8") {
					t.Fatalf("unexpected notification %d: %q", i, sent[i])
				}
				if title == "Новый сервер готов" && !strings.Contains(sent[i], "Новый IP: 1.1.1.1") {
					t.Fatalf("ready notification is missing its IPv4: %q", sent[i])
				}
			}
		})
	}
}
