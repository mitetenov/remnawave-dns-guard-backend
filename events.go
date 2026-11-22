package guard

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type eventCursor struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func (s *Store) initializeEventIndexes() {
	s.exec("CREATE INDEX IF NOT EXISTS events_by_time_and_id ON events(created_at, id)")
	s.exec("CREATE INDEX IF NOT EXISTS events_by_target_and_time ON events(target_id, created_at, id)")
	s.exec("DROP INDEX IF EXISTS events_by_time")
}

func decodeEventCursor(value string) eventCursor {
	var cursor eventCursor
	if len(value) > 1024 {
		invalid("cursor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(payload, &cursor) != nil || cursor.ID == "" {
		invalid("cursor")
	}
	if _, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt); err != nil {
		invalid("cursor")
	}
	return cursor
}

func (a *App) eventsRoute(_ http.ResponseWriter, r *http.Request) any {
	params := r.URL.Query()
	limit := 100
	if values, ok := params["limit"]; ok {
		n, e := strconv.Atoi(values[0])
		if e != nil {
			invalid("request")
		}
		limit = max(1, min(n, 500))
	}
	paginated := params.Get("paginated") == "1"
	if value := params.Get("paginated"); value != "" && value != "0" && !paginated {
		invalid("paginated")
	}
	conditions := []string{}
	args := []any{}
	for _, key := range []string{"level", "type", "pool_id", "target_id"} {
		if values, ok := params[key]; ok {
			conditions = append(conditions, key+"=?")
			args = append(args, values[0])
		}
	}
	if params.Has("cursor") {
		if !paginated {
			invalid("cursor")
		}
		cursor := decodeEventCursor(params.Get("cursor"))
		conditions = append(conditions, "(created_at,id)<(?,?)")
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	query := "SELECT * FROM events"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC,id DESC LIMIT ?"
	queryLimit := limit
	if paginated {
		queryLimit++
	}
	args = append(args, queryLimit)
	events := a.withStore(func() any { return a.s.all(query, args...) }).([]row)
	if !paginated {
		return events
	}
	var next any
	if len(events) > limit {
		events = events[:limit]
		last := events[len(events)-1]
		cursor := eventCursor{CreatedAt: str(last["created_at"]), ID: str(last["id"])}
		payload, err := json.Marshal(cursor)
		mustErr(err)
		next = base64.RawURLEncoding.EncodeToString(payload)
	}
	return row{"events": events, "next_cursor": next}
}
