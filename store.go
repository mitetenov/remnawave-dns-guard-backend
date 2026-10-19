package guard

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type row map[string]any

func str(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
func num(v any) float64 {
	switch n := v.(type) {
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case float64:
		return n
	case bool:
		if n {
			return 1
		}
	}
	return 0
}
func truth(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		return s != ""
	}
	return num(v) != 0
}
func iso(t time.Time) string          { return t.UTC().Format("2006-01-02T15:04:05.000000Z") }
func nowSeconds() float64             { return float64(time.Now().UnixNano()) / 1e9 }
func fromSeconds(t float64) time.Time { return time.Unix(0, int64(t*1e9)) }

type Store struct {
	mu     sync.Mutex
	db     *sql.DB
	cipher fernet
}

func openStore(c Config) (*Store, error) {
	if c.DatabasePath != ":memory:" {
		if e := os.MkdirAll(filepath.Dir(c.DatabasePath), 0700); e != nil {
			return nil, e
		}
	}
	db, e := sql.Open("sqlite", c.DatabasePath)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, cipher: newFernet(c.AppSecret)}
	if e = s.initialize(c); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) exec(q string, args ...any) sql.Result {
	r, e := s.db.Exec(q, args...)
	if e != nil {
		panic(e)
	}
	return r
}
func (s *Store) all(q string, args ...any) []row {
	rows, e := s.db.Query(q, args...)
	if e != nil {
		panic(e)
	}
	defer rows.Close()
	cols, e := rows.Columns()
	if e != nil {
		panic(e)
	}
	result := []row{}
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if e = rows.Scan(ptrs...); e != nil {
			panic(e)
		}
		r := row{}
		for i, k := range cols {
			if b, ok := values[i].([]byte); ok {
				r[k] = string(b)
			} else {
				r[k] = values[i]
			}
		}
		result = append(result, r)
	}
	if e = rows.Err(); e != nil {
		panic(e)
	}
	return result
}
func (s *Store) one(q string, args ...any) row {
	rows := s.all(q, args...)
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

// Caller holds mu. A SAVEPOINT keeps durable intent and state atomic and allows nesting.
func (s *Store) transaction(fn func()) {
	name := "tx_" + digest(uid())[:16]
	s.exec("SAVEPOINT " + name)
	defer func() {
		if p := recover(); p != nil {
			s.exec("ROLLBACK TO " + name)
			s.exec("RELEASE " + name)
			panic(p)
		}
	}()
	fn()
	s.exec("RELEASE " + name)
}
func (s *Store) get(key string) string {
	r := s.one("SELECT value FROM settings WHERE key=?", key)
	if r == nil {
		return ""
	}
	plain, e := s.cipher.decrypt(str(r["value"]))
	if e != nil {
		panic(e)
	}
	return string(plain)
}
func (s *Store) set(key, value string) {
	s.exec("INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, s.cipher.encrypt([]byte(value)))
}
func (s *Store) encrypt(value any) string {
	plain, e := json.Marshal(value)
	if e != nil {
		panic(e)
	}
	return s.cipher.encrypt(plain)
}
func (s *Store) profile(p row) Profile {
	plain, e := s.cipher.decrypt(str(p["profile"]))
	if e != nil {
		panic(e)
	}
	out := defaultProfile()
	if e = json.Unmarshal(plain, &out); e != nil {
		panic(e)
	}
	return out
}
func (s *Store) event(level, kind, message string, poolID, targetID any) {
	s.exec("INSERT INTO events VALUES (?,?,?,?,?,?,?)", uid(), iso(time.Now()), level, kind, message, poolID, targetID)
	s.exec("DELETE FROM events WHERE created_at < ?", iso(time.Now().Add(-30*24*time.Hour)))
	s.exec("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY created_at DESC LIMIT -1 OFFSET 100000)")
}
func (s *Store) initialize(c Config) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("database initialization failed: %w", safeDBError(p))
		}
	}()
	s.exec("PRAGMA journal_mode=WAL")
	s.exec("PRAGMA foreign_keys=ON")
	s.exec("PRAGMA busy_timeout=10000")
	s.exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, expires REAL);
 CREATE TABLE IF NOT EXISTS pools (id TEXT PRIMARY KEY, name TEXT, hostname TEXT UNIQUE, zone_id TEXT, ttl INTEGER, interval_seconds INTEGER, failure_threshold INTEGER, recovery_threshold INTEGER, automation_enabled INTEGER, profile TEXT, revision INTEGER DEFAULT 0, created_at TEXT);
 CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY, pool_id TEXT REFERENCES pools(id), name TEXT, ip TEXT, remnawave_uuid TEXT, manual_enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'unknown', dns_present INTEGER DEFAULT 1, dns_uncertain INTEGER DEFAULT 0, failures INTEGER DEFAULT 0, successes INTEGER DEFAULT 0, last_checked_at TEXT, last_latency_ms REAL, last_error TEXT, next_due REAL DEFAULT 0, last_agent_id TEXT, UNIQUE(pool_id,ip));
 CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, last_seen REAL, healthy INTEGER);
 CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, target_id TEXT REFERENCES targets(id) ON DELETE CASCADE, agent_id TEXT, revision INTEGER, issued REAL, expires REAL, consumed INTEGER DEFAULT 0);
 CREATE UNIQUE INDEX IF NOT EXISTS target_active_job ON jobs(target_id) WHERE consumed=0;
 CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, created_at TEXT, level TEXT, type TEXT, message TEXT, pool_id TEXT, target_id TEXT);`)
	migrations := map[string]map[string]string{"targets": {"dns_uncertain": "INTEGER DEFAULT 0", "last_agent_id": "TEXT", "dns_new_ip": "TEXT", "dns_replace_present": "INTEGER", "dns_action": "TEXT", "dns_operation_id": "TEXT", "dns_previous_enabled": "INTEGER", "dns_profile_revision": "INTEGER", "dns_next_retry": "REAL DEFAULT 0", "dns_error": "TEXT", "dns_checked_at": "TEXT", "dns_drift": "INTEGER DEFAULT 0"}, "pools": {"dns_checked_at": "TEXT", "dns_error": "TEXT", "dns_next_check": "REAL DEFAULT 0", "dns_drift_count": "INTEGER DEFAULT 0"}}
	for table, columns := range migrations {
		existing := map[string]bool{}
		for _, r := range s.all("PRAGMA table_info(" + table + ")") {
			existing[str(r["name"])] = true
		}
		for name, definition := range columns {
			if !existing[name] {
				s.exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)
			}
		}
	}
	revision := authRevision(c)
	previous := s.one("SELECT value FROM settings WHERE key='auth_revision'")
	if previous == nil || !constantEqual(str(previous["value"]), revision) {
		s.transaction(func() {
			s.exec("DELETE FROM sessions")
			s.exec("INSERT INTO settings VALUES ('auth_revision',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", revision)
		})
	}
	s.exec("CREATE INDEX IF NOT EXISTS events_by_time ON events(created_at)")
	for key, value := range map[string]string{"cloudflare_api_token": c.CloudflareAPIToken, "remnawave_url": c.RemnawaveURL, "remnawave_api_token": c.RemnawaveAPIToken} {
		if value != "" && s.one("SELECT key FROM settings WHERE key=?", key) == nil {
			s.set(key, value)
		}
	}
	return nil
}
func safeDBError(p any) error { return fmt.Errorf("cannot open or migrate SQLite database") }
