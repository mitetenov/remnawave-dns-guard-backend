import base64
import contextlib
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4
from cryptography.fernet import Fernet


def iso(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat().replace('+00:00', 'Z')

def uid():
    return str(uuid4())

class Store:
    def __init__(self, config):
        parent = os.path.dirname(config.database_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.db = sqlite3.connect(config.database_path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA busy_timeout=10000')
        self.lock = threading.RLock()
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(config.app_secret.encode()).digest()))
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, expires REAL);
        CREATE TABLE IF NOT EXISTS pools (id TEXT PRIMARY KEY, name TEXT, hostname TEXT UNIQUE, zone_id TEXT, ttl INTEGER, interval_seconds INTEGER, failure_threshold INTEGER, recovery_threshold INTEGER, automation_enabled INTEGER, profile TEXT, revision INTEGER DEFAULT 0, created_at TEXT);
        CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY, pool_id TEXT REFERENCES pools(id), name TEXT, ip TEXT, remnawave_uuid TEXT, manual_enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'unknown', dns_present INTEGER DEFAULT 1, dns_uncertain INTEGER DEFAULT 0, failures INTEGER DEFAULT 0, successes INTEGER DEFAULT 0, last_checked_at TEXT, last_latency_ms REAL, last_error TEXT, next_due REAL DEFAULT 0, last_agent_id TEXT, UNIQUE(pool_id,ip));
        CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, last_seen REAL, healthy INTEGER);
        CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, target_id TEXT REFERENCES targets(id) ON DELETE CASCADE, agent_id TEXT, revision INTEGER, issued REAL, expires REAL, consumed INTEGER DEFAULT 0);
        CREATE UNIQUE INDEX IF NOT EXISTS target_active_job ON jobs(target_id) WHERE consumed=0;
        CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, created_at TEXT, level TEXT, type TEXT, message TEXT, pool_id TEXT, target_id TEXT);
        ''')
        if 'dns_uncertain' not in {r[1] for r in self.db.execute('PRAGMA table_info(targets)')}:
            self.db.execute('ALTER TABLE targets ADD COLUMN dns_uncertain INTEGER DEFAULT 0')
        if 'last_agent_id' not in {r[1] for r in self.db.execute('PRAGMA table_info(targets)')}:
            self.db.execute('ALTER TABLE targets ADD COLUMN last_agent_id TEXT')
        migrations = {
            'targets': {
                'dns_action': 'TEXT', 'dns_operation_id': 'TEXT',
                'dns_previous_enabled': 'INTEGER', 'dns_profile_revision': 'INTEGER',
                'dns_next_retry': 'REAL DEFAULT 0', 'dns_error': 'TEXT',
                'dns_checked_at': 'TEXT', 'dns_drift': 'INTEGER DEFAULT 0',
            },
            'pools': {
                'dns_checked_at': 'TEXT', 'dns_error': 'TEXT',
                'dns_next_check': 'REAL DEFAULT 0', 'dns_drift_count': 'INTEGER DEFAULT 0',
            },
        }
        for table, columns in migrations.items():
            existing = {r[1] for r in self.db.execute(f'PRAGMA table_info({table})')}
            for name, definition in columns.items():
                if name not in existing:
                    self.db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
        # Bind persisted sessions to credentials without storing a password hash usable offline.
        identity = json.dumps([config.username, config.password]).encode()
        revision = hmac.new(config.app_secret.encode(), identity, hashlib.sha256).hexdigest()
        previous = self.one("SELECT value FROM settings WHERE key='auth_revision'")
        if not previous or not hmac.compare_digest(previous['value'], revision):
            with self.transaction():
                self.db.execute('DELETE FROM sessions')
                self.db.execute("INSERT INTO settings VALUES ('auth_revision', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (revision,))
        self.db.execute('CREATE INDEX IF NOT EXISTS events_by_time ON events(created_at)')
        for key in ['cloudflare_api_token','remnawave_url','remnawave_api_token']:
            if getattr(config, key) and not self.one('SELECT key FROM settings WHERE key=?', (key,)):
                self.set(key, getattr(config, key))

    def one(self, sql, args=()):
        row = self.db.execute(sql, args).fetchone()
        return dict(row) if row else None

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            name = 'tx_' + uuid4().hex
            self.db.execute('SAVEPOINT ' + name)
            try:
                yield
            except BaseException:
                self.db.execute('ROLLBACK TO ' + name)
                self.db.execute('RELEASE ' + name)
                raise
            else:
                self.db.execute('RELEASE ' + name)

    def all(self, sql, args=()):
        return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def set(self, key, value):
        encrypted = self.cipher.encrypt(value.encode()).decode()
        self.db.execute('INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, encrypted))

    def get(self, key):
        row = self.one('SELECT value FROM settings WHERE key=?', (key,))
        return self.cipher.decrypt(row['value'].encode()).decode() if row else ''

    def encrypt(self, value):
        return self.cipher.encrypt(json.dumps(value).encode()).decode()

    def profile(self, pool):
        return json.loads(self.cipher.decrypt(pool['profile'].encode()))

    def event(self, level, type_, message, pool_id=None, target_id=None):
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?)', (uid(),iso(),level,type_,message,pool_id,target_id))
        self.db.execute('DELETE FROM events WHERE created_at < ?', (iso(time.time()-30*86400),))
        self.db.execute('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY created_at DESC LIMIT -1 OFFSET 100000)')
