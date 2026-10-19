-- Golden SQLite fixture generated with the retired Python Store schema and
-- cryptography.fernet.Fernet (SHA256(APP_SECRET) -> URL-safe base64 key).
-- APP_SECRET = S repeated 32; username = админ; password = пароль.
-- Session raw cookie = python-session-cookie-v1; expires 2100-01-01 UTC.
-- Tokens are inert fixture values. DNS observation deferred beyond test lifetime;
-- no test is allowed to send requests to Cloudflare or Remnawave.
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE sessions (token TEXT PRIMARY KEY, username TEXT, expires REAL);
CREATE TABLE pools (id TEXT PRIMARY KEY, name TEXT, hostname TEXT UNIQUE, zone_id TEXT, ttl INTEGER, interval_seconds INTEGER, failure_threshold INTEGER, recovery_threshold INTEGER, automation_enabled INTEGER, profile TEXT, revision INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE targets (id TEXT PRIMARY KEY, pool_id TEXT REFERENCES pools(id), name TEXT, ip TEXT, remnawave_uuid TEXT, manual_enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'unknown', dns_present INTEGER DEFAULT 1, failures INTEGER DEFAULT 0, successes INTEGER DEFAULT 0, last_checked_at TEXT, last_latency_ms REAL, last_error TEXT, next_due REAL DEFAULT 0);
CREATE TABLE agents (id TEXT PRIMARY KEY, last_seen REAL, healthy INTEGER);
CREATE TABLE jobs (id TEXT PRIMARY KEY, target_id TEXT REFERENCES targets(id) ON DELETE CASCADE, agent_id TEXT, revision INTEGER, issued REAL, expires REAL, consumed INTEGER DEFAULT 0);
CREATE UNIQUE INDEX target_active_job ON jobs(target_id) WHERE consumed=0;
CREATE TABLE events (id TEXT PRIMARY KEY, created_at TEXT, level TEXT, type TEXT, message TEXT, pool_id TEXT, target_id TEXT);
ALTER TABLE pools ADD COLUMN dns_next_check REAL DEFAULT 0;
INSERT INTO settings VALUES ('auth_revision','69e42474fcc2d052a015b91aeb03ff361edfc5f51114c849e5327b205ad27aa0');
INSERT INTO settings VALUES ('cloudflare_api_token','gAAAAABq1eK_wDtOEghog5Uq2q1rE3p3XJ-tRIFSe081sgX5khQqPijou7Mi6nbLV1_WNnUOxeiZKZA2qItqeZxC0lKx4nZ4BjJy4foGfo-cnoYWTiHvY2s=');
INSERT INTO settings VALUES ('remnawave_url','gAAAAABq1eK_4MST_6OtKfr8Zf3LJtkUvwrDNg5OXwge0wndZVcrpFoodt6GEQsa_Oin7Nqc3CH6RgKde9QrTOFiJL1CEGQt_NwAt9x8vAwdhB1MgufS7Oo=');
INSERT INTO settings VALUES ('remnawave_api_token','gAAAAABq1eK_yAgjzbzP5gq6tXJ-msdxNQc1yfuZk_g3aFanBFxt0BXtrUKmWvMNAkKOQPA6bXySOUG6kjLCJUokFPg8PTP42PYcvSRchQ2r7ZOmr32D5DA=');
INSERT INTO sessions VALUES ('218af1ba600a5687594ee9c3164cd35236fc26e3f0883420923788039da8e160','админ',4102444800);
INSERT INTO pools (id,name,hostname,zone_id,ttl,interval_seconds,failure_threshold,recovery_threshold,automation_enabled,profile,revision,created_at,dns_next_check) VALUES ('legacy-pool','Legacy pool','legacy.example.com','zone',120,60,3,2,0,'gAAAAABq1eK_bFOo54fLpqOCRJ9vE7YaFVANa1jwqyqCYz2-ny0ApmxRlSZD4BlIN4W2I3caC5MjqvV1aaGA3m7YgjlrncIqdj47HOY9m5Nc5fbmxBAgewoh0EudBTriU_UaBCl5hp5CISwriGEbZR8VbJr57XghKa5mZphN-sbnlohTRYniAK_G7t41krYzL_T0dkgkRKrE5YyKuM1LSJQoaqR_HZ2AfTsiESynK0n-fIjDkI49ENIYM2qTozPfvs8Nvxznv-RnCexJa6dyGdap-rcP1w1dgFAad0t3SAHj0jTqcIf8RMXnM_XuVcO9f5CEGeOXwDjKrfSUCta431JtPFKT071xBcc_FUdeWadR1f-hKpMaMVmGUIapRHcrGdCkP4gIElevllpOFi8pOtzoJxTgiF-CXw==',3,'2026-01-01T00:00:00Z',4102444800);
INSERT INTO targets (id,pool_id,name,ip,manual_enabled,status,dns_present,failures,successes,next_due) VALUES ('legacy-target','legacy-pool','Legacy target','1.1.1.1',1,'suspect',1,1,0,0);
INSERT INTO events VALUES ('legacy-event','2099-01-01T00:00:00Z','info','manual','Legacy event','legacy-pool','legacy-target');
