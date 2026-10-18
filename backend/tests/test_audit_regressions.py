import dataclasses
import hashlib
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Config
from backend.store import iso
from test_backend import AH, PROFILE, FakeCloudflare, env, poll, result, round_, setup, targets


def test_legacy_database_migration_preserves_targets_and_revokes_legacy_cookie(tmp_path):
    path = str(tmp_path/'legacy.db')
    with sqlite3.connect(path) as db:
        # The tables from the audited release, before durable DNS intent columns.
        db.executescript('''
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE sessions (token TEXT PRIMARY KEY, username TEXT, expires REAL);
        CREATE TABLE pools (id TEXT PRIMARY KEY, name TEXT, hostname TEXT UNIQUE, zone_id TEXT, ttl INTEGER, interval_seconds INTEGER, failure_threshold INTEGER, recovery_threshold INTEGER, automation_enabled INTEGER, profile TEXT, revision INTEGER DEFAULT 0, created_at TEXT);
        CREATE TABLE targets (id TEXT PRIMARY KEY, pool_id TEXT REFERENCES pools(id), name TEXT, ip TEXT, remnawave_uuid TEXT, manual_enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'unknown', dns_present INTEGER DEFAULT 1, dns_uncertain INTEGER DEFAULT 0, failures INTEGER DEFAULT 0, successes INTEGER DEFAULT 0, last_checked_at TEXT, last_latency_ms REAL, last_error TEXT, next_due REAL DEFAULT 0, last_agent_id TEXT, UNIQUE(pool_id,ip));
        ''')
        db.execute('INSERT INTO sessions VALUES (?,?,?)',(hashlib.sha256(b'legacy-cookie').hexdigest(),'admin',time.time()+3600))
        db.execute('INSERT INTO pools VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',('legacy-pool','Legacy','vpn.example.com','zone',120,60,3,5,0,None,0,iso()))
        db.execute("INSERT INTO targets (id,pool_id,name,ip,status,successes,last_checked_at) VALUES ('legacy-target','legacy-pool','Legacy node','1.1.1.1','healthy',2,?)",(iso(),))
    cfg = Config('admin','password','S'*32,'T'*32,path,False,'http://testserver')
    app = create_app(cfg,background_tasks=False)
    with TestClient(app,headers={'X-Requested-With':'DNSGuard'}) as c:
        c.cookies.set('dns_guard_session','legacy-cookie')
        assert c.get('/api/auth/me').status_code == 401
        c.cookies.clear()
        assert c.post('/api/auth/login',json={'username':'admin','password':'password'}).status_code == 200
        response = c.get('/api/pools/legacy-pool/targets')
        assert response.status_code == 200, response.text
        t = response.json()[0]
        assert t['id'] == 'legacy-target' and t['ip'] == '1.1.1.1' and t['successes'] == 2
        assert t['status'] == 'stale' and t['last_status'] == 'healthy'
        assert t['dns_pending_action'] is None and not t['dns_drift']
        assert app.state.store.one('PRAGMA integrity_check')['integrity_check'] == 'ok'


@pytest.mark.parametrize('action', ['enroll', 'disable', 'enable', 'delete'])
def test_manual_intent_survives_committed_timeout_and_restart(tmp_path, action):
    cfg = Config('admin', 'password', 'S'*32, 'T'*32, str(tmp_path/'guard.db'), False, 'http://testserver', cloudflare_api_token='synthetic')
    fake = FakeCloudflare()
    for phase in range(2):
        app = create_app(cfg, cf_factory=lambda _: fake.adapter, background_tasks=False)
        with TestClient(app, headers={'X-Requested-With':'DNSGuard'}) as c:
            c.post('/api/auth/login', json={'username':'admin','password':'password'})
            store = app.state.store
            if phase == 0:
                p, ts = setup(c, auto=False)
                tid = ts[0]['id']
                if action == 'enable':
                    assert c.post(f'/api/targets/{tid}/disable').status_code == 200
                fake.fail = 'post' if action in ('enroll', 'enable') else 'delete'
                if action == 'enroll':
                    response = c.post(f"/api/pools/{p['id']}/targets", json={'name':'new','ip':'9.9.9.9'})
                    tid = store.one("SELECT id FROM targets WHERE ip='9.9.9.9'")['id']
                else:
                    response = c.delete(f'/api/targets/{tid}') if action == 'delete' else c.post(f'/api/targets/{tid}/{action}')
                assert response.status_code == 502
                t = store.one('SELECT * FROM targets WHERE id=?', (tid,))
                assert t['dns_action'] == action and t['dns_uncertain']
                assert bool(t['manual_enabled']) == (action in ('enroll', 'enable'))
                if action in ('disable','delete'):
                    assert all(j['target_id'] != tid for j in poll(c))
            else:
                fake.fail = None
                store.db.execute('UPDATE targets SET dns_next_retry=0')
                app.state.reconciler.run_once()
                t = store.one('SELECT * FROM targets WHERE id=?', (tid,))
                if action == 'delete':
                    assert t is None
                else:
                    assert not t['dns_uncertain'] and t['dns_action'] is None
                    assert bool(t['dns_present']) == (action in ('enroll','enable'))
                    assert bool(t['manual_enabled']) == (action in ('enroll','enable'))
                assert any(r['content'] == ('9.9.9.9' if action == 'enroll' else ts[0]['ip']) for r in fake.records) == (action in ('enroll','enable'))
    fake.client.close()


@pytest.mark.parametrize('changed', ['password', 'username'])
def test_rotation_revokes_cookie_but_ordinary_restart_preserves_it(tmp_path, changed):
    cfg = Config('admin','password','S'*32,'T'*32,str(tmp_path/'guard.db'),False,'http://testserver')
    cookie = None
    for phase in range(3):
        if phase == 2:
            cfg = dataclasses.replace(cfg, **{changed:'replacement'})
        with TestClient(create_app(cfg, background_tasks=False), headers={'X-Requested-With':'DNSGuard'}) as c:
            if phase == 0:
                assert c.post('/api/auth/login',json={'username':cfg.username,'password':cfg.password}).status_code == 200
                cookie = c.cookies.get('dns_guard_session')
            else:
                c.cookies.set('dns_guard_session',cookie)
                assert c.get('/api/settings').status_code == (200 if phase == 1 else 401)


@pytest.mark.parametrize('kind', ['A','AAAA'])
def test_other_proxied_address_blocks_publication(env, kind):
    c, s, fake, _ = env
    p, _ = setup(c, count=0, auto=False)
    fake.unrelated(hostname=p['hostname'], proxied=True)
    fake.records[-1]['type'] = kind
    fake.records[-1]['content'] = '2606:4700:4700::1111' if kind == 'AAAA' else '9.9.9.9'
    fake.calls.clear()
    response = c.post(f"/api/pools/{p['id']}/targets",json={'name':'new','ip':'1.1.1.1'})
    assert response.status_code == 409
    assert all(method == 'GET' for method, _ in fake.calls)
    assert not any(r['content'] == '1.1.1.1' for r in fake.records)
    assert s.one("SELECT id FROM targets WHERE ip='1.1.1.1'") is None


def test_stale_agent_removes_green_status_without_dns_mutation(env, monkeypatch):
    c, _, fake, _ = env
    p, _ = setup(c)
    round_(c, p, True)
    fake.calls.clear()
    future = time.time() + 3600
    monkeypatch.setattr('backend.app.time.time',lambda:future)
    overview = c.get('/api/overview').json()
    assert not overview['agent_healthy'] and overview['healthy'] == 0 and overview['stale'] == 2
    assert all(t['status'] == 'stale' and t['last_status'] == 'healthy' for t in targets(c,p))
    assert not fake.calls


@pytest.mark.parametrize(('interval','age','fresh'), [(60,181,False),(600,181,True),(600,1801,False)])
def test_fresh_heartbeat_does_not_hide_overdue_target_probe(env, interval, age, fresh):
    c, s, _, _ = env
    p, _ = setup(c)
    round_(c,p,True)
    s.db.execute('UPDATE pools SET interval_seconds=?',(interval,))
    s.db.execute('UPDATE targets SET last_checked_at=?',(iso(time.time()-age),))
    assert all(t['probe_fresh'] == fresh for t in targets(c,p))
    assert c.get('/api/overview').json()['healthy'] == (2 if fresh else 0)


def test_periodic_drift_scan_and_recovery_requires_new_successes(env):
    c, s, fake, _ = env
    p, ts = setup(c, recovery=2)
    round_(c,p,True)
    fake.records = [r for r in fake.records if r['content'] != ts[0]['ip']]
    s.db.execute('UPDATE pools SET dns_next_check=0')
    fake.calls.clear()
    c.app.state.reconciler.run_once()
    t = next(t for t in targets(c,p) if t['id'] == ts[0]['id'])
    assert not t['dns_present'] and t['dns_drift'] and t['successes'] == 0
    assert all(method == 'GET' for method, _ in fake.calls)
    assert c.get('/api/pools').json()[0]['dns_drift_count'] == 1
    round_(c,p,True)
    assert not any(r['content'] == ts[0]['ip'] for r in fake.records)
    round_(c,p,True)
    assert any(r['content'] == ts[0]['ip'] for r in fake.records)
    assert c.get('/api/pools').json()[0]['dns_drift_count'] == 0


def test_excluded_and_protected_failures_do_not_repeat_dns_requests_or_events(env):
    c, _, fake, _ = env
    p, _ = setup(c, failure=1)
    round_(c,p,False)
    events = [e for e in c.get('/api/events').json() if e['type'] == 'dns']
    fake.calls.clear()
    for _ in range(3):
        round_(c,p,False)
    assert not fake.calls
    assert [e for e in c.get('/api/events').json() if e['type'] == 'dns'] == events


@pytest.mark.parametrize('operation', ['integration', 'manual', 'automatic', 'scan'])
def test_slow_provider_never_blocks_agent_ingress(env, operation):
    c, s, fake, _ = env
    p, ts = setup(c, failure=1)
    jobs = poll(c)
    entered, release = threading.Event(), threading.Event()

    def stalled(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    attribute = 'zones' if operation == 'integration' else 'address_records' if operation == 'scan' else 'ensure'
    original = getattr(fake.adapter, attribute)
    setattr(fake.adapter, attribute, stalled)
    if operation == 'automatic':
        assert c.post('/api/agent/results',headers=AH,json={'agent_id':'ru-1','results':[{'job_id':jobs[0]['job_id'],'ok':False,'error':'connection_failed'}]}).json()['accepted'] == 1
    with ThreadPoolExecutor(max_workers=3) as executor:
        if operation == 'integration':
            blocked = executor.submit(c.post,'/api/integrations/cloudflare/test')
        elif operation == 'manual':
            blocked = executor.submit(c.post,f"/api/targets/{ts[0]['id']}/disable")
        elif operation == 'scan':
            blocked = executor.submit(c.app.state.reconciler.scan_pool,p['id'])
        else:
            blocked = executor.submit(c.app.state.reconciler.run_once)
        try:
            assert entered.wait(2)
            heartbeat = executor.submit(c.post,'/api/agent/poll',headers=AH,json={'agent_id':'ru-1','version':'1','control_ok':True})
            assert heartbeat.result(timeout=1).status_code == 200
            busy_target = jobs[0]['target_id'] if operation == 'automatic' else ts[0]['id']
            usable = next(j for j in jobs if j['target_id'] != busy_target)
            submitted = executor.submit(c.post,'/api/agent/results',headers=AH,json={'agent_id':'ru-1','results':[{'job_id':usable['job_id'],'ok':True}]})
            assert submitted.result(timeout=1).json()['accepted'] == 1
        finally:
            release.set()
            blocked.result(timeout=3)


def test_concurrent_manual_removals_preserve_last_record(env):
    c, _, fake, _ = env
    _, ts = setup(c)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda t:c.post(f"/api/targets/{t['id']}/disable"),ts))
    assert sorted(r.status_code for r in responses) == [200,409]
    assert len(fake.records) == 1


@pytest.mark.parametrize('change', ['pause','profile'])
def test_paused_or_replaced_profile_cancels_queued_auto_removal(env, change):
    c, _, fake, _ = env
    p, _ = setup(c, failure=1)
    j = poll(c)[0]
    assert c.post('/api/agent/results',headers=AH,json={'agent_id':'ru-1','results':[{'job_id':j['job_id'],'ok':False}]}).json()['accepted'] == 1
    response = c.patch(f"/api/pools/{p['id']}",json={'automation_enabled':False}) if change == 'pause' else c.put(f"/api/pools/{p['id']}/profile",json={**PROFILE,'port':8443})
    assert response.status_code == 200
    c.app.state.reconciler.run_once()
    assert len(fake.records) == 2
    assert not any(t['dns_pending_action'] for t in targets(c,p))


def test_no_auto_removal_from_stale_agent_and_streaks_reset_on_reconnect(env):
    c, s, fake, _ = env
    p, _ = setup(c,failure=2)
    round_(c,p,False)
    c.post(f"/api/pools/{p['id']}/check")
    j = poll(c)[0]
    assert c.post('/api/agent/results',headers=AH,json={'agent_id':'ru-1','results':[{'job_id':j['job_id'],'ok':False}]}).json()['accepted'] == 1
    s.db.execute('UPDATE agents SET last_seen=?',(time.time()-91,))
    c.app.state.reconciler.run_once()
    assert len(fake.records) == 2
    poll(c)
    assert all(t['failures'] == 0 for t in targets(c,p))
    c.app.state.reconciler.run_once()
    assert len(fake.records) == 2


def test_background_worker_recovers_manual_pending_without_agent(tmp_path):
    cfg = Config('admin','password','S'*32,'T'*32,str(tmp_path/'guard.db'),False,'http://testserver',cloudflare_api_token='synthetic')
    fake = FakeCloudflare()
    app = create_app(cfg,cf_factory=lambda _:fake.adapter)
    with TestClient(app,headers={'X-Requested-With':'DNSGuard'}) as c:
        c.post('/api/auth/login',json={'username':'admin','password':'password'})
        p, ts = setup(c,auto=False)
        fake.fail = 'delete'
        assert c.post(f"/api/targets/{ts[0]['id']}/disable").status_code == 502
        fake.fail = None
        with app.state.store.lock:
            app.state.store.db.execute('UPDATE targets SET dns_next_retry=0')
        app.state.reconciler.wake.set()
        deadline = time.monotonic()+3
        while True:
            t = next(t for t in targets(c,p) if t['id'] == ts[0]['id'])
            if not t['dns_pending_action']:
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert not t['manual_enabled'] and not t['dns_present'] and not t['dns_uncertain']
    assert not app.state.reconciler.thread.is_alive()
    fake.client.close()
