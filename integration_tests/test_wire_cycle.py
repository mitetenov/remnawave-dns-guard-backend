"""Black-box contract/migration tests against a compiled backend, stdlib only.

DNS_GUARD_BACKEND_BINARY=/absolute/path/dns-guard-backend \
python3 -m unittest discover -s integration_tests -v

No retired Python service imports or live providers. Every process, DB and port
is temporary. The inert encrypted fixture defers DNS scans until year 2100.
"""
import hashlib
import http.client
import http.cookies
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest

PROFILE = {'port': 443, 'uuid': '550e8400-e29b-41d4-a716-446655440000',
           'transport': 'tcp', 'security': 'tls', 'server_name': 'example.com',
           'public_key': '', 'short_id': '', 'flow': '', 'fingerprint': 'chrome',
           'path': '/', 'host': '', 'xhttp_mode': 'auto'}
TOKEN = 'T' * 32
POOL = '/api/pools/legacy-pool'
FIXTURE = Path(__file__).with_name('fixtures') / 'legacy_python.sql'


class Backend:
    def __init__(self, binary, fixture=False, legacy_revision=True):
        self.directory = tempfile.TemporaryDirectory(prefix='dns-guard-contract-')
        self.database = Path(self.directory.name) / 'guard.db'
        self.logs = open(Path(self.directory.name) / 'backend.log', 'w+b')
        self.process = None
        self.binary = binary
        self.username = 'админ' if fixture else 'admin'
        self.password = 'пароль' if fixture else 'password'
        self.cookie = 'dns_guard_session=python-session-cookie-v1' if fixture else ''
        if fixture:
            with self.db() as db:
                db.executescript(FIXTURE.read_text())
                if not legacy_revision:
                    db.execute("DELETE FROM settings WHERE key='auth_revision'")
        try:
            self.start()
        except BaseException:
            self.close()
            raise

    def db(self):
        return sqlite3.connect(self.database, timeout=10)

    def start(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        env = dict(os.environ)
        for key in ('CLOUDFLARE_API_TOKEN', 'REMNAWAVE_URL', 'REMNAWAVE_API_TOKEN'):
            env.pop(key, None)
        env.update(ADMIN_USERNAME=self.username, ADMIN_PASSWORD=self.password,
                   APP_SECRET='S' * 32, AGENT_TOKEN=TOKEN,
                   DATABASE_PATH=str(self.database), COOKIE_SECURE='false',
                   PUBLIC_ORIGIN='http://guard.contract.test',
                   LISTEN_ADDR=f'127.0.0.1:{self.port}')
        self.process = subprocess.Popen([self.binary], cwd=self.directory.name,
                                        env=env, stdout=self.logs, stderr=self.logs)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise AssertionError('Backend exited: ' + self.logs.read().decode(errors='replace'))
            try:
                if self.request('GET', '/api/health')[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.025)
        raise AssertionError('Backend did not become healthy on its temporary port')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                raise AssertionError('Backend did not shut down after SIGTERM')
        self.process = None

    def restart(self):
        self.stop()
        self.start()

    def close(self):
        try:
            self.stop()
        finally:
            self.logs.close()
            self.directory.cleanup()

    def request(self, method, path, data=None, headers=None, browser=True):
        supplied = {'Content-Type': 'application/json'}
        if browser:
            supplied['X-Requested-With'] = 'DNSGuard'
            if self.cookie:
                supplied['Cookie'] = self.cookie
        supplied.update(headers or {})
        body = json.dumps(data).encode() if data is not None else None
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=supplied)
            response = conn.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, response.headers
        finally:
            conn.close()

    def login(self):
        status, body, headers = self.request('POST', '/api/auth/login', {
            'username': self.username, 'password': self.password})
        if status != 200:
            raise AssertionError(f'Login failed: {status}: {body}')
        cookie = http.cookies.SimpleCookie(headers['Set-Cookie'])['dns_guard_session']
        self.cookie = 'dns_guard_session=' + cookie.value
        return body, cookie

    def poll(self, healthy=True, agent_id='ru-contract'):
        return self.request('POST', '/api/agent/poll', {
            'agent_id': agent_id, 'version': 'contract-test', 'control_ok': healthy,
            'control_error': None if healthy else 'control_unreachable'},
            {'Authorization': 'Bearer ' + TOKEN}, browser=False)

    def results(self, jobs, ok=True, agent_id='ru-contract', error=None):
        return self.request('POST', '/api/agent/results', {
            'agent_id': agent_id,
            'results': [{'job_id': j['job_id'], 'ok': ok,
                         'latency_ms': 12.5 if ok else None, 'error': error} for j in jobs]},
            {'Authorization': 'Bearer ' + TOKEN}, browser=False)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get('DNS_GUARD_BACKEND_BINARY')
        if not configured:
            raise unittest.SkipTest('Set DNS_GUARD_BACKEND_BINARY to the compiled backend')
        cls.binary = str(Path(configured).resolve())
        if not Path(cls.binary).is_file():
            raise AssertionError('DNS_GUARD_BACKEND_BINARY does not name a compiled binary')

    def backend(self, **kwargs):
        server = Backend(self.binary, **kwargs)
        self.addCleanup(server.close)
        return server

    def error(self, server, method, path, data, expected, **kwargs):
        status, body, _ = server.request(method, path, data, **kwargs)
        self.assertEqual(status, expected, body)
        self.assertIsInstance(body, dict)
        self.assertIsInstance(body.get('detail'), str)
        return body['detail']

    def test_frontend_auth_and_empty_state_contract(self):
        s = self.backend()
        self.assertEqual(s.request('GET', '/api/health')[:2], (200, {'ok': True}))
        self.error(s, 'GET', '/api/pools', None, 401)
        credentials = {'username': 'admin', 'password': 'password'}
        self.error(s, 'POST', '/api/auth/login', credentials, 403, browser=False)
        self.error(s, 'POST', '/api/auth/login', credentials, 403,
                   headers={'Origin': 'https://foreign.example'})
        self.error(s, 'POST', '/api/auth/login', {**credentials, 'password': 'wrong'}, 401)
        body, cookie = s.login()
        self.assertEqual(body, {'username': 'admin'})
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'].lower(), 'strict')
        self.assertEqual(cookie['path'], '/api')
        self.assertFalse(cookie['secure'])
        self.assertEqual(s.request('GET', '/api/auth/me')[:2], (200, body))
        status, overview, _ = s.request('GET', '/api/overview')
        self.assertEqual(status, 200)
        for key in ('pools', 'targets', 'healthy', 'excluded', 'stale'):
            self.assertEqual(overview[key], 0)
        for key in ('agent_healthy', 'cloudflare_configured', 'remnawave_configured'):
            self.assertIs(overview[key], False)
        self.assertIsNone(overview['agent_last_seen'])
        self.assertEqual(s.request('GET', '/api/pools')[:2], (200, []))
        self.assertEqual(s.request('GET', '/api/events')[:2], (200, []))
        self.error(s, 'POST', '/api/agent/poll', {
            'agent_id': 'ru', 'version': '1', 'control_ok': True}, 401)
        self.error(s, 'GET', '/api/pools', None, 401,
                   headers={'Authorization': 'Bearer ' + TOKEN}, browser=False)
        self.assertEqual(s.poll(False)[1], {'jobs': [], 'poll_after_seconds': 10})
        self.assertEqual(s.request('POST', '/api/auth/logout')[:2], (200, {'ok': True}))
        self.error(s, 'GET', '/api/auth/me', None, 401)

    def test_pool_profile_forms_and_sanitized_provider_errors(self):
        s = self.backend()
        s.login()
        status, pool, _ = s.request('POST', '/api/pools', {
            'name': 'Новый пул', 'hostname': 'VPN.Example.COM.', 'zone_id': 'zone'})
        self.assertEqual(status, 200, pool)
        self.assertEqual(pool['hostname'], 'vpn.example.com')
        self.assertEqual((pool['ttl'], pool['interval_seconds'], pool['failure_threshold'],
                          pool['recovery_threshold']), (120, 60, 3, 5))
        self.assertIs(pool['automation_enabled'], False)
        self.assertIs(pool['profile_configured'], False)
        self.assertNotIn('profile', pool)
        path = '/api/pools/' + pool['id']
        self.error(s, 'POST', '/api/pools', {
            'name': 'Duplicate', 'hostname': pool['hostname'], 'zone_id': 'zone'}, 409)
        self.error(s, 'PATCH', path, {'automation_enabled': True}, 409)
        self.error(s, 'POST', path + '/check', None, 409)
        self.error(s, 'PATCH', path, {'name': None}, 422)
        self.error(s, 'PATCH', path, {'not_a_field': 'do-not-echo-me'}, 422)
        detail = self.error(s, 'PUT', path + '/profile', {
            **PROFILE, 'public_key': {'credential': 'do-not-echo-me'}}, 422)
        self.assertNotIn('do-not-echo-me', detail)
        self.assertEqual(s.request('PUT', path + '/profile', PROFILE)[:2], (200, {'ok': True}))
        pools = s.request('GET', '/api/pools')[1]
        self.assertIs(pools[0]['profile_configured'], True)
        self.assertNotIn(PROFILE['uuid'], json.dumps(pools))
        self.assertEqual(s.request('PATCH', path, {'name': 'Обновлённый'})[1]['name'], 'Обновлённый')
        self.assertEqual(s.request('GET', path + '/targets')[:2], (200, []))
        self.error(s, 'POST', path + '/check', None, 409)
        for method, endpoint in (('GET', '/api/cloudflare/zones'), ('GET', '/api/remnawave/nodes'),
                                 ('GET', '/api/remnawave/hosts'),
                                 ('POST', '/api/integrations/cloudflare/test'),
                                 ('POST', '/api/integrations/remnawave/test')):
            self.error(s, method, endpoint, None, 400)
        self.error(s, 'POST', path + '/sync', None, 502)
        for ip in ('127.0.0.1', '10.1.2.3', '224.0.0.1', '2001:4860:4860::8888'):
            self.error(s, 'POST', path + '/targets', {'name': 'Invalid', 'ip': ip}, 422)
        self.error(s, 'POST', path + '/targets', {'name': 'Valid', 'ip': '8.8.8.8'}, 400)
        self.error(s, 'GET', '/api/pools/missing/targets', None, 404)
        detail = self.error(s, 'PUT', '/api/settings', {
            'cloudflare_api_token': {'secret': 'do-not-echo-me'}}, 422)
        self.assertNotIn('do-not-echo-me', detail)
        self.error(s, 'PUT', '/api/settings', {'remnawave_url': 'http://127.0.0.1'}, 502)
        status, events, _ = s.request('GET', '/api/events?limit=2&type=manual&pool_id=' + pool['id'])
        self.assertEqual(status, 200)
        self.assertLessEqual(len(events), 2)
        self.assertTrue(events)
        self.assertTrue(all(e['type'] == 'manual' and e['pool_id'] == pool['id'] for e in events))

    def test_python_fernet_profile_and_session_survive_go_upgrade_and_restart(self):
        s = self.backend(fixture=True)
        self.assertEqual(s.request('GET', '/api/auth/me')[:2], (200, {'username': 'админ'}))
        status, settings, _ = s.request('GET', '/api/settings')
        self.assertEqual(status, 200)
        self.assertIs(settings['cloudflare_configured'], True)
        self.assertIs(settings['remnawave_configured'], True)
        self.assertEqual(settings['remnawave_url'], 'https://panel.example.com')
        self.assertNotIn('legacy-cloudflare-secret', json.dumps(settings))
        self.assertNotIn('legacy-remnawave-secret', json.dumps(settings))
        status, targets, _ = s.request('GET', POOL + '/targets')
        self.assertEqual(status, 200)
        self.assertEqual(len(targets), 1)
        target = targets[0]
        self.assertEqual((target['id'], target['failures']), ('legacy-target', 1))
        for key in ('manual_enabled', 'dns_present', 'dns_uncertain', 'dns_drift', 'probe_fresh'):
            self.assertIsInstance(target[key], bool)
        for key in ('dns_pending_action', 'dns_error', 'dns_checked_at', 'last_status'):
            self.assertIn(key, target)
        self.assertNotIn('dns_action', target)
        status, batch, _ = s.poll()
        self.assertEqual(status, 200, batch)
        self.assertEqual(batch['poll_after_seconds'], 10)
        self.assertEqual(len(batch['jobs']), 1)
        job = batch['jobs'][0]
        self.assertEqual((job['target_id'], job['ip'], job['timeout_seconds']), ('legacy-target', '1.1.1.1', 15))
        self.assertEqual(job['profile'], PROFILE)
        self.assertEqual(s.results([job])[1], {'accepted': 1})
        before = s.request('GET', POOL + '/targets')[1][0]
        self.assertEqual((before['status'], before['successes']), ('healthy', 1))
        s.restart()
        self.assertEqual(s.request('GET', '/api/auth/me')[:2], (200, {'username': 'админ'}))
        after = s.request('GET', POOL + '/targets')[1][0]
        self.assertEqual(after['successes'], before['successes'])
        self.assertEqual(after['last_checked_at'], before['last_checked_at'])
        self.assertIs(after['probe_fresh'], True)
        with s.db() as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0], 1)
            self.assertTrue(db.execute('SELECT profile FROM pools').fetchone()[0].startswith('gAAAA'))

    def test_agent_wire_leases_replay_control_and_profile_invalidation(self):
        s = self.backend(fixture=True)
        bearer = {'Authorization': 'Bearer ' + TOKEN}
        self.error(s, 'POST', '/api/agent/poll', {
            'agent_id': 'ru-contract', 'version': '1'}, 422,
            headers=bearer, browser=False)
        for result in ({'job_id': 'unknown'},
                       {'job_id': 'unknown', 'ok': True, 'unexpected': 'do-not-echo-me'},
                       {'job_id': 'unknown', 'ok': True, 'latency_ms': -1}):
            detail = self.error(s, 'POST', '/api/agent/results', {
                'agent_id': 'ru-contract', 'results': [result]}, 422,
                headers=bearer, browser=False)
            self.assertNotIn('do-not-echo-me', detail)
        self.error(s, 'POST', '/api/agent/results', {
            'agent_id': 'ru-contract', 'results': [{'job_id': 'unknown', 'ok': True}] * 5},
            422, headers=bearer, browser=False)
        self.assertEqual(s.poll(False)[1]['jobs'], [])
        first = s.poll()[1]['jobs']
        self.assertEqual(len(first), 1)
        self.assertEqual(s.poll()[1]['jobs'], [])
        self.assertEqual(s.results(first, agent_id='wrong-agent')[1], {'accepted': 0})
        self.assertEqual(s.results(first, ok=False, error='connection_failed')[1], {'accepted': 1})
        self.assertEqual(s.results(first, ok=False, error='connection_failed')[1], {'accepted': 0})
        self.assertEqual(s.request('GET', POOL + '/targets')[1][0]['failures'], 2)
        self.assertEqual(s.request('POST', POOL + '/check')[0], 200)
        second = s.poll()[1]['jobs']
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first[0]['job_id'], second[0]['job_id'])
        self.assertEqual(s.request('PUT', POOL + '/profile', {**PROFILE, 'port': 8443})[0], 200)
        self.assertEqual(s.results(second)[1], {'accepted': 0})
        third = s.poll()[1]['jobs']
        self.assertEqual(third[0]['profile']['port'], 8443)
        self.assertEqual(s.poll(False)[1]['jobs'], [])
        self.assertEqual(s.results(third, ok=False, error='connection_failed')[1], {'accepted': 0})
        target = s.request('GET', POOL + '/targets')[1][0]
        self.assertEqual(target['failures'], 0)
        self.assertIs(target['dns_present'], True)
        self.assertIs(s.request('GET', '/api/overview')[1]['agent_healthy'], False)
        fourth = s.poll()[1]['jobs']
        self.assertEqual(len(fourth), 1)
        self.assertNotEqual(third[0]['job_id'], fourth[0]['job_id'])
        self.assertEqual(s.results(third)[1], {'accepted': 0})
        with s.db() as db:
            db.execute('UPDATE jobs SET expires=0 WHERE consumed=0')
        fifth = s.poll()[1]['jobs']
        self.assertEqual(len(fifth), 1)
        self.assertNotEqual(fourth[0]['job_id'], fifth[0]['job_id'])
        self.assertEqual(s.results(fourth)[1], {'accepted': 0})
        self.assertEqual(s.results(fifth, ok=False, error='xray_start_failed')[1], {'accepted': 1})
        target = s.request('GET', POOL + '/targets')[1][0]
        self.assertEqual((target['failures'], target['status']), (0, 'unknown'))
        self.assertIs(target['dns_present'], True)
        self.assertEqual(s.request('GET', '/api/events?type=dns')[1], [])

    def test_legacy_sessions_revoked_once_and_rotated_credentials_revoke_new_sessions(self):
        s = self.backend(fixture=True, legacy_revision=False)
        self.error(s, 'GET', '/api/auth/me', None, 401)
        s.login()
        self.assertEqual(s.request('GET', '/api/auth/me')[0], 200)
        s.restart()
        self.assertEqual(s.request('GET', '/api/auth/me')[0], 200)
        s.password = 'changed-password'
        s.restart()
        self.error(s, 'GET', '/api/auth/me', None, 401)
        s.login()
        s.username = 'changed-admin'
        s.restart()
        self.error(s, 'GET', '/api/auth/me', None, 401)
        s.login()
        self.assertEqual(s.request('GET', '/api/auth/me')[1], {'username': 'changed-admin'})
        with s.db() as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM targets').fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM settings WHERE key='auth_revision'").fetchone()[0], 1)

    def test_session_hash_and_settings_encryption_survive_writes(self):
        s = self.backend()
        s.login()
        secret = 'new-inert-fixture-token'
        status, settings, _ = s.request('PUT', '/api/settings', {
            'cloudflare_api_token': secret, 'remnawave_url': 'https://panel.example.com/',
            'remnawave_api_token': secret})
        self.assertEqual(status, 200, settings)
        self.assertEqual(settings['remnawave_url'], 'https://panel.example.com')
        self.assertIs(settings['cloudflare_configured'], True)
        self.assertIs(settings['remnawave_configured'], True)
        self.assertNotIn(secret, json.dumps(settings))
        self.assertNotIn(secret, json.dumps(s.request('GET', '/api/events')[1]))
        cookie = s.cookie.split('=', 1)[1]
        with s.db() as db:
            session = db.execute('SELECT token FROM sessions').fetchone()[0]
            self.assertEqual(session, hashlib.sha256(cookie.encode()).hexdigest())
            values = dict(db.execute('SELECT key,value FROM settings'))
            self.assertNotEqual(values['cloudflare_api_token'], secret)
            self.assertTrue(values['cloudflare_api_token'].startswith('gAAAA'))
            self.assertNotEqual(values['remnawave_url'], 'https://panel.example.com')
        self.assertEqual(s.request('PUT', '/api/settings', {'cloudflare_api_token': ''})[0], 200)
        self.assertIs(s.request('GET', '/api/settings')[1]['cloudflare_configured'], True)
        s.restart()
        self.assertEqual(s.request('GET', '/api/settings')[1]['remnawave_url'], 'https://panel.example.com')

    def test_sigterm_drains_an_active_request_before_closing_sqlite(self):
        s = self.backend()
        conn = socket.create_connection(('127.0.0.1', s.port), timeout=3)
        self.addCleanup(conn.close)
        body = json.dumps({'username': 'admin', 'password': 'password'}).encode()
        headers = (f'POST /api/auth/login HTTP/1.1\r\nHost: guard.contract.test\r\n'
                   f'X-Requested-With: DNSGuard\r\nContent-Type: application/json\r\n'
                   f'Connection: close\r\nContent-Length: {len(body)}\r\n\r\n').encode()
        # Keep a handler reading its body while shutdown closes the listener.
        conn.sendall(headers + body[:10])
        time.sleep(0.05)
        s.process.terminate()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', s.port), timeout=0.1):
                    pass
            except OSError:
                break
            time.sleep(0.01)
        else:
            self.fail('SIGTERM did not stop the listener')
        time.sleep(0.1)
        self.assertIsNone(s.process.poll(), 'Backend exited before draining its active request')
        conn.sendall(body[10:])
        response = http.client.HTTPResponse(conn)
        response.begin()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read()), {'username': 'admin'})
        cookie = http.cookies.SimpleCookie(response.getheader('Set-Cookie'))['dns_guard_session']
        s.cookie = 'dns_guard_session=' + cookie.value
        response.close()
        self.assertEqual(s.process.wait(timeout=5), 0)
        s.restart()
        self.assertEqual(s.request('GET', '/api/auth/me')[:2], (200, {'username': 'admin'}))


if __name__ == '__main__':
    unittest.main()
