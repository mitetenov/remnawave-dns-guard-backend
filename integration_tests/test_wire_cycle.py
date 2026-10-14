"""Real agent/backend protocol integration; provider HTTP and probes remain mocked."""
import asyncio
import json
from unittest.mock import AsyncMock

import httpx
from fastapi.testclient import TestClient

from agent.probe_agent import Agent, Settings
from backend.app import create_app
from backend.config import Config
from backend.integrations import Cloudflare


def environment(tmp_path, count=8):
    records = []

    def provider(request):
        if request.method == 'GET':
            return httpx.Response(200, json={'success': True, 'result': list(records)})
        if request.method == 'POST':
            records.append({**json.loads(request.content), 'id': str(len(records) + 1)})
        elif request.method == 'DELETE':
            record_id = request.url.path.rsplit('/', 1)[-1]
            records[:] = [record for record in records if record['id'] != record_id]
        return httpx.Response(200, json={'success': True, 'result': {}})

    transport = httpx.Client(base_url='https://api.cloudflare.com/client/v4',
                             transport=httpx.MockTransport(provider))
    config = Config('admin', 'password', 'S' * 32, 'T' * 32,
                    str(tmp_path / 'wire.db'), False, 'http://testserver',
                    cloudflare_api_token='mock-token')
    app = create_app(config, cf_factory=lambda token: Cloudflare(token, transport))
    client = TestClient(app, headers={'X-Requested-With': 'DNSGuard'})
    assert client.post('/api/auth/login', json={'username': 'admin', 'password': 'password'}).status_code == 200
    pool = client.post('/api/pools', json={'name': 'Wire test', 'hostname': 'vpn.example.com',
                        'zone_id': 'mock-zone'}).json()
    profile = {'port': 443, 'uuid': '550e8400-e29b-41d4-a716-446655440000',
               'transport': 'tcp', 'security': 'tls', 'server_name': 'example.com'}
    assert client.put(f"/api/pools/{pool['id']}/profile", json=profile).status_code == 200
    for i in range(count):
        response = client.post(f"/api/pools/{pool['id']}/targets",
                               json={'name': str(i), 'ip': f'8.8.8.{i + 1}'})
        assert response.status_code == 200, response.text

    agent = Agent(Settings('https://guard.example.com', config.agent_token))
    requests = []

    async def api(path, body):
        response = client.post(path, headers={'Authorization': f'Bearer {config.agent_token}'}, json=body)
        assert response.status_code == 200, response.text
        requests.append((path, body, response.json()))
        return response.json()

    async def probe(job):
        return {'job_id': job['job_id'], 'ok': True, 'latency_ms': 12.5, 'error': None}

    agent.api = api
    agent._probe = probe
    return agent, client, app.state.store, pool, transport, requests


def test_two_agent_cycles_execute_eight_targets_without_discarded_leases(tmp_path):
    agent, client, store, pool, transport, requests = environment(tmp_path)
    agent.control_health = AsyncMock(return_value=True)
    try:
        assert asyncio.run(agent.cycle()) == 10
        assert asyncio.run(agent.cycle()) == 10
        batches = [r for path, body, r in requests if path.endswith('/poll')]
        assert len(batches) == 2
        assert [len(batch['jobs']) for batch in batches] == [4, 4]
        assert len({job['target_id'] for batch in batches for job in batch['jobs']}) == 8
        results = [r['accepted'] for path, body, r in requests if path.endswith('/results')]
        assert results == [4, 4]
        assert store.one('SELECT COUNT(*) n FROM jobs WHERE consumed=0')['n'] == 0
        targets = client.get(f"/api/pools/{pool['id']}/targets").json()
        assert len(targets) == 8 and all(t['status'] == 'healthy' for t in targets)
    finally:
        client.close()
        transport.close()
        store.db.close()


def test_control_loss_before_submission_suppresses_target_failures(tmp_path):
    agent, client, store, pool, transport, requests = environment(tmp_path, count=2)
    agent.control_health = AsyncMock(side_effect=[True, False])

    async def failed_probe(job):
        return {'job_id': job['job_id'], 'ok': False, 'latency_ms': None, 'error': 'probe_timeout'}

    agent._probe = failed_probe
    try:
        asyncio.run(agent.cycle())
        assert not any(path.endswith('/results') for path, body, response in requests)
        assert requests[-1][1]['control_ok'] is False
        assert requests[-1][2]['jobs'] == []
        targets = client.get(f"/api/pools/{pool['id']}/targets").json()
        assert all(t['failures'] == 0 and t['dns_present'] for t in targets)
        assert client.get('/api/overview').json()['agent_healthy'] is False
    finally:
        client.close()
        transport.close()
        store.db.close()


def test_missing_local_xray_is_inconclusive_and_preserves_every_a(tmp_path):
    agent, client, store, pool, transport, requests = environment(tmp_path, count=2)
    agent.settings = Settings('https://guard.example.com', 'T' * 32,
                              xray_bin=str(tmp_path / 'missing-xray'))
    agent.control_health = AsyncMock(return_value=True)
    # Exercise the real subprocess error path, not a fabricated target response.
    agent._probe = Agent._probe.__get__(agent, Agent)
    response = client.patch(f"/api/pools/{pool['id']}",
                            json={'automation_enabled': True, 'failure_threshold': 1})
    assert response.status_code == 200, response.text
    try:
        for _ in range(2):
            client.post(f"/api/pools/{pool['id']}/check")
            asyncio.run(agent.cycle())
        results = [body['results'] for path, body, response in requests if path.endswith('/results')]
        assert len(results) == 2
        assert all(result['error'] == 'xray_start_failed' for batch in results for result in batch)
        targets = client.get(f"/api/pools/{pool['id']}/targets").json()
        assert all(t['failures'] == 0 and t['dns_present'] and t['status'] == 'unknown' for t in targets)
        actual = Cloudflare('mock-token', transport).records({'zone_id': 'mock-zone', 'hostname': 'vpn.example.com'})
        assert len(actual) == 2
    finally:
        client.close()
        transport.close()
        store.db.close()
