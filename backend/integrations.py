import httpx
from urllib.parse import urlparse

class IntegrationError(Exception):
    pass

class LastRecordError(IntegrationError):
    pass

class Cloudflare:
    def __init__(self, token, client=None):
        self.client = client or httpx.Client(base_url='https://api.cloudflare.com/client/v4', timeout=20, follow_redirects=False, trust_env=False)
        self.token = token

    def request(self, method, path, **kwargs):
        try:
            response = self.client.request(method, path, headers={'Authorization': f'Bearer {self.token}'}, **kwargs)
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not body.get('success') or 'result' not in body:
                raise IntegrationError('Cloudflare rejected the operation; verify token permissions and zone')
            return body
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            raise IntegrationError('Cloudflare API unavailable or request rejected') from None

    def pages(self, path, params):
        rows = []
        for page in range(1, 1001):
            body = self.request('GET', path, params={**params, 'page': page, 'per_page': 100})
            if not isinstance(body['result'], list) or any(not isinstance(row, dict) for row in body['result']):
                raise IntegrationError('Cloudflare returned an invalid response')
            rows.extend(body['result'])
            info = body.get('result_info') or {}
            total = info.get('total_pages', 1) if isinstance(info, dict) else None
            if not isinstance(total, int) or total < 1:
                raise IntegrationError('Cloudflare returned invalid pagination metadata')
            if page >= total:
                return rows
        raise IntegrationError('Cloudflare response exceeds the record limit')

    def zones(self):
        rows = self.pages('/zones', {})
        if any(not isinstance(z.get('id'), str) or not isinstance(z.get('name'), str) for z in rows):
            raise IntegrationError('Cloudflare returned an invalid zone response')
        return [{'id': z['id'], 'name': z['name']} for z in rows]

    def records(self, pool):
        rows = self.pages(f"/zones/{pool['zone_id']}/dns_records", {'type': 'A', 'name': pool['hostname']})
        if any(not all(isinstance(r.get(k), str) for k in ('id','type','name','content')) for r in rows):
            raise IntegrationError('Cloudflare returned an invalid record response')
        return [r for r in rows if r.get('type') == 'A' and r.get('name', '').rstrip('.').lower() == pool['hostname']]

    def ensure(self, pool, ip, present):
        records = self.records(pool)
        matching = [r for r in records if r.get('content') == ip]
        if any(r.get('proxied') for r in matching):
            raise IntegrationError('Disable Cloudflare proxy for this A record before enrolling it')
        if present:
            if not matching:
                self.request('POST', f"/zones/{pool['zone_id']}/dns_records", json={'type':'A','name':pool['hostname'],'content':ip,'ttl':pool['ttl'],'proxied':False})
        else:
            if matching and len(records) <= len(matching):
                raise LastRecordError('The final actual A record must be preserved')
            for record in matching:
                self.request('DELETE', f"/zones/{pool['zone_id']}/dns_records/{record['id']}")
        verified = self.records(pool)
        exists = any(r.get('content') == ip for r in verified)
        if exists != present:
            raise IntegrationError('Cloudflare DNS change could not be verified; retry later')
        return exists

class Remnawave:
    def __init__(self, url, token, client=None):
        parsed = urlparse(url)
        if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise IntegrationError('Remnawave URL must be an HTTPS base URL without credentials')
        self.url = url.rstrip('/')
        if self.url.endswith('/api'):
            self.url = self.url[:-4]
        self.token = token
        self.client = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)

    def get(self, resource):
        try:
            response = self.client.get(f'{self.url}/api/{resource}', headers={'Authorization': f'Bearer {self.token}'})
            response.raise_for_status()
            data = response.json()['response']
            if isinstance(data, dict):
                data = data.get(resource, [])
            if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                raise ValueError()
            return data
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise IntegrationError('Remnawave API unavailable or request rejected') from None

    def nodes(self):
        rows = self.get('nodes')
        if any(not all(isinstance(n.get(k), str) for k in ('uuid','name','address')) or not isinstance(n.get('configProfile') or {}, dict) for n in rows):
            raise IntegrationError('Remnawave returned an invalid node response')
        return [{'uuid': n['uuid'], 'name': n['name'], 'address': n['address'], 'is_connected': bool(n.get('isConnected')), 'config_profile_uuid': (n.get('configProfile') or {}).get('activeConfigProfileUuid')} for n in rows]

    def hosts(self):
        rows = self.get('hosts')
        if any(not all(isinstance(h.get(k), str) for k in ('uuid','address')) or not isinstance(h.get('port'), int) or not isinstance(h.get('nodes', []), list) or any(not isinstance(n, str) for n in h.get('nodes', [])) for h in rows):
            raise IntegrationError('Remnawave returned an invalid host response')
        return [{'uuid': h['uuid'], 'remark': h.get('remark', ''), 'address': h['address'], 'port': h['port'], 'node_uuids': [n['uuid'] if isinstance(n, dict) else n for n in h.get('nodes', [])]} for h in rows]
