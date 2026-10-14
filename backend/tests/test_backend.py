import time
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.config import Config
from backend.integrations import Cloudflare, Remnawave, IntegrationError

PROFILE = {'port':443,'uuid':'d74dbd5f-4f3a-40a1-b267-e7e726b192f7','transport':'tcp','security':'tls','server_name':'example.com'}

class FakeCloudflare:
    """Actual adapter exercised through MockTransport, never live DNS."""
    def __init__(self):
        self.records=[]
        self.fail=None
        self.calls=[]
        self.counter=0
        self.client=httpx.Client(base_url='https://api.cloudflare.com/client/v4',transport=httpx.MockTransport(self.handle))
        self.adapter=Cloudflare('hidden-token',self.client)

    def handle(self, req):
        self.calls.append((req.method,req.url.path))
        if self.fail == 'get' and req.method == 'GET':
            return httpx.Response(403,json={'success':False,'errors':[{'message':'hidden-token'}]})
        if req.url.path.endswith('/zones'):
            return httpx.Response(200,json={'success':True,'result':[{'id':'zone','name':'example.com'}]})
        if req.method == 'GET':
            return httpx.Response(200,json={'success':True,'result':self.records,'result_info':{'total_pages':1}})
        if req.method == 'POST':
            import json
            data=json.loads(req.content); self.counter+=1
            self.records.append({**data,'id':str(self.counter)})
        elif req.method == 'DELETE':
            self.records=[r for r in self.records if r['id']!=req.url.path.rsplit('/',1)[1]]
        if self.fail == req.method.lower():
            raise httpx.ReadTimeout('hidden-token and secret',request=req)
        return httpx.Response(200,json={'success':True,'result':{'id':str(self.counter)}})

    def unrelated(self, ip='9.9.9.9', hostname='other.example.com', proxied=False):
        self.counter+=1
        self.records.append({'id':str(self.counter),'type':'A','name':hostname,'content':ip,'proxied':proxied})

@pytest.fixture
def env(tmp_path):
    config=Config('admin','password','S'*32,'T'*32,str(tmp_path/'guard.db'),False,'http://testserver',cloudflare_api_token='hidden-token')
    fake=FakeCloudflare()
    app=create_app(config,cf_factory=lambda token:fake.adapter)
    with TestClient(app,headers={'X-Requested-With':'DNSGuard'}) as client:
        assert client.post('/api/auth/login',json={'username':'admin','password':'password'}).status_code==200
        yield client, app.state.store, fake, config
    fake.client.close()

def setup(client, count=2, auto=True, failure=2, recovery=2):
    r=client.post('/api/pools',json={'name':'Pool','hostname':'vpn.example.com','zone_id':'zone','failure_threshold':failure,'recovery_threshold':recovery})
    assert r.status_code==200, r.text
    p=r.json()
    assert client.put(f"/api/pools/{p['id']}/profile",json=PROFILE).status_code==200
    targets=[]
    for i,ip in enumerate(['1.1.1.1','8.8.8.8'][:count]):
        r=client.post(f"/api/pools/{p['id']}/targets",json={'name':str(i),'ip':ip})
        assert r.status_code==200,r.text
        targets.append(r.json())
    if auto:
        assert client.patch(f"/api/pools/{p['id']}",json={'automation_enabled':True}).status_code==200
    return p,targets

AH={'Authorization':'Bearer '+'T'*32}
def poll(client, healthy=True, agent='ru-1'):
    return client.post('/api/agent/poll',headers=AH,json={'agent_id':agent,'version':'1','control_ok':healthy,'control_error':None}).json()['jobs']

def result(client, job, ok, agent='ru-1', error='connection_failed'):
    return client.post('/api/agent/results',headers=AH,json={'agent_id':agent,'results':[{'job_id':job['job_id'],'ok':ok,'latency_ms':12 if ok else None,'error':None if ok else error}]}).json()['accepted']

def round_(client,p,ok):
    client.post(f"/api/pools/{p['id']}/check")
    jobs=poll(client)
    for job in jobs: assert result(client,job,ok)==1
    return jobs

def targets(client,p): return client.get(f"/api/pools/{p['id']}/targets").json()

def test_failure_recovery_last_record_and_replay(env):
    c,s,f,_=env;p,ts=setup(c)
    first=round_(c,p,False)
    assert result(c,first[0],False)==0
    assert all(t['status']=='suspect' for t in targets(c,p))
    round_(c,p,False)
    states=targets(c,p)
    assert sorted(t['status'] for t in states)==['excluded','protected']
    assert len(f.records)==1
    round_(c,p,True)
    assert any(t['status']=='recovering' for t in targets(c,p))
    round_(c,p,True)
    assert len(f.records)==2
    assert all(t['status']=='healthy' for t in targets(c,p))

def test_final_actual_record_ignores_unrelated_and_duplicate_same_ip(env):
    c,s,f,_=env;p,ts=setup(c,count=1,failure=1)
    f.unrelated()
    f.unrelated(ip='1.1.1.1',hostname='vpn.example.com')
    round_(c,p,False)
    assert targets(c,p)[0]['status']=='protected'
    assert len(f.records)==3
    assert c.post(f"/api/targets/{ts[0]['id']}/disable").status_code==409
    assert c.delete(f"/api/targets/{ts[0]['id']}").status_code==409
    assert len(f.records)==3
    # An unmanaged A at this exact hostname counts as the remaining record.
    f.unrelated(ip='8.8.4.4',hostname='vpn.example.com')
    round_(c,p,False)
    assert targets(c,p)[0]['status']=='excluded'
    assert all(r['content']!='1.1.1.1' for r in f.records)

def test_manual_disable_never_probed_or_restored(env):
    c,s,f,_=env;p,ts=setup(c)
    jobs=poll(c)
    assert c.post(f"/api/targets/{ts[0]['id']}/disable").status_code==200
    stale=next(j for j in jobs if j['target_id']==ts[0]['id'])
    assert result(c,stale,True)==0
    # Consume other outstanding job, then manually request new checks.
    for j in jobs: result(c,j,True)
    for _ in range(3):
        due=round_(c,p,True)
        assert all(j['target_id']!=ts[0]['id'] for j in due)
    t=next(t for t in targets(c,p) if t['id']==ts[0]['id'])
    assert t['status']=='disabled' and not t['dns_present'] and not t['manual_enabled']

def test_offline_stale_expired_wrong_agent_profile_revision(env):
    c,s,f,_=env;p,ts=setup(c)
    assert poll(c,False)==[]
    jobs=poll(c)
    assert len(poll(c))==0 # no overlapping target leases
    assert result(c,jobs[0],False,agent='intruder')==0
    s.db.execute('UPDATE agents SET last_seen=?',(time.time()-1000,))
    assert result(c,jobs[0],False)==0
    poll(c,False)
    assert result(c,jobs[0],False)==0
    s.db.execute('UPDATE jobs SET expires=?',(time.time()-1,))
    assert result(c,jobs[0],False)==0
    new=poll(c)
    assert len(new)==2
    assert all(t['failures']==0 for t in targets(c,p))
    assert c.put(f"/api/pools/{p['id']}/profile",json={**PROFILE,'port':8443}).status_code==200
    assert result(c,new[0],False)==0
    assert all(t['failures']==0 for t in targets(c,p))
    assert all(j['profile']['port']==8443 for j in poll(c))

def test_pause_keeps_probing_and_sync_keeps_excluded(env):
    c,s,f,_=env;p,ts=setup(c,failure=1)
    round_(c,p,False)
    excluded=next(t for t in targets(c,p) if t['status']=='excluded')
    assert c.post(f"/api/pools/{p['id']}/sync").json()['added']==0
    assert any(t['id']==excluded['id'] for t in targets(c,p))
    assert c.patch(f"/api/pools/{p['id']}",json={'automation_enabled':False}).status_code==200
    before=len(f.records)
    round_(c,p,True); round_(c,p,True)
    assert len(f.records)==before
    assert any(t['status']=='recovering' for t in targets(c,p))

def test_dns_timeout_retry_idempotent_and_errors_sanitized(env):
    c,s,f,_=env;p,ts=setup(c,failure=1,recovery=1)
    f.fail='delete'
    round_(c,p,False)
    # Provider may have committed deletion but timed out: no false local success.
    assert all(t['dns_present'] for t in targets(c,p))
    f.fail=None
    round_(c,p,False)
    assert any(t['status']=='excluded' for t in targets(c,p))
    f.fail='post'
    round_(c,p,True)
    assert len(f.records)==2
    assert any(not t['dns_present'] for t in targets(c,p))
    f.fail=None
    round_(c,p,True)
    assert len(f.records)==2 and all(t['dns_present'] for t in targets(c,p))
    f.fail='get'
    assert c.post('/api/integrations/cloudflare/test').status_code==502
    body=c.get('/api/events').text
    assert 'hidden-token' not in body and 'secret' not in body

def test_exact_sync_proxy_reject_public_ip_and_no_hostname_migration(env):
    c,s,f,_=env;p,ts=setup(c)
    f.unrelated(hostname='vpn.example.com',proxied=True)
    assert c.post(f"/api/pools/{p['id']}/sync").status_code==409
    assert c.post(f"/api/pools/{p['id']}/targets",json={'name':'private','ip':'127.0.0.1'}).status_code==422
    assert c.patch(f"/api/pools/{p['id']}",json={'hostname':'new.example.com'}).status_code==409

def test_auth_origin_no_secret_echo_or_storage(env):
    c,s,f,config=env
    assert c.get('/api/settings').json()['cloudflare_configured']
    assert 'hidden-token' not in c.get('/api/settings').text
    assert 'hidden-token' not in s.one("SELECT value FROM settings WHERE key='cloudflare_api_token'")['value']
    assert c.put('/api/settings',headers={'Origin':'https://evil.test'},json={'cloudflare_api_token':'dont-echo-secret'}).status_code==403
    assert c.put('/api/settings',json={'cloudflare_api_token':{'secret':'dont-echo-secret'}}).status_code==422
    assert 'dont-echo-secret' not in c.put('/api/settings',json={'cloudflare_api_token':{'secret':'dont-echo-secret'}}).text
    assert c.post('/api/agent/poll',json={'agent_id':'x','version':'1','control_ok':True,'control_error':None}).status_code==401
    assert c.post('/api/auth/logout').status_code==200
    assert c.get('/api/pools').status_code==401

def test_profile_and_streaks_survive_restart(tmp_path):
    cfg=Config('admin','password','S'*32,'T'*32,str(tmp_path/'persistent.db'),False,'http://testserver',cloudflare_api_token='hidden-token')
    fake=FakeCloudflare()
    for iteration in range(2):
        app=create_app(cfg,cf_factory=lambda token:fake.adapter)
        with TestClient(app,headers={'X-Requested-With':'DNSGuard'}) as c:
            c.post('/api/auth/login',json={'username':'admin','password':'password'})
            if iteration==0:
                p,ts=setup(c);round_(c,p,False)
            else:
                assert all(t['failures']==1 for t in targets(c,p))
                round_(c,p,False)
                assert any(t['status']=='excluded' for t in targets(c,p))

def test_remnawave_current_read_only_shapes_and_errors():
    calls=[]
    def handle(req):
        calls.append(req)
        assert req.method=='GET'
        assert req.headers['authorization']=='Bearer api-token'
        data=[{'uuid':'node','name':'n','address':'host.example.com','isConnected':True,'configProfile':{'activeConfigProfileUuid':'profile'}}] if req.url.path.endswith('nodes') else [{'uuid':'host','remark':'h','address':'1.1.1.1','port':443,'nodes':['node']}]
        return httpx.Response(200,json={'response':data})
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        r=Remnawave('https://panel.example.com','api-token',client)
        assert r.nodes()[0]['config_profile_uuid']=='profile'
        assert r.nodes()[0]['address']=='host.example.com'
        assert r.hosts()[0]['node_uuids']==['node']
    def forbidden(req): return httpx.Response(403,text='api-token')
    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(IntegrationError,match='unavailable'):
            Remnawave('https://panel.example.com','api-token',client).nodes()

def test_uncertain_delete_then_recovery_after_restart(tmp_path):
    cfg=Config('admin','password','S'*32,'T'*32,str(tmp_path/'restart.db'),False,'http://testserver',cloudflare_api_token='hidden-token')
    fake=FakeCloudflare()
    app=create_app(cfg,cf_factory=lambda token:fake.adapter)
    with TestClient(app,headers={'X-Requested-With':'DNSGuard'}) as c:
        c.post('/api/auth/login',json={'username':'admin','password':'password'})
        p,ts=setup(c,failure=1,recovery=1)
        # DELETE commits remotely, but response times out before backend verifies.
        fake.fail='delete'
        jobs=poll(c)
        assert result(c,jobs[0],False)==1
        assert len(fake.records)==1
        uncertain=app.state.store.one('SELECT * FROM targets WHERE id=?',(jobs[0]['target_id'],))
        assert uncertain['dns_present'] and uncertain['dns_uncertain']
        # Finish the second job so process restart doesn't leave a lease.
        result(c,jobs[1],True)
    fake.fail=None
    app=create_app(cfg,cf_factory=lambda token:fake.adapter)
    with TestClient(app,headers={'X-Requested-With':'DNSGuard'}) as c:
        c.post('/api/auth/login',json={'username':'admin','password':'password'})
        round_(c,p,True)
        assert len(fake.records)==2
        assert all(t['status']=='healthy' for t in targets(c,p))
        assert not app.state.store.one('SELECT * FROM targets WHERE id=?',(uncertain['id'],))['dns_uncertain']

def test_outage_resets_streaks_even_between_completed_batches(env):
    c,s,f,_=env;p,ts=setup(c)
    round_(c,p,False)
    assert all(t['failures']==1 for t in targets(c,p))
    poll(c,False)
    assert all(t['failures']==0 for t in targets(c,p))
    round_(c,p,False)
    assert all(t['status']=='suspect' for t in targets(c,p))
    assert len(f.records)==2

@pytest.mark.parametrize('update',[{'ip':'224.0.0.1'},{'server_name':'..'},{'host':'bad/host'},{'path':'//bad'},{'transport':'xhttp','flow':'xtls-rprx-vision'}])
def test_backend_rejects_profiles_agent_cannot_probe(env,update):
    c,s,f,_=env;p,ts=setup(c)
    if 'ip' in update:
        r=c.post(f"/api/pools/{p['id']}/targets",json={'name':'bad',**update})
    else:
        r=c.put(f"/api/pools/{p['id']}/profile",json={**PROFILE,**update})
    assert r.status_code==422

def test_login_rate_limit_reset_and_utf8(env,monkeypatch):
    c,s,f,cfg=env
    cfg.username='админ';cfg.password='секрет'
    assert c.post('/api/auth/login',json={'username':'админ','password':'секрет'}).status_code==200
    for _ in range(10):
        assert c.post('/api/auth/login',json={'username':'x','password':'x'}).status_code==401
    limited=c.post('/api/auth/login',json={'username':'админ','password':'секрет'})
    assert limited.status_code==429 and int(limited.headers['retry-after'])>0
    now=time.time()
    monkeypatch.setattr('backend.app.time.time',lambda:now+61)
    assert c.post('/api/auth/login',json={'username':'админ','password':'секрет'}).status_code==200

@pytest.mark.parametrize('body',[[],{'success':False,'errors':[{'message':'secret'}]},{'success':True,'result':[None]},{'success':True,'result':[],'result_info':{'total_pages':'bad'}},{'success':True,'result':[{'id':'zone'}]}])
def test_cloudflare_malformed_and_api_errors_are_safe(body):
    with httpx.Client(base_url='https://api.cloudflare.com/client/v4',transport=httpx.MockTransport(lambda req:httpx.Response(200,json=body))) as client:
        with pytest.raises(IntegrationError) as caught:
            Cloudflare('secret',client).zones()
        assert 'secret' not in str(caught.value)

def test_delete_commit_then_verification_read_fails_and_recovers(env):
    c,s,f,_=env;p,ts=setup(c,failure=1,recovery=1)
    original=f.handle
    def handle(req):
        response=original(req)
        if req.method=='DELETE': f.fail='get'
        return response
    f.client.close()
    f.client=httpx.Client(base_url='https://api.cloudflare.com/client/v4',transport=httpx.MockTransport(handle))
    f.adapter=Cloudflare('hidden-token',f.client)
    jobs=poll(c)
    assert result(c,jobs[0],False)==1
    assert len(f.records)==1
    t=s.one('SELECT * FROM targets WHERE id=?',(jobs[0]['target_id'],))
    assert t['dns_uncertain'] and t['dns_present']
    result(c,jobs[1],True)
    f.fail=None
    round_(c,p,True)
    assert len(f.records)==2
    assert all(t['status']=='healthy' for t in targets(c,p))

@pytest.mark.parametrize('error',['xray_start_failed','xray_config_invalid','invalid_job','control_unhealthy','control_unreachable','proxy_unavailable'])
def test_local_probe_error_is_inconclusive_and_never_removes_dns(env,error):
    c,s,f,_=env;p,ts=setup(c,failure=1)
    for _ in range(3):
        c.post(f"/api/pools/{p['id']}/check")
        for job in poll(c):
            assert result(c,job,False,error=error)==1
        assert len(f.records)==2
        assert all(t['status']=='unknown' and t['failures']==0 and t['successes']==0 for t in targets(c,p))
    assert any('inconclusive' in e['message'] for e in c.get('/api/events').json())
