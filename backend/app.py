import hashlib
import hmac
import secrets
import sqlite3
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from .config import Config
from .models import Login, Settings, PoolCreate, PoolPatch, ProbeProfile, TargetCreate, Poll, Results
from .store import Store, uid, iso
from .integrations import Cloudflare, Remnawave, IntegrationError, LastRecordError, ProxyConflictError
from .reconciliation import DNSReconciler, DNS_CHECK_SECONDS, CONTROL_FRESH_SECONDS

LEASE_SECONDS = 180
INCONCLUSIVE_ERRORS = {'xray_start_failed','xray_config_invalid','invalid_job','control_unhealthy','control_unreachable','proxy_unavailable'}
KNOWN_ERRORS = {'probe_failed','probe_timeout','xray_start_failed','xray_config_invalid','control_unhealthy','invalid_job','proxy_unavailable','http_error','tls_error','connection_failed','timeout','target_unreachable','tunnel_unreachable'}

def create_app(config=None, cf_factory=None, remna_factory=None, background_tasks=True):
    config = config or Config.from_env()
    config.validate()
    s = Store(config)
    cf_client = httpx.Client(base_url='https://api.cloudflare.com/client/v4', timeout=20, follow_redirects=False, trust_env=False)
    remna_client = httpx.Client(timeout=20, follow_redirects=False, trust_env=False)

    @asynccontextmanager
    async def lifespan(app):
        if background_tasks:
            reconciler.start()
        try:
            yield
        finally:
            reconciler.stop()
            cf_client.close()
            remna_client.close()
            s.db.close()

    app = FastAPI(title='DNS Guard', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = s
    app.state.config = config
    login_failures = deque(maxlen=10)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo request inputs: profiles and token settings contain credentials.
        known_fields = set().union(*(set(model.model_fields) for model in (Login, Settings, PoolCreate, PoolPatch, ProbeProfile, TargetCreate, Poll, Results)))
        fields = sorted({str(e['loc'][1]) if len(e['loc']) > 1 and e['loc'][1] in known_fields else 'request' for e in exc.errors()})
        return JSONResponse(status_code=422, content={'detail': 'Invalid request fields: ' + ', '.join(fields)})

    @app.exception_handler(IntegrationError)
    async def integration_error(request, exc):
        status = 409 if isinstance(exc, (LastRecordError, ProxyConflictError)) else 502
        return JSONResponse(status_code=status, content={'detail': str(exc)})

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict(request, exc):
        return JSONResponse(status_code=409, content={'detail':'A pool hostname or target IP already exists'})

    def origin(request: Request):
        value = request.headers.get('origin')
        if (value and value != config.public_origin) or (not value and request.headers.get('x-requested-with') != 'DNSGuard'):
            raise HTTPException(403, 'Invalid request origin')

    def auth(request: Request):
        if request.method not in ('GET','HEAD'):
            origin(request)
        token = request.cookies.get('dns_guard_session', '')
        digest = hashlib.sha256(token.encode()).hexdigest()
        with s.lock:
            session = s.one('SELECT * FROM sessions WHERE token=? AND expires>?', (digest,time.time()))
        if not session:
            raise HTTPException(401, 'Authentication required')
        return session['username']

    def agent_auth(request: Request):
        supplied = request.headers.get('authorization', '')
        if not hmac.compare_digest(supplied, 'Bearer ' + config.agent_token):
            raise HTTPException(401, 'Invalid agent credentials')

    def pool(id):
        value = s.one('SELECT * FROM pools WHERE id=?', (id,))
        if not value: raise HTTPException(404, 'Pool not found')
        return value

    def target(id):
        value = s.one('SELECT * FROM targets WHERE id=?', (id,))
        if not value: raise HTTPException(404, 'Target not found')
        return value

    def pool_view(row):
        return {**{k:v for k,v in row.items() if k not in ('profile','revision','dns_next_check')}, 'automation_enabled':bool(row['automation_enabled']), 'profile_configured':bool(row['profile'])}

    def target_view(row, context=None):
        hidden = {'next_due','last_agent_id','dns_operation_id','dns_previous_enabled','dns_profile_revision','dns_next_retry','dns_action'}
        value = {k:v for k,v in row.items() if k not in hidden}
        for key in ('manual_enabled','dns_present','dns_uncertain','dns_drift'):
            value[key] = bool(value[key])
        value['dns_pending_action'] = row['dns_action']
        if context is None:
            interval = pool(row['pool_id'])['interval_seconds']
            agent = s.one('SELECT * FROM agents WHERE id=?', (row['last_agent_id'],))
            now = time.time()
        else:
            intervals, agents, now = context
            interval, agent = intervals[row['pool_id']], agents.get(row['last_agent_id'])
        expires = datetime.fromisoformat(row['last_checked_at'].replace('Z', '+00:00')).timestamp() + max(LEASE_SECONDS, interval * 3) if row['last_checked_at'] else None
        value['probe_fresh'] = bool(expires and expires > now and agent and agent['healthy'] and now - agent['last_seen'] <= CONTROL_FRESH_SECONDS)
        value['last_status'] = row['status']
        if row['manual_enabled'] and row['last_checked_at'] and not value['probe_fresh']:
            value['status'] = 'stale'
        return value

    def target_views(rows):
        context = ({p['id']:p['interval_seconds'] for p in s.all('SELECT id,interval_seconds FROM pools')},
                   {a['id']:a for a in s.all('SELECT * FROM agents')}, time.time())
        return [target_view(row, context) for row in rows]

    def cf():
        with s.lock:
            token = s.get('cloudflare_api_token')
        if not token: raise HTTPException(400, 'Configure Cloudflare first')
        return cf_factory(token) if cf_factory else Cloudflare(token, cf_client)

    def remna():
        with s.lock:
            url, token = s.get('remnawave_url'), s.get('remnawave_api_token')
        if not url or not token: raise HTTPException(400, 'Configure Remnawave first')
        return remna_factory(url, token) if remna_factory else Remnawave(url, token, remna_client)

    def settings_view():
        agent = s.one('SELECT * FROM agents ORDER BY last_seen DESC LIMIT 1')
        return {'cloudflare_configured':bool(s.get('cloudflare_api_token')), 'remnawave_configured':bool(s.get('remnawave_url') and s.get('remnawave_api_token')), 'remnawave_url':s.get('remnawave_url'), 'agent_last_seen':iso(agent['last_seen']) if agent else None, 'agent_healthy':bool(agent and agent['healthy'] and time.time()-agent['last_seen'] <= CONTROL_FRESH_SECONDS)}

    def dns_provider():
        try:
            return cf()
        except HTTPException as error:
            raise IntegrationError(str(error.detail)) from None

    reconciler = DNSReconciler(s, dns_provider)
    app.state.reconciler = reconciler

    def manual_dns(id, action):
        with reconciler.dns_lock:
            with s.lock:
                target(id)
            reconciler.queue(id, action)
            reconciler.execute(id, raise_errors=True)
            with s.lock:
                return {'ok':True} if action == 'delete' else target_view(target(id))

    @app.get('/api/health')
    def health(): return {'ok':True}

    @app.post('/api/auth/login', dependencies=[Depends(origin)])
    def login(data: Login, response: Response):
        with s.lock:
            # A global limit stays bounded and cannot be bypassed using forwarded headers.
            now = time.time()
            while login_failures and login_failures[0] <= now - 60:
                login_failures.popleft()
            if len(login_failures) >= 10:
                retry = max(1, int(61 - (now - login_failures[0])))
                raise HTTPException(429, 'Too many login attempts; retry later', headers={'Retry-After':str(retry)})
            # Generic response; no credential or request-body logging.
            if not (hmac.compare_digest(data.username.encode(),config.username.encode()) and hmac.compare_digest(data.password.encode(),config.password.encode())):
                login_failures.append(now)
                raise HTTPException(401,'Invalid credentials')
            token = secrets.token_urlsafe(32)
            s.db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
            s.db.execute('INSERT INTO sessions VALUES (?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),config.username,time.time()+12*3600))
            response.set_cookie('dns_guard_session',token,max_age=12*3600,httponly=True,secure=config.cookie_secure,samesite='strict',path='/api')
            return {'username':config.username}

    @app.get('/api/auth/me')
    def me(username=Depends(auth)): return {'username':username}

    @app.post('/api/auth/logout')
    def logout(request: Request, response: Response, _=Depends(auth)):
        with s.lock:
            s.db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(request.cookies.get('dns_guard_session','').encode()).hexdigest(),))
        response.delete_cookie('dns_guard_session',path='/api',secure=config.cookie_secure,httponly=True,samesite='strict')
        return {'ok':True}

    @app.get('/api/settings')
    def get_settings(_=Depends(auth)):
        with s.lock: return settings_view()

    @app.put('/api/settings')
    def put_settings(data: Settings, _=Depends(auth)):
        with s.lock:
            if data.remnawave_url:
                Remnawave(data.remnawave_url, '', remna_client)
            for key,value in data.model_dump(exclude_unset=True).items():
                if value: s.set(key,value.rstrip('/') if key == 'remnawave_url' else value)
            s.event('info','system','Integration settings updated')
            return settings_view()

    @app.get('/api/overview')
    def overview(_=Depends(auth)):
        with s.lock:
            result = settings_view(); result.pop('remnawave_url')
            views = target_views(s.all('SELECT * FROM targets'))
            result.update(pools=s.one('SELECT COUNT(*) n FROM pools')['n'],targets=len(views),healthy=sum(t['status']=='healthy' and not t['dns_uncertain'] for t in views),excluded=sum(t['manual_enabled'] and not t['dns_present'] and not t['dns_uncertain'] for t in views),stale=sum(t['status']=='stale' for t in views))
            return result

    @app.post('/api/integrations/cloudflare/test')
    def test_cf(_=Depends(auth)):
        cf().zones()
        return {'ok':True,'message':'Cloudflare zone access verified'}

    @app.post('/api/integrations/remnawave/test')
    def test_remna(_=Depends(auth)):
        remna().nodes()
        return {'ok':True,'message':'Remnawave read access verified'}

    @app.get('/api/cloudflare/zones')
    def zones(_=Depends(auth)):
        return cf().zones()

    @app.get('/api/remnawave/nodes')
    def nodes(_=Depends(auth)):
        return remna().nodes()

    @app.get('/api/remnawave/hosts')
    def hosts(_=Depends(auth)):
        return remna().hosts()

    @app.get('/api/pools')
    def pools(_=Depends(auth)):
        with s.lock: return [pool_view(p) for p in s.all('SELECT * FROM pools ORDER BY created_at')]

    @app.post('/api/pools')
    def create_pool(data: PoolCreate, _=Depends(auth)):
        with s.lock:
            if data.automation_enabled: raise HTTPException(409,'Save profile and add targets before enabling automation')
            id = uid(); d=data.model_dump()
            s.db.execute('INSERT INTO pools (id,name,hostname,zone_id,ttl,interval_seconds,failure_threshold,recovery_threshold,automation_enabled,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',(id,d['name'],d['hostname'],d['zone_id'],d['ttl'],d['interval_seconds'],d['failure_threshold'],d['recovery_threshold'],0,iso()))
            s.db.execute('UPDATE pools SET dns_next_check=? WHERE id=?',(time.time()+DNS_CHECK_SECONDS,id))
            s.event('info','manual','Pool created',id)
            return pool_view(pool(id))

    @app.patch('/api/pools/{id}')
    def patch_pool(id: str, data: PoolPatch, _=Depends(auth)):
        with reconciler.dns_lock, s.lock:
            old = pool(id)
            updates = data.model_dump(exclude_unset=True)
            if any(v is None for v in updates.values()): raise HTTPException(422,'Pool fields cannot be null')
            try: valid = PoolCreate.model_validate({**{k:old[k] for k in PoolCreate.model_fields},**updates})
            except ValueError: raise HTTPException(422,'Invalid pool fields') from None
            if (valid.hostname != old['hostname'] or valid.zone_id != old['zone_id']) and s.one('SELECT id FROM targets WHERE pool_id=?',(id,)):
                raise HTTPException(409,'Hostname and zone cannot change while targets are enrolled')
            if valid.automation_enabled and (not old['profile'] or not s.one('SELECT id FROM targets WHERE pool_id=? AND manual_enabled=1',(id,))):
                raise HTTPException(409,'Save profile and add enabled targets before enabling automation')
            for key,value in valid.model_dump().items():
                s.db.execute(f'UPDATE pools SET {key}=? WHERE id=?',(value,id))
            s.event('info','manual','Pool settings updated',id)
            return pool_view(pool(id))

    @app.put('/api/pools/{id}/profile')
    def profile(id: str, data: ProbeProfile, _=Depends(auth)):
        with reconciler.dns_lock, s.lock:
            pool(id)
            s.db.execute('UPDATE pools SET profile=?, revision=revision+1 WHERE id=?',(s.encrypt(data.model_dump()),id))
            s.db.execute('UPDATE jobs SET consumed=1 WHERE target_id IN (SELECT id FROM targets WHERE pool_id=?)',(id,))
            s.db.execute("UPDATE targets SET failures=0, successes=0, next_due=0, status=CASE WHEN manual_enabled=0 THEN 'disabled' WHEN dns_present=0 THEN 'excluded' ELSE 'unknown' END WHERE pool_id=?",(id,))
            s.event('info','manual','Probe profile updated; pending jobs invalidated',id)
            return {'ok':True}

    @app.get('/api/pools/{id}/targets')
    def targets(id: str, _=Depends(auth)):
        with s.lock:
            pool(id)
            return target_views(s.all('SELECT * FROM targets WHERE pool_id=? ORDER BY name',(id,)))

    @app.post('/api/pools/{id}/targets')
    def create_target(id: str, data: TargetCreate, _=Depends(auth)):
        with reconciler.dns_lock:
            with s.lock:
                p = pool(id)
                existing = s.one('SELECT * FROM targets WHERE pool_id=? AND ip=?', (id,data.ip))
            if existing:
                if existing['dns_action'] != 'enroll':
                    raise HTTPException(409,'Target IP already enrolled')
                tid = existing['id']
            else:
                # A known configuration conflict must not become an enrollment
                # that can publish later without another explicit user action.
                adapter = cf()
                adapter.check_proxy(adapter.address_records(p))
                with s.transaction():
                    tid = uid()
                    s.db.execute('INSERT INTO targets (id,pool_id,name,ip,remnawave_uuid,dns_present) VALUES (?,?,?,?,?,0)', (tid,id,data.name,data.ip,data.remnawave_uuid))
                    reconciler.queue(tid, 'enroll')
            return manual_dns(tid, 'enroll')

    @app.post('/api/targets/{id}/disable')
    def disable(id: str, _=Depends(auth)):
        return manual_dns(id, 'disable')

    @app.post('/api/targets/{id}/enable')
    def enable(id: str, _=Depends(auth)):
        return manual_dns(id, 'enable')

    @app.delete('/api/targets/{id}')
    def delete(id: str, _=Depends(auth)):
        return manual_dns(id, 'delete')

    @app.post('/api/pools/{id}/sync')
    def sync(id: str, _=Depends(auth)):
        with s.lock:
            pool(id)
        added = reconciler.scan_pool(id, adopt=True)
        with s.lock:
            s.event('info','manual',f'Exact hostname DNS sync complete; adopted {added} targets',id)
        return {'added':added,'message':'Exact A records adopted; excluded targets retained'}

    @app.post('/api/pools/{id}/check')
    def check(id: str, _=Depends(auth)):
        with s.lock:
            pool(id); s.db.execute('UPDATE targets SET next_due=0 WHERE pool_id=? AND manual_enabled=1',(id,))
            return {'ok':True}

    @app.get('/api/events')
    def events(limit: int=100, level: str|None=None, type: str|None=None, pool_id: str|None=None, _=Depends(auth)):
        with s.lock:
            conditions=[]; args=[]
            for key,value in [('level',level),('type',type),('pool_id',pool_id)]:
                if value is not None: conditions.append(key+'=?'); args.append(value)
            query='SELECT * FROM events'+(' WHERE '+' AND '.join(conditions) if conditions else '')+' ORDER BY created_at DESC LIMIT ?'
            return s.all(query,(*args,max(1,min(limit,500))))

    @app.post('/api/agent/poll', dependencies=[Depends(agent_auth)])
    def poll(data: Poll):
        with s.lock:
            now=time.time()
            previous=s.one('SELECT * FROM agents WHERE id=?',(data.agent_id,))
            if previous and now - previous['last_seen'] > CONTROL_FRESH_SECONDS:
                s.db.execute('UPDATE targets SET failures=0,successes=0,next_due=0 WHERE last_agent_id=?', (data.agent_id,))
            s.db.execute('INSERT INTO agents VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,healthy=excluded.healthy',(data.agent_id,now,int(data.control_ok)))
            if not previous or bool(previous['healthy']) != data.control_ok:
                s.event('info' if data.control_ok else 'warning','system','Agent control connectivity healthy' if data.control_ok else 'Agent control connectivity unavailable; probing paused')
            for j in s.all('SELECT jobs.*,targets.pool_id FROM jobs JOIN targets ON targets.id=jobs.target_id WHERE consumed=0 AND expires<=?',(now,)):
                s.db.execute('UPDATE jobs SET consumed=1 WHERE id=?',(j['id'],))
                s.db.execute("UPDATE targets SET status=CASE WHEN manual_enabled=0 THEN 'disabled' WHEN dns_present=0 THEN 'excluded' ELSE 'unknown' END, failures=0,successes=0,next_due=0 WHERE id=?",(j['target_id'],))
                s.event('warning','check','Probe lease expired; target health unknown, no failure counted',j['pool_id'],j['target_id'])
            s.db.execute('DELETE FROM jobs WHERE consumed=1 AND expires<?',(now-86400,))
            if not data.control_ok:
                s.db.execute('UPDATE targets SET failures=0,successes=0,next_due=0 WHERE last_agent_id=? OR id IN (SELECT target_id FROM jobs WHERE agent_id=? AND consumed=0)',(data.agent_id,data.agent_id))
                s.db.execute('UPDATE jobs SET consumed=1 WHERE agent_id=? AND consumed=0',(data.agent_id,))
                return {'jobs':[],'poll_after_seconds':10}
            available=s.all('SELECT targets.* FROM targets JOIN pools ON pools.id=targets.pool_id WHERE manual_enabled=1 AND profile IS NOT NULL AND next_due<=? AND NOT EXISTS (SELECT 1 FROM jobs WHERE target_id=targets.id AND consumed=0) ORDER BY next_due,targets.id LIMIT 4',(now,))
            jobs=[]
            for t in available:
                p=pool(t['pool_id']); jid=uid()
                s.db.execute('INSERT INTO jobs (id,target_id,agent_id,revision,issued,expires) VALUES (?,?,?,?,?,?)',(jid,t['id'],data.agent_id,p['revision'],now,now+LEASE_SECONDS))
                s.db.execute('UPDATE targets SET next_due=? WHERE id=?',(now+p['interval_seconds'],t['id']))
                jobs.append({'job_id':jid,'target_id':t['id'],'ip':t['ip'],'profile':s.profile(p),'timeout_seconds':15})
            return {'jobs':jobs,'poll_after_seconds':10}

    @app.post('/api/agent/results', dependencies=[Depends(agent_auth)])
    def results(data: Results):
        with s.transaction():
            now=time.time(); a=s.one('SELECT * FROM agents WHERE id=?',(data.agent_id,))
            if not a or not a['healthy'] or now-a['last_seen']>CONTROL_FRESH_SECONDS:
                return {'accepted':0}
            accepted=0
            for result in data.results:
                j=s.one('SELECT * FROM jobs WHERE id=? AND consumed=0 AND agent_id=? AND expires>?',(result.job_id,data.agent_id,now))
                if not j: continue
                t=target(j['target_id']); p=pool(t['pool_id'])
                if p['revision'] != j['revision'] or not t['manual_enabled']: continue
                # Consume before reconciliation. DNS errors cannot replay this result.
                s.db.execute('UPDATE jobs SET consumed=1 WHERE id=?',(j['id'],)); accepted+=1
                if not result.ok and result.error in INCONCLUSIVE_ERRORS:
                    status='unknown' if t['dns_present'] else 'excluded'
                    s.db.execute('UPDATE targets SET failures=0,successes=0,status=?,last_checked_at=?,last_latency_ms=NULL,last_error=?,last_agent_id=? WHERE id=?',(status,iso(now),result.error,data.agent_id,t['id']))
                    s.event('error','check','Probe inconclusive: '+result.error,p['id'],t['id'])
                    continue
                failures=0 if result.ok else t['failures']+1
                successes=t['successes']+1 if result.ok else 0
                error=None if result.ok else (result.error if result.error in KNOWN_ERRORS else 'probe_failed')
                status=('healthy' if t['dns_present'] and not t['dns_uncertain'] else 'recovering') if result.ok else ('suspect' if t['dns_present'] else 'excluded')
                if not result.ok and t['status'] == 'protected':
                    status = 'protected'
                s.db.execute('UPDATE targets SET failures=?,successes=?,last_checked_at=?,last_latency_ms=?,last_error=?,status=?,last_agent_id=? WHERE id=?',(failures,successes,iso(now),result.latency_ms,error,status,data.agent_id,t['id']))
                manual_pending = t['dns_action'] and not t['dns_action'].startswith('auto_')
                if p['automation_enabled'] and not manual_pending:
                    if not result.ok and failures >= p['failure_threshold'] and (t['dns_present'] or t['dns_uncertain']) and status != 'protected':
                        reconciler.queue(t['id'], 'auto_remove')
                    elif result.ok and (not t['dns_present'] or t['dns_uncertain']) and successes >= p['recovery_threshold']:
                        reconciler.queue(t['id'], 'auto_restore')
                s.event('info' if result.ok else 'warning','check','Probe succeeded' if result.ok else 'Probe failed: '+error,p['id'],t['id'])
            return {'accepted':accepted}
    return app
