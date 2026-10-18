"""Durable DNS intents; provider I/O never holds the database lock."""
import logging
import threading
import time

from .integrations import IntegrationError, LastRecordError, ProxyConflictError
from .models import public_ipv4
from .store import iso, uid

DNS_CHECK_SECONDS = 300
RETRY_SECONDS = 30
CONTROL_FRESH_SECONDS = 90


def observed_status(t, present, uncertain=False):
    if not t['manual_enabled']:
        return 'disabled'
    if not t['last_checked_at']:
        return 'unknown' if present else 'excluded'
    if t['successes']:
        return 'healthy' if present and not uncertain else 'recovering'
    if t['failures']:
        return 'suspect' if present else 'excluded'
    return 'unknown' if present else 'excluded'


class DNSReconciler:
    def __init__(self, store, provider):
        self.s = store
        self.provider = provider
        self.dns_lock = threading.RLock()
        self.wake = threading.Event()
        self.stopped = threading.Event()
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._run, name='dns-reconciler', daemon=True)
        self.thread.start()

    def stop(self):
        self.stopped.set()
        self.wake.set()
        if self.thread:
            self.thread.join()

    def _run(self):
        while not self.stopped.is_set():
            try:
                self.run_once()
            except Exception:
                # Provider exceptions can contain credentials; never log their text.
                logging.getLogger(__name__).error('DNS reconciliation cycle failed')
            self.wake.wait(1)
            self.wake.clear()

    def queue(self, target_id, action):
        with self.s.transaction():
            t = self.s.one('SELECT * FROM targets WHERE id=?', (target_id,))
            if not t:
                return
            manual = not action.startswith('auto_')
            # Retrying the same intent preserves its identity and original enabled state.
            operation_id = t['dns_operation_id'] if t['dns_action'] == action else uid()
            previous = t['dns_previous_enabled'] if t['dns_action'] == action else t['manual_enabled']
            p = self.s.one('SELECT revision FROM pools WHERE id=?', (t['pool_id'],))
            self.s.db.execute('UPDATE targets SET dns_action=?,dns_operation_id=?,dns_previous_enabled=?,dns_profile_revision=?,dns_uncertain=1,dns_next_retry=0 WHERE id=?',
                              (action, operation_id, previous, p['revision'], target_id))
            if manual:
                enabled = action in ('enroll', 'enable')
                self.s.db.execute("UPDATE targets SET manual_enabled=?,status=?,failures=0,successes=0,next_due=0,last_checked_at=NULL,last_error=NULL WHERE id=?",
                                  (int(enabled), 'unknown' if enabled else 'disabled', target_id))
                self.s.db.execute('UPDATE jobs SET consumed=1 WHERE target_id=?', (target_id,))
        self.wake.set()

    def execute(self, target_id, raise_errors=False):
        with self.dns_lock:
            with self.s.lock:
                t = self.s.one('SELECT * FROM targets WHERE id=?', (target_id,))
                if not t or not t['dns_action']:
                    return
                p = self.s.one('SELECT * FROM pools WHERE id=?', (t['pool_id'],))
                action, operation = t['dns_action'], t['dns_operation_id']
                if action.startswith('auto_'):
                    valid = p['automation_enabled'] and t['manual_enabled'] and p['revision'] == t['dns_profile_revision']
                    valid = valid and (t['failures'] >= p['failure_threshold'] if action == 'auto_remove' else t['successes'] >= p['recovery_threshold'])
                    if not valid:
                        self.s.db.execute('UPDATE targets SET dns_action=NULL,dns_uncertain=CASE WHEN dns_error IS NULL THEN 0 ELSE dns_uncertain END WHERE id=?', (target_id,))
                        return
                    agent = self.s.one('SELECT * FROM agents WHERE id=?', (t['last_agent_id'],))
                    if not agent or not agent['healthy'] or time.time() - agent['last_seen'] > CONTROL_FRESH_SECONDS:
                        self.s.db.execute('UPDATE targets SET dns_next_retry=? WHERE id=?', (time.time() + RETRY_SECONDS, target_id))
                        return
            present = action in ('enroll', 'enable', 'auto_restore')
            try:
                actual = self.provider().ensure(p, t['ip'], present)
            except LastRecordError:
                with self.s.lock:
                    current = self.s.one('SELECT * FROM targets WHERE id=?', (target_id,))
                    if current and current['dns_operation_id'] == operation:
                        enabled = current['dns_previous_enabled'] if not action.startswith('auto_') else current['manual_enabled']
                        if current['status'] != 'protected':
                            self.s.event('warning', 'dns', 'Removal prevented: final actual A record preserved', p['id'], target_id)
                        self.s.db.execute("UPDATE targets SET manual_enabled=?,dns_present=1,dns_uncertain=0,dns_action=NULL,dns_error=NULL,dns_checked_at=?,status=? WHERE id=?",
                                          (enabled, iso(), 'protected' if enabled else 'disabled', target_id))
                if raise_errors:
                    raise
                return
            except IntegrationError as error:
                with self.s.lock:
                    current = self.s.one('SELECT * FROM targets WHERE id=?', (target_id,))
                    if current and current['dns_operation_id'] == operation:
                        message = str(error)  # Adapters expose only sanitized messages.
                        if current['dns_error'] != message:
                            self.s.event('error', 'dns', 'DNS change pending: ' + message, p['id'], target_id)
                        self.s.db.execute('UPDATE targets SET dns_error=?,dns_next_retry=? WHERE id=?', (message, time.time() + RETRY_SECONDS, target_id))
                if raise_errors:
                    if isinstance(error, ProxyConflictError):
                        raise
                    raise IntegrationError(str(error) + '. Операция сохранена; DNS ожидает подтверждения и будет проверен повторно.') from None
                return
            with self.s.transaction():
                current = self.s.one('SELECT * FROM targets WHERE id=?', (target_id,))
                if not current or current['dns_operation_id'] != operation:
                    return
                self.s.db.execute('UPDATE pools SET dns_next_check=0 WHERE id=?', (p['id'],))
                if action == 'delete':
                    self.s.db.execute('DELETE FROM targets WHERE id=?', (target_id,))
                    self.s.event('warning', 'manual', 'Target removed; exact A record absence verified', p['id'], target_id)
                    return
                status = observed_status(current, actual)
                self.s.db.execute('UPDATE targets SET dns_present=?,dns_uncertain=0,dns_action=NULL,dns_error=NULL,dns_checked_at=?,dns_drift=0,status=? WHERE id=?',
                                  (int(actual), iso(), status, target_id))
                if actual != bool(t['dns_present']) or not action.startswith('auto_'):
                    message = 'Exact A record presence verified' if actual else 'Exact A record absence verified'
                    self.s.event('info' if actual else 'warning', 'dns' if action.startswith('auto_') else 'manual', message, p['id'], target_id)
                if actual:
                    # A newly available peer permits retrying a previously protected removal.
                    self.s.db.execute("UPDATE targets SET status='suspect' WHERE pool_id=? AND id!=? AND status='protected'", (p['id'], target_id))

    def scan_pool(self, pool_id, adopt=False):
        with self.dns_lock:
            with self.s.lock:
                p = self.s.one('SELECT * FROM pools WHERE id=?', (pool_id,))
                if not p:
                    return 0
            try:
                adapter = self.provider()
                addresses = adapter.address_records(p)
                adapter.check_proxy(addresses)
                records = [r for r in addresses if r['type'] == 'A']
            except IntegrationError as error:
                with self.s.lock:
                    if p['dns_error'] != str(error):
                        self.s.event('error', 'dns', 'DNS verification failed: ' + str(error), pool_id)
                    self.s.db.execute('UPDATE pools SET dns_error=?,dns_next_check=? WHERE id=?', (str(error), time.time() + RETRY_SECONDS, pool_id))
                    self.s.db.execute('UPDATE targets SET dns_uncertain=1 WHERE pool_id=?', (pool_id,))
                if adopt:
                    raise
                return 0
            added = 0
            actual_ips = {r['content'] for r in records}
            with self.s.transaction():
                if adopt:
                    for ip in actual_ips:
                        try:
                            public_ipv4(ip)
                        except ValueError:
                            continue
                        if not self.s.one('SELECT id FROM targets WHERE pool_id=? AND ip=?', (pool_id, ip)):
                            self.s.db.execute('INSERT INTO targets (id,pool_id,name,ip) VALUES (?,?,?,?)', (uid(), pool_id, ip, ip))
                            added += 1
                enrolled = self.s.all('SELECT * FROM targets WHERE pool_id=?', (pool_id,))
                drift_count = len(actual_ips - {t['ip'] for t in enrolled})
                for t in enrolled:
                    if t['dns_action']:
                        continue  # Pending intent owns its state until verified.
                    present = t['ip'] in actual_ips
                    changed = present != bool(t['dns_present'])
                    drift = (changed or bool(t['dns_drift'])) and not adopt
                    drift = drift or (present and not t['manual_enabled'])
                    drift_count += int(drift)
                    status = observed_status(t, present)
                    if changed:
                        if not t['dns_drift']:
                            self.s.event('warning', 'dns', 'External DNS change detected; actual A record ' + ('present' if present else 'absent'), pool_id, t['id'])
                        self.s.db.execute('UPDATE targets SET failures=0,successes=0 WHERE id=?', (t['id'],))
                        status = 'disabled' if not t['manual_enabled'] else ('unknown' if present else 'excluded')
                    elif t['status'] == 'protected' and len(actual_ips) == 1:
                        status = 'protected'
                    self.s.db.execute('UPDATE targets SET dns_present=?,dns_uncertain=0,dns_checked_at=?,dns_drift=?,status=? WHERE id=?',
                                      (int(present), iso(), int(drift), status, t['id']))
                if drift_count and drift_count != p['dns_drift_count']:
                    self.s.event('warning', 'dns', f'DNS drift detected: {drift_count} discrepancies', pool_id)
                self.s.db.execute('UPDATE pools SET dns_checked_at=?,dns_error=NULL,dns_next_check=?,dns_drift_count=? WHERE id=?',
                                  (iso(), time.time() + DNS_CHECK_SECONDS, drift_count, pool_id))
            return added

    def run_once(self):
        with self.s.lock:
            pending = self.s.all('SELECT id FROM targets WHERE dns_action IS NOT NULL AND dns_next_retry<=?', (time.time(),))
        for t in pending:
            if self.stopped.is_set():
                return
            self.execute(t['id'])
        with self.s.lock:
            pools = self.s.all('SELECT id FROM pools WHERE dns_next_check<=?', (time.time(),))
        for p in pools:
            if self.stopped.is_set():
                return
            self.scan_pool(p['id'])
