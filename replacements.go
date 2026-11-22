package guard

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"
)

const replacementDelay = 5 * time.Minute

type replacementProvider interface {
	Snapshot(ctx context.Context, serverID, oldIP, operationID string) (json.RawMessage, error)
	Retire(ctx context.Context, serverID, oldIP string, snapshot json.RawMessage) error
	Provision(ctx context.Context, snapshot json.RawMessage, operationID, oldIP string, claimCreate func() (bool, error)) (serverID, ip string, err error)
	ReleaseOldIP(ctx context.Context, snapshot json.RawMessage, serverID, newIP, oldIP string) error
}

var (
	errReplacementCreateRejected    = errors.New("provider rejected the replacement create request")
	errReplacementCreateUnconfirmed = errors.New("replacement create outcome is unconfirmed")
	errReplacementPending           = errors.New("provider operation is in progress")
)

type replacementAdapter struct {
	serverID func(string) (string, bool)
	open     func() (replacementProvider, error)
}

type nodeInstaller interface {
	Ready() error
	ReadyForNode(string) error
	Run(context.Context, string, string) error
}

type replacementWorker struct {
	a         *App
	providers map[string]replacementAdapter
	ansible   nodeInstaller
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
}

func newReplacementWorker(a *App) *replacementWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &replacementWorker{
		a: a, ctx: ctx, cancel: cancel, ansible: newReplacementAnsible(),
		providers: map[string]replacementAdapter{
			"upcloud": {serverID: canonicalUUID, open: func() (replacementProvider, error) {
				a.s.mu.Lock()
				defer a.s.mu.Unlock()
				token := a.s.get("upcloud_token")
				if token == "" {
					return nil, errors.New("укажите токен UpCloud в разделе автозамены")
				}
				return newUpCloudReplacement(a.client, token), nil
			}},
		},
	}
}

func (w *replacementWorker) start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-w.ctx.Done():
				return
			case <-ticker.C:
				func() {
					defer func() {
						if recover() != nil {
							log.Print("Server replacement cycle failed")
						}
					}()
					w.runOnce()
				}()
			}
		}
	}()
}

func (w *replacementWorker) close() { w.cancel(); w.wg.Wait() }

// The timer uses the same fresh removal vote and protected-final-record state
// as DNS Guard. A missing record alone is also possible for a newly enrolled IP.
func replacementBlocked(t, p row, summary probeSummary) bool {
	status, _ := summary.statuses(t)
	return truth(t["manual_enabled"]) && truth(p["automation_enabled"]) && t["dns_action"] == nil &&
		!truth(t["dns_uncertain"]) && summary.Remove && oneOf(status, "excluded", "protected")
}

func replacementDue(since any, now float64) bool {
	return since != nil && now-num(since) >= replacementDelay.Seconds()
}

const replacementObservedBindings = `SELECT b.target_id,b.provider,b.server_uuid,b.node_uuid,b.blocked_since,
 EXISTS(SELECT 1 FROM replacement_jobs WHERE target_id=b.target_id AND ` + replacementActive + `) AS active
 FROM replacement_bindings b`

const replacementObservedFilter = `b.enabled=1 AND NOT EXISTS(SELECT 1 FROM server_orders WHERE target_id=b.target_id AND stage='deleting')`

func (s *Store) observeReplacement(t, p, b row, summary probeSummary, now float64) float64 {
	if b == nil {
		return 0
	}
	if !replacementBlocked(t, p, summary) {
		if b["blocked_since"] != nil {
			s.exec("UPDATE replacement_bindings SET blocked_since=NULL WHERE target_id=?", t["id"])
		}
		return 0
	}
	delay := replacementDelay.Seconds()
	if b["blocked_since"] != nil && !replacementDue(b["blocked_since"], now) {
		return num(b["blocked_since"]) + delay
	}
	if truth(b["active"]) {
		return 0
	}
	if b["blocked_since"] == nil {
		s.exec("UPDATE replacement_bindings SET blocked_since=? WHERE target_id=?", now, t["id"])
		return now + delay
	}
	stamp := iso(fromSeconds(now))
	s.exec(`INSERT INTO replacement_jobs(id,target_id,pool_id,name,provider,server_uuid,node_uuid,old_ip,stage,created_at,updated_at)
 VALUES(?,?,?,?,?,?,?,?,'preflight',?,?)`, uid(), t["id"], p["id"], t["name"], b["provider"], b["server_uuid"], b["node_uuid"], t["ip"], stamp, stamp)
	s.event("warning", "system", "Начата проверка перед автозаменой сервера", p["id"], t["id"])
	return 0
}

// Re-read after external preflight calls. Once the retirement intent commits,
// all subsequent retries use the immutable identities and saved provider plan.
func (w *replacementWorker) preflightCurrent(j row) bool {
	s := w.a.s
	b := s.one("SELECT * FROM replacement_bindings WHERE target_id=?", j["target_id"])
	t := s.one("SELECT * FROM targets WHERE id=?", j["target_id"])
	if t == nil || b == nil || !truth(b["enabled"]) || !replacementDue(b["blocked_since"], nowSeconds()) || t["ip"] != j["old_ip"] || b["provider"] != j["provider"] || b["server_uuid"] != j["server_uuid"] || b["node_uuid"] != j["node_uuid"] {
		return false
	}
	p := s.one("SELECT id,automation_enabled,interval_seconds,failure_threshold,recovery_threshold FROM pools WHERE id=?", t["pool_id"])
	return replacementBlocked(t, p, s.targetProbeSummary(t["id"], p))
}

func (w *replacementWorker) runOnce() {
	w.mu.Lock()
	defer w.mu.Unlock()
	a := w.a
	var jobs []row
	a.withStore(func() any {
		jobs = a.s.all("SELECT id FROM replacement_jobs WHERE "+replacementActive+" AND next_retry<=? AND (stage!='cleanup' OR release_after<=?) ORDER BY created_at", nowSeconds(), nowSeconds())
		return nil
	})
	for _, j := range jobs {
		if w.ctx.Err() != nil {
			return
		}
		job := w.nextStep(j["id"])
		if job == nil {
			continue
		}
		if err := w.step(job); err != nil && w.ctx.Err() == nil {
			w.retry(job, err)
		}
	}
}

// Select just before each step because a long-running playbook for another
// target may have overlapped a pause or a change of binding.
func (w *replacementWorker) nextStep(id any) row {
	s := w.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.one(`SELECT j.* FROM replacement_jobs j JOIN replacement_bindings b ON b.target_id=j.target_id
 JOIN pools p ON p.id=j.pool_id WHERE j.id=? AND `+replacementActive+` AND j.next_retry<=?
 AND (j.stage='preflight' OR (b.enabled=1 AND p.automation_enabled=1))`, id, nowSeconds())
}

func (w *replacementWorker) retry(job row, err error) {
	s := w.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.one("SELECT stage,error FROM replacement_jobs WHERE id=?", job["id"])
	if current["stage"] != job["stage"] {
		return
	}
	if errors.Is(err, errReplacementPending) {
		s.exec("UPDATE replacement_jobs SET error=NULL,can_retry_create=0,next_retry=? WHERE id=?", nowSeconds()+5, job["id"])
		return
	}
	s.transaction(func() {
		if current["error"] != err.Error() {
			s.event("error", "system", "Автозамена: "+err.Error(), job["pool_id"], job["target_id"])
		}
		s.exec(`UPDATE replacement_jobs SET error=?,next_retry=?,updated_at=?,
 can_retry_create=CASE WHEN create_attempted=1 AND (provider!='virtua' OR (new_server_uuid IS NULL AND host_key IS NULL)) THEN ? ELSE 0 END WHERE id=?`, err.Error(), nowSeconds()+retrySeconds, iso(time.Now()), errors.Is(err, errReplacementCreateUnconfirmed), job["id"])
	})
}

func (w *replacementWorker) commit(j row, next string, change func()) {
	s := w.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.one("SELECT stage FROM replacement_jobs WHERE id=?", j["id"])
	if current["stage"] != j["stage"] {
		return
	}
	s.transaction(func() {
		if change != nil {
			change()
		}
		s.setReplacementStage(j, next)
	})
}

func (w *replacementWorker) preflight(j row, prepare func() (json.RawMessage, string, error)) error {
	a := w.a
	order := w.replacementOrder(j)
	if j["provider"] == virtuaOrderProvider {
		j["node_domain"] = order["domain"]
	}
	if order != nil {
		if err := a.orders.installer.ReadyForOrder(w.ctx, orderNode(order)); err != nil {
			return err
		}
	} else {
		if err := w.ansible.ReadyForNode(str(j["node_uuid"])); err != nil {
			return err
		}
	}
	panel, err := a.remnawaveProvider()
	if err != nil {
		return err
	}
	if err = panel.checkReplacementNode(j, false); err != nil {
		return err
	}
	if err = panel.replacementHosts(j, false); err != nil {
		return err
	}
	if j["provider"] == virtuaOrderProvider {
		if _, err = panel.orderNodeSecret(w.ctx); err != nil {
			return err
		}
	}
	dns, err := a.dnsProvider()
	if err != nil {
		return err
	}
	var pool row
	a.withStore(func() any { pool = a.pool(str(j["pool_id"])); return nil })
	records, err := dns.addressRecords(pool)
	if err != nil {
		return err
	}
	if err = checkProxy(records); err != nil {
		return err
	}
	ttl := replacementRecordTTL(records, str(j["old_ip"]), num(pool["ttl"]))
	var originTTL float64
	if order != nil {
		originTTL, err = checkReplacementOrigin(dns, order, str(j["old_ip"]), "", false)
		if err != nil {
			return err
		}
		ttl = max(ttl, originTTL)
	}
	snapshot, credential, err := prepare()
	if err != nil {
		return err
	}

	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	s := a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.one("SELECT stage FROM replacement_jobs WHERE id=?", j["id"])
	if current["stage"] != "preflight" {
		return nil
	}
	if !w.preflightCurrent(j) {
		s.setReplacementStage(j, "cancelled")
		return nil
	}
	if truth(order["manual_origin"]) && s.replacementDomainUsed(j["target_id"], str(order["domain"])) {
		return errors.New("этот домен уже используется в DNS Guard")
	}
	if s.one("SELECT id FROM targets WHERE id!=? AND (ip=? OR dns_new_ip=? OR lower(remnawave_uuid)=?)", j["target_id"], j["old_ip"], j["old_ip"], j["node_uuid"]) != nil {
		return errors.New("эта нода или её IP используется ещё одной целью. Проверьте привязки перед заменой")
	}
	s.transaction(func() {
		s.exec("UPDATE replacement_jobs SET snapshot=?,enroll_digest=NULLIF(?,''),release_after=?,old_record_ttl=MAX(old_record_ttl,?) WHERE id=?",
			s.cipher.encrypt(snapshot), credential, nowSeconds()+max(num(pool["ttl"]), ttl), originTTL, j["id"])
		s.exec("UPDATE replacement_bindings SET blocked_since=NULL WHERE target_id=?", j["target_id"])
		s.exec("UPDATE jobs SET consumed=1 WHERE target_id=?", j["target_id"])
		stage := "retire"
		if j["provider"] == virtuaOrderProvider {
			stage = "provision"
		}
		s.setReplacementStage(j, stage)
	})
	return nil
}

func (w *replacementWorker) step(j row) error {
	stage := str(j["stage"])
	switch stage {
	case "preflight", "retire", "provision", "cleanup":
		if stage == "preflight" {
			var valid bool
			w.a.withStore(func() any { valid = w.preflightCurrent(j); return nil })
			if !valid {
				w.commit(j, "cancelled", nil)
				return nil
			}
		}
		if j["provider"] == virtuaOrderProvider {
			return w.stepVirtua(j)
		}
		adapter, ok := w.providers[str(j["provider"])]
		if !ok {
			return errors.New("провайдер автозамены недоступен")
		}
		cloud, err := adapter.open()
		if err != nil {
			return err
		}
		if stage == "preflight" {
			return w.preflight(j, func() (json.RawMessage, string, error) {
				snapshot, err := cloud.Snapshot(w.ctx, str(j["server_uuid"]), str(j["old_ip"]), str(j["id"]))
				return snapshot, "", err
			})
		}
		return w.changeServer(j, cloud)
	case "enrollment":
		return w.stepVirtua(j)
	case "ansible":
		if err := w.installReplacement(j); err != nil {
			return err
		}
		w.commit(j, "remnawave", nil)
	case "remnawave":
		return w.moveNode(j)
	case "verify":
		if w.recovered(j) {
			w.commit(j, "dns", nil)
		}
	case "dns":
		return w.publish(j)
	default:
		return errors.New("неизвестный этап автозамены")
	}
	return nil
}

func (w *replacementWorker) managedOrder(j row) row {
	if w.a.orders == nil {
		return nil
	}
	return w.a.orders.managed(j["target_id"], str(j["node_uuid"]))
}

func (w *replacementWorker) installReplacement(j row) error {
	oldIP, newIP, nodeID := str(j["old_ip"]), str(j["new_ip"]), str(j["node_uuid"])
	order := w.replacementOrder(j)
	if order == nil {
		return w.ansible.Run(w.ctx, newIP, nodeID)
	}
	if j["provider"] == virtuaOrderProvider {
		order["host_key"] = j["host_key"]
	}
	a := w.a
	dns, err := a.dnsProvider()
	if err != nil {
		return err
	}
	err = func() error {
		a.reconciler.dnsMu.Lock()
		defer a.reconciler.dnsMu.Unlock()
		if truth(order["manual_origin"]) && a.withStore(func() any {
			return a.s.replacementDomainUsed(j["target_id"], str(order["domain"]))
		}).(bool) {
			return errors.New("этот домен уже используется в DNS Guard")
		}
		ttl, err := checkReplacementOrigin(dns, order, oldIP, newIP, false)
		if err != nil {
			return err
		}
		// The old address can be cached after the domain moves. Save its TTL
		// before the PATCH, since the existing record may be gone on retry.
		a.withStore(func() any {
			a.s.exec("UPDATE replacement_jobs SET old_record_ttl=MAX(old_record_ttl,?) WHERE id=?", ttl, j["id"])
			return nil
		})
		ttl, err = checkReplacementOrigin(dns, order, oldIP, newIP, true)
		if err != nil {
			return err
		}
		a.withStore(func() any {
			a.s.exec("UPDATE replacement_jobs SET release_after=MAX(release_after,?+MAX(old_record_ttl,?)) WHERE id=?", nowSeconds(), ttl, j["id"])
			return nil
		})
		return nil
	}()
	if err != nil {
		return err
	}
	return a.orders.install(w.ctx, order, newIP, nodeID)
}

func (w *replacementWorker) changeServer(j row, cloud replacementProvider) error {
	s := w.a.s
	raw, err := s.cipher.decrypt(str(j["snapshot"]))
	if err != nil {
		return errors.New("не удалось прочитать сохранённую конфигурацию сервера")
	}
	snapshot := json.RawMessage(raw)
	oldIP := str(j["old_ip"])
	switch j["stage"] {
	case "retire":
		if order := w.managedOrder(j); order != nil {
			dns, err := w.a.dnsProvider()
			if err != nil {
				return err
			}
			if _, err := dns.checkOrderOrigin(order, oldIP, "", false); err != nil {
				return err
			}
		}
		if err = cloud.Retire(w.ctx, str(j["server_uuid"]), oldIP, snapshot); err != nil {
			return err
		}
		w.commit(j, "provision", nil)
	case "provision":
		claim := func() (bool, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			result := s.exec("UPDATE replacement_jobs SET create_attempted=1,can_retry_create=0 WHERE id=? AND stage='provision' AND create_attempted=0", j["id"])
			n, err := result.RowsAffected()
			return n == 1, err
		}
		server, ip, err := cloud.Provision(w.ctx, snapshot, str(j["id"]), oldIP, claim)
		if errors.Is(err, errReplacementCreateRejected) {
			w.a.withStore(func() any { s.exec("UPDATE replacement_jobs SET create_attempted=0 WHERE id=?", j["id"]); return nil })
		}
		if err != nil {
			return err
		}
		if server == "" || server == j["server_uuid"] || !publicIPv4(ip) || ip == oldIP {
			return errors.New("провайдер не подтвердил новый сервер с другим публичным IPv4")
		}
		w.commit(j, "ansible", func() {
			s.exec("UPDATE replacement_jobs SET new_server_uuid=?,new_ip=? WHERE id=?", server, ip, j["id"])
		})
	case "cleanup":
		return w.cleanup(j, func() error {
			return cloud.ReleaseOldIP(w.ctx, snapshot, str(j["new_server_uuid"]), str(j["new_ip"]), oldIP)
		})
	}
	return nil
}

func (w *replacementWorker) cleanup(j row, release func() error) error {
	if num(j["release_after"]) > nowSeconds() {
		return nil
	}
	a, s := w.a, w.a.s
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	dns, err := a.dnsProvider()
	if err != nil {
		return err
	}
	if order := w.replacementOrder(j); order != nil {
		if j["provider"] == virtuaOrderProvider {
			j["node_domain"] = order["domain"]
		}
		if _, err = checkReplacementOrigin(dns, order, "", str(j["new_ip"]), false); err != nil {
			return err
		}
	}
	var pool row
	a.withStore(func() any { pool = a.pool(str(j["pool_id"])); return nil })
	records, err := dns.addressRecords(pool)
	if err != nil {
		return err
	}
	if err = checkProxy(records); err != nil {
		return err
	}
	if ttl := replacementRecordTTL(records, str(j["old_ip"]), num(pool["ttl"])); ttl > 0 {
		a.withStore(func() any {
			s.exec("UPDATE replacement_jobs SET release_after=? WHERE id=?", nowSeconds()+ttl, j["id"])
			return nil
		})
		return errors.New("прежний IP снова присутствует в DNS")
	}
	if j["provider"] == virtuaOrderProvider && replacementRecordTTL(records, str(j["new_ip"]), num(pool["ttl"])) == 0 {
		return errors.New("в DNS-пуле отсутствует новый IP сервера Virtua.Cloud")
	}
	if err = release(); err != nil {
		return err
	}
	w.commit(j, "complete", func() {
		s.exec("UPDATE replacement_bindings SET server_uuid=?,blocked_since=NULL WHERE target_id=?", j["new_server_uuid"], j["target_id"])
		s.exec("UPDATE replacement_jobs SET snapshot=NULL,enroll_digest=NULL WHERE id=?", j["id"])
	})
	return nil
}

func (w *replacementWorker) moveNode(j row) error {
	a, s := w.a, w.a.s
	if j["provider"] == virtuaOrderProvider {
		j["node_domain"] = w.replacementOrder(j)["domain"]
	}
	panel, err := a.remnawaveProvider()
	if err != nil {
		return err
	}
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	var conflict bool
	a.withStore(func() any {
		conflict = s.one("SELECT id FROM targets WHERE id!=? AND (ip=? OR dns_new_ip=?)", j["target_id"], j["new_ip"], j["new_ip"]) != nil
		return nil
	})
	if conflict {
		return errors.New("новый IP уже используется другой целью")
	}
	if err = panel.checkReplacementNode(j, true); err != nil {
		return err
	}
	w.commit(j, "verify", func() {
		s.exec(`UPDATE targets SET ip=?,status='excluded',dns_present=0,dns_uncertain=0,dns_error=NULL,dns_checked_at=NULL,
 dns_drift=0,successes=0,failures=0,next_due=0,last_checked_at=NULL,last_error=NULL,last_latency_ms=NULL,last_agent_id=NULL WHERE id=?`, j["new_ip"], j["target_id"])
		s.exec("UPDATE jobs SET consumed=1 WHERE target_id=?", j["target_id"])
		s.exec("DELETE FROM target_checks WHERE target_id=?", j["target_id"])
	})
	return nil
}

func (w *replacementWorker) publish(j row) error {
	a, s := w.a, w.a.s
	order := w.replacementOrder(j)
	if j["provider"] == virtuaOrderProvider {
		j["node_domain"] = order["domain"]
	}
	a.reconciler.dnsMu.Lock()
	defer a.reconciler.dnsMu.Unlock()
	if !w.recovered(j) {
		w.commit(j, "verify", nil)
		return nil
	}
	panel, err := a.remnawaveProvider()
	if err != nil {
		return err
	}
	if err = panel.checkReplacementNode(j, true); err != nil {
		return err
	}
	if err = panel.replacementHosts(j, true); err != nil {
		return err
	}
	dns, err := a.dnsProvider()
	if err != nil {
		return err
	}
	if order != nil {
		if _, err := checkReplacementOrigin(dns, order, "", str(j["new_ip"]), false); err != nil {
			return err
		}
	}
	var pool row
	a.withStore(func() any { pool = a.pool(str(j["pool_id"])); return nil })
	records, err := dns.addressRecords(pool)
	if err != nil {
		return err
	}
	ttl := max(num(j["old_record_ttl"]), replacementRecordTTL(records, str(j["old_ip"]), num(pool["ttl"])))
	if ttl > num(j["old_record_ttl"]) {
		// Remember the TTL before the provider can drop the old record, even
		// if the process exits after a successful remote change.
		a.withStore(func() any {
			s.exec("UPDATE replacement_jobs SET old_record_ttl=? WHERE id=?", ttl, j["id"])
			return nil
		})
	}
	if _, err = dns.replaceIP(pool, str(j["old_ip"]), str(j["new_ip"]), true); err != nil {
		return err
	}
	w.commit(j, "cleanup", func() {
		s.exec("UPDATE replacement_jobs SET release_after=MAX(release_after,?) WHERE id=?", nowSeconds()+ttl, j["id"])
		s.exec("UPDATE targets SET dns_present=1,dns_uncertain=0,dns_drift=0,dns_checked_at=?,status='healthy' WHERE id=?", iso(time.Now()), j["target_id"])
		s.exec("UPDATE pools SET dns_next_check=0,remnawave_next_check=0 WHERE id=?", j["pool_id"])
	})
	return nil
}

func (w *replacementWorker) recovered(j row) bool {
	s := w.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.one("SELECT * FROM targets WHERE id=?", j["target_id"])
	p := s.one("SELECT * FROM pools WHERE id=?", j["pool_id"])
	return t["ip"] == j["new_ip"] && truth(p["automation_enabled"]) && truth(t["manual_enabled"]) && s.targetProbeSummary(t["id"], p).Restore
}

// Cloudflare encodes its automatic TTL as 1 (five minutes).
func replacementRecordTTL(records []row, ip string, poolTTL float64) float64 {
	var ttl float64
	for _, record := range records {
		if record["type"] != "A" || record["content"] != ip {
			continue
		}
		seconds := num(record["ttl"])
		if seconds <= 1 {
			seconds = max(300, poolTTL)
		}
		ttl = max(ttl, seconds)
	}
	return ttl
}
