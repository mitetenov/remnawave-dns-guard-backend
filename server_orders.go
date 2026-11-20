package guard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	upCloudOrderProvider = "upcloud"
	virtuaOrderProvider  = "virtua"
)

func orderProviderName(provider string) string {
	if provider == virtuaOrderProvider {
		return "Virtua.Cloud"
	}
	return "UpCloud"
}

func validOrderZone(provider, zone string) bool {
	switch provider {
	case "", upCloudOrderProvider:
		return upCloudOrderZonePattern.MatchString(zone)
	case virtuaOrderProvider:
		return virtuaZonePattern.MatchString(zone)
	}
	return false
}

type orderChoice struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Family string `json:"family,omitempty"`
}

type orderSelection struct {
	Zone      string `json:"zone"`
	Plan      string `json:"plan"`
	PoolID    string `json:"pool_id"`
	Group     string `json:"group"`
	ProfileID string `json:"profile_id"`
	Provider  string `json:"provider,omitempty"`
}

type orderInstaller interface {
	checkOrderConfiguration(context.Context) error
	ReadyForOrder(context.Context, orderAnsibleNode) error
	RunOrder(context.Context, string, string, orderAnsibleNode) error
	loginPublicKey(context.Context) (string, error)
}

type orderManager struct {
	a             *App
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	mu            sync.Mutex
	cloud         func() (orderCloudProvider, error)
	virtuaCatalog virtuaCatalogCache
	installer     orderInstaller
	sshUser       string
}

var orderStages = map[string]string{
	"preflight": "Проверка заказа", "provision": "Создание сервера у хостинга",
	"enrollment": "Ожидание SSH-ключа сервера", "origin": "Настройка домена ноды",
	"panel": "Регистрация ноды в Remnawave", "ansible": "Установка и настройка ноды",
	"target": "Добавление в DNS Guard", "verify": "Проверка доступности и публикация DNS",
	"complete": "Готово", "cancelled": "Отменён", "rejected": "Провайдер отклонил заказ",
}

var errOrderQuoteChanged = errors.New("тариф, его цена или характеристики изменились. Выберите актуальный тариф и подтвердите новый заказ")

const orderActive = "stage NOT IN ('complete','cancelled','rejected')"

func (s *Store) initializeOrders() {
	s.exec(`CREATE TABLE IF NOT EXISTS server_order_templates(
 pool_id TEXT PRIMARY KEY REFERENCES pools(id) ON DELETE CASCADE, domain_template TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS server_orders(
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, selection_hash TEXT NOT NULL,
 pool_id TEXT NOT NULL,pool_hostname TEXT NOT NULL,zone_id TEXT NOT NULL,ttl INTEGER NOT NULL,
 zone TEXT NOT NULL,country TEXT NOT NULL,plan TEXT NOT NULL,quote TEXT NOT NULL,
 group_name TEXT NOT NULL,profile_id TEXT NOT NULL,profile_name TEXT NOT NULL,inbounds TEXT NOT NULL,
 serial INTEGER NOT NULL,alias TEXT NOT NULL,domain TEXT NOT NULL UNIQUE,
 stage TEXT NOT NULL DEFAULT 'preflight',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 snapshot TEXT,enroll_digest TEXT,host_key TEXT,create_attempted INTEGER NOT NULL DEFAULT 0,
 can_retry_create INTEGER NOT NULL DEFAULT 0,server_uuid TEXT,ip TEXT,node_uuid TEXT,target_id TEXT,
 error TEXT,next_retry REAL NOT NULL DEFAULT 0, UNIQUE(country,serial))`)
	if !slices.ContainsFunc(s.all("PRAGMA table_info(server_orders)"), func(column row) bool { return column["name"] == "provider" }) {
		s.exec("ALTER TABLE server_orders ADD COLUMN provider TEXT NOT NULL DEFAULT 'upcloud'")
	}
	s.exec("CREATE INDEX IF NOT EXISTS server_orders_target ON server_orders(target_id)")
}

func newOrderManager(a *App) *orderManager {
	ctx, cancel := context.WithCancel(context.Background())
	installer := newOrderAnsible()
	return &orderManager{a: a, ctx: ctx, cancel: cancel, installer: installer, sshUser: installer.sshUser,
		cloud: func() (orderCloudProvider, error) {
			s := a.s
			s.mu.Lock()
			defer s.mu.Unlock()
			token := s.get("upcloud_token")
			if token == "" {
				return nil, errors.New("сохраните API-токен UpCloud в разделе автозамены")
			}
			return newUpCloudOrder(a.client, token), nil
		}}
}

func (m *orderManager) cloudFor(provider string) (orderCloudProvider, error) {
	switch provider {
	case "", upCloudOrderProvider:
		return m.cloud()
	case virtuaOrderProvider:
		var token string
		m.a.withStore(func() any { token = m.a.s.get("virtua_token"); return nil })
		if token == "" {
			return nil, errors.New("сохраните API-токен Virtua.Cloud в разделе «Серверы»")
		}
		return &virtuaOrder{client: providerClient(m.a.client), token: token, cache: &m.virtuaCatalog}, nil
	default:
		return nil, errors.New("выберите доступный хостинг")
	}
}

func (m *orderManager) start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-t.C:
				func() {
					defer func() {
						if recover() != nil {
							log.Print("Server order cycle failed")
						}
					}()
					m.runOnce()
				}()
			}
		}
	}()
}
func (m *orderManager) close() { m.cancel(); m.wg.Wait() }

func renderOrderDomain(pattern, country, pool string, serial int) (string, error) {
	if !strings.Contains(pattern, "{n}") {
		return "", errors.New("шаблон домена должен содержать {n}")
	}
	domain := strings.NewReplacer("{n}", fmt.Sprintf("%02d", serial), "{country}", strings.ToLower(country), "{pool}", pool).Replace(pattern)
	if !validReplacementOrderDomain(domain) || domain != strings.ToLower(domain) || domain == pool {
		return "", errors.New("шаблон должен давать отдельное доменное имя. Доступны {country}, {n} и {pool}")
	}
	return domain, nil
}

func orderPlanChoice(zone string, p orderCloudPlan) orderChoice {
	const monthlyBillableHours = 24 * 28

	data, _ := json.Marshal(p)
	id := p.Code + "@" + digest(zone + " " + string(data))[:16]
	if p.Country != "" {
		prices := fmt.Sprintf("%.10g %s/ч", p.Price, p.Currency)
		if p.MonthlyPrice > 0 {
			prices += fmt.Sprintf(" · ≈ %.2f %s/мес.", p.MonthlyPrice, p.Currency)
		}
		return orderChoice{
			ID: id,
			Label: fmt.Sprintf("%s · %d vCPU · %d МиБ RAM · %d ГиБ %s · %s без НДС",
				p.Name, p.CPU, p.MemoryMB, p.StorageGB, p.StorageTier, prices),
		}
	}
	family := p.Family
	if !oneOf(family, "starter", "premium") {
		family = ""
	}
	return orderChoice{
		ID: id, Family: family,
		Label: fmt.Sprintf("≈ %.2f %s/мес. · %s · %d vCPU · %d МиБ RAM · %d ГиБ %s · %.10g %s/ч",
			p.Price*monthlyBillableHours, p.Currency, p.Code, p.CPU, p.MemoryMB, p.StorageGB, p.StorageTier, p.Price, p.Currency),
	}
}

func (m *orderManager) options(ctx context.Context, kind, zone, poolID, group, provider string) ([]orderChoice, error) {
	choices := []orderChoice{}
	switch kind {
	case "zone", "plan":
		if kind == "zone" {
			_, originErr := m.enrollmentOrigin()
			if err := errors.Join(originErr, m.installer.checkOrderConfiguration(ctx)); err != nil {
				return nil, err
			}
		}
		c, err := m.cloudFor(provider)
		if err != nil {
			return nil, err
		}
		if kind == "plan" {
			if !validOrderZone(provider, zone) {
				return nil, errors.New("выберите локацию хостинга")
			}
			plans, err := c.Plans(ctx, zone)
			if err != nil {
				return nil, err
			}
			for _, p := range plans {
				choices = append(choices, orderPlanChoice(zone, p))
			}
		} else {
			countries, err := c.Countries(ctx)
			if err != nil {
				return nil, err
			}
			for _, c := range countries {
				for _, z := range c.Zones {
					choices = append(choices, orderChoice{ID: z, Label: c.Name + " · " + z})
				}
			}
		}
	case "group":
		choices = []orderChoice{{ID: "nodes", Label: "Обычная нода (nodes)"}, {ID: "nodes_wl", Label: "Нода за CDN (nodes_wl)"}}
	case "profile":
		if group != "" {
			if err := m.checkOrderGroup(ctx, group); err != nil {
				return nil, err
			}
		}
		r, err := m.a.remnawaveProvider()
		if err != nil {
			return nil, err
		}
		profiles, err := r.orderProfiles(ctx)
		if err != nil {
			return nil, err
		}
		var eligible map[string]bool
		if poolID != "" {
			var pool row
			m.a.withStore(func() any { pool = m.a.s.one("SELECT hostname FROM pools WHERE id=?", poolID); return nil })
			if pool == nil {
				return nil, errors.New("выберите существующий DNS-пул")
			}
			hosts, err := orderRemnawaveList[orderRemnawaveHost](ctx, r, "hosts")
			if err != nil {
				return nil, err
			}
			eligible = map[string]bool{}
			for _, host := range hosts {
				id, valid := canonicalUUID(host.Inbound.UUID)
				if valid && strings.EqualFold(strings.TrimSuffix(host.Address, "."), str(pool["hostname"])) {
					eligible[id] = true
				}
			}
		}
		for _, p := range profiles {
			if slices.ContainsFunc(p.Inbounds, func(in orderPanelInboundChoice) bool { return eligible == nil || eligible[in.ID] }) {
				choices = append(choices, orderChoice{ID: p.ID, Label: p.Name})
			}
		}
	case "pool":
		m.a.withStore(func() any {
			for _, p := range m.a.s.all(`SELECT p.* FROM pools p JOIN server_order_templates t ON t.pool_id=p.id
 WHERE p.profile IS NOT NULL AND t.domain_template!='' ORDER BY p.name,p.hostname`) {
				choices = append(choices, orderChoice{ID: str(p["id"]), Label: str(p["name"]) + " · " + str(p["hostname"])})
			}
			return nil
		})
	default:
		return nil, errors.New("неизвестный список параметров заказа")
	}
	return choices, nil
}

func selectionDigest(sel orderSelection) string {
	// Keep request fingerprints for old UpCloud orders and pending clients.
	if sel.Provider == upCloudOrderProvider {
		sel.Provider = ""
	}
	data, _ := json.Marshal(sel)
	return digest(string(data))
}

func matchOrderRequest(j row, sel orderSelection) (string, error) {
	if str(j["selection_hash"]) != selectionDigest(sel) {
		return "", errors.New("этот запрос уже использован для другого заказа")
	}
	return str(j["id"]), nil
}

func (m *orderManager) selectedPlan(ctx context.Context, provider, zone, quote string) (orderCloudPlan, error) {
	c, err := m.cloudFor(provider)
	if err != nil {
		return orderCloudPlan{}, err
	}
	plans, err := c.Plans(ctx, zone)
	if err != nil {
		return orderCloudPlan{}, err
	}
	return matchOrderQuote(zone, quote, plans)
}

func matchOrderQuote(zone, quote string, plans []orderCloudPlan) (orderCloudPlan, error) {
	for _, p := range plans {
		if orderPlanChoice(zone, p).ID == quote {
			return p, nil
		}
	}
	return orderCloudPlan{}, errOrderQuoteChanged
}

func (m *orderManager) checkOrderGroup(ctx context.Context, group string) error {
	if !oneOf(group, "nodes", "nodes_wl") {
		return errors.New("выберите тип ноды")
	}
	node := orderAnsibleNode{Alias: "dns-guard-preflight", Group: group, Domain: "node.invalid"}
	return m.installer.ReadyForOrder(ctx, node)
}

func (m *orderManager) queue(ctx context.Context, requestID string, sel orderSelection) (string, error) {
	requestID, ok := canonicalUUID(requestID)
	if !ok || !validOrderZone(sel.Provider, sel.Zone) || !oneOf(sel.Group, "nodes", "nodes_wl") {
		return "", errors.New("проверьте локацию и тип ноды")
	}
	if sel.Provider == "" {
		sel.Provider = upCloudOrderProvider
	}
	s := m.a.s
	var prev row
	m.a.withStore(func() any {
		prev = s.one("SELECT id,selection_hash FROM server_orders WHERE request_id=?", requestID)
		return nil
	})
	if prev != nil {
		return matchOrderRequest(prev, sel)
	}
	if _, err := m.enrollmentOrigin(); err != nil {
		return "", err
	}
	if err := m.checkOrderGroup(ctx, sel.Group); err != nil {
		return "", err
	}
	plan, err := m.selectedPlan(ctx, sel.Provider, sel.Zone, sel.Plan)
	if err != nil {
		return "", err
	}
	panel, err := m.a.remnawaveProvider()
	if err != nil {
		return "", err
	}
	profiles, err := panel.orderProfiles(ctx)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(profiles, func(p orderPanelProfile) bool { return p.ID == sel.ProfileID && len(p.Inbounds) > 0 })
	if i < 0 {
		return "", errors.New("выберите существующий профиль Remnawave с настроенными входящими подключениями")
	}
	profile := profiles[i]
	inbounds := make([]string, 0, len(profile.Inbounds))
	for _, ib := range profile.Inbounds {
		inbounds = append(inbounds, ib.ID)
	}
	encoded, _ := json.Marshal(inbounds)
	nodes, err := panel.nodes()
	if err != nil {
		return "", err
	}
	names := map[string]bool{}
	for _, n := range nodes {
		names[strings.ToLower(str(n["name"]))] = true
	}
	country := plan.Country
	if sel.Provider == upCloudOrderProvider {
		country = strings.ToUpper(sel.Zone[:2])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if j := s.one("SELECT id,selection_hash FROM server_orders WHERE request_id=?", requestID); j != nil {
		return matchOrderRequest(j, sel)
	}
	p := s.one("SELECT p.*,t.domain_template FROM pools p JOIN server_order_templates t ON p.id=t.pool_id WHERE p.id=? AND p.profile IS NOT NULL", sel.PoolID)
	if p == nil {
		return "", errors.New("настройте шаблон домена и профиль проверок выбранного DNS-пула")
	}
	serial := int(num(s.one("SELECT MAX(serial) AS n FROM server_orders WHERE country=?", country)["n"])) + 1
	for {
		alias := fmt.Sprintf("%s-%02d", strings.ToLower(country), serial)
		domain, err := renderOrderDomain(str(p["domain_template"]), country, str(p["hostname"]), serial)
		if err != nil {
			return "", err
		}
		if names[alias] || s.replacementDomainUsed("", domain) {
			serial++
			continue
		}
		id, stamp := uid(), iso(time.Now())
		s.exec(`INSERT INTO server_orders(id,request_id,selection_hash,pool_id,pool_hostname,zone_id,ttl,zone,country,plan,quote,group_name,profile_id,profile_name,inbounds,serial,alias,domain,created_at,updated_at,provider)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, requestID, selectionDigest(sel), sel.PoolID, p["hostname"], p["zone_id"], p["ttl"], sel.Zone, country, plan.Code, sel.Plan, sel.Group, profile.ID, profile.Name, string(encoded), serial, alias, domain, stamp, stamp, sel.Provider)
		return id, nil
	}
}

func orderNode(j row) orderAnsibleNode {
	return orderAnsibleNode{Alias: str(j["alias"]), Group: str(j["group_name"]), Domain: str(j["domain"]), HostKey: str(j["host_key"])}
}
func (m *orderManager) managed(targetID any, nodeID string) row {
	s := m.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.one("SELECT * FROM server_orders WHERE target_id=? AND node_uuid=?", targetID, nodeID)
}
func (m *orderManager) install(ctx context.Context, j row, ip, nodeID string) error {
	p, err := m.a.remnawaveProvider()
	if err != nil {
		return err
	}
	node := orderNode(j)
	node.Secret, err = p.orderNodeSecret(ctx)
	if err != nil {
		return err
	}
	return m.installer.RunOrder(ctx, ip, nodeID, node)
}

func enrollmentToken() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
