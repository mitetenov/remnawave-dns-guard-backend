package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const virtuaAPIBase = "https://api.virtua.cloud/v1"

var (
	virtuaZonePattern    = regexp.MustCompile("^[a-z0-9][a-z0-9-]{0,23}$")
	virtuaCountryPattern = regexp.MustCompile("^[A-Z]{2}$")
	virtuaIDPattern      = regexp.MustCompile("^[A-Za-z0-9._-]{1,255}$")
	virtuaErrorPattern   = regexp.MustCompile("^[a-z0-9_]{1,80}$")
)

type virtuaOrder struct {
	client *http.Client
	token  string
	cache  *virtuaCatalogCache
}

type virtuaAPIError struct {
	operation string
	status    int
	code      string
	detail    string
}

func (e *virtuaAPIError) Error() string {
	prefix := fmt.Sprintf("Virtua.Cloud %s (HTTP %d)", e.operation, e.status)
	if e.code == "" {
		return prefix
	}
	if e.detail != "" {
		return fmt.Sprintf("%s: %s (%s)", prefix, e.code, e.detail)
	}
	return prefix + ": " + e.code
}

// Only describe the expected schema and JSON kinds. Decoder error strings can
// include values from an account record or a bootstrap script.
func virtuaDecodeProblem(err error) string {
	var field *json.UnmarshalTypeError
	var syntax *json.SyntaxError
	switch {
	case errors.As(err, &field):
		kind, _, _ := strings.Cut(field.Value, " ")
		where := "корень ответа"
		if field.Field != "" {
			where = "поле " + field.Field
		}
		return fmt.Sprintf("%s: тип %s, ожидается %s", where, kind, field.Type.Kind())
	case errors.As(err, &syntax):
		return fmt.Sprintf("некорректный JSON, позиция %d", syntax.Offset)
	default:
		return "значение не соответствует схеме ответа"
	}
}

func validVirtuaOffer(id string) bool {
	return id != "" && len(id) <= 255 && !strings.ContainsFunc(id, unicode.IsControl)
}

func validVirtuaToken(token string) bool {
	return token != "" && len(token) <= 4096 && !strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r >= 127 })
}

func (c *virtuaOrder) request(ctx context.Context, method, path string, input url.Values, output any) (http.Header, error) {
	operation := method + " /v1" + path
	var body io.Reader
	if input != nil {
		body = strings.NewReader(input.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, virtuaAPIBase+path, body)
	if err != nil {
		return nil, integration("не удалось подготовить запрос Virtua.Cloud")
	}
	req.Header.Set("Accept", "application/json")
	if path != "/offers" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, integration("нет ответа от Virtua.Cloud " + operation)
	}
	defer resp.Body.Close()
	if method == http.MethodDelete && resp.StatusCode == http.StatusNoContent && output == nil {
		return resp.Header, nil
	}
	const maxReply = 8 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	responseError := func(reason string) error {
		return integration(fmt.Sprintf("Virtua.Cloud %s (HTTP %d): %s", operation, resp.StatusCode, reason))
	}
	if err != nil {
		return nil, responseError("не удалось прочитать тело ответа")
	}
	if len(data) > maxReply {
		return nil, responseError("размер ответа превышает 8 МиБ")
	}
	var result struct {
		Success *bool  `json:"success"`
		Error   string `json:"error"`
		Code    string `json:"error_code"`
	}
	parseErr := json.Unmarshal(data, &result)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || (result.Success != nil && !*result.Success) {
		apiErr := &virtuaAPIError{operation: operation, status: resp.StatusCode}
		if parseErr == nil && virtuaErrorPattern.MatchString(result.Error) {
			apiErr.code = result.Error
			if virtuaErrorPattern.MatchString(result.Code) {
				apiErr.detail = result.Code
			}
		}
		return nil, apiErr
	}
	if parseErr != nil {
		return nil, responseError(virtuaDecodeProblem(parseErr))
	}
	// /account is documented without a success flag.
	if result.Success == nil && path != "/account" {
		return nil, responseError("отсутствует обязательный признак success")
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return nil, responseError(virtuaDecodeProblem(err))
		}
	}
	return resp.Header, nil
}

func (c *virtuaOrder) checkAccount(ctx context.Context) error {
	var account struct {
		Balance  string `json:"balance"`
		Currency string `json:"currency"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/account", nil, &account); err != nil {
		return err
	}
	if account.Balance == "" || account.Currency == "" {
		return integration("Virtua.Cloud не вернул данные аккаунта")
	}
	return nil
}

func (c *virtuaOrder) image(ctx context.Context, diskGB int) (string, error) {
	var list struct {
		Systems []struct {
			ID           string          `json:"uuid"`
			Distribution string          `json:"distribution"`
			Version      string          `json:"version"`
			Category     string          `json:"category"`
			Windows      json.RawMessage `json:"is_windows"`
			MinDisk      int             `json:"min_disk_space"`
		} `json:"systems"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud/systems", nil, &list); err != nil {
		return "", err
	}
	for _, image := range list.Systems {
		major, _, _ := strings.Cut(image.Version, ".")
		if image.Category == "linux" && image.Distribution == "debian" && major == "13" &&
			oneOf(string(image.Windows), `"0"`, "0", "false") && image.MinDisk > 0 && image.MinDisk <= diskGB &&
			virtuaIDPattern.MatchString(image.ID) {
			return image.ID, nil
		}
	}
	return "", errors.New("Virtua.Cloud не предлагает Debian 13 для выбранного размера диска")
}

type virtuaOrderSnapshot struct {
	OperationID string `json:"operation_id"`
	Zone        string `json:"zone"`
	Offer       string `json:"offer"`
	System      string `json:"system"`
	Script      string `json:"script"`
}

func (c *virtuaOrder) PrepareOrder(ctx context.Context, req orderCloudRequest) (json.RawMessage, string, string, error) {
	if id, ok := canonicalUUID(req.OperationID); !ok || id != req.OperationID || !virtuaZonePattern.MatchString(req.Zone) {
		return nil, "", "", errors.New("некорректные параметры заказа Virtua.Cloud")
	}
	script, err := virtuaBootstrap(req)
	if err != nil {
		return nil, "", "", err
	}
	plans, err := c.Plans(ctx, req.Zone)
	if err != nil {
		return nil, "", "", err
	}
	for _, plan := range plans {
		if plan.Code == req.Plan && plan.Country == req.Country && orderPlanChoice(req.Zone, plan).ID == req.Quote {
			image, err := c.image(ctx, plan.StorageGB)
			if err != nil {
				return nil, "", "", err
			}
			snap, err := json.Marshal(virtuaOrderSnapshot{OperationID: req.OperationID, Zone: req.Zone, Offer: plan.Code, System: image, Script: script})
			return snap, "", req.Zone, err
		}
	}
	return nil, "", "", errOrderQuoteChanged
}

func readVirtuaSnapshot(data json.RawMessage, id string) (virtuaOrderSnapshot, error) {
	var snap virtuaOrderSnapshot
	orderID, valid := canonicalUUID(id)
	if err := json.Unmarshal(data, &snap); err != nil || !valid || orderID != id || snap.OperationID != id ||
		!virtuaZonePattern.MatchString(snap.Zone) || !validVirtuaOffer(snap.Offer) ||
		!virtuaIDPattern.MatchString(snap.System) || !strings.HasPrefix(snap.Script, "#!/bin/bash\n") {
		return snap, errors.New("некорректный сохранённый заказ Virtua.Cloud")
	}
	return snap, nil
}

func (s virtuaOrderSnapshot) name() string { return "dns-guard-" + s.OperationID }

func (c *virtuaOrder) scriptIDs(ctx context.Context, snap virtuaOrderSnapshot) ([]string, error) {
	var scripts struct {
		Scripts []struct {
			ID      string `json:"uuid"`
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"scripts"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/script", nil, &scripts); err != nil {
		return nil, err
	}
	if scripts.Scripts == nil {
		return nil, integration("Virtua.Cloud не вернул список скриптов")
	}
	var ids []string
	for _, script := range scripts.Scripts {
		if script.Name != snap.name() {
			continue
		}
		id, valid := canonicalUUID(script.ID)
		if !valid || script.Content != snap.Script {
			return nil, errors.New("найден скрипт Virtua.Cloud с именем заказа и другим содержимым")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (c *virtuaOrder) ensureScript(ctx context.Context, snap virtuaOrderSnapshot) (string, error) {
	ids, err := c.scriptIDs(ctx, snap)
	if err != nil {
		return "", err
	}
	if len(ids) > 0 {
		return ids[0], nil
	}
	_, err = c.request(ctx, http.MethodPost, "/script", url.Values{"name": {snap.name()}, "content": {snap.Script}}, nil)
	if err != nil {
		return "", err
	}
	ids, err = c.scriptIDs(ctx, snap)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", errors.New("Virtua.Cloud не подтвердил создание скрипта настройки")
	}
	return ids[0], nil
}

func (c *virtuaOrder) cleanupScript(ctx context.Context, snap virtuaOrderSnapshot) error {
	ids, err := c.scriptIDs(ctx, snap)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = c.request(ctx, http.MethodDelete, "/script", url.Values{"uuid": {id}}, nil); err != nil {
			return err
		}
	}
	return nil
}

type virtuaServer struct {
	ID         string `json:"uuid"`
	Name       string `json:"name"`
	Label      string `json:"label"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	Setup      *bool  `json:"is_setup"`
	Processing *bool  `json:"is_processing"`
}

func (c *virtuaOrder) findServer(ctx context.Context, name string) (string, error) {
	var list struct {
		Servers []virtuaServer `json:"cloud_servers"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud-server", nil, &list); err != nil {
		return "", err
	}
	if list.Servers == nil {
		return "", integration("Virtua.Cloud не вернул список серверов")
	}
	var found string
	for _, server := range list.Servers {
		if server.Name != name && server.Label != name && server.Hostname != name {
			continue
		}
		id, ok := canonicalUUID(server.ID)
		if !ok || (found != "" && found != id) {
			return "", errors.New("Virtua.Cloud вернул неоднозначный сервер для заказа " + name)
		}
		found = id
	}
	return found, nil
}

func (c *virtuaOrder) readyAddress(ctx context.Context, id string) (string, error) {
	server, err := c.server(ctx, id)
	if err != nil {
		return "", err
	}
	if server.Setup == nil || server.Processing == nil {
		return "", integration("Virtua.Cloud вернул неполные сведения о сервере")
	}
	if !*server.Setup || *server.Processing || server.Status != "running" {
		return "", errReplacementPending
	}
	ip, err := c.publicAddress(ctx, id)
	if err == nil && ip == "" {
		return "", errReplacementPending
	}
	return ip, err
}

func (c *virtuaOrder) server(ctx context.Context, id string) (virtuaServer, error) {
	var details struct {
		Server virtuaServer `json:"cloud_server"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/cloud-server/"+id, nil, &details); err != nil {
		return virtuaServer{}, err
	}
	server := details.Server
	if returned, ok := canonicalUUID(server.ID); !ok || returned != id {
		return virtuaServer{}, integration("Virtua.Cloud вернул неполные сведения о сервере")
	}
	return server, nil
}

func (c *virtuaOrder) publicAddress(ctx context.Context, id string) (string, error) {
	var addresses struct {
		IPs []struct {
			Address string `json:"address"`
			Version int    `json:"version"`
		} `json:"ip_addresses"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/network/cloud-server/"+id+"/show", nil, &addresses); err != nil {
		return "", err
	}
	var ip string
	for _, address := range addresses.IPs {
		if address.Version == 4 && publicIPv4(address.Address) {
			if ip != "" && ip != address.Address {
				return "", errors.New("Virtua.Cloud вернул несколько публичных IPv4 для сервера")
			}
			ip = address.Address
		}
	}
	return ip, nil
}

func (c *virtuaOrder) createServer(ctx context.Context, snap virtuaOrderSnapshot, script string) (string, error) {
	var reply struct {
		ID       string       `json:"uuid"`
		ServerID string       `json:"cloud_server_uuid"`
		Server   virtuaServer `json:"cloud_server"`
	}
	_, err := c.request(ctx, http.MethodPost, "/cloud/order", url.Values{
		"offer": {snap.Offer}, "system": {snap.System}, "hostname": {snap.name()}, "script": {script}, "billing_period": {"0"},
	}, &reply)
	if err != nil {
		var refusal *virtuaAPIError
		if errors.As(err, &refusal) && refusal.status < 500 && oneOf(refusal.code,
			"missing_offer", "invalid_offer", "cloud_zone_not_available", "cloud_zone_sold_out",
			"ip_address_v4_available_too_low", "cloud_offer_is_out_of_stock", "system_not_available_in_zone",
			"windows", "system_disk_too_small", "cloud_server_limits_reached", "balance_too_low") {
			return "", fmt.Errorf("%w: %s", errReplacementCreateRejected, refusal)
		}
		return "", err // An ambiguous outcome is reconciled without repeating the charge.
	}
	for _, candidate := range []string{reply.Server.ID, reply.ServerID, reply.ID} {
		if id, valid := canonicalUUID(candidate); valid {
			return id, nil
		}
	}
	return "", errReplacementPending
}

func (c *virtuaOrder) ProvisionOrder(ctx context.Context, data json.RawMessage, operationID, existingServer string, claimCreate func() (bool, error)) (string, string, error) {
	snap, err := readVirtuaSnapshot(data, operationID)
	if err != nil {
		return "", "", err
	}
	id := existingServer
	if id != "" {
		if checked, ok := canonicalUUID(id); !ok || checked != id {
			return "", "", errors.New("некорректный UUID сохранённого сервера Virtua.Cloud")
		}
	} else {
		id, err = c.findServer(ctx, snap.name())
		if err != nil {
			return "", "", err
		}
	}
	if id == "" {
		script, err := c.ensureScript(ctx, snap)
		if err != nil {
			return "", "", err
		}
		claimed, err := claimCreate()
		if err != nil {
			return "", "", err
		}
		if !claimed {
			return "", "", fmt.Errorf("%w: %s", errReplacementCreateUnconfirmed, snap.name())
		}
		id, err = c.createServer(ctx, snap, script)
		if err != nil {
			return "", "", err
		}
	}
	ip, err := c.readyAddress(ctx, id)
	return id, ip, err
}
