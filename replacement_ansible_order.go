package guard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type orderAnsibleNode struct {
	Alias, Group, Domain, HostKey, Secret string
	alloyTokens                           map[string]string
}

var replacementOrderDomainLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

const (
	replacementOrderCheckID = "00000000-0000-4000-8000-000000000000"
	replacementLoginKeyEnv  = replacementAnsibleEnv + "SSH_KEY_BASE64"
)

func (a *replacementAnsible) checkOrderConfiguration(ctx context.Context) error {
	_, readyErr := a.ready(ctx, true, a.vaultSettings())
	if a != nil && a.repoDir == bundledReplacementAnsibleDir {
		if dir, err := a.orderGroupVars(); err == nil && dir == "" {
			return errors.Join(readyErr, validateBundledOrderVars(a.bundledOrderVars("nodes"), "nodes"))
		}
	}
	return readyErr
}

func (a *replacementAnsible) ReadyForOrder(ctx context.Context, node orderAnsibleNode) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return a.processOrder(ctx, "192.0.2.1", replacementOrderCheckID, node, true)
}

func (a *replacementAnsible) RunOrder(ctx context.Context, ip, nodeID string, node orderAnsibleNode) error {
	if !publicIPv4(ip) {
		return errors.New("new node playbooks require a public IPv4 address")
	}
	id, ok := canonicalUUID(nodeID)
	if !ok {
		return errors.New("new node playbooks require a valid node UUID")
	}
	return a.processOrder(ctx, ip, id, node, false)
}

func (a *replacementAnsible) processOrder(ctx context.Context, ip, id string, node orderAnsibleNode, checkOnly bool) error {
	if !validReplacementRepositoryAlias(node.Alias) || (node.Group != "nodes" && node.Group != "nodes_wl") {
		return errors.New("new node playbooks require one safe alias in nodes or nodes_wl")
	}
	if !validReplacementOrderDomain(node.Domain) {
		return errors.New("new node playbooks require a valid node domain")
	}
	vault := a.vaultSettings()
	timeout, err := a.ready(ctx, true, vault)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var knownHosts string
	if !checkOnly {
		if strings.TrimSpace(node.Secret) == "" {
			return errors.New("new node playbooks require the node secret key")
		}
		key, ok := replacementPublicKeyFields(node.HostKey)
		if !ok {
			return errors.New("new node playbooks require the server SSH host public key")
		}
		knownHosts = id + " " + key + "\n"
		if err := validateReplacementPinnedHostKeys(ctx, knownHosts, "new node playbooks require a valid server SSH host public key"); err != nil {
			return err
		}
	}
	work, err := a.createAnsibleWorkspace(ctx, knownHosts)
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	a, err = a.withVaultPassword(work, vault.password)
	if err != nil {
		return err
	}
	if a.repoDir == bundledReplacementAnsibleDir && vault.variables != "" {
		node.alloyTokens, err = a.readAlloyVault(ctx, work, vault.variables)
		if err != nil {
			return err
		}
	}
	return a.processRepository(ctx, work, ip, id, nil, &node, checkOnly)
}

func validReplacementOrderDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !replacementOrderDomainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func (a *replacementAnsible) orderGroupVars() (string, error) {
	dir := a.orderGroupVarsDir
	optional := dir == "" && a.repoDir == bundledReplacementAnsibleDir
	if optional {
		dir = defaultOrderGroupVarsDir
	} else if dir == "" {
		dir = filepath.Join(a.repoDir, "inventory", "group_vars")
	}
	info, err := os.Stat(dir)
	if optional && errors.Is(err, os.ErrNotExist) {
		dir = filepath.Join(filepath.Dir(defaultOrderGroupVarsDir), "ansible", "inventory", "group_vars")
		info, err = os.Stat(dir)
		if errors.Is(err, os.ErrNotExist) {
			dir = a.bundledGroupVars()
			info, err = os.Stat(dir)
			if errors.Is(err, os.ErrNotExist) {
				return "", nil
			}
		}
	}
	if !filepath.IsAbs(dir) || err != nil || !info.IsDir() {
		return "", fmt.Errorf("подключите каталог настроек нод %s или задайте REPLACEMENT_ANSIBLE_GROUP_VARS_DIR с абсолютным путём внутри backend", dir)
	}
	return dir, nil
}

func (a *replacementAnsible) bundledGroupVars() string {
	return filepath.Join(a.repoDir, "inventory", "group_vars")
}

func (a *replacementAnsible) bundledOrderVars(group string) map[string]any {
	defaults := map[string]any{
		"node_initial_ssh_port": 22,
		"node_ssh_listen_port":  22222,
		"stack_project_src":     "/opt/remnawave-node",
		"stack_files_src":       filepath.Join(a.repoDir, "files", "nodes"),
		"nginx_node_listen":     "127.0.0.1:4321 ssl proxy_protocol",
		"nginx_acme_webroot":    "/var/www/certbot",
		"nodes_certbot_enabled": true,
		"ssl_certbot_email":     a.orderCertbotEmail,
		"ssl_certbot_domains":   []string{"{{ nginx_node_domain }}"},
		"ssl_fullchain_path":    "/etc/letsencrypt/live/{{ nginx_node_domain }}/fullchain.pem",
		"ssl_privkey_path":      "/etc/letsencrypt/live/{{ nginx_node_domain }}/privkey.pem",
	}
	if group == "nodes_wl" {
		upstream := a.orderXHTTPUpstream
		if upstream == "" {
			upstream = "127.0.0.1:8443"
		}
		defaults["stack_nodes_nginx_default_template"] = "conf/default-wl.conf.j2"
		defaults["nginx_node_xhttp_path"] = a.orderXHTTPPath
		defaults["nginx_node_xhttp_upstream"] = upstream
	}
	for name, value := range defaults {
		raw, _ := json.Marshal(value)
		defaults[name] = json.RawMessage(raw)
	}
	return defaults
}

func validateBundledOrderVars(vars map[string]any, group string) error {
	var problems []string
	if replacementUsesCertbot(vars) {
		email := replacementVarString(vars, "ssl_certbot_email")
		if !strings.Contains(email, "{{") {
			addr, err := mail.ParseAddress(email)
			if err != nil || addr.Address != email {
				problems = append(problems, "укажите email Certbot в REPLACEMENT_ANSIBLE_CERTBOT_EMAIL или ssl_certbot_email")
			}
		}
	}
	if group == "nodes_wl" {
		path := replacementVarString(vars, "nginx_node_xhttp_path")
		if !strings.Contains(path, "{{") && !replacementNodeXHTTPPath.MatchString(path) {
			problems = append(problems, "укажите путь XHTTP из профиля Remnawave в REPLACEMENT_ANSIBLE_XHTTP_PATH или nginx_node_xhttp_path")
		}
		upstream := replacementVarString(vars, "nginx_node_xhttp_upstream")
		if !strings.Contains(upstream, "{{") && !validReplacementXHTTPUpstream(upstream) {
			problems = append(problems, "укажите адрес 127.0.0.1 с портом XHTTP в REPLACEMENT_ANSIBLE_XHTTP_UPSTREAM или nginx_node_xhttp_upstream")
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, ". "))
	}
	return nil
}

func (a *replacementAnsible) prepareOrderInventory(work string, node orderAnsibleNode) (string, error) {
	input := filepath.Join(work, "input")
	if err := os.Mkdir(input, 0o700); err != nil {
		return "", errors.New("cannot prepare new node Ansible inventory")
	}
	groupVars, err := a.orderGroupVars()
	if err != nil {
		return "", err
	}
	if groupVars != "" {
		if err := os.Symlink(groupVars, filepath.Join(input, "group_vars")); err != nil {
			return "", errors.New("cannot load new node Ansible group variables")
		}
	}
	// Start with an empty host entry and only the matching group. This source has
	// no host_vars or existing addresses and loads repository group variables only.
	inventory := fmt.Sprintf(`{"%s":{"hosts":{"%s":{}}}}`, node.Group, node.Alias)
	path := filepath.Join(input, "inventory.yml")
	if err := os.WriteFile(path, []byte(inventory), 0o600); err != nil {
		return "", errors.New("cannot prepare new node Ansible inventory")
	}
	return path, nil
}

func (a *replacementAnsible) loginKeySetting() string {
	if a.sshKeyBase64 != "" {
		return replacementLoginKeyEnv
	}
	if a.useManagedLoginKey() {
		return "the managed Ansible SSH key"
	}
	return replacementAnsibleEnv + "SSH_KEY"
}

func (a *replacementAnsible) useManagedLoginKey() bool {
	return a.store != nil && a.sshKey == "" && a.sshKeyBase64 == ""
}

func (a *replacementAnsible) stageLoginKey(ctx context.Context, path string) error {
	if a.useManagedLoginKey() {
		return a.stageManagedLoginKey(ctx, path)
	}
	if a.sshKeyBase64 == "" {
		if err := os.Symlink(a.sshKey, path); err != nil {
			return errors.New("cannot prepare replacement Ansible SSH identity")
		}
		return nil
	}
	const keyLimit = 64 << 10
	invalidKey := errors.New("REPLACEMENT_ANSIBLE_SSH_KEY_BASE64 must contain a base64-encoded private SSH key")
	if len(a.sshKeyBase64) > base64.StdEncoding.EncodedLen(keyLimit) {
		return invalidKey
	}
	key, err := base64.StdEncoding.Strict().DecodeString(a.sshKeyBase64)
	defer clear(key)
	if err != nil || len(key) == 0 || len(key) > keyLimit {
		return invalidKey
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return errors.New("cannot prepare replacement Ansible SSH identity")
	}
	return nil
}

func (a *replacementAnsible) loginPublicKey(ctx context.Context) (string, error) {
	if a == nil || !replacementAnsibleSupported {
		return "", errors.New("replacement Ansible runner is unavailable")
	}
	if a.sshKeyBase64 == "" && !a.useManagedLoginKey() && !filepath.IsAbs(a.sshKey) {
		return "", errors.New("REPLACEMENT_ANSIBLE_SSH_KEY must point to an absolute path")
	}
	output, err := a.readLoginPublicKey(ctx)
	if err != nil {
		return "", err
	}
	if key, ok := replacementPublicKeyFields(string(output)); ok {
		return key, nil
	}
	return "", fmt.Errorf("cannot read the public SSH login key from %s", a.loginKeySetting())
}

func (a *replacementAnsible) readLoginPublicKey(ctx context.Context) ([]byte, error) {
	path := a.sshKey
	if a.sshKeyBase64 != "" || a.useManagedLoginKey() {
		work, err := os.MkdirTemp("/tmp", "dns-guard-login-key-")
		if err != nil {
			return nil, errors.New("cannot create a temporary SSH key directory")
		}
		defer os.RemoveAll(work)
		path = filepath.Join(work, "login_key")
		if err := a.stageLoginKey(ctx, path); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := replacementCommand(ctx, "ssh-keygen", "-y", "-P", "", "-f", path)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	keyError := fmt.Errorf("%s must contain a usable unencrypted private key", a.loginKeySetting())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, keyError
	}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, keyError
	}
	const limit = 16 << 10
	key, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	_ = stdout.Close()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if readErr != nil || waitErr != nil || len(key) > limit {
		return nil, keyError
	}
	return key, nil
}

func replacementPublicKeyFields(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
		return "", false
	}
	fields := strings.Fields(value)
	if len(fields) < 2 || (!strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && !strings.HasPrefix(fields[0], "sk-")) {
		return "", false
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", false
	}
	return fields[0] + " " + fields[1], true
}
