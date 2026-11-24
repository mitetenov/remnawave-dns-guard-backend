package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	ansibleVaultPasswordKey  = "ansible_vault_password"
	ansibleVaultVariablesKey = "ansible_vault_variables"
	ansibleSSHKey            = "ansible_ssh_private_key"
)

var (
	ansibleVaultHeader  = regexp.MustCompile(`^\$ANSIBLE_VAULT;(1\.1;AES256|1\.2;AES256;[^;\r\n\x00]+)$`)
	ansibleVaultPayload = regexp.MustCompile(`^[0-9a-fA-F\r\n]+$`)
	grafanaToken        = regexp.MustCompile(`^[A-Za-z0-9_.+/=-]+$`)
)

type ansibleVaultSettings struct {
	password, variables string
}

func validAnsibleVaultFile(file string) bool {
	header, body, ok := strings.Cut(file, "\n")
	return ok && len(file) <= 64<<10 && ansibleVaultHeader.MatchString(strings.TrimSuffix(header, "\r")) &&
		strings.TrimSpace(body) != "" && ansibleVaultPayload.MatchString(body)
}

func (a *replacementAnsible) vaultSettings() ansibleVaultSettings {
	if a == nil || a.store == nil {
		return ansibleVaultSettings{}
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	return ansibleVaultSettings{
		password:  a.store.get(ansibleVaultPasswordKey),
		variables: a.store.get(ansibleVaultVariablesKey),
	}
}

func (a *replacementAnsible) withVaultPassword(work, password string) (*replacementAnsible, error) {
	if password == "" {
		return a, nil
	}
	runner := *a
	runner.vaultPasswordFile = filepath.Join(work, "vault_password")
	if err := os.WriteFile(runner.vaultPasswordFile, []byte(password+"\n"), 0o600); err != nil {
		return nil, errors.New("cannot prepare Ansible Vault password file")
	}
	return &runner, nil
}

func (a *replacementAnsible) readAlloyVault(ctx context.Context, work, encrypted string) (map[string]string, error) {
	file := filepath.Join(work, "grafana.vault")
	if err := os.WriteFile(file, []byte(encrypted), 0o600); err != nil {
		return nil, errors.New("cannot prepare Ansible Vault variables")
	}
	cmd := replacementCommand(ctx, "ansible-vault", "view", file)
	cmd.Dir, cmd.Env = work, a.environment(work)
	plain, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("не удалось расшифровать Vault-файл Grafana. Проверьте файл и пароль в настройках Ansible")
	}
	return parseAlloyVault(plain)
}

func parseAlloyVault(plain []byte) (map[string]string, error) {
	formatError := errors.New("в расшифрованном Vault-файле Grafana укажите YAML или JSON с непустыми строковыми токенами grafana_cloud_prometheus_token и grafana_cloud_loki_token")
	var jsonTokens struct {
		Prometheus string `json:"grafana_cloud_prometheus_token"`
		Loki       string `json:"grafana_cloud_loki_token"`
	}
	jsonErr := json.Unmarshal(plain, &jsonTokens)
	tokens := map[string]string{
		"grafana_cloud_prometheus_token": jsonTokens.Prometheus,
		"grafana_cloud_loki_token":       jsonTokens.Loki,
	}
	if jsonErr != nil {
		var values map[string]yaml.Node
		decoder := yaml.NewDecoder(bytes.NewReader(plain))
		if decoder.Decode(&values) != nil || decoder.Decode(&yaml.Node{}) != io.EOF {
			return nil, formatError
		}
		for key := range tokens {
			value := values[key]
			if value.Kind == yaml.AliasNode {
				value = *value.Alias
			}
			if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
				return nil, formatError
			}
			tokens[key] = value.Value
		}
	}
	for _, token := range tokens {
		if len(token) > 4096 || !grafanaToken.MatchString(token) {
			return nil, formatError
		}
	}
	return tokens, nil
}

func (a *replacementAnsible) stageManagedLoginKey(ctx context.Context, path string) error {
	keyError := errors.New("cannot prepare Ansible SSH identity")
	key := a.store.ansibleSSHIdentity("")
	if key == "" {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := replacementCommand(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "dns-guard-ansible", "-f", path)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		if err := cmd.Run(); err != nil {
			return keyError
		}
		generated, err := os.ReadFile(path)
		if err != nil || len(generated) == 0 {
			return keyError
		}
		key = a.store.ansibleSSHIdentity(string(generated))
	}
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return keyError
	}
	return nil
}

func (s *Store) ansibleSSHIdentity(candidate string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key := s.get(ansibleSSHKey); key != "" {
		return key
	}
	if candidate != "" {
		s.set(ansibleSSHKey, candidate)
	}
	return candidate
}

func validAnsibleSSHIdentity(ctx context.Context, key string) bool {
	if !replacementAnsibleSupported || len(key) > 16<<10 || strings.ContainsRune(key, '\x00') {
		return false
	}
	work, err := os.MkdirTemp("/tmp", "dns-guard-ssh-import-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(work)
	path := filepath.Join(work, "login_key")
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return false
	}
	runner := &replacementAnsible{sshKey: path}
	_, err = runner.loginPublicKey(ctx)
	return err == nil
}
