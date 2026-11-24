//go:build unix

package guard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAnsibleManagedLoginKeyPersistsAcrossRuns(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is unavailable")
	}
	a, _ := panelTestApp(t)
	runner := &replacementAnsible{store: a.s}
	first, err := runner.loginPublicKey(t.Context())
	if err != nil || !strings.HasPrefix(first, "ssh-ed25519 ") {
		t.Fatalf("could not load the generated public key: %v", err)
	}
	second, err := (&replacementAnsible{store: a.s}).loginPublicKey(t.Context())
	if err != nil || first != second {
		t.Fatal("the installed nodes need the same SSH identity on subsequent runs")
	}
	private := a.s.get(ansibleSSHKey)
	if private == "" || str(a.s.one("SELECT value FROM settings WHERE key=?", ansibleSSHKey)["value"]) == private {
		t.Fatal("the private key must be stored encrypted")
	}
}

func TestAnsibleAlloyVaultDecryptsUsingSavedPassword(t *testing.T) {
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skip("ansible-vault is unavailable")
	}
	for _, tc := range []struct{ name, payload string }{
		{"JSON", `{"grafana_cloud_prometheus_token":"metrics-fixture","grafana_cloud_loki_token":"logs-fixture"}`},
		{"YAML", `---
# Grafana Cloud credentials
grafana_cloud_prometheus_token: metrics-fixture
grafana_cloud_loki_token: "logs-fixture" # Token for Alloy
grafana_cloud_loki_url: https://logs.example.invalid
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			runner, err := (&replacementAnsible{}).withVaultPassword(work, "vault-test-password")
			if err != nil {
				t.Fatal(err)
			}
			if info, err := os.Stat(runner.vaultPasswordFile); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("the password file must be readable only by its owner")
			}
			encryptedPath := filepath.Join(work, "fixture.vault")
			cmd := exec.CommandContext(t.Context(), "ansible-vault", "encrypt", "--output", encryptedPath)
			cmd.Dir, cmd.Env, cmd.Stdin = work, runner.environment(work), strings.NewReader(tc.payload)
			if err := cmd.Run(); err != nil {
				t.Fatalf("could not encrypt fixture: %v", err)
			}
			encrypted, err := os.ReadFile(encryptedPath)
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := runner.readAlloyVault(t.Context(), work, string(encrypted))
			if err != nil || len(tokens) != 2 || tokens["grafana_cloud_prometheus_token"] != "metrics-fixture" || tokens["grafana_cloud_loki_token"] != "logs-fixture" {
				t.Fatalf("could not decrypt Vault tokens: %v", err)
			}
			invalid, err := runner.withVaultPassword(work, "incorrect-password")
			if err != nil {
				t.Fatal(err)
			}
			if tokens, err := invalid.readAlloyVault(t.Context(), work, string(encrypted)); err == nil || tokens != nil || strings.Contains(err.Error(), "incorrect-password") {
				t.Fatal("a bad Vault password must fail without disclosing it")
			}
		})
	}
}

func TestParseAlloyVaultReadsYAML(t *testing.T) {
	const payload = `---
logs_token: &logs "logs-fixture"
grafana_cloud_loki_token: *logs
grafana_cloud_prometheus_token: 'metrics-fixture'
`
	tokens, err := parseAlloyVault([]byte(payload))
	if err != nil || len(tokens) != 2 || tokens["grafana_cloud_prometheus_token"] != "metrics-fixture" || tokens["grafana_cloud_loki_token"] != "logs-fixture" {
		t.Fatalf("could not parse YAML Vault tokens: %v", err)
	}
}

func TestParseAlloyVaultRejectsInvalidYAML(t *testing.T) {
	for _, tc := range []struct{ name, rest string }{
		{"missing token", ""},
		{"empty token", "grafana_cloud_loki_token: ''\n"},
		{"numeric token", "grafana_cloud_loki_token: 12345\n"},
		{"invalid characters", "grafana_cloud_loki_token: 'a b'\n"},
		{"multiple documents", "grafana_cloud_loki_token: logs-fixture\n---\nextra: value\n"},
		{"malformed YAML", "grafana_cloud_loki_token: [\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const prefix = "grafana_cloud_prometheus_token: secret-fixture\n"
			tokens, err := parseAlloyVault([]byte(prefix + tc.rest))
			if err == nil || tokens != nil || strings.Contains(err.Error(), "secret-fixture") {
				t.Fatal("invalid input must fail without disclosing tokens")
			}
		})
	}
}

func TestAnsibleLoginKeyFromEnvironment(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("requires ssh-keygen")
	}
	keyPath := filepath.Join(t.TempDir(), "fixture_key")
	if err := exec.Command(sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", keyPath).Run(); err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	publicData, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	expectedPublic, ok := replacementPublicKeyFields(string(publicData))
	if !ok {
		t.Fatal("invalid fixture public key")
	}
	t.Setenv("REPLACEMENT_ANSIBLE_SSH_KEY", filepath.Join(t.TempDir(), "missing"))
	t.Setenv(replacementLoginKeyEnv, base64.StdEncoding.EncodeToString(data))
	runner := newOrderAnsible()
	if key, err := runner.loginPublicKey(t.Context()); err != nil || key != expectedPublic {
		t.Fatalf("could not derive expected public key: %v", err)
	}
	work, err := runner.createAnsibleWorkspace(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	stagedPath := filepath.Join(work, "login_key")
	staged, err := os.ReadFile(stagedPath)
	if err != nil || string(staged) != string(data) {
		t.Fatal("workspace does not contain the expected private key")
	}
	info, err := os.Lstat(stagedPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("workspace key must be a regular file readable only by its owner")
	}
	t.Setenv(replacementLoginKeyEnv, "invalid-private-key-value!")
	if _, err := newOrderAnsible().loginPublicKey(t.Context()); err == nil ||
		!strings.Contains(err.Error(), replacementLoginKeyEnv) || strings.Contains(err.Error(), "invalid-private-key-value") {
		t.Fatalf("expected an error identifying the setting without its value, got %v", err)
	}
}

func TestOrderAnsibleDefaultsToBundledFiles(t *testing.T) {
	t.Setenv("REPLACEMENT_ANSIBLE_REPO_DIR", "")
	t.Setenv("REPLACEMENT_ANSIBLE_GROUP_VARS_DIR", "")
	manualRepo := t.TempDir()
	t.Setenv("REPLACEMENT_ANSIBLE_MANUAL_REPO_DIR", manualRepo)
	if a := newOrderAnsible(); a.repoDir != bundledReplacementAnsibleDir || a.orderGroupVarsDir != "" {
		t.Fatalf("unexpected bundled paths: %q, %q", a.repoDir, a.orderGroupVarsDir)
	}
	if a := newReplacementAnsible(); a.repoDir != manualRepo {
		t.Fatalf("manual inventory path = %q, want %q", a.repoDir, manualRepo)
	}
	externalRepo := t.TempDir()
	t.Setenv("REPLACEMENT_ANSIBLE_REPO_DIR", externalRepo)
	groupVars := filepath.Join(externalRepo, "inventory", "group_vars")
	if err := os.MkdirAll(groupVars, 0o700); err != nil {
		t.Fatal(err)
	}
	if a := newOrderAnsible(); a.repoDir != externalRepo {
		t.Fatalf("unexpected external repository: %q", a.repoDir)
	} else if dir, err := a.orderGroupVars(); err != nil || dir != groupVars {
		t.Fatalf("unexpected external group variables: %q, %v", dir, err)
	}
}

func TestBundledOrderVarsUseExternalDeploymentSettings(t *testing.T) {
	t.Setenv("REPLACEMENT_ANSIBLE_REPO_DIR", "")
	t.Setenv("REPLACEMENT_ANSIBLE_CERTBOT_EMAIL", "")
	t.Setenv("REPLACEMENT_ANSIBLE_XHTTP_PATH", "")
	t.Setenv("REPLACEMENT_ANSIBLE_XHTTP_UPSTREAM", "")
	runner := newOrderAnsible()
	if err := validateBundledOrderVars(runner.bundledOrderVars("nodes_wl"), "nodes_wl"); err == nil ||
		!strings.Contains(err.Error(), "REPLACEMENT_ANSIBLE_CERTBOT_EMAIL") || !strings.Contains(err.Error(), "REPLACEMENT_ANSIBLE_XHTTP_PATH") {
		t.Fatalf("expected both deployment settings in the error, got %v", err)
	}

	t.Setenv("REPLACEMENT_ANSIBLE_CERTBOT_EMAIL", "admin@example.test")
	t.Setenv("REPLACEMENT_ANSIBLE_XHTTP_PATH", "/selected-profile/")
	t.Setenv("REPLACEMENT_ANSIBLE_XHTTP_UPSTREAM", "127.0.0.1:9443")
	runner = newOrderAnsible()
	for _, group := range []string{"nodes", "nodes_wl"} {
		vars := runner.bundledOrderVars(group)
		vars["nginx_node_domain"] = json.RawMessage(`"node.example.test"`)
		if err := validateBundledOrderVars(vars, group); err != nil {
			t.Fatalf("%s: %v", group, err)
		}
		if err := validateReplacementRepositoryVars(vars, group); err != nil {
			t.Fatalf("%s: %v", group, err)
		}
		if group == "nodes_wl" && replacementVarString(vars, "nginx_node_xhttp_upstream") != "127.0.0.1:9443" {
			t.Fatal("expected configured XHTTP upstream")
		}
	}
}

func TestReplacementAnsibleOrdersUseGeneratedHostAndGroupVars(t *testing.T) {
	for _, tc := range []struct {
		group, playbook, fixtureAlias string
		port                          int
	}{
		{"nodes", "nodes.yml", "germany-01", 11327},
		{"nodes_wl", "nodes-wl.yml", "denmark-01", 2222},
	} {
		t.Run(tc.group, func(t *testing.T) {
			f := newReplacementRepositoryFixture(t)
			t.Setenv("REPLACEMENT_ANSIBLE_NODE_VARS_DIR", "")
			t.Setenv("REPLACEMENT_ANSIBLE_KNOWN_HOSTS", "")
			if err := os.Remove(filepath.Join(f.repo, "inventory", "hosts.yml")); err != nil {
				t.Fatal(err)
			}
			groupVars := filepath.Join(f.root, "external group vars")
			if err := os.Rename(filepath.Join(f.repo, "inventory", "group_vars"), groupVars); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REPLACEMENT_ANSIBLE_GROUP_VARS_DIR", groupVars)
			const alias = "ordered-node-4d19a9eb"
			const domain = "ordered-node.example.invalid"
			const hostKey = "ssh-ed25519 AQID"
			const secret = "fixture-new-node-secret"
			writeReplacementRepositoryFixture(t, filepath.Join(f.root, "ansible-inventory"), `#!/bin/sh
set -eu
observer=${0%/*}
test "$1" = -i
case "$2" in */input/inventory.yml) ;; *) exit 1 ;; esac
test "$3" = --list && test "$4" = --limit && test "$5" = ordered-node-4d19a9eb
test "$6" = --playbook-dir && test "$7" = "${2%/*}"
test -L "$7/group_vars" && test ! -e "$7/host_vars"
test "$(readlink "$7/group_vars")" = "$observer/external group vars"
cp "$2" "$observer/order-inventory-source"
cat "$observer/order-normalized-inventory.json"
`, 0o700)
			writeReplacementRepositoryFixture(t, filepath.Join(f.root, "ssh-keygen"), `#!/bin/sh
if [ "$1" = -l ]; then cat >/dev/null; else printf 'ssh-ed25519 AAAA login-comment\n'; fi
`, 0o700)
			var normalized struct {
				Meta struct {
					Vars map[string]map[string]any `json:"hostvars"`
				} `json:"_meta"`
			}
			if err := json.Unmarshal([]byte(f.read(t, "normalized-inventory.json")), &normalized); err != nil {
				t.Fatal(err)
			}
			values := normalized.Meta.Vars[tc.fixtureAlias]
			values["nginx_node_domain"] = "placeholder.example.com"
			values["stack_nodes_env_content"] = "inherited-fixture-secret"
			values["stack_node_port"] = 30000
			listed, err := json.Marshal(map[string]any{
				"_meta":  map[string]any{"hostvars": map[string]any{alias: values}},
				"all":    map[string]any{"children": []string{tc.group}},
				tc.group: map[string]any{"hosts": []string{alias}},
			})
			if err != nil {
				t.Fatal(err)
			}
			writeReplacementRepositoryFixture(t, filepath.Join(f.root, "order-normalized-inventory.json"), string(listed), 0o600)

			runner := newOrderAnsible()
			order := orderAnsibleNode{Alias: alias, Group: tc.group, Domain: domain, Port: tc.port}
			if err := runner.ReadyForOrder(context.Background(), order); err != nil {
				t.Fatal(err)
			}
			f.wantNoPlaybookRun(t)
			if key, err := runner.loginPublicKey(context.Background()); err != nil || key != "ssh-ed25519 AAAA" {
				t.Fatal("configured login public key was not derived")
			}
			if err := runner.RunOrder(context.Background(), "8.8.4.4", replacementTestNodeID, order); err == nil {
				t.Fatal("new node playbook ran without an SSH pin and node secret")
			}
			f.wantNoPlaybookRun(t)
			order.HostKey, order.Secret = hostKey, secret
			if err := runner.RunOrder(context.Background(), "8.8.4.4", replacementTestNodeID, order); err != nil {
				t.Fatal(err)
			}
			if f.read(t, "order-inventory-source") != `{"`+tc.group+`":{"hosts":{"`+alias+`":{}}}}` {
				t.Fatal("new node inventory input must contain one generated host with no existing address")
			}
			inventory := f.read(t, "captured-inventory")
			if !strings.Contains(inventory, `"`+alias+`":{`) || !strings.Contains(inventory, `"nginx_node_domain":"`+domain+`"`) ||
				!strings.Contains(inventory, `"stack_node_secret_key":"`+secret+`"`) || strings.Contains(inventory, "inherited-fixture-secret") {
				t.Fatal("new node inventory must use the generated alias and the assigned domain and secret")
			}
			if !strings.Contains(inventory, `"stack_node_port":`+strconv.Itoa(tc.port)+`,`) {
				t.Fatal("the inventory must use the Remnawave node control port")
			}
			if f.read(t, "captured-host-keys") != replacementTestNodeID+" "+hostKey+"\n" {
				t.Fatal("new node SSH trust must pin the provided host key against the job UUID")
			}
			if calls := f.read(t, "playbook-calls"); strings.Count(calls, "run "+alias+" "+filepath.Join(f.repo, "playbooks", tc.playbook)+"\n") != 1 {
				t.Fatal("new node must execute the selected playbook once")
			}
			writeReplacementRepositoryFixture(t, filepath.Join(f.root, "unreachable-run"), "", 0o600)
			err = runner.RunOrder(context.Background(), "8.8.4.4", replacementTestNodeID, order)
			if want := tc.playbook + " playbook failed (exit 4): SSH-соединение отклонено"; err == nil || err.Error() != want {
				t.Fatalf("expected safe order diagnostic %q, got %v", want, err)
			}
		})
	}
}
