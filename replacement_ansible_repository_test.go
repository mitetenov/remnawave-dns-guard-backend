//go:build unix

package guard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const replacementRepositoryInventory = `all:
  children:
    main:
      hosts:
        panel:
          ansible_host: 192.0.2.2
        finland-01:
    nodes:
      hosts:
        germany-01:
          ansible_host: 192.0.2.3
        finland-01:
          ansible_host: 192.0.2.4
    nodes_wl:
      hosts:
        denmark-01:
          ansible_host: 192.0.2.5
`

type replacementRepositoryFixture struct {
	root     string
	repo     string
	nodeVars string
}

func newReplacementRepositoryFixture(t *testing.T) replacementRepositoryFixture {
	t.Helper()
	root := t.TempDir()
	f := replacementRepositoryFixture{
		root:     root,
		repo:     filepath.Join(root, "operator repository"),
		nodeVars: filepath.Join(root, "node-vars", replacementTestNodeID+".json"),
	}
	for name, contents := range map[string]string{
		"ansible.cfg": `[defaults]
inventory = inventory/hosts.yml
roles_path = roles
collections_path = ./collections
inject_facts_as_vars = false
interpreter_python = auto_silent
[privilege_escalation]
become = True
`,
		"inventory/hosts.yml":                                            replacementRepositoryInventory,
		"inventory/group_vars/nodes.yml":                                 "node_initial_ssh_port: 2200\nnode_ssh_listen_port: 2201\n",
		"inventory/group_vars/nodes_wl.yml":                              "node_initial_ssh_port: 2202\nnode_ssh_listen_port: 2203\n",
		"inventory/host_vars/germany-01.yml":                             "stack_node_secret_key: fixture-normal\n",
		"inventory/host_vars/denmark-01.yml":                             "stack_node_secret_key: fixture-allowlist\n",
		"playbooks/nodes.yml":                                            replacementRepositoryPlaybook("nodes"),
		"playbooks/nodes-wl.yml":                                         replacementRepositoryPlaybook("nodes_wl"),
		"roles/common/tasks/main.yml":                                    "[]\n",
		"roles/docker/tasks/main.yml":                                    "[]\n",
		"roles/ssl/tasks/main.yml":                                       "[]\n",
		"roles/stack_nodes/tasks/main.yml":                               "[]\n",
		"roles/warp_native/tasks/main.yml":                               "[]\n",
		"requirements.yml":                                               "collections:\n  - name: community.docker\n    version: 5.2.2\n  - name: ansible.posix\n    version: 2.2.2\n",
		"collections/ansible_collections/ansible/posix/MANIFEST.json":    "{}\n",
		"collections/ansible_collections/community/docker/MANIFEST.json": "{}\n",
	} {
		writeReplacementRepositoryFixture(t, filepath.Join(f.repo, name), contents, 0o600)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("APP_SECRET", "backend-only-secret")
	t.Setenv("REPLACEMENT_ANSIBLE_REPO_DIR", f.repo)
	t.Setenv("REPLACEMENT_ANSIBLE_INSTALL_PLAYBOOK", "")
	t.Setenv("REPLACEMENT_ANSIBLE_TUNING_PLAYBOOK", "")
	t.Setenv("REPLACEMENT_ANSIBLE_SSH_USER", "ubuntu")
	t.Setenv("REPLACEMENT_ANSIBLE_SSH_KEY", filepath.Join(root, "login key"))
	t.Setenv("REPLACEMENT_ANSIBLE_KNOWN_HOSTS", filepath.Join(root, "operator known hosts"))
	t.Setenv("REPLACEMENT_ANSIBLE_NODE_VARS_DIR", filepath.Dir(f.nodeVars))
	t.Setenv("REPLACEMENT_ANSIBLE_TIMEOUT", "15s")
	writeReplacementRepositoryFixture(t, filepath.Join(root, "login key"), "private key fixture", 0o600)
	writeReplacementRepositoryFixture(t, filepath.Join(root, "operator known hosts"),
		replacementTestNodeID+" ssh-ed25519 node-key-fixture\n* ssh-ed25519 wildcard-key\n", 0o600)
	writeReplacementRepositoryFixture(t, filepath.Join(root, "ssh"), "#!/bin/sh\nexit 1\n", 0o700)
	writeReplacementRepositoryFixture(t, filepath.Join(root, "ssh-keyscan"), "#!/bin/sh\nexit 1\n", 0o700)
	writeReplacementRepositoryFixture(t, filepath.Join(root, "ssh-keygen"),
		"#!/bin/sh\nif [ \"$1\" = -l ]; then cat >/dev/null; fi\n", 0o700)
	writeReplacementRepositoryFixture(t, filepath.Join(root, "ansible-inventory"), `#!/bin/sh
set -eu
observer=${0%/*}
test -z "${APP_SECRET-}"
printf '%s\n' "$@" > "$observer/inventory-args"
cat "$observer/normalized-inventory.json"
`, 0o700)
	writeReplacementRepositoryFixture(t, filepath.Join(root, "ansible-playbook"), replacementRepositoryPlaybookCommand, 0o700)
	hostVars := map[string]map[string]any{"panel": {"ansible_host": "192.0.2.2"}}
	for _, host := range []struct {
		alias, address, secret string
		initialPort, port      int
	}{
		{"germany-01", "192.0.2.3", "fixture-normal", 2200, 2201},
		{"finland-01", "192.0.2.4", "fixture-unselected", 2200, 2201},
		{"denmark-01", "192.0.2.5", "fixture-allowlist", 2202, 2203},
	} {
		hostVars[host.alias] = map[string]any{
			"ansible_host":              host.address,
			"ansible_port":              host.port,
			"ansible_ssh_host":          host.address,
			"ansible_ssh_port":          22299,
			"node_initial_ssh_port":     host.initialPort,
			"node_ssh_listen_port":      host.port,
			"stack_project_src":         "/srv/node",
			"stack_files_src":           "{{ playbook_dir }}/../files/stack-nodes",
			"ssl_fullchain_path":        "/srv/node/certs/fullchain.pem",
			"ssl_privkey_path":          "/srv/node/certs/key.pem",
			"nginx_node_domain":         host.alias + ".example.invalid",
			"stack_node_secret_key":     host.secret,
			"nginx_node_xhttp_path":     "/x/",
			"nginx_node_xhttp_upstream": "127.0.0.1:8443",
		}
	}
	normalized := map[string]any{
		"_meta":    map[string]any{"hostvars": hostVars},
		"all":      map[string]any{"children": []string{"ungrouped", "main", "nodes", "nodes_wl"}},
		"main":     map[string]any{"hosts": []string{"panel", "finland-01"}},
		"nodes":    map[string]any{"hosts": []string{"germany-01", "finland-01"}},
		"nodes_wl": map[string]any{"hosts": []string{"denmark-01"}},
	}
	inventory, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	writeReplacementRepositoryFixture(t, filepath.Join(root, "normalized-inventory.json"), string(inventory), 0o600)
	f.mapping(t, `{"inventory_hostname":"germany-01","access_token":"fixture-node-data"}`)
	return f
}

func writeReplacementRepositoryFixture(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func (f replacementRepositoryFixture) mapping(t *testing.T, contents string) {
	t.Helper()
	writeReplacementRepositoryFixture(t, f.nodeVars, contents, 0o600)
}

func (f replacementRepositoryFixture) read(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(f.root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

const replacementRepositoryPlaybookCommand = `#!/bin/sh
set -eu
observer=${0%/*}
test -z "${APP_SECRET-}"
test "$ANSIBLE_HOST_KEY_CHECKING" = True
mode=run
inventory=
vars=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --inventory|-i) inventory=$2; shift 2 ;;
    --limit|-l) limit=$2; shift 2 ;;
    --extra-vars|-e) vars=${2#@}; shift 2 ;;
    --forks|-f) test "$2" = 1; shift 2 ;;
    --list-hosts) mode=list; shift ;;
    --syntax-check) mode=syntax; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
test "$#" -eq 1
printf '%s %s %s\n' "$mode" "$limit" "$1" >> "$observer/playbook-calls"
if [ "$mode" != run ] && [ -f "$observer/missing-collection" ]; then
  printf 'could not resolve module; setup contained fixture-collection-secret\n' >&2
  exit 4
fi
if [ "$mode" = list ]; then
  printf '  play #1 (nodes): Install \tTAGS: []\n    pattern: [\047nodes\047]\n    hosts (1):\n      %s\n' "$limit"
  if [ -f "$observer/extra-play-host" ]; then
    printf '  play #2 (nodes): Tune \tTAGS: []\n    pattern: [\047nodes\047]\n    hosts (2):\n      %s\n      panel\n' "$limit"
  else
    printf '  play #2 (nodes): Tune \tTAGS: []\n    pattern: [\047nodes\047]\n    hosts (1):\n      %s\n' "$limit"
  fi
  exit 0
fi
if [ "$mode" = run ]; then
  cp "$inventory" "$observer/captured-inventory"
  cp "$vars" "$observer/captured-vars"
  cp "${vars%/*}/known_hosts" "$observer/captured-host-keys"
  cp "${vars%/*}/login_key" "$observer/captured-login-key"
  cp "$ANSIBLE_CONFIG" "$observer/captured-config"
  printf '%s\n' "$PWD" > "$observer/captured-cwd"
  printf '%s\n' "$ANSIBLE_ROLES_PATH" "$ANSIBLE_COLLECTIONS_PATH" > "$observer/captured-search-paths"
  if [ -f "$observer/fail-run" ]; then
    printf 'play failed with fixture-playbook-secret\n' >&2
    exit 2
  fi
fi
`

func replacementRepositoryPlaybook(group string) string {
	return `- name: Install and tune node
  hosts: ` + group + `
  gather_facts: false
  tasks:
    - name: Wait for managed SSH port
      ansible.builtin.wait_for_connection:
      vars:
        ansible_port: "{{ node_ssh_listen_port }}"
    - name: Confirm managed port
      ansible.builtin.wait_for:
        host: "{{ ansible_host }}"
        port: "{{ node_ssh_listen_port }}"
      delegate_to: localhost
      become: false
- name: Apply node tuning
  hosts: ` + group + `
  gather_facts: false
  tasks: []
`
}

func (f replacementRepositoryFixture) wantNoPlaybookRun(t *testing.T) {
	t.Helper()
	calls, err := os.ReadFile(filepath.Join(f.root, "playbook-calls"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "run ") {
		t.Fatalf("playbook ran after failed preflight: %q", calls)
	}
}

func TestReplacementRepositoryRunsMatchingNodePlaybookWithScopedConnection(t *testing.T) {
	for _, tc := range []struct {
		alias, group, playbook, secret string
		initialPort, managedPort       float64
	}{
		{"germany-01", "nodes", "nodes.yml", "fixture-normal", 2200, 2201},
		{"denmark-01", "nodes_wl", "nodes-wl.yml", "fixture-allowlist", 2202, 2203},
	} {
		t.Run(tc.group, func(t *testing.T) {
			f := newReplacementRepositoryFixture(t)
			f.mapping(t, `{"inventory_hostname":"`+tc.alias+`","access_token":"fixture-node-data","ansible_connection":"local","ansible_port":1}`)
			runner := newReplacementAnsible()
			if err := runner.ReadyForNode(replacementTestNodeID); err != nil {
				t.Fatal(err)
			}
			f.wantNoPlaybookRun(t)
			if err := runner.Run(context.Background(), "8.8.4.4", replacementTestNodeID); err != nil {
				t.Fatal(err)
			}

			wantPlay := filepath.Join(f.repo, "playbooks", tc.playbook)
			runCalls := 0
			listCalls := 0
			for _, call := range strings.Split(strings.TrimSpace(f.read(t, "playbook-calls")), "\n") {
				mode, args, _ := strings.Cut(call, " ")
				if args != tc.alias+" "+wantPlay {
					t.Fatalf("wrong play or limit: %q", call)
				}
				switch mode {
				case "run":
					runCalls++
				case "list":
					listCalls++
				}
			}
			if runCalls != 1 || listCalls == 0 {
				t.Fatalf("got %d launches and %d host checks", runCalls, listCalls)
			}
			inventoryArgs := f.read(t, "inventory-args")
			if !strings.Contains(inventoryArgs, "\n"+filepath.Join(f.repo, "inventory/hosts.yml")+"\n") ||
				!strings.Contains(inventoryArgs, "\n"+tc.alias+"\n") {
				t.Fatalf("inventory query did not use the original inventory and mapped alias: %q", inventoryArgs)
			}
			if original := f.read(t, "operator repository/inventory/hosts.yml"); original != replacementRepositoryInventory {
				t.Fatal("the runner modified the repository inventory")
			}
			if f.read(t, "captured-cwd") != f.repo+"\n" ||
				f.read(t, "captured-search-paths") != filepath.Join(f.repo, "roles")+"\n"+filepath.Join(f.repo, "collections")+"\n" {
				t.Fatal("the playbook must find the repository's roles and installed collections")
			}
			if cfg := f.read(t, "captured-config"); !strings.Contains(cfg, "inject_facts_as_vars = false") ||
				!strings.Contains(cfg, "become = true") {
				t.Fatal("the staged Ansible configuration must preserve the node playbook's fact and privilege settings")
			}

			var inventory struct {
				All struct {
					Hosts    map[string]map[string]any
					Children map[string]struct{ Hosts map[string]map[string]any }
				}
			}
			if err := json.Unmarshal([]byte(f.read(t, "captured-inventory")), &inventory); err != nil {
				t.Fatal(err)
			}
			groupHosts := inventory.All.Children[tc.group].Hosts
			host := groupHosts[tc.alias]
			if len(inventory.All.Children) != 1 || len(groupHosts) != 1 || host == nil {
				t.Fatalf("expected only %s in group %s", tc.alias, tc.group)
			}
			if len(inventory.All.Hosts) != 1 || inventory.All.Hosts["localhost"]["ansible_connection"] != "local" {
				t.Fatal("expected a local connection for delegated tasks")
			}
			if host["node_initial_ssh_port"] != tc.initialPort || host["node_ssh_listen_port"] != tc.managedPort ||
				host["stack_node_secret_key"] != tc.secret || host["nginx_node_domain"] != tc.alias+".example.invalid" ||
				host["stack_files_src"] != "{{ playbook_dir }}/../files/stack-nodes" {
				t.Fatal("expected selected host and group settings to survive staging")
			}
			if host["ansible_user"] != "ubuntu" || host["ansible_connection"] != "ssh" {
				t.Fatal("expected the configured SSH login on the mapped host")
			}
			for _, key := range []string{"ansible_host", "ansible_ssh_host"} {
				if host[key] != nil && host[key] != "8.8.4.4" {
					t.Fatal("the original SSH address survived the replacement")
				}
			}
			if host["ansible_port"] == float64(1) || host["ansible_ssh_port"] != nil {
				t.Fatal("a fixed SSH alias port can override the playbook's dynamic ansible_port")
			}
			sshArgs, _ := host["ansible_ssh_args"].(string)
			if !strings.Contains(sshArgs, "HostKeyAlias="+replacementTestNodeID) ||
				!strings.Contains(sshArgs, "StrictHostKeyChecking=yes") ||
				!strings.Contains(sshArgs, "UserKnownHostsFile=") {
				t.Fatalf("expected pinned SSH identity options, got %q", sshArgs)
			}
			if pinned := f.read(t, "captured-host-keys"); pinned != replacementTestNodeID+" ssh-ed25519 node-key-fixture\n" {
				t.Fatal("expected only the exact node key in the temporary trust file")
			}
			if loginKey := f.read(t, "captured-login-key"); loginKey != "private key fixture" {
				t.Fatal("expected the configured SSH login key")
			}

			var vars map[string]json.RawMessage
			if err := json.Unmarshal([]byte(f.read(t, "captured-vars")), &vars); err != nil {
				t.Fatal(err)
			}
			for key := range vars {
				if strings.HasPrefix(key, "ansible_") && key != "ansible_host" {
					t.Errorf("global extra variable %s overrides task settings or affects delegated connections", key)
				}
			}
			if string(vars["ansible_host"]) != `"8.8.4.4"` {
				t.Fatal("the delegated port probe must target the replacement address")
			}
			if string(vars["dns_guard_node_uuid"]) != `"`+replacementTestNodeID+`"` ||
				string(vars["dns_guard_replacement_ip"]) != `"8.8.4.4"` {
				t.Fatal("missing replacement identity variables")
			}
			var nodeVars map[string]any
			if err := json.Unmarshal(vars["dns_guard_node_vars"], &nodeVars); err != nil || nodeVars["access_token"] != "fixture-node-data" {
				t.Fatal("the per-node payload must remain available as node variables")
			}
		})
	}
}

func TestReplacementRepositoryPreflightFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, mapping, marker string
	}{
		{"missing mapping", `{"access_token":"fixture-mapping-secret"}`, ""},
		{"inventory pattern", `{"inventory_hostname":"nodes:!fixture-mapping-secret"}`, ""},
		{"unknown alias", `{"inventory_hostname":"fixture-mapping-secret"}`, ""},
		{"non-node alias", `{"inventory_hostname":"panel"}`, ""},
		{"node also in main group", `{"inventory_hostname":"finland-01"}`, ""},
		{"unresolved collection", "", "missing-collection"},
		{"additional play target", "", "extra-play-host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReplacementRepositoryFixture(t)
			if tc.mapping != "" {
				f.mapping(t, tc.mapping)
			}
			if tc.marker != "" {
				writeReplacementRepositoryFixture(t, filepath.Join(f.root, tc.marker), "", 0o600)
			}
			runner := newReplacementAnsible()
			err := runner.ReadyForNode(replacementTestNodeID)
			if err == nil {
				t.Fatal("invalid repository setup passed preflight")
			}
			if strings.Contains(err.Error(), "fixture-mapping-secret") || strings.Contains(err.Error(), "fixture-collection-secret") {
				t.Fatalf("preflight leaked sensitive details: %v", err)
			}
			if err := runner.Run(context.Background(), "8.8.4.4", replacementTestNodeID); err == nil {
				t.Fatal("the runner accepted an invalid setup after preflight failed")
			}
			f.wantNoPlaybookRun(t)
		})
	}
}

func TestReplacementRepositoryHidesPlaybookFailureOutput(t *testing.T) {
	f := newReplacementRepositoryFixture(t)
	writeReplacementRepositoryFixture(t, filepath.Join(f.root, "fail-run"), "", 0o600)
	err := newReplacementAnsible().Run(context.Background(), "8.8.4.4", replacementTestNodeID)
	if err == nil || !strings.Contains(err.Error(), "exit 2") || strings.Contains(err.Error(), "fixture-playbook-secret") {
		t.Fatalf("expected a sanitized playbook process error, got %v", err)
	}
}

func TestReplacementRepositoryRequiresInventoryCommand(t *testing.T) {
	f := newReplacementRepositoryFixture(t)
	t.Setenv("PATH", f.root)
	if err := os.Remove(filepath.Join(f.root, "ansible-inventory")); err != nil {
		t.Fatal(err)
	}
	err := newReplacementAnsible().ReadyForNode(replacementTestNodeID)
	if err == nil || !strings.Contains(err.Error(), "ansible-inventory") {
		t.Fatalf("expected preflight to require ansible-inventory, got %v", err)
	}
	f.wantNoPlaybookRun(t)
}

func TestReplacementRepositoryRequiresInstalledDependencies(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"role", "roles/docker/tasks/main.yml"},
		{"collection", "collections/ansible_collections/community/docker/MANIFEST.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReplacementRepositoryFixture(t)
			if err := os.Remove(filepath.Join(f.repo, tc.path)); err != nil {
				t.Fatal(err)
			}
			runner := newReplacementAnsible()
			if err := runner.Ready(); err == nil {
				t.Fatalf("missing %s passed configuration validation", tc.name)
			}
			if err := runner.ReadyForNode(replacementTestNodeID); err == nil {
				t.Fatalf("missing %s passed node preflight", tc.name)
			}
			f.wantNoPlaybookRun(t)
		})
	}
}
