//go:build unix

package guard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const replacementTestNodeID = "123e4567-e89b-12d3-a456-426614174000"

func replacementTestRunner(t *testing.T) (*replacementAnsible, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	write := func(name, contents string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("ssh", "#!/bin/sh\nexit 1\n", 0o700)
	write("ssh-keygen", "#!/bin/sh\nif [ \"$1\" = -l ]; then cat >/dev/null; fi\n", 0o700)
	write("ansible-playbook", `#!/bin/sh
set -eu
test -z "${APP_SECRET-}"
test "$ANSIBLE_HOST_KEY_CHECKING" = True
observer=${0%/*}
list=no
while [ "$#" -gt 0 ]; do
  case "$1" in
    --inventory) inventory=$2; shift 2 ;;
    --limit) test "$2" = replacement; shift 2 ;;
    --extra-vars) vars=${2#@}; shift 2 ;;
    --forks) test "$2" = 1; shift 2 ;;
    --list-hosts) list=yes; shift ;;
    --) shift; break ;;
    *) exit 10 ;;
  esac
done
play=${1##*/}
printf '%s\n' "$list $play" >> "$observer/calls"
if [ "$list" = yes ]; then
  if [ -e "$observer/no-host-$play" ]; then
    printf '      hosts (0):\n'
  else
    printf '      hosts (1):\n        replacement\n'
  fi
  exit 0
fi
cp "$inventory" "$observer/captured-inventory"
cp "$vars" "$observer/captured-vars"
cp "${vars%/*}/known_hosts" "$observer/captured-host-keys"
printf 'never show this secret\n' >&2
if [ -e "$observer/fail-$play" ]; then
  exit 2
fi
`, 0o700)
	t.Setenv("APP_SECRET", "backend-only-secret")
	t.Setenv("REPLACEMENT_ANSIBLE_REPO_DIR", "")
	t.Setenv("REPLACEMENT_ANSIBLE_INSTALL_PLAYBOOK", write("install node.yml", "install", 0o600))
	t.Setenv("REPLACEMENT_ANSIBLE_TUNING_PLAYBOOK", write("tune server.yml", "tune", 0o600))
	t.Setenv("REPLACEMENT_ANSIBLE_SSH_USER", "ubuntu")
	t.Setenv("REPLACEMENT_ANSIBLE_SSH_KEY", write("login key", "key", 0o600))
	t.Setenv("REPLACEMENT_ANSIBLE_KNOWN_HOSTS", write("known_hosts", replacementTestNodeID+" ssh-ed25519 source_key\n* ssh-ed25519 other-key\n", 0o600))
	write(replacementTestNodeID+".json", `{"access_token":"node-data","ansible_host":"1.1.1.1"}`, 0o600)
	t.Setenv("REPLACEMENT_ANSIBLE_NODE_VARS_DIR", dir)
	t.Setenv("REPLACEMENT_ANSIBLE_TIMEOUT", "15s")
	return newReplacementAnsible(), dir
}

func TestReplacementAnsibleDefaultsSSHUserToRoot(t *testing.T) {
	const key = "REPLACEMENT_ANSIBLE_SSH_USER"
	t.Setenv(key, "")
	if got := newReplacementAnsible().sshUser; got != "root" {
		t.Errorf("SSH user with an empty environment variable = %q, want root", got)
	}
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	if got := newReplacementAnsible().sshUser; got != "root" {
		t.Errorf("SSH user with no environment variable = %q, want root", got)
	}
}

func TestReplacementAnsibleScopesBothPlaybooks(t *testing.T) {
	a, dir := replacementTestRunner(t)
	if err := a.ReadyForNode(replacementTestNodeID); err != nil {
		t.Fatal(err)
	}
	if err := a.Run(context.Background(), "8.8.4.4", replacementTestNodeID); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if calls := read("calls"); calls != "yes install node.yml\nyes tune server.yml\nyes install node.yml\nyes tune server.yml\nno install node.yml\nno tune server.yml\n" {
		t.Fatalf("playbook calls = %q", calls)
	}
	if inventory := read("captured-inventory"); inventory != `{"all":{"hosts":{"replacement":{}}}}` {
		t.Fatalf("unexpected inventory %q", inventory)
	}
	if hostKeys := read("captured-host-keys"); hostKeys != replacementTestNodeID+" ssh-ed25519 source_key\n" {
		t.Fatalf("unexpected pinned host keys %q", hostKeys)
	}
	var vars map[string]any
	if err := json.Unmarshal([]byte(read("captured-vars")), &vars); err != nil {
		t.Fatal(err)
	}
	if vars["ansible_host"] != "8.8.4.4" || vars["dns_guard_node_uuid"] != replacementTestNodeID || vars["ansible_user"] != "ubuntu" {
		t.Fatalf("unexpected connection variables %+v", vars)
	}
	sshArgs := vars["ansible_ssh_args"].(string)
	if !strings.Contains(sshArgs, "HostKeyAlias="+replacementTestNodeID) || !strings.Contains(sshArgs, "StrictHostKeyChecking=yes") {
		t.Fatalf("unexpected host checking arguments %q", sshArgs)
	}
	nodeVars := vars["dns_guard_node_vars"].(map[string]any)
	if nodeVars["access_token"] != "node-data" {
		t.Fatalf("unexpected node variables %+v", nodeVars)
	}
}

func TestReplacementAnsibleChecksSourceIdentityAndPlaybookHosts(t *testing.T) {
	a, dir := replacementTestRunner(t)
	if err := a.ReadyForNode("557b85f7-6c59-46ae-a5d4-74aa8ac7c271"); err == nil || !strings.Contains(err.Error(), "original SSH host key") {
		t.Fatalf("expected exact source identity check, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "no-host-tune server.yml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.ReadyForNode(replacementTestNodeID); err == nil || !strings.Contains(err.Error(), "server tuning playbook must target the replacement host") {
		t.Fatalf("expected error for playbook without a matching host, got %v", err)
	}
}

func TestReplacementAnsibleStopsAndHidesPlaybookOutputOnFailure(t *testing.T) {
	a, dir := replacementTestRunner(t)
	if err := os.WriteFile(filepath.Join(dir, "fail-install node.yml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.Run(context.Background(), "8.8.4.4", replacementTestNodeID)
	if err == nil || err.Error() != "node install playbook failed (exit 2)" {
		t.Fatalf("unexpected install error %v", err)
	}
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "no tune server.yml") {
		t.Fatalf("tuning ran after install failed, calls = %q", calls)
	}
}
