package guard

import (
	"io"
	"strings"
	"testing"
)

func TestOrderPlaybookDiagnostics(t *testing.T) {
	const taskPath = "playbooks/nodes.yml:42"
	d := orderPlaybookDiagnostics{alias: "node-1", bundled: true}
	for _, output := range []string{
		"TASK [fixture-task-secret] ********\ntask path: ",
		bundledReplacementAnsibleDir + "/" + taskPath + "\n",
		`fatal: [node-1]: UNREACHABLE! => {"msg":"node-1: Permission denied (publickey). fixture-ssh-secret", "unreachable":true}` + "\n",
		`fatal: [other-node]: UNREACHABLE! => {"msg":"Connection refused"}` + "\n",
		"TASK [next task] **\ntask path: /tmp/fixture-private-role.yml:5\n",
		strings.Repeat("x", 9000) + "\n",
	} {
		if n, err := io.WriteString(&d, output); err != nil || n != len(output) {
			t.Fatalf("diagnostic output write: %d of %d bytes, %v", n, len(output), err)
		}
	}
	if got, want := d.detail(4), "SSH-сервер отклонил аутентификацию ("+taskPath+")"; got != want {
		t.Fatalf("diagnostic = %q, want %q", got, want)
	}
	if got := d.detail(0); got != "" {
		t.Fatalf("successful run has a diagnostic: %q", got)
	}
	_, _ = io.WriteString(&d, `fatal: [node-1]: UNREACHABLE! => {"censored":"fixture-hidden-value"}`+"\n")
	if got := d.detail(4); got != "Ansible не смог подключиться к ноде" {
		t.Fatalf("diagnostic for censored result = %q", got)
	}
}
