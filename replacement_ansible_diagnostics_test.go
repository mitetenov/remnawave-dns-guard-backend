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

func TestOrderPlaybookDiagnosticsDelegatedFailure(t *testing.T) {
	const taskPath = "playbooks/nodes.yml:105"
	const ip = "192.0.2.1"
	for _, tc := range []struct {
		label, want string
	}{
		{"de-05", "ошибка в задаче " + taskPath},
		{"de-05 -> localhost", "ошибка в задаче " + taskPath},
		{"de-05 -> localhost(" + ip + ")", "ошибка в задаче " + taskPath},
		{"other-node -> localhost", ""},
		{"de-05 -> other-node", ""},
		{"de-05 -> localhost(private-value)", ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			d := orderPlaybookDiagnostics{alias: "de-05", ip: ip, bundled: true}
			_, _ = io.WriteString(&d, "TASK [Check managed SSH port] *****\n"+
				"task path: "+bundledReplacementAnsibleDir+"/"+taskPath+"\n"+
				"fatal: ["+tc.label+`]: FAILED! => {"msg":"fixture-private-value"}`+"\n")
			if got := d.detail(2); got != tc.want {
				t.Fatalf("diagnostic = %q, want %q", got, tc.want)
			}
		})
	}
}
