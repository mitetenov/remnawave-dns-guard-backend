package guard

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

var bundledOrderTaskPath = regexp.MustCompile(`^(playbooks/nodes(-wl)?\.yml|roles/(common|docker|ssl|stack_nodes|warp_native)/(tasks|handlers)/[a-z0-9_-]+\.yml):[1-9][0-9]{0,4}$`)

// Keep only bundled task locations and fixed descriptions. Ansible results can
// contain node secrets, including in SSH failure messages and task names.
type orderPlaybookDiagnostics struct {
	alias   string
	ip      string
	bundled bool
	line    []byte
	drop    bool

	task, failedTask, unreachableTask, unreachableReason string
}

func (d *orderPlaybookDiagnostics) Write(data []byte) (int, error) {
	const maxLine = 8 << 10
	count := len(data)
	for len(data) > 0 {
		part, rest, complete := bytes.Cut(data, []byte{'\n'})
		d.drop = d.drop || len(d.line)+len(part) > maxLine
		if !d.drop {
			d.line = append(d.line, part...)
		}
		if complete {
			if !d.drop {
				d.observe(strings.TrimSuffix(string(d.line), "\r"))
			}
			d.line = d.line[:0]
			d.drop = false
		}
		data = rest
	}
	return count, nil
}

func (d *orderPlaybookDiagnostics) observe(line string) {
	if d.bundled {
		if strings.HasPrefix(line, "TASK [") || strings.HasPrefix(line, "RUNNING HANDLER [") || strings.HasPrefix(line, "PLAY [") {
			d.task = ""
		}
		if path, ok := strings.CutPrefix(line, "task path: "+bundledReplacementAnsibleDir+"/"); ok && bundledOrderTaskPath.MatchString(path) {
			d.task = path
		}
	}
	failure, ok := strings.CutPrefix(line, "fatal: [")
	if !ok {
		return
	}
	label, result, ok := strings.Cut(failure, "]: ")
	if !ok {
		return
	}
	switch label {
	case d.alias, d.alias + " -> localhost", d.alias + " -> localhost(" + d.ip + ")":
	default:
		return
	}
	if payload, ok := strings.CutPrefix(result, "UNREACHABLE! => "); ok {
		var failure struct{ Msg string }
		_ = json.Unmarshal([]byte(payload), &failure)
		d.unreachableTask, d.unreachableReason = d.task, orderSSHFailureReason(failure.Msg)
	} else if strings.HasPrefix(result, "FAILED! => ") {
		d.failedTask = d.task
	}
}

func (d *orderPlaybookDiagnostics) detail(exitCode int) string {
	switch {
	case exitCode == 4 && d.unreachableReason != "":
		if d.unreachableTask != "" {
			return d.unreachableReason + " (" + d.unreachableTask + ")"
		}
		return d.unreachableReason
	case exitCode == 2 && d.failedTask != "":
		return "ошибка в задаче " + d.failedTask
	default:
		return ""
	}
}

func orderSSHFailureReason(message string) string {
	message = strings.ToLower(message)
	switch {
	case strings.Contains(message, "host key verification failed"), strings.Contains(message, "remote host identification has changed"):
		return "не удалось проверить ключ SSH-сервера"
	case strings.Contains(message, "permission denied ("), strings.Contains(message, "no supported authentication methods available"):
		return "SSH-сервер отклонил аутентификацию"
	case strings.Contains(message, "connection refused"):
		return "SSH-соединение отклонено"
	case strings.Contains(message, "connection timed out"), strings.Contains(message, "operation timed out"):
		return "истекло время ожидания SSH-соединения"
	case strings.Contains(message, "no route to host"), strings.Contains(message, "network is unreachable"):
		return "нет сетевого маршрута к SSH-серверу"
	case strings.Contains(message, "connection reset"), strings.Contains(message, "connection closed"):
		return "SSH-соединение прервано"
	default:
		return "Ansible не смог подключиться к ноде"
	}
}
