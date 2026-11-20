package guard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func virtuaBootstrap(req orderCloudRequest) (string, error) {
	loginKey, valid := cleanOrderLoginKey(req.SSHKey)
	endpoint, err := url.Parse(req.EnrollURL)
	if !valid || !replacementSSHUser.MatchString(req.SSHUser) || err != nil ||
		endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.Path != "/api/server-orders/"+req.OperationID+"/enroll" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		!upCloudEnrollmentToken.MatchString(req.EnrollToken) {
		return "", errors.New("некорректные параметры SSH для заказа Virtua.Cloud")
	}
	credentials, err := json.Marshal(row{"url": req.EnrollURL, "token": req.EnrollToken})
	if err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString(`#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
`)
	fmt.Fprintf(&script, "login_user='%s'\nlogin_key='%s'\n", req.SSHUser, loginKey)
	script.WriteString(`packages=()
command -v python3 >/dev/null || packages+=(python3 ca-certificates)
if [ "$login_user" != root ]; then
    command -v sudo >/dev/null || packages+=(sudo)
fi
if [ "${#packages[@]}" -gt 0 ]; then
    apt-get update
    apt-get install -y "${packages[@]}"
fi
if ! id "$login_user" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$login_user"
fi
login_home="$(getent passwd "$login_user" | cut -d: -f6)"
login_group="$(id -gn "$login_user")"
test -n "$login_home"
install -d -m 0700 -o "$login_user" -g "$login_group" "$login_home/.ssh"
keyfile="$login_home/.ssh/authorized_keys"
touch "$keyfile"
if ! grep -Fxq -- "$login_key" "$keyfile"; then
    printf '\n%s\n' "$login_key" >> "$keyfile"
fi
chown "$login_user:$login_group" "$keyfile"
chmod 0600 "$keyfile"
if [ "$login_user" != root ]; then
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$login_user" > /etc/sudoers.d/90-dns-guard
    chmod 0440 /etc/sudoers.d/90-dns-guard
fi
install -d -m 0755 /etc/ssh/sshd_config.d
printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin prohibit-password' > /etc/ssh/sshd_config.d/00-dns-guard.conf
ssh-keygen -A
/usr/sbin/sshd -t
systemctl reload-or-restart ssh.service
install -d -m 0700 /var/lib/dns-guard /usr/local/lib/dns-guard
`)
	writeFile := func(path string, data []byte, mode string) {
		fmt.Fprintf(&script, "printf '%%s' '%s' | base64 -d > %s\nchmod %s %s\n", base64.StdEncoding.EncodeToString(data), path, mode, path)
	}
	writeFile("/var/lib/dns-guard/enroll.json", credentials, "0600")
	writeFile("/usr/local/lib/dns-guard/enroll.py", []byte(orderCloudEnrollScript), "0700")
	writeFile("/etc/systemd/system/dns-guard-enroll.service", []byte(orderCloudEnrollUnit), "0644")
	script.WriteString("systemctl daemon-reload\nsystemctl enable --now --no-block dns-guard-enroll.service\n")
	return script.String(), nil
}
