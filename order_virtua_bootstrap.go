package guard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const virtuaBootstrapUnit = `[Unit]
Description=Prepare SSH access and register the VPS with DNS Guard
Wants=network-online.target
After=network-online.target ssh.service
ConditionPathExists=/var/lib/dns-guard/enroll.json

[Service]
Type=oneshot
ExecStart=/usr/local/lib/dns-guard/bootstrap.sh
TimeoutStartSec=45min
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
`

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
	var bootstrap strings.Builder
	bootstrap.WriteString(`#!/bin/sh
set -eu
umask 077
export DEBIAN_FRONTEND=noninteractive
`)
	fmt.Fprintf(&bootstrap, "login_user='%s'\nlogin_key='%s'\n", req.SSHUser, loginKey)
	bootstrap.WriteString(`set --
command -v python3 >/dev/null || set -- "$@" python3
test -s /etc/ssl/certs/ca-certificates.crt || set -- "$@" ca-certificates
if [ "$login_user" != root ]; then
    command -v sudo >/dev/null || set -- "$@" sudo
fi
if [ "$#" -gt 0 ]; then
    apt-get -o Acquire::Retries=3 update
    apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=120 install -y "$@"
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
exec /usr/bin/python3 /usr/local/lib/dns-guard/enroll.py
`)
	// The provider can run the installer before the guest has network access or
	// a systemd instance. Write the unit and enable it without contacting PID 1.
	var script strings.Builder
	script.WriteString(`#!/bin/sh
set -eu
umask 077
if [ -f /usr/local/lib/dns-guard/bootstrap.sh ] && [ ! -f /var/lib/dns-guard/enroll.json ]; then
    exit 0
fi
install -d -m 0700 /var/lib/dns-guard /usr/local/lib/dns-guard
install -d -m 0755 /etc/systemd/system/multi-user.target.wants
`)
	writeFile := func(path string, data []byte, mode string) {
		fmt.Fprintf(&script, "printf '%%s' '%s' | base64 -d > %s\nchmod %s %s\n", base64.StdEncoding.EncodeToString(data), path, mode, path)
	}
	writeFile("/var/lib/dns-guard/enroll.json", credentials, "0600")
	writeFile("/usr/local/lib/dns-guard/enroll.py", []byte(orderCloudEnrollScript), "0700")
	writeFile("/usr/local/lib/dns-guard/bootstrap.sh", []byte(bootstrap.String()), "0700")
	writeFile("/etc/systemd/system/dns-guard-enroll.service", []byte(virtuaBootstrapUnit), "0644")
	script.WriteString(`ln -sfn ../dns-guard-enroll.service /etc/systemd/system/multi-user.target.wants/dns-guard-enroll.service
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl start --no-block dns-guard-enroll.service
fi
`)
	return script.String(), nil
}
