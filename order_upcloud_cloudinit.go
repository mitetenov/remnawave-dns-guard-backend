package guard

import "encoding/json"

const orderCloudEnrollScript = `import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, url):
        return None

credentials = pathlib.Path("/var/lib/dns-guard/enroll.json")
host_key = pathlib.Path("/etc/ssh/ssh_host_ed25519_key.pub")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

try:
    order = json.loads(credentials.read_text())
    parts = host_key.read_text().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("incorrect SSH host key")
    public_key = " ".join(parts[:2])
    request = urllib.request.Request(
        order["url"],
        data=json.dumps({"host_key": public_key}).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + order["token"]},
    )
except (KeyError, ValueError, OSError):
    sys.exit("Could not prepare DNS Guard enrollment")

for attempt in range(90):
    try:
        with opener.open(request, timeout=10) as response:
            if 200 <= response.status < 300:
                credentials.unlink(missing_ok=True)
                sys.exit(0)
    except (urllib.error.URLError, OSError, ValueError):
        pass
    if attempt < 89:
        time.sleep(15)
sys.exit("DNS Guard enrollment was not confirmed")
`

const orderCloudEnrollUnit = `[Unit]
Description=Register the VM's SSH host key with DNS Guard
Wants=network-online.target
After=network-online.target
ConditionPathExists=/var/lib/dns-guard/enroll.json

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/dns-guard/enroll.py
TimeoutStartSec=40min
Restart=on-failure
RestartSec=5min

[Install]
WantedBy=multi-user.target
`

func orderCloudInit(endpoint, token, sshUser string) (string, error) {
	credentials, err := json.Marshal(row{"url": endpoint, "token": token})
	if err != nil {
		return "", err
	}
	config := row{
		"disable_root":     sshUser != "root",
		"ssh_deletekeys":   true,
		"ssh_genkeytypes":  []string{"ed25519"},
		"ssh_pwauth":       false,
		"ssh_quiet_keygen": true,
		"write_files": []row{
			{"path": "/etc/cloud/cloud.cfg.d/99-dns-guard-host-identity.cfg", "permissions": "0644", "content": "ssh_deletekeys: false\n"},
			{"path": "/var/lib/dns-guard/enroll.json", "permissions": "0600", "content": string(credentials)},
			{"path": "/usr/local/lib/dns-guard/enroll.py", "permissions": "0700", "content": orderCloudEnrollScript},
			{"path": "/etc/systemd/system/dns-guard-enroll.service", "permissions": "0644", "content": orderCloudEnrollUnit},
		},
		"runcmd": [][]string{
			{"systemctl", "daemon-reload"},
			{"systemctl", "enable", "--now", "--no-block", "dns-guard-enroll.service"},
		},
	}
	data, err := json.Marshal(config)
	return "#cloud-config\n" + string(data) + "\n", err
}
