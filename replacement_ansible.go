package guard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	replacementAnsibleEnv        = "REPLACEMENT_ANSIBLE_"
	bundledReplacementAnsibleDir = "/opt/dns-guard/ansible"
	defaultOrderGroupVarsDir     = "/run/dns-guard/replacement/group_vars"
	defaultOrderSSHKey           = "/run/dns-guard/replacement/ssh_key"
)

var replacementSSHUser = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$`)
var replacementListedHost = regexp.MustCompile(`(?m)^[\t ]+hosts \(1\):\r?\n[\t ]+replacement[\t ]*\r?$`)

type replacementAnsible struct {
	installPlaybook, tuningPlaybook   string
	repoDir                           string
	orderGroupVarsDir                 string
	orderCertbotEmail, orderXHTTPPath string
	orderXHTTPUpstream                string
	sshUser, sshKey, knownHosts       string
	sshKeyBase64                      string
	vaultPasswordFile                 string
	nodeVarsDir, timeout              string
	store                             *Store
}

func newReplacementAnsible() *replacementAnsible {
	sshUser := os.Getenv(replacementAnsibleEnv + "SSH_USER")
	if sshUser == "" {
		sshUser = "root"
	}
	repoDir := os.Getenv(replacementAnsibleEnv + "MANUAL_REPO_DIR")
	if repoDir == "" {
		repoDir = os.Getenv(replacementAnsibleEnv + "REPO_DIR")
	}

	return &replacementAnsible{
		installPlaybook:   os.Getenv(replacementAnsibleEnv + "INSTALL_PLAYBOOK"),
		tuningPlaybook:    os.Getenv(replacementAnsibleEnv + "TUNING_PLAYBOOK"),
		repoDir:           repoDir,
		orderGroupVarsDir: os.Getenv(replacementAnsibleEnv + "GROUP_VARS_DIR"),
		sshUser:           sshUser,
		sshKey:            os.Getenv(replacementAnsibleEnv + "SSH_KEY"),
		sshKeyBase64:      strings.TrimSpace(os.Getenv(replacementLoginKeyEnv)),
		vaultPasswordFile: os.Getenv(replacementAnsibleEnv + "VAULT_PASSWORD_FILE"),
		knownHosts:        os.Getenv(replacementAnsibleEnv + "KNOWN_HOSTS"),
		nodeVarsDir:       os.Getenv(replacementAnsibleEnv + "NODE_VARS_DIR"),
		timeout:           env(replacementAnsibleEnv+"TIMEOUT", "20m"),
	}
}

func newOrderAnsible() *replacementAnsible {
	a := newReplacementAnsible()
	a.repoDir = os.Getenv(replacementAnsibleEnv + "REPO_DIR")
	if a.repoDir == "" {
		a.repoDir = bundledReplacementAnsibleDir
	}
	if a.sshKey == "" {
		if _, err := os.Stat(defaultOrderSSHKey); !errors.Is(err, os.ErrNotExist) {
			a.sshKey = defaultOrderSSHKey
		}
	}
	a.orderCertbotEmail = strings.TrimSpace(os.Getenv(replacementAnsibleEnv + "CERTBOT_EMAIL"))
	a.orderXHTTPPath = strings.TrimSpace(os.Getenv(replacementAnsibleEnv + "XHTTP_PATH"))
	a.orderXHTTPUpstream = strings.TrimSpace(os.Getenv(replacementAnsibleEnv + "XHTTP_UPSTREAM"))
	return a
}

func (a *replacementAnsible) Ready() error {
	_, err := a.ready(context.Background(), false, a.vaultSettings())
	return err
}

func (a *replacementAnsible) ready(ctx context.Context, order bool, vault ansibleVaultSettings) (time.Duration, error) {
	if a == nil || !replacementAnsibleSupported {
		return 0, errors.New("replacement Ansible runner is unavailable")
	}
	timeout, err := time.ParseDuration(a.timeout)
	if err != nil || timeout <= 0 {
		return 0, errors.New("REPLACEMENT_ANSIBLE_TIMEOUT must be a positive duration")
	}
	if !replacementSSHUser.MatchString(a.sshUser) {
		return 0, errors.New("REPLACEMENT_ANSIBLE_SSH_USER must be a valid SSH login")
	}
	type requiredFile struct{ name, path string }
	var files []requiredFile
	binaries := []string{"ansible-playbook", "ssh", "ssh-keygen"}
	if order && a.repoDir == "" {
		return 0, errors.New("new node orders require the bundled Ansible files or REPLACEMENT_ANSIBLE_REPO_DIR")
	}
	if a.repoDir != "" {
		if err := a.readyRepository(order); err != nil {
			return 0, err
		}
		if !order && a.nodeVarsDir == "" {
			return 0, errors.New("REPLACEMENT_ANSIBLE_NODE_VARS_DIR is required in repository mode for existing nodes")
		}
		binaries = append(binaries, "ansible-inventory", "ssh-keyscan")
	} else {
		if a.installPlaybook == "" && a.tuningPlaybook == "" {
			return 0, errors.New("для нод с ручной привязкой подключите репозиторий Ansible через REPLACEMENT_ANSIBLE_MANUAL_REPO_DIR")
		}
		files = []requiredFile{{"INSTALL_PLAYBOOK", a.installPlaybook}, {"TUNING_PLAYBOOK", a.tuningPlaybook}}
	}
	if order {
		dir, err := a.orderGroupVars()
		if err != nil {
			return 0, err
		}
		if a.repoDir == bundledReplacementAnsibleDir {
			if (dir == "" || dir == a.bundledGroupVars()) && vault.variables == "" {
				return 0, errors.New("загрузите Vault-файл с токенами Grafana в настройках Ansible")
			}
			if vault.variables != "" {
				if vault.password == "" && a.vaultPasswordFile == "" {
					return 0, errors.New("сохраните пароль Ansible Vault в настройках")
				}
				binaries = append(binaries, "ansible-vault")
			}
		}
	}
	if !order {
		files = append(files, requiredFile{"KNOWN_HOSTS", a.knownHosts})
	}
	if a.sshKeyBase64 == "" && !a.useManagedLoginKey() {
		files = append(files, requiredFile{"SSH_KEY", a.sshKey})
	}
	if vault.password == "" && a.vaultPasswordFile != "" {
		files = append(files, requiredFile{"VAULT_PASSWORD_FILE", a.vaultPasswordFile})
	}
	for _, file := range files {
		info, err := os.Stat(file.path)
		if !filepath.IsAbs(file.path) || err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			if order && file.name == "SSH_KEY" {
				return 0, errors.New("добавьте приватный SSH-ключ в .env через REPLACEMENT_ANSIBLE_SSH_KEY_BASE64 или подключите файл через REPLACEMENT_ANSIBLE_SSH_KEY")
			}
			return 0, fmt.Errorf("%s%s must point to a nonempty regular file using an absolute path", replacementAnsibleEnv, file.name)
		}
		f, err := os.Open(file.path)
		if err != nil {
			return 0, fmt.Errorf("cannot read %s%s", replacementAnsibleEnv, file.name)
		}
		_ = f.Close()
		if file.name == "SSH_KEY" && info.Mode().Perm()&0o077 != 0 {
			return 0, errors.New("REPLACEMENT_ANSIBLE_SSH_KEY must be readable only by its owner")
		}
	}
	if !order && a.nodeVarsDir != "" {
		info, err := os.Stat(a.nodeVarsDir)
		if !filepath.IsAbs(a.nodeVarsDir) || err != nil || !info.IsDir() {
			return 0, errors.New("REPLACEMENT_ANSIBLE_NODE_VARS_DIR must point to a directory using an absolute path")
		}
	}
	for _, binary := range binaries {
		if _, err := exec.LookPath(binary); err != nil {
			return 0, fmt.Errorf("%s is required for replacement playbooks", binary)
		}
	}
	if !a.useManagedLoginKey() {
		if _, err := a.readLoginPublicKey(ctx); err != nil {
			return 0, err
		}
	}
	return timeout, nil
}

func (a *replacementAnsible) ReadyForNode(nodeID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Listing checks syntax and host matching before a replacement IP exists.
	return a.process(ctx, "192.0.2.1", nodeID, true)
}

func (a *replacementAnsible) nodeInputs(ctx context.Context, nodeID string) (string, string, map[string]json.RawMessage, error) {
	id, ok := canonicalUUID(nodeID)
	if !ok {
		return "", "", nil, errors.New("replacement requires a valid Remnawave node UUID")
	}
	knownHosts, err := a.pinnedHostKeys(ctx, id)
	if err != nil {
		return "", "", nil, err
	}
	nodeVars := make(map[string]json.RawMessage)
	if a.nodeVarsDir != "" {
		path := filepath.Join(a.nodeVarsDir, id+".json")
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", "", nil, errors.New("replacement Ansible variables for this node must be a readable regular file")
		}
		varsFile, err := os.Open(path)
		if err != nil {
			return "", "", nil, errors.New("cannot read replacement Ansible variables for this node")
		}
		defer varsFile.Close()
		const limit = 1 << 20
		data, err := io.ReadAll(io.LimitReader(varsFile, limit+1))
		if err != nil || len(data) > limit || json.Unmarshal(data, &nodeVars) != nil || nodeVars == nil {
			return "", "", nil, errors.New("replacement Ansible variables for this node must be a JSON object up to 1 MiB")
		}
	}
	return id, knownHosts, nodeVars, nil
}

func (a *replacementAnsible) pinnedHostKeys(ctx context.Context, id string) (string, error) {
	knownHosts, err := os.Open(a.knownHosts)
	if err != nil {
		return "", errors.New("cannot read REPLACEMENT_ANSIBLE_KNOWN_HOSTS")
	}
	defer knownHosts.Close()
	var pinned strings.Builder
	scanner := bufio.NewScanner(knownHosts)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[0] == id {
			// Copy only exact aliases for this node into the SSH trust store.
			fmt.Fprintf(&pinned, "%s %s %s\n", id, fields[1], fields[2])
		}
	}
	if scanner.Err() != nil {
		return "", errors.New("cannot read REPLACEMENT_ANSIBLE_KNOWN_HOSTS")
	}
	if pinned.Len() == 0 {
		return "", errors.New("REPLACEMENT_ANSIBLE_KNOWN_HOSTS requires an original SSH host key for this node UUID")
	}
	if err := validateReplacementPinnedHostKeys(ctx, pinned.String(), "REPLACEMENT_ANSIBLE_KNOWN_HOSTS contains an invalid host key for this node"); err != nil {
		return "", err
	}
	return pinned.String(), nil
}

func validateReplacementPinnedHostKeys(ctx context.Context, keys, invalidMessage string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := replacementCommand(ctx, "ssh-keygen", "-l", "-f", "/dev/stdin")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdin = strings.NewReader(keys)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New(invalidMessage)
	}
	return nil
}

func (a *replacementAnsible) Run(ctx context.Context, ip, nodeID string) error {
	if !publicIPv4(ip) {
		return errors.New("replacement playbooks require a public IPv4 address")
	}
	return a.process(ctx, ip, nodeID, false)
}

func (a *replacementAnsible) process(ctx context.Context, ip, nodeID string, checkOnly bool) error {
	vault := a.vaultSettings()
	timeout, err := a.ready(ctx, false, vault)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id, knownHosts, nodeVars, err := a.nodeInputs(ctx, nodeID)
	if err != nil {
		return err
	}
	work, err := a.createAnsibleWorkspace(ctx, knownHosts)
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	a, err = a.withVaultPassword(work, vault.password)
	if err != nil {
		return err
	}
	if a.repoDir != "" {
		return a.processRepository(ctx, work, ip, id, nodeVars, nil, checkOnly)
	}
	hostKeys := filepath.Join(work, "known_hosts")
	keyFile := filepath.Join(work, "login_key")
	vars, err := json.Marshal(map[string]any{
		"dns_guard_node_uuid":           id,
		"dns_guard_replacement_ip":      ip,
		"dns_guard_node_vars":           nodeVars,
		"ansible_connection":            "ssh",
		"ansible_host":                  ip,
		"ansible_port":                  22,
		"ansible_user":                  a.sshUser,
		"ansible_ssh_host":              ip,
		"ansible_ssh_port":              22,
		"ansible_ssh_user":              a.sshUser,
		"ansible_ssh_private_key_file":  keyFile,
		"ansible_ssh_host_key_checking": true,
		"ansible_ssh_args":              replacementSSHArgs(hostKeys, id, 20),
		"ansible_ssh_common_args":       "",
		"ansible_ssh_extra_args":        "",
		"ansible_scp_extra_args":        "",
		"ansible_sftp_extra_args":       "",
	})
	if err != nil {
		return errors.New("cannot prepare replacement Ansible variables")
	}
	files := []struct {
		path string
		data []byte
	}{
		{filepath.Join(work, "ansible.cfg"), []byte("[defaults]\n")},
		{filepath.Join(work, "inventory.yml"), []byte(`{"all":{"hosts":{"replacement":{}}}}`)},
		{filepath.Join(work, "vars.json"), vars},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
			return errors.New("cannot prepare replacement Ansible workspace")
		}
	}
	if err := a.play(ctx, work, true); err != nil || checkOnly {
		return err
	}
	return a.play(ctx, work, false)
}

func (a *replacementAnsible) createAnsibleWorkspace(ctx context.Context, knownHosts string) (string, error) {
	// The /tmp prefix also keeps the generated paths free of characters
	// interpreted by OpenSSH's option parser.
	work, err := os.MkdirTemp("/tmp", "dns-guard-replacement-")
	if err != nil {
		return "", errors.New("cannot create replacement Ansible workspace")
	}
	if err := a.stageLoginKey(ctx, filepath.Join(work, "login_key")); err != nil {
		_ = os.RemoveAll(work)
		return "", err
	}
	mode := os.FileMode(0o600)
	if a.repoDir != "" {
		mode = 0o400
	}
	if err := os.WriteFile(filepath.Join(work, "known_hosts"), []byte(knownHosts), mode); err != nil {
		_ = os.RemoveAll(work)
		return "", errors.New("cannot prepare replacement Ansible SSH host key pins")
	}
	return work, nil
}

func replacementSSHArgs(hostKeys, id string, connectionAttempts int) string {
	return strings.Join([]string{
		"-o ControlMaster=no", "-o ControlPath=none", "-o ControlPersist=no",
		"-F /dev/null", "-o StrictHostKeyChecking=yes", "-o UserKnownHostsFile=" + hostKeys,
		"-o HostKeyAlias=" + id, "-o GlobalKnownHostsFile=/dev/null", "-o VerifyHostKeyDNS=no",
		"-o CheckHostIP=no", "-o UpdateHostKeys=no", "-o BatchMode=yes", "-o IdentitiesOnly=yes",
		"-o IdentityAgent=none", "-o ForwardAgent=no", fmt.Sprintf("-o ConnectionAttempts=%d", connectionAttempts), "-o ProxyCommand=none",
	}, " ")
}

func (a *replacementAnsible) environment(work string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + work, "TMPDIR=" + work, "LC_ALL=C.UTF-8",
		"ANSIBLE_CONFIG=" + filepath.Join(work, "ansible.cfg"),
		"ANSIBLE_HOST_KEY_CHECKING=True", "ANSIBLE_RETRY_FILES_ENABLED=False",
	}
	if a.vaultPasswordFile != "" {
		env = append(env, "ANSIBLE_VAULT_PASSWORD_FILE="+a.vaultPasswordFile)
	}
	return env
}

func (a *replacementAnsible) play(ctx context.Context, work string, listHosts bool) error {
	plays := []struct{ name, path string }{
		{"node install", a.installPlaybook},
		{"server tuning", a.tuningPlaybook},
	}
	for _, play := range plays {
		args := []string{"--inventory", filepath.Join(work, "inventory.yml"), "--limit", "replacement", "--extra-vars", "@" + filepath.Join(work, "vars.json"), "--forks", "1"}
		if listHosts {
			args = append(args, "--list-hosts")
		}
		cmd := replacementCommand(ctx, "ansible-playbook", append(args, "--", play.path)...)
		cmd.Dir = filepath.Dir(play.path)
		// Give the playbooks only their explicit inputs. Play output can contain
		// secrets. Only the response to --list-hosts is checked, in memory.
		cmd.Env = a.environment(work)
		var listed bytes.Buffer
		if listHosts {
			cmd.Stdout = &listed
		}
		if err := runReplacementAnsibleCommand(ctx, cmd, play.name+" playbook"); err != nil {
			return err
		}
		if listHosts && !replacementListedHost.Match(listed.Bytes()) {
			return fmt.Errorf("%s playbook must target the replacement host", play.name)
		}
	}
	return nil
}

func runReplacementAnsibleCommand(ctx context.Context, cmd *exec.Cmd, name string) error {
	// Diagnostics report only the operation and exit status. Process output can contain secrets.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s stopped: %w", name, ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("%s failed (exit %d)", name, exit.ExitCode())
		}
		return fmt.Errorf("could not start %s", name)
	}
	return nil
}
