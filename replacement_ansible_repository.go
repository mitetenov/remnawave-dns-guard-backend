package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var replacementInventoryAlias = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}$`)
var replacementInventoryHosts = regexp.MustCompile(`(?m)^[\t ]+hosts \(([0-9]+)\):[\t ]*\r?(?:\n([^\n]*))?`)
var replacementNodeXHTTPPath = regexp.MustCompile(`^/[a-zA-Z0-9/_-]+/$`)
var replacementNodeXHTTPUpstream = regexp.MustCompile(`^127\.0\.0\.1:[0-9]{1,5}$`)

type replacementInventoryGroup struct {
	Hosts    []string `json:"hosts"`
	Children []string `json:"children"`
}

func (a *replacementAnsible) readyRepository(order bool) error {
	if !filepath.IsAbs(a.repoDir) {
		return errors.New("REPLACEMENT_ANSIBLE_REPO_DIR must point to the Ansible repository using an absolute path")
	}
	files := []string{
		"playbooks/nodes.yml", "playbooks/nodes-wl.yml",
		"roles/common/tasks/main.yml", "roles/docker/tasks/main.yml", "roles/stack_nodes/tasks/main.yml",
		"roles/ssl/tasks/main.yml", "roles/warp_native/tasks/main.yml",
	}
	if !order {
		files = append(files, "inventory/hosts.yml")
	} else if a.repoDir == bundledReplacementAnsibleDir {
		files = append(files, "files/nodes/docker-compose.yml")
	}
	for _, name := range files {
		info, err := os.Stat(filepath.Join(a.repoDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			if a.repoDir == bundledReplacementAnsibleDir {
				return fmt.Errorf("в образе backend отсутствует файл Ansible %s", name)
			}
			return fmt.Errorf("REPLACEMENT_ANSIBLE_REPO_DIR requires %s", name)
		}
	}
	for _, collection := range []string{"ansible/posix", "community/docker"} {
		info, err := os.Stat(filepath.Join(a.repoDir, "collections", "ansible_collections", collection, "MANIFEST.json"))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("replacement Ansible needs the %s collection installed in the repository from requirements.yml", strings.ReplaceAll(collection, "/", "."))
		}
	}
	return nil
}

func validReplacementRepositoryAlias(alias string) bool {
	switch strings.ToLower(strings.TrimSuffix(alias, ".")) {
	case "all", "ungrouped", "nodes", "nodes_wl", "main", "webproxy", "localhost", "localhost.localdomain":
		return false
	}
	return replacementInventoryAlias.MatchString(alias) && net.ParseIP(alias) == nil
}

func (a *replacementAnsible) processRepository(ctx context.Context, work, ip, id string, nodeVars map[string]json.RawMessage, order *orderAnsibleNode, checkOnly bool) error {
	var alias string
	source := filepath.Join(a.repoDir, "inventory", "hosts.yml")
	varsBase := filepath.Join(a.repoDir, "playbooks")
	if order == nil {
		if json.Unmarshal(nodeVars["inventory_hostname"], &alias) != nil || !validReplacementRepositoryAlias(alias) {
			return errors.New("replacement Ansible variables must specify one non-reserved inventory_hostname alias")
		}
	} else {
		alias = order.Alias
		var err error
		source, err = a.prepareOrderInventory(work, *order)
		if err != nil {
			return err
		}
		varsBase = filepath.Dir(source)
	}
	if err := os.Mkdir(filepath.Join(work, ".ssh"), 0o700); err != nil {
		return errors.New("cannot create replacement Ansible SSH workspace")
	}
	const config = `[defaults]
inject_facts_as_vars = false
interpreter_python = auto_silent

[inventory]
enable_plugins = yaml
any_unparsed_is_failed = true

[privilege_escalation]
become = true
`
	configFile := filepath.Join(work, "ansible.cfg")
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		return errors.New("cannot prepare replacement Ansible configuration")
	}
	env := append(replacementAnsibleEnvironment(work),
		"ANSIBLE_ROLES_PATH="+filepath.Join(a.repoDir, "roles"),
		"ANSIBLE_COLLECTIONS_PATH="+filepath.Join(a.repoDir, "collections"),
		"ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=False",
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(work, "ansible-tmp"),
	)
	group, inventoryVars, err := a.loadRepositoryHost(ctx, env, alias, source, varsBase)
	if err != nil {
		return err
	}
	if order != nil && group != order.Group {
		return errors.New("new node Ansible inventory must retain the requested group")
	}
	bundledOrder := order != nil && a.repoDir == bundledReplacementAnsibleDir
	hostVars := make(map[string]any)
	if bundledOrder {
		hostVars = a.bundledOrderVars(group)
	}
	for _, values := range []map[string]json.RawMessage{inventoryVars, nodeVars} {
		for name, value := range values {
			if replacementRepositoryVariable(name) {
				hostVars[name] = value
			}
		}
	}
	if order != nil {
		domain, _ := json.Marshal(order.Domain)
		secret, _ := json.Marshal(order.Secret)
		hostVars["nginx_node_domain"] = json.RawMessage(domain)
		hostVars["stack_node_secret_key"] = json.RawMessage(secret)
		hostVars["stack_node_port"] = orderRemnawaveNodePort
		delete(hostVars, "stack_nodes_env_content")
		if bundledOrder {
			// The bundled roles omit the upstream's deployment-specific Alloy configuration.
			hostVars["common_alloy_enabled"] = false
			if err := validateBundledOrderVars(hostVars, group); err != nil {
				return err
			}
		}
	}
	if err := validateReplacementRepositoryVars(hostVars, group); err != nil {
		return err
	}

	// A delegated connection uses localhost's settings, while the tasks' explicit
	// ansible_host argument still refers to the new node. Leave port selection to
	// the playbook's task vars and set_fact calls.
	hostVars["ansible_connection"] = "ssh"
	hostVars["ansible_host"] = ip
	hostVars["ansible_user"] = a.sshUser
	hostVars["ansible_ssh_private_key_file"] = filepath.Join(work, "login_key")
	hostVars["ansible_ssh_args"] = replacementSSHArgs(filepath.Join(work, "known_hosts"), id, 1)
	inventory := map[string]any{"all": map[string]any{
		"hosts": map[string]any{"localhost": map[string]any{
			"ansible_connection":         "local",
			"ansible_become":             false,
			"ansible_python_interpreter": "{{ ansible_playbook_python }}",
		}},
		"children": map[string]any{group: map[string]any{
			"hosts": map[string]any{alias: hostVars},
		}},
	}}
	delete(nodeVars, "inventory_hostname")
	extraVars := map[string]any{
		"ansible_host":             ip,
		"dns_guard_node_uuid":      id,
		"dns_guard_replacement_ip": ip,
		"dns_guard_node_vars":      nodeVars,
	}
	for name, value := range map[string]any{"inventory.yml": inventory, "vars.json": extraVars} {
		data, err := json.Marshal(value)
		if err != nil || os.WriteFile(filepath.Join(work, name), data, 0o600) != nil {
			return errors.New("cannot prepare replacement Ansible inventory and variables")
		}
	}

	// All applicable conventional inventory and playbook variables were resolved
	// above. Do not reload playbook host_vars/group_vars over the scoped transport.
	env = append(env, "ANSIBLE_VARS_ENABLED=")
	playbook := "nodes.yml"
	if group == "nodes_wl" {
		playbook = "nodes-wl.yml"
	}
	playPath := filepath.Join(a.repoDir, "playbooks", playbook)
	args := []string{"--inventory", filepath.Join(work, "inventory.yml"), "--limit", alias,
		"--extra-vars", "@" + filepath.Join(work, "vars.json"), "--forks", "1"}
	listArgs := append(append([]string{}, args...), "--list-hosts", "--", playPath)
	cmd := replacementCommand(ctx, "ansible-playbook", listArgs...)
	cmd.Dir, cmd.Env = a.repoDir, env
	var listed bytes.Buffer
	cmd.Stdout = &listed
	if err := runReplacementAnsibleCommand(ctx, cmd, playbook+" playbook preflight"); err != nil {
		return err
	}
	matches := replacementInventoryHosts.FindAllSubmatch(listed.Bytes(), -1)
	if len(matches) == 0 {
		return fmt.Errorf("%s playbook must target the selected replacement host", playbook)
	}
	for _, hosts := range matches {
		if string(hosts[1]) != "1" || strings.TrimSpace(string(hosts[2])) != alias {
			return fmt.Errorf("%s playbook must target only the selected replacement host in every play", playbook)
		}
	}
	if checkOnly {
		return nil
	}
	cmd = replacementCommand(ctx, "ansible-playbook", append(args, "--", playPath)...)
	cmd.Dir, cmd.Env = a.repoDir, env
	return runReplacementAnsibleCommand(ctx, cmd, playbook+" playbook")
}

func (a *replacementAnsible) loadRepositoryHost(ctx context.Context, env []string, alias, source, varsBase string) (string, map[string]json.RawMessage, error) {
	cmd := replacementCommand(ctx, "ansible-inventory", "-i", source, "--list", "--limit", alias, "--playbook-dir", varsBase)
	cmd.Dir, cmd.Env = a.repoDir, env
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := runReplacementAnsibleCommand(ctx, cmd, "replacement Ansible inventory"); err != nil {
		return "", nil, err
	}
	var inventory map[string]json.RawMessage
	var inventoryMeta struct {
		HostVars map[string]map[string]json.RawMessage `json:"hostvars"`
	}
	if json.Unmarshal(output.Bytes(), &inventory) != nil || json.Unmarshal(inventory["_meta"], &inventoryMeta) != nil {
		return "", nil, errors.New("cannot read replacement Ansible inventory listing")
	}
	groups := make(map[string]replacementInventoryGroup)
	for name, data := range inventory {
		if name == "_meta" {
			continue
		}
		var group replacementInventoryGroup
		if json.Unmarshal(data, &group) != nil {
			return "", nil, errors.New("cannot read replacement Ansible inventory groups")
		}
		groups[name] = group
	}
	if _, exists := groups[alias]; exists {
		return "", nil, errors.New("replacement Ansible inventory_hostname conflicts with an inventory group")
	}
	for _, name := range []string{"main", "webproxy"} {
		if replacementGroupContains(groups, name, alias, make(map[string]bool)) {
			return "", nil, errors.New("replacement Ansible inventory_hostname cannot belong to main or webproxy")
		}
	}
	nodes := replacementGroupContains(groups, "nodes", alias, make(map[string]bool))
	wl := replacementGroupContains(groups, "nodes_wl", alias, make(map[string]bool))
	if nodes == wl {
		return "", nil, errors.New("replacement Ansible inventory_hostname must belong to exactly one of nodes or nodes_wl")
	}
	group := "nodes"
	if wl {
		group = "nodes_wl"
	}
	return group, inventoryMeta.HostVars[alias], nil
}

func replacementGroupContains(groups map[string]replacementInventoryGroup, name, alias string, visited map[string]bool) bool {
	if visited[name] {
		return false
	}
	visited[name] = true
	group := groups[name]
	for _, host := range group.Hosts {
		if host == alias {
			return true
		}
	}
	for _, child := range group.Children {
		if replacementGroupContains(groups, child, alias, visited) {
			return true
		}
	}
	return false
}

func replacementRepositoryVariable(name string) bool {
	for _, prefix := range []string{"ansible_", "_ansible_", "inventory_", "dns_guard_"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	switch name {
	case "groups", "group_names", "hostvars", "playbook_dir", "environment", "omit":
		return false
	}
	return true
}

func replacementVarString(vars map[string]any, name string) (value string) {
	raw, _ := vars[name].(json.RawMessage)
	_ = json.Unmarshal(raw, &value)
	return strings.TrimSpace(value)
}

func replacementUsesCertbot(vars map[string]any) bool {
	certbot, _ := vars["nodes_certbot_enabled"].(json.RawMessage)
	switch strings.ToLower(strings.Trim(string(certbot), `"`)) {
	case "true", "yes", "on", "1":
		provider := replacementVarString(vars, "ssl_provider")
		return provider == "" || provider == "certbot"
	}
	return false
}

func validReplacementXHTTPUpstream(upstream string) bool {
	if !replacementNodeXHTTPUpstream.MatchString(upstream) {
		return false
	}
	port, _ := strconv.Atoi(strings.TrimPrefix(upstream, "127.0.0.1:"))
	return port >= 1 && port <= 65535
}

func validateReplacementRepositoryVars(vars map[string]any, group string) error {
	value := func(name string) string { return replacementVarString(vars, name) }
	for _, name := range []string{"stack_project_src", "stack_files_src", "nginx_node_domain", "ssl_fullchain_path", "ssl_privkey_path"} {
		if value(name) == "" {
			return fmt.Errorf("replacement Ansible inventory requires %s for the selected host", name)
		}
	}
	domain := strings.ToLower(strings.TrimSuffix(value("nginx_node_domain"), "."))
	if domain == "example.com" || strings.HasSuffix(domain, ".example.com") {
		return errors.New("replacement Ansible nginx_node_domain still uses an example domain")
	}
	for _, name := range []string{"node_initial_ssh_port", "node_ssh_listen_port"} {
		port := value(name)
		if port == "" {
			raw, _ := vars[name].(json.RawMessage)
			port = string(raw)
		}
		if strings.Contains(port, "{{") {
			continue
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("replacement Ansible inventory requires a valid %s for the selected host", name)
		}
	}
	if group == "nodes_wl" {
		path, upstream := value("nginx_node_xhttp_path"), value("nginx_node_xhttp_upstream")
		if !strings.Contains(path, "{{") && !replacementNodeXHTTPPath.MatchString(path) {
			return errors.New("replacement Ansible inventory requires a valid nginx_node_xhttp_path for the selected CDN host")
		}
		if !strings.Contains(upstream, "{{") && !validReplacementXHTTPUpstream(upstream) {
			return errors.New("replacement Ansible inventory requires a loopback nginx_node_xhttp_upstream for the selected CDN host")
		}
	}
	if replacementUsesCertbot(vars) {
		for _, name := range []string{"ssl_certbot_email", "nginx_acme_webroot"} {
			if value(name) == "" {
				return fmt.Errorf("replacement Ansible inventory requires %s for Certbot", name)
			}
		}
		var domains []string
		raw, _ := vars["ssl_certbot_domains"].(json.RawMessage)
		if value("ssl_certbot_domains") == "" && (json.Unmarshal(raw, &domains) != nil || len(domains) == 0) {
			return errors.New("replacement Ansible inventory requires ssl_certbot_domains for Certbot")
		}
	}
	return nil
}
