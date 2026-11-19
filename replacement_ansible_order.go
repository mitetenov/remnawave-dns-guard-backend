package guard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type orderAnsibleNode struct {
	Alias, Group, Domain, HostKey, Secret string
}

var replacementOrderDomainLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

const replacementOrderCheckID = "00000000-0000-4000-8000-000000000000"

func (a *replacementAnsible) checkOrderConfiguration(ctx context.Context) error {
	_, err := a.ready(ctx, true)
	return err
}

func (a *replacementAnsible) ReadyForOrder(node orderAnsibleNode) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return a.processOrder(ctx, "192.0.2.1", replacementOrderCheckID, node, true)
}

func (a *replacementAnsible) RunOrder(ctx context.Context, ip, nodeID string, node orderAnsibleNode) error {
	if !publicIPv4(ip) {
		return errors.New("new node playbooks require a public IPv4 address")
	}
	id, ok := canonicalUUID(nodeID)
	if !ok {
		return errors.New("new node playbooks require a valid node UUID")
	}
	return a.processOrder(ctx, ip, id, node, false)
}

func (a *replacementAnsible) processOrder(ctx context.Context, ip, id string, node orderAnsibleNode, checkOnly bool) error {
	if !validReplacementRepositoryAlias(node.Alias) || (node.Group != "nodes" && node.Group != "nodes_wl") {
		return errors.New("new node playbooks require one safe alias in nodes or nodes_wl")
	}
	if !validReplacementOrderDomain(node.Domain) {
		return errors.New("new node playbooks require a valid node domain")
	}
	timeout, err := a.ready(ctx, true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var knownHosts string
	if !checkOnly {
		if strings.TrimSpace(node.Secret) == "" {
			return errors.New("new node playbooks require the node secret key")
		}
		key, ok := replacementPublicKeyFields(node.HostKey)
		if !ok {
			return errors.New("new node playbooks require the server SSH host public key")
		}
		knownHosts = id + " " + key + "\n"
		if err := validateReplacementPinnedHostKeys(ctx, knownHosts, "new node playbooks require a valid server SSH host public key"); err != nil {
			return err
		}
	}
	work, err := a.createAnsibleWorkspace(knownHosts)
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	return a.processRepository(ctx, work, ip, id, nil, &node, checkOnly)
}

func validReplacementOrderDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !replacementOrderDomainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func (a *replacementAnsible) prepareOrderInventory(work string, node orderAnsibleNode) (string, error) {
	input := filepath.Join(work, "input")
	if err := os.Mkdir(input, 0o700); err != nil {
		return "", errors.New("cannot prepare new node Ansible inventory")
	}
	if err := os.Symlink(a.orderGroupVarsDir, filepath.Join(input, "group_vars")); err != nil {
		return "", errors.New("cannot load new node Ansible group variables")
	}
	// Start with an empty host entry and only the matching group. This source has
	// no host_vars or existing addresses and loads repository group variables only.
	inventory := fmt.Sprintf(`{"%s":{"hosts":{"%s":{}}}}`, node.Group, node.Alias)
	path := filepath.Join(input, "inventory.yml")
	if err := os.WriteFile(path, []byte(inventory), 0o600); err != nil {
		return "", errors.New("cannot prepare new node Ansible inventory")
	}
	return path, nil
}

func (a *replacementAnsible) loginPublicKey(ctx context.Context) (string, error) {
	if a == nil || !replacementAnsibleSupported {
		return "", errors.New("replacement Ansible runner is unavailable")
	}
	if !filepath.IsAbs(a.sshKey) {
		return "", errors.New("REPLACEMENT_ANSIBLE_SSH_KEY must point to an absolute path")
	}
	output, err := a.readLoginPublicKey(ctx)
	if err != nil {
		return "", err
	}
	if key, ok := replacementPublicKeyFields(string(output)); ok {
		return key, nil
	}
	return "", errors.New("cannot read the public SSH login key from REPLACEMENT_ANSIBLE_SSH_KEY")
}

func (a *replacementAnsible) readLoginPublicKey(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := replacementCommand(ctx, "ssh-keygen", "-y", "-P", "", "-f", a.sshKey)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	keyError := errors.New("REPLACEMENT_ANSIBLE_SSH_KEY must contain a usable unencrypted private key")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, keyError
	}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, keyError
	}
	const limit = 16 << 10
	key, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	_ = stdout.Close()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if readErr != nil || waitErr != nil || len(key) > limit {
		return nil, keyError
	}
	return key, nil
}

func replacementPublicKeyFields(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
		return "", false
	}
	fields := strings.Fields(value)
	if len(fields) < 2 || (!strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && !strings.HasPrefix(fields[0], "sk-")) {
		return "", false
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", false
	}
	return fields[0] + " " + fields[1], true
}
