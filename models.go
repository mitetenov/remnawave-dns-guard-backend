package guard

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Settings struct {
	CloudflareAPIToken *string `json:"cloudflare_api_token"`
	RemnawaveURL       *string `json:"remnawave_url"`
	RemnawaveAPIToken  *string `json:"remnawave_api_token"`
}
type PoolInput struct {
	Name                   string `json:"name"`
	Hostname               string `json:"hostname"`
	ZoneID                 string `json:"zone_id"`
	TTL                    int    `json:"ttl"`
	IntervalSeconds        int    `json:"interval_seconds"`
	FailureThreshold       int    `json:"failure_threshold"`
	RecoveryThreshold      int    `json:"recovery_threshold"`
	AutomationEnabled      bool   `json:"automation_enabled"`
	DisableHostWhenAllDown bool   `json:"disable_host_when_all_down"`
}

func defaultPool() PoolInput {
	return PoolInput{TTL: 120, IntervalSeconds: 60, FailureThreshold: 3, RecoveryThreshold: 5}
}
func (p PoolInput) values() row {
	return row{"name": p.Name, "hostname": p.Hostname, "zone_id": p.ZoneID, "ttl": p.TTL, "interval_seconds": p.IntervalSeconds, "failure_threshold": p.FailureThreshold, "recovery_threshold": p.RecoveryThreshold, "automation_enabled": p.AutomationEnabled, "disable_host_when_all_down": p.DisableHostWhenAllDown}
}

type TargetInput struct {
	Name          string  `json:"name"`
	IP            string  `json:"ip"`
	RemnawaveUUID *string `json:"remnawave_uuid"`
}
type Profile struct {
	Protocol     string          `json:"protocol,omitempty"`
	Password     string          `json:"password,omitempty"`
	Obfs         string          `json:"obfs,omitempty"`
	ObfsPassword string          `json:"obfs_password,omitempty"`
	PinSHA256    string          `json:"pin_sha256,omitempty"`
	Congestion   string          `json:"hysteria_congestion,omitempty"`
	Port         int             `json:"port"`
	UUID         string          `json:"uuid"`
	Transport    string          `json:"transport"`
	Security     string          `json:"security"`
	ServerName   string          `json:"server_name"`
	PublicKey    string          `json:"public_key"`
	ShortID      string          `json:"short_id"`
	Flow         string          `json:"flow"`
	Fingerprint  string          `json:"fingerprint"`
	Path         string          `json:"path"`
	Host         string          `json:"host"`
	XHTTPMode    string          `json:"xhttp_mode"`
	XHTTPExtra   json.RawMessage `json:"xhttp_extra,omitempty"`
	ALPN         []string        `json:"alpn,omitempty"`
}

func defaultProfile() Profile { return Profile{Fingerprint: "chrome", Path: "/", XHTTPMode: "auto"} }

type Poll struct {
	AgentID      string  `json:"agent_id"`
	Version      string  `json:"version"`
	ControlOK    bool    `json:"control_ok"`
	ControlError *string `json:"control_error"`
}
type Result struct {
	Routes    *RouteResults `json:"routes,omitempty"`
	JobID     string        `json:"job_id"`
	OK        bool          `json:"ok"`
	LatencyMS *float64      `json:"latency_ms"`
	Error     *string       `json:"error"`
}
type Results struct {
	AgentID string   `json:"agent_id"`
	Results []Result `json:"results"`
}

var hostnamePattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var agentPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var realityPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func textLength(s string, min, max int) bool {
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max
}
func oneOf(value string, allowed ...string) bool {
	for _, s := range allowed {
		if value == s {
			return true
		}
	}
	return false
}
func validHost(s string) bool {
	if !textLength(s, 1, 253) {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
func validatePool(p *PoolInput) {
	p.Hostname = strings.ToLower(strings.TrimRight(p.Hostname, "."))
	if !textLength(p.Name, 1, 100) {
		invalid("name")
	}
	if !textLength(p.Hostname, 1, 253) || !hostnamePattern.MatchString(p.Hostname) {
		invalid("hostname")
	}
	if !textLength(p.ZoneID, 1, 100) {
		invalid("zone_id")
	}
	if p.TTL < 60 || p.TTL > 86400 {
		invalid("ttl")
	}
	if p.IntervalSeconds < 10 || p.IntervalSeconds > 86400 {
		invalid("interval_seconds")
	}
	if p.FailureThreshold < 1 || p.FailureThreshold > 100 {
		invalid("failure_threshold")
	}
	if p.RecoveryThreshold < 1 || p.RecoveryThreshold > 100 {
		invalid("recovery_threshold")
	}
}
func canonicalUUID(s string) (string, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "urn:uuid:"), "uuid:")
	s = strings.Trim(s, "{}")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return "", false
	}
	if _, e := hex.DecodeString(s); e != nil {
		return "", false
	}
	s = strings.ToLower(s)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], true
}
func validateProfile(p *Profile) {
	if !validALPN(p.ALPN, p.Security) {
		invalid("alpn")
	}
	if !validXHTTPExtra(p.XHTTPExtra, p.Transport, p.XHTTPMode) {
		invalid("xhttp_extra")
	}
	if p.Congestion != "" && (p.Protocol != "hysteria2" || !oneOf(p.Congestion, "bbr", "reno", "brutal")) {
		invalid("hysteria_congestion")
	}
	if p.Port < 1 || p.Port > 65535 {
		invalid("port")
	}
	if p.Protocol == "hysteria2" {
		validateHysteriaProfile(*p)
		return
	}
	if !oneOf(p.Protocol, "", "vless") {
		invalid("protocol")
	}
	if p.Password != "" || p.Obfs != "" || p.ObfsPassword != "" || p.PinSHA256 != "" {
		invalid("protocol")
	}
	// Keep VLESS profiles readable by agents with strict legacy decoders.
	p.Protocol = ""
	id, ok := canonicalUUID(p.UUID)
	if !ok {
		invalid("uuid")
	}
	p.UUID = id
	if !oneOf(p.Transport, "tcp", "xhttp") {
		invalid("transport")
	}
	if !oneOf(p.Security, "reality", "tls") {
		invalid("security")
	}
	if !validHost(p.ServerName) || p.Host != "" && !validHost(p.Host) {
		invalid("request")
	}
	if !textLength(p.PublicKey, 0, 43) || p.Security == "reality" && !realityPattern.MatchString(p.PublicKey) {
		invalid("request")
	}
	if len(p.ShortID) > 16 || len(p.ShortID)%2 != 0 {
		invalid("request")
	}
	if _, e := hex.DecodeString(p.ShortID); e != nil {
		invalid("request")
	}
	if !oneOf(p.Flow, "", "xtls-rprx-vision") || p.Transport == "xhttp" && p.Flow != "" {
		invalid("request")
	}
	if !oneOf(p.Fingerprint, "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized") {
		invalid("fingerprint")
	}
	if !oneOf(p.XHTTPMode, "auto", "packet-up", "stream-up", "stream-one") {
		invalid("xhttp_mode")
	}
	if !textLength(p.Path, 1, 2048) || !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") {
		invalid("request")
	}
	for _, r := range p.Path + p.Host + p.PublicKey {
		if r < 32 || r == 127 {
			invalid("request")
		}
	}
}

func validateHysteriaProfile(p Profile) {
	if p.Transport != "udp" || p.Security != "tls" || !validHost(p.ServerName) {
		invalid("request")
	}
	if !textLength(p.Password, 0, 2048) || !textLength(p.ObfsPassword, 0, 2048) || !oneOf(p.Obfs, "", "salamander") || (p.Obfs == "salamander") != (p.ObfsPassword != "") {
		invalid("password")
	}
	for _, r := range p.Password + p.ObfsPassword {
		if r < 32 || r == 127 {
			invalid("password")
		}
	}
	if p.PinSHA256 != "" {
		if hash, err := hex.DecodeString(p.PinSHA256); err != nil || len(hash) != 32 {
			invalid("pin_sha256")
		}
	}
	if len(p.ALPN) > 0 && (len(p.ALPN) != 1 || p.ALPN[0] != "h3") {
		invalid("alpn")
	}
	if p.UUID != "" || p.PublicKey != "" || p.ShortID != "" || p.Flow != "" || p.Host != "" || !oneOf(p.Fingerprint, "", "chrome") || !oneOf(p.Path, "", "/") || !oneOf(p.XHTTPMode, "", "auto") {
		invalid("request")
	}
}

var deniedIPv4 = func() []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func publicIPv4(value string) bool {
	ip, e := netip.ParseAddr(value)
	if e != nil || !ip.Is4() {
		return false
	}
	// Match Python 3.12 ipaddress: the protocol-assignment subnet is not
	// globally reachable, except the two globally reachable anycast addresses.
	if value == "192.0.0.9" || value == "192.0.0.10" {
		return true
	}
	for _, prefix := range deniedIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
