package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ErrorNotVlessLink 非法的 vless 链接
var ErrorNotVlessLink = errors.New("not a correct vless link")

// Vless 是 vless 协议代理
//
// 支持形式：
//   - 传输：tcp / ws / grpc
//   - 安全：tls / reality（pbk + sid）
//   - flow：xtls-rprx-vision 等
//   - 输出：Clash / Loon / QuanX / vless:// 链接
//   - 健康检查/测速（mihomo 解析）
type Vless struct {
	Base
	UUID           string `yaml:"uuid" json:"uuid"`
	Encryption     string `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	Flow           string `yaml:"flow,omitempty" json:"flow,omitempty"`
	Network        string `yaml:"network,omitempty" json:"network,omitempty"`
	WSPath         string `yaml:"ws-path,omitempty" json:"ws-path,omitempty"`
	Host           string `yaml:"host,omitempty" json:"host,omitempty"`
	ServerName     string `yaml:"servername,omitempty" json:"servername,omitempty"`
	Fingerprint    string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	TLS            bool   `yaml:"tls,omitempty" json:"tls,omitempty"`
	SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	UDP            bool   `yaml:"udp,omitempty" json:"udp,omitempty"`
	// Reality 参数（security=reality）
	RealityPublicKey string `yaml:"reality-public-key,omitempty" json:"reality-public-key,omitempty"`
	RealityShortID   string `yaml:"reality-short-id,omitempty" json:"reality-short-id,omitempty"`
	SpiderX          string `yaml:"spiderx,omitempty" json:"spiderx,omitempty"` // 客户端本地行为，仅用于链接往返
	// grpc 传输参数（type=grpc）
	GrpcServiceName string `yaml:"grpc-service-name,omitempty" json:"grpc-service-name,omitempty"`
}

func (v Vless) Identifier() string {
	return net.JoinHostPort(v.Server, strconv.Itoa(v.Port)) + v.UUID
}

func (v Vless) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// ToQuanX converts proxy to quanx string
func (v Vless) ToQuanX() string {
	host := v.Host
	if host == "" {
		host = v.ServerName
	}
	text := fmt.Sprintf(`vless=%s:%d, method=none, password=%s, udp-relay=true, tag=%s`,
		v.Server, v.Port, v.UUID, v.Name)
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	// obfs 仅按传输设置一次（官方示例：ws→wss、tcp+tls→over-tls），避免重复
	switch network {
	case "ws":
		path := v.WSPath
		if path == "" {
			path = "/"
		}
		text += fmt.Sprintf(", obfs=wss, obfs-uri=%s, obfs-host=%s", path, host)
	case "grpc":
		text += ", obfs=none"
		if v.GrpcServiceName != "" {
			text += ", grpc-service-name=" + v.GrpcServiceName
		}
	default: // tcp
		if v.TLS {
			obfsHost := v.ServerName
			if obfsHost == "" {
				obfsHost = v.Server
			}
			text += fmt.Sprintf(", obfs=over-tls, obfs-host=%s", obfsHost)
			if v.SkipCertVerify {
				text += ", tls-verification=false"
			}
		}
	}
	// Reality 参数独立于传输（官方示例 ws 也带 reality-base64-pubkey）
	if v.RealityPublicKey != "" {
		text += ", reality-base64-pubkey=" + v.RealityPublicKey
		if v.RealityShortID != "" {
			text += ", reality-hex-shortid=" + v.RealityShortID
		}
	}
	if v.Flow != "" {
		text += ", vless-flow=" + v.Flow
	}
	return text
}

func (v Vless) Clone() Proxy {
	return &v
}

// UnmarshalJSON 兼容 clash 配置的 ws-opts 嵌套结构：
// clash 配置里 ws 传输用 ws-opts:{path, headers:{Host}}，而结构体字段是扁平的
func (v *Vless) UnmarshalJSON(data []byte) error {
	type alias Vless
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*v = Vless(a)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if wsOpts, ok := raw["ws-opts"]; ok {
		var opts struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		}
		if err := json.Unmarshal(wsOpts, &opts); err == nil {
			if v.WSPath == "" {
				v.WSPath = opts.Path
			}
			if v.Host == "" && opts.Headers != nil {
				v.Host = opts.Headers["Host"]
			}
		}
	}
	return nil
}

// ToClash 输出 clash 配置（vless 使用 ws-opts 嵌套结构）
func (v Vless) ToClash() string {
	m := map[string]interface{}{
		"name": v.Name, "type": "vless", "server": v.Server, "port": v.Port,
		"uuid": v.UUID, "udp": v.UDP,
	}
	if v.TLS {
		m["tls"] = true
	}
	if v.ServerName != "" {
		m["servername"] = v.ServerName
	}
	if v.Fingerprint != "" {
		m["client-fingerprint"] = v.Fingerprint
	}
	if v.Flow != "" {
		m["flow"] = v.Flow
	}
	if v.SkipCertVerify {
		m["skip-cert-verify"] = true
	}

	network := v.Network
	if network == "" {
		network = "tcp"
	}
	m["network"] = network
	switch network {
	case "ws":
		wsOpts := map[string]interface{}{"path": "/"}
		if v.WSPath != "" {
			wsOpts["path"] = v.WSPath
		}
		host := v.Host
		if host == "" {
			host = v.ServerName
		}
		if host != "" {
			wsOpts["headers"] = map[string]string{"Host": host}
		}
		m["ws-opts"] = wsOpts
	case "grpc":
		if v.GrpcServiceName != "" {
			m["grpc-opts"] = map[string]interface{}{"grpc-service-name": v.GrpcServiceName}
		}
	}

	// Reality 参数
	if v.RealityPublicKey != "" {
		realityOpts := map[string]interface{}{"public-key": v.RealityPublicKey}
		if v.RealityShortID != "" {
			realityOpts["short-id"] = v.RealityShortID
		}
		m["reality-opts"] = realityOpts
	}

	data, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return "  - " + string(data)
}

// ToSurge 输出 surge 配置
func (v Vless) ToSurge() string {
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	text := fmt.Sprintf("%s = vless, %s, %d, username=%s, tls=%t, skip-cert-verify=%v",
		v.Name, v.Server, v.Port, v.UUID, v.TLS, v.SkipCertVerify)
	if v.TLS && v.ServerName != "" {
		text += fmt.Sprintf(", sni=%s", v.ServerName)
	}
	if network == "ws" {
		path := v.WSPath
		if path == "" {
			path = "/"
		}
		text += fmt.Sprintf(", ws=true, ws-path=%s", path)
		if v.Host != "" {
			text += fmt.Sprintf(`, ws-headers="Host:%s"`, v.Host)
		}
	}
	return text
}

// ToLoon 输出 loon 配置（官方格式：name = VLESS, server, port, "uuid", transport=..., flow=..., public-key=..., over-tls=true, sni=...）
func (v Vless) ToLoon() string {
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	text := fmt.Sprintf(`%s = VLESS, %s, %d, "%s", transport=%s`,
		v.Name, v.Server, v.Port, v.UUID, network)
	if network == "ws" {
		path := v.WSPath
		if path == "" {
			path = "/"
		}
		text += fmt.Sprintf(", ws-path=%s", path)
		if v.Host != "" {
			text += fmt.Sprintf(`, ws-headers="Host:%s"`, v.Host)
		}
	}
	if network == "grpc" && v.GrpcServiceName != "" {
		text += ", grpc-service-name=" + v.GrpcServiceName
	}
	if v.Flow != "" {
		text += ", flow=" + v.Flow
	}
	if v.TLS {
		text += ", over-tls=true"
		// 官方 example.conf 用 tls-name（非 sni）
		tlsName := v.ServerName
		if tlsName == "" {
			tlsName = v.Server
		}
		text += ", tls-name=" + tlsName
		if v.SkipCertVerify {
			text += ", skip-cert-verify=true"
		}
	}
	if v.RealityPublicKey != "" {
		text += fmt.Sprintf(`, public-key="%s"`, v.RealityPublicKey)
		if v.RealityShortID != "" {
			text += ", short-id=" + v.RealityShortID
		}
	}
	if v.UDP {
		text += ", udp=true"
	}
	return text
}

// Link 生成 vless:// 链接
func (v Vless) Link() (link string) {
	host := v.Server
	if isIPv6(host) {
		host = "[" + host + "]"
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(v.UUID),
		Host:     net.JoinHostPort(host, strconv.Itoa(v.Port)),
		Fragment: v.Name,
	}
	q := u.Query()
	encryption := v.Encryption
	if encryption == "" {
		encryption = "none"
	}
	q.Set("encryption", encryption)
	if v.TLS {
		if v.RealityPublicKey != "" {
			q.Set("security", "reality")
		} else {
			q.Set("security", "tls")
		}
	}
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	q.Set("type", network)
	if v.Flow != "" {
		q.Set("flow", v.Flow)
	}
	if v.WSPath != "" {
		q.Set("path", v.WSPath)
	}
	if v.Host != "" {
		q.Set("host", v.Host)
	}
	if v.ServerName != "" {
		q.Set("sni", v.ServerName)
	}
	if v.Fingerprint != "" {
		q.Set("fp", v.Fingerprint)
	}
	// Reality 参数
	if v.RealityPublicKey != "" {
		q.Set("pbk", v.RealityPublicKey)
	}
	if v.RealityShortID != "" {
		q.Set("sid", v.RealityShortID)
	}
	if v.SpiderX != "" {
		q.Set("spiderX", v.SpiderX)
	}
	// grpc 传输
	if network == "grpc" && v.GrpcServiceName != "" {
		q.Set("serviceName", v.GrpcServiceName)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ParseVlessLink 解析 vless://uuid@host:port?...#name 链接
func ParseVlessLink(link string) (*Vless, error) {
	if !strings.HasPrefix(link, "vless://") {
		return nil, ErrorNotVlessLink
	}

	u, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotVlessLink
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if server == "" || port == 0 || uuid == "" {
		return nil, ErrorNotVlessLink
	}

	q := u.Query()
	v := &Vless{
		Base:       Base{Name: u.Fragment, Server: server, Port: port, Type: "vless"},
		UUID:       uuid,
		Encryption: q.Get("encryption"),
	}
	if v.Encryption == "" {
		v.Encryption = "none"
	}

	// 安全层
	switch q.Get("security") {
	case "tls":
		v.TLS = true
		v.ServerName = q.Get("sni")
		if v.ServerName == "" {
			v.ServerName = q.Get("peer")
		}
		v.Fingerprint = q.Get("fp")
		if v.Fingerprint == "" {
			v.Fingerprint = q.Get("fingerprint")
		}
	case "reality":
		v.TLS = true
		v.ServerName = q.Get("sni")
		if v.ServerName == "" {
			v.ServerName = q.Get("peer")
		}
		v.Fingerprint = q.Get("fp")
		if v.Fingerprint == "" {
			v.Fingerprint = q.Get("fingerprint")
		}
		// Reality 参数：pbk(public-key) / sid(short-id) / spiderX(客户端行为)
		v.RealityPublicKey = q.Get("pbk")
		if v.RealityPublicKey == "" {
			v.RealityPublicKey = q.Get("publicKey")
		}
		v.RealityShortID = q.Get("sid")
		v.SpiderX = q.Get("spiderX")
		if v.SpiderX == "" {
			v.SpiderX = q.Get("spiderx")
		}
	}

	v.Flow = q.Get("flow")

	// 传输层（tcp / ws / grpc）
	v.Network = q.Get("type")
	if v.Network == "" {
		v.Network = "tcp"
	}
	switch v.Network {
	case "ws":
		v.WSPath = q.Get("path")
		v.Host = q.Get("host")
	case "grpc":
		v.GrpcServiceName = q.Get("serviceName")
		if v.GrpcServiceName == "" {
			v.GrpcServiceName = q.Get("service_name")
		}
	}

	if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
		v.SkipCertVerify = true
	}
	return v, nil
}

// vlessPlainRe 要求 uuid@host:port 结构，避免把普通文本（如 vless://some）误抓为链接
var vlessPlainRe = regexp.MustCompile(`vless://[^\s]+@[^\s]+:\d+[^\s]*`)

// isIPv6 判断地址是否为纯 IPv6
func isIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && len(ip) == net.IPv6len && ip.To4() == nil
}

// GrepVlessLinkFromString 从文本中抓取 vless 链接
func GrepVlessLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "vless://")
	for _, text := range texts {
		results = append(results, vlessPlainRe.FindAllString("vless://"+text, -1)...)
	}
	return results
}
