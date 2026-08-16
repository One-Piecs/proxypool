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

// ErrorNotAnyTLSLink 非法的 anytls 链接
var ErrorNotAnyTLSLink = errors.New("not a correct anytls link")

// AnyTLS 是 anytls 协议代理（基于 TLS，2025 新协议，mihomo 原生支持）
type AnyTLS struct {
	Base
	Password       string   `yaml:"password" json:"password"`
	ALPN           []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	UDP            bool     `yaml:"udp,omitempty" json:"udp,omitempty"`
}

func (a AnyTLS) Identifier() string {
	return net.JoinHostPort(a.Server, strconv.Itoa(a.Port)) + a.Password
}

func (a AnyTLS) String() string {
	data, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return string(data)
}

func (a AnyTLS) Clone() Proxy {
	return &a
}

// ToClash 输出 clash 配置
func (a AnyTLS) ToClash() string {
	m := map[string]interface{}{
		"name": a.Name, "type": "anytls", "server": a.Server, "port": a.Port,
		"password": a.Password, "udp": a.UDP,
	}
	if a.SNI != "" {
		m["sni"] = a.SNI
	}
	if len(a.ALPN) > 0 {
		m["alpn"] = a.ALPN
	}
	if a.SkipCertVerify {
		m["skip-cert-verify"] = true
	}
	data, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return "  - " + string(data)
}

// ToSurge 不支持 anytls（Surge 客户端无此协议）
func (a AnyTLS) ToSurge() string {
	return ""
}

// ToLoon 输出 loon 配置（anytls 在 Loon 3.3+ 支持）
func (a AnyTLS) ToLoon() string {
	text := fmt.Sprintf(`%s = anytls, %s, %d, "%s", over-tls=true`,
		a.Name, a.Server, a.Port, a.Password)
	sni := a.SNI
	if sni == "" {
		sni = a.Server
	}
	text += ", tls-name=" + sni
	if a.SkipCertVerify {
		text += ", skip-cert-verify=true"
	}
	if a.UDP {
		text += ", udp=true"
	}
	return text
}

// ToQuanX 输出 quanx 配置（官方格式）
func (a AnyTLS) ToQuanX() string {
	text := fmt.Sprintf(`anytls=%s:%d, password=%s, over-tls=true, udp-relay=true, tag=%s`,
		a.Server, a.Port, a.Password, a.Name)
	host := a.SNI
	if host == "" {
		host = a.Server
	}
	text += ", tls-host=" + host
	if a.SkipCertVerify {
		text += ", tls-verification=false"
	}
	return text
}

// Link 生成 anytls:// 链接
func (a AnyTLS) Link() (link string) {
	host := a.Server
	if isIPv6(host) {
		host = "[" + host + "]"
	}
	u := url.URL{
		Scheme:   "anytls",
		User:     url.User(a.Password),
		Host:     net.JoinHostPort(host, strconv.Itoa(a.Port)),
		Fragment: a.Name,
	}
	q := u.Query()
	if a.SNI != "" {
		q.Set("sni", a.SNI)
	}
	if len(a.ALPN) > 0 {
		q.Set("alpn", strings.Join(a.ALPN, ","))
	}
	if a.SkipCertVerify {
		q.Set("allowInsecure", "1")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ParseAnyTLSLink 解析 anytls://password@host:port?sni=...&alpn=...#name
func ParseAnyTLSLink(link string) (*AnyTLS, error) {
	if !strings.HasPrefix(link, "anytls://") {
		return nil, ErrorNotAnyTLSLink
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotAnyTLSLink
	}
	server := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if server == "" || port == 0 || password == "" {
		return nil, ErrorNotAnyTLSLink
	}

	q := u.Query()
	a := &AnyTLS{
		Base:     Base{Name: u.Fragment, Server: server, Port: port, Type: "anytls"},
		Password: password,
		SNI:      q.Get("sni"),
	}
	if alpn := q.Get("alpn"); alpn != "" {
		a.ALPN = strings.Split(alpn, ",")
	}
	if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
		a.SkipCertVerify = true
	}
	return a, nil
}

var anytlsPlainRe = regexp.MustCompile(`anytls://[^\s]+@[^\s]+:\d+[^\s]*`)

// GrepAnyTLSLinkFromString 从文本中抓取 anytls 链接
func GrepAnyTLSLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "anytls://")
	for _, text := range texts {
		results = append(results, anytlsPlainRe.FindAllString("anytls://"+text, -1)...)
	}
	return results
}
