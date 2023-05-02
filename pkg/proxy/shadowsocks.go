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

	"github.com/One-Piecs/proxypool/pkg/tool"
)

// ErrorNotSSLink is an error type
var ErrorNotSSLink = errors.New("not a correct ss link")

// Shadowsocks is a type of proxy
type Shadowsocks struct {
	Base
	Password   string                 `yaml:"password" json:"password"`
	Cipher     string                 `yaml:"cipher" json:"cipher"`
	Plugin     string                 `yaml:"plugin,omitempty" json:"plugin,omitempty"`
	PluginOpts map[string]interface{} `yaml:"plugin-opts,omitempty" json:"plugin-opts,omitempty"`
}

// Identifier generates an unique identifier of one proxy
func (ss Shadowsocks) Identifier() string {
	return net.JoinHostPort(ss.Server, strconv.Itoa(ss.Port)) + ss.Password
}

func (ss Shadowsocks) String() string {
	data, err := json.Marshal(ss)
	if err != nil {
		return ""
	}
	return string(data)
}

// ToClash converts proxy to clash proxy string
func (ss Shadowsocks) ToClash() string {
	data, err := json.Marshal(ss)
	if err != nil {
		return ""
	}
	return "  - " + string(data)
}

// ToSurge converts proxy to surge proxy string
func (ss Shadowsocks) ToSurge() string {
	// node1 = ss, server, port, encrypt-method=, password=, obfs=, obfs-host=, udp-relay=false
	if ss.Plugin == "obfs" {
		text := fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s, obfs=%s, udp-relay=%v",
			ss.Name, ss.Server, ss.Port, ss.Cipher, ss.Password, ss.PluginOpts["mode"], ss.UDP)
		if ss.PluginOpts["host"].(string) != "" {
			text += ", obfs-host=" + ss.PluginOpts["host"].(string)
		}
		return text
	} else {
		return fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s, udp-relay=%v",
			ss.Name, ss.Server, ss.Port, ss.Cipher, ss.Password, ss.UDP)
	}
}

// ToLoon converts proxy to loon proxy string
func (ss Shadowsocks) ToLoon() string {
	// 节点名称 = 协议，服务器地址，服务器端口，加密协议，密码，
	// Shadowsocks, 1.2.3.4, 443, aes-128-gcm, "password"
	if ss.Plugin == "obfs" {
		// TODO: #ss+simple obfs
		// ssObfs1 = Shadowsocks,example.com,80,aes-128-gcm,"password",obfs-name=http,obfs-host=www.micsoft.com,fast-open=true,udp=true
		// ssObfs2 = Shadowsocks,example.com,443,aes-128-gcm,"password",obfs-name=tls,obfs-host=www.micsoft.com,fast-open=true,udp=true
		return fmt.Sprintf(`%s = Shadowsocks,%s,%d,%s,"%s",%s,%s,udp=%v`,
			ss.Name, ss.Server, ss.Port, ss.Cipher, ss.Password, ss.PluginOpts["mode"], ss.PluginOpts["host"], ss.UDP)
	} else {
		// TODO: #ss
		// ss1 = Shadowsocks,example.com,443,aes-128-gcm,"password",fast-open=false,udp=true
		// ss2 = Shadowsocks,example2.com,443,chacha20,"password",fast-open=true,udp=true
		return fmt.Sprintf(`%s = Shadowsocks,%s,%d,%s,"%s",udp=%v,`,
			ss.Name, ss.Server, ss.Port, ss.Cipher, ss.Password, ss.UDP)
	}
}

func (ss Shadowsocks) Clone() Proxy {
	return &ss
}

// https://shadowsocks.org/en/config/quick-guide.html
// Link converts a ss proxy to string
func (ss Shadowsocks) Link() (link string) {
	payload := fmt.Sprintf("%s:%s@%s:%d", ss.Cipher, ss.Password, ss.Server, ss.Port)
	payload = tool.Base64EncodeString(payload, false)
	return fmt.Sprintf("ss://%s#%s", payload, ss.Name)
}

// ParseSSLink() parses an ss link to ss proxy
func ParseSSLink(link string) (*Shadowsocks, error) {
	if !strings.HasPrefix(link, "ss://") {
		return nil, ErrorNotSSRLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotSSLink
	}

	cipher := ""
	password := ""
	if uri.User.String() == "" {
		// base64的情况
		infos, err := tool.Base64DecodeString(uri.Hostname())
		if err != nil {
			return nil, err
		}
		uri, err = url.Parse("ss://" + infos)
		if err != nil {
			return nil, err
		}
		cipher = uri.User.Username()
		password, _ = uri.User.Password()
	} else {
		cipherInfoString, err := tool.Base64DecodeString(uri.User.Username())
		if err != nil {
			return nil, ErrorPasswordParseFail
		}
		cipherInfo := strings.SplitN(cipherInfoString, ":", 2)
		if len(cipherInfo) < 2 {
			return nil, ErrorPasswordParseFail
		}
		cipher = strings.ToLower(cipherInfo[0])
		password = cipherInfo[1]
	}
	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	pluginString := moreInfos.Get("plugin")
	plugin := ""
	pluginOpts := make(map[string]interface{})
	if strings.Contains(pluginString, ";") {
		pluginInfos, err := url.ParseQuery(pluginString)
		if err == nil {
			if strings.Contains(pluginString, "obfs") {
				plugin = "obfs"
				pluginOpts["mode"] = pluginInfos.Get("obfs")
				pluginOpts["host"] = pluginInfos.Get("obfs-host")
			} else if strings.Contains(pluginString, "v2ray") {
				plugin = "v2ray-plugin"
				pluginOpts["mode"] = pluginInfos.Get("mode")
				pluginOpts["host"] = pluginInfos.Get("host")
				pluginOpts["tls"] = strings.Contains(pluginString, "tls")
			}
		}
	}
	if port == 0 || cipher == "" {
		return nil, ErrorNotSSLink
	}

	return &Shadowsocks{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "ss",
		},
		Password:   password,
		Cipher:     cipher,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
	}, nil
}

var ssPlainRe = regexp.MustCompile("ss://([A-Za-z0-9+/_&?=@:%.-])+")

// GrepSSLinkFromString() remove web fuzz characters before a ss link
func GrepSSLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "ss://")
	for _, text := range texts {
		results = append(results, ssPlainRe.FindAllString("ss://"+text, -1)...)
	}
	return results
}
