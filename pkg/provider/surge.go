package provider

import (
	"strings"

	"github.com/One-Piecs/proxypool/pkg/proxy"

	"github.com/One-Piecs/proxypool/pkg/tool"
)

// Surge provides functions that make proxies support clash client
type Surge struct {
	Base
}

// Provide of Surge generates proxy list supported by surge
func (s Surge) Provide() string {
	s.preFilter()

	var resultBuilder strings.Builder
	for _, p := range *s.Proxies {
		if checkSurgeSupport(p) {
			if s.UnderlyingProxy == "" {
				resultBuilder.WriteString(p.ToSurge() + "\n")
			} else {
				resultBuilder.WriteString(p.ToSurge())
				resultBuilder.WriteString(", underlying-proxy=")
				resultBuilder.WriteString(s.UnderlyingProxy)
				resultBuilder.WriteString("\n")
			}
		}
	}
	return resultBuilder.String()
}

func checkSurgeSupport(p proxy.Proxy) bool {
	switch p := p.(type) {
	case *proxy.ShadowsocksR:
		return false
	case *proxy.Vmess:
		return true
	case *proxy.Shadowsocks:
		ss := p
		if tool.CheckInList(proxy.SSCipherList, ss.Cipher) {
			return true
		}
	case *proxy.Trojan:
		return true
	default:
		return false
	}
	return false
}
