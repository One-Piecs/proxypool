package provider

import (
	"strings"

	"github.com/One-Piecs/proxypool/pkg/proxy"

	"github.com/One-Piecs/proxypool/pkg/tool"
)

// QuanX 提供 Quantumult X 格式的代理输出
type QuanX struct {
	Base
}

// Provide 生成 QuanX 支持格式的节点列表
func (q QuanX) Provide() string {
	q.preFilter()

	var resultBuilder strings.Builder
	for _, p := range *q.Proxies {
		if checkQuanXSupport(p) {
			resultBuilder.WriteString(p.ToQuanX() + "\n")
		}
	}
	return resultBuilder.String()
}

func checkQuanXSupport(p proxy.Proxy) bool {
	switch p := p.(type) {
	case *proxy.ShadowsocksR:
		ssr := p
		if tool.CheckInList(proxy.SSRCipherList, ssr.Cipher) && tool.CheckInList(ssrProtocolList, ssr.Protocol) && tool.CheckInList(ssrObfsList, ssr.Obfs) {
			return true
		}
	case *proxy.Vmess:
		return true
	case *proxy.Shadowsocks:
		ss := p
		if tool.CheckInList(proxy.SSCipherList, ss.Cipher) {
			return true
		}
	case *proxy.Trojan:
		return true
	case *proxy.Vless:
		return true
	default:
		return false
	}
	return false
}
