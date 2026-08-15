package provider

import (
	"testing"

	"github.com/One-Piecs/proxypool/pkg/proxy"
)

// TestVlessSupport 验证各客户端的支持校验对 vless 的放行/拒绝符合预期：
// clash/loon/quanx 支持 vless；surge 客户端不支持 vless 协议（官方仅 ss/ssr/vmess/trojan 等），
// 其输出不应包含 vless 节点。
func TestVlessSupport(t *testing.T) {
	v := &proxy.Vless{
		Base: proxy.Base{Name: "v1", Server: "example.com", Port: 443, Type: "vless"},
		UUID: "11111111-1111-1111-1111-111111111111",
	}
	if !checkLoonSupport(v) {
		t.Error("checkLoonSupport should support vless")
	}
	if checkSurgeSupport(v) {
		t.Error("checkSurgeSupport should NOT support vless (Surge 客户端不支持 vless 协议)")
	}
	if !checkClashSupport(v) {
		t.Error("checkClashSupport should support vless")
	}
	if !checkQuanXSupport(v) {
		t.Error("checkQuanXSupport should support vless")
	}
}
