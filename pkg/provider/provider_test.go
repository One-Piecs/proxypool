package provider

import (
	"testing"

	"github.com/One-Piecs/proxypool/pkg/proxy"
)

// TestVlessSupport 验证所有客户端的支持校验都放行 vless，
// 防止 /loon|/surge|/clash|/quanx/proxies?type=vless 输出为空。
func TestVlessSupport(t *testing.T) {
	v := &proxy.Vless{
		Base: proxy.Base{Name: "v1", Server: "example.com", Port: 443, Type: "vless"},
		UUID: "11111111-1111-1111-1111-111111111111",
	}
	if !checkLoonSupport(v) {
		t.Error("checkLoonSupport should support vless")
	}
	if !checkSurgeSupport(v) {
		t.Error("checkSurgeSupport should support vless")
	}
	if !checkClashSupport(v) {
		t.Error("checkClashSupport should support vless")
	}
	if !checkQuanXSupport(v) {
		t.Error("checkQuanXSupport should support vless")
	}
}
