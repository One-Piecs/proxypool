package provider

import (
	"strings"
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

// TestTLSRealityFilter 验证 tls/reality 过滤条件生效
func TestTLSRealityFilter(t *testing.T) {
	vlessTLS := &proxy.Vless{Base: proxy.Base{Name: "t1", Server: "a.com", Port: 443, Type: "vless"}, UUID: "11111111-1111-1111-1111-111111111111", TLS: true, Network: "tcp"}
	vlessReality := &proxy.Vless{Base: proxy.Base{Name: "r1", Server: "b.com", Port: 443, Type: "vless"}, UUID: "22222222-2222-2222-2222-222222222222", TLS: true, Network: "tcp", RealityPublicKey: "pk"}
	vlessPlain := &proxy.Vless{Base: proxy.Base{Name: "p1", Server: "c.com", Port: 443, Type: "vless"}, UUID: "33333333-3333-3333-3333-333333333333", Network: "tcp"}
	ss := &proxy.Shadowsocks{Base: proxy.Base{Name: "s1", Server: "d.com", Port: 8388, Type: "ss"}, Password: "p", Cipher: "aes-256-gcm"}

	// 通过 Clash.Provide 触发 preFilter，以输出中的节点数验证（Provide 为值接收者，不能检查入参长度）
	run := func(tls, reality string) int {
		cp := make(proxy.ProxyList, 4)
		copy(cp, []proxy.Proxy{vlessTLS, vlessReality, vlessPlain, ss})
		clash := Clash{Base: Base{Proxies: &cp, TLS: tls, Reality: reality}}
		return strings.Count(clash.Provide(), `"name":`)
	}

	if n := run("true", ""); n != 2 {
		t.Errorf("tls=true -> %d, want 2 (tls + reality 节点)", n)
	}
	if n := run("false", ""); n != 2 {
		t.Errorf("tls=false -> %d, want 2 (plain vless + ss)", n)
	}
	if n := run("", "true"); n != 1 {
		t.Errorf("reality=true -> %d, want 1 (仅 reality 节点)", n)
	}
	if n := run("", "false"); n != 3 {
		t.Errorf("reality=false -> %d, want 3 (非 reality 节点)", n)
	}
	if n := run("true", "true"); n != 1 {
		t.Errorf("tls=true&reality=true -> %d, want 1 (仅 reality 节点)", n)
	}
}
