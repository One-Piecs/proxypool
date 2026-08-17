package provider

import (
	"reflect"
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
	// 默认不区分：不带参数返回所有节点
	if n := run("", ""); n != 4 {
		t.Errorf("no filter -> %d, want 4 (全部节点)", n)
	}
}

// TestMultiTypeFilter 验证 type=trojan,reality,anytls 多类型逗号匹配：
// 协议类型精确匹配 + reality/tls 特性匹配
func TestMultiTypeFilter(t *testing.T) {
	vlessReality := &proxy.Vless{
		Base: proxy.Base{Name: "r1", Server: "r.com", Port: 443, Type: "vless"},
		UUID: "u", Flow: "xtls-rprx-vision", TLS: true,
		RealityPublicKey: "pk", RealityShortID: "sid", ServerName: "sni",
	}
	trojan := &proxy.Trojan{Base: proxy.Base{Name: "t1", Server: "t.com", Port: 443, Type: "trojan"}, Password: "p"}
	anytls := &proxy.AnyTLS{Base: proxy.Base{Name: "a1", Server: "a.com", Port: 8443, Type: "anytls"}, Password: "p"}
	ss := &proxy.Shadowsocks{Base: proxy.Base{Name: "s1", Server: "d.com", Port: 8388, Type: "ss"}, Password: "p", Cipher: "aes-256-gcm"}

	run := func(types string) []string {
		cp := make(proxy.ProxyList, 4)
		copy(cp, []proxy.Proxy{vlessReality, trojan, anytls, ss})
		clash := Clash{Base: Base{Proxies: &cp, Types: types}}
		out := clash.Provide()
		names := []string{}
		for _, n := range []string{"r1", "t1", "a1", "s1"} {
			if strings.Contains(out, `"name":"`+n+`"`) {
				names = append(names, n)
			}
		}
		return names
	}

	// trojan + reality + anytls: t1 + r1 + a1(不含 ss)
	if got := run("trojan,reality,anytls"); !reflect.DeepEqual(got, []string{"r1", "t1", "a1"}) {
		t.Errorf("type=trojan,reality,anytls -> %v, want [r1 t1 a1]", got)
	}
	// 仅协议类型
	if got := run("trojan,anytls"); !reflect.DeepEqual(got, []string{"t1", "a1"}) {
		t.Errorf("type=trojan,anytls -> %v, want [t1 a1]", got)
	}
	// tls 特性: vless-reality + trojan + anytls 都算 TLS(ss 不算)
	if got := run("tls"); !reflect.DeepEqual(got, []string{"r1", "t1", "a1"}) {
		t.Errorf("type=tls -> %v, want [r1 t1 a1]", got)
	}
	// 无匹配
	if got := run("ssr"); len(got) != 0 {
		t.Errorf("type=ssr -> %v, want empty", got)
	}
	// 空/所有类型: 全部返回
	if got := run(""); !reflect.DeepEqual(got, []string{"r1", "t1", "a1", "s1"}) {
		t.Errorf("type= -> %v, want all", got)
	}
}
