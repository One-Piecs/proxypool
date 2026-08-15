package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestVlessLinkRoundTrip 验证 vless 链接解析与生成的往返一致性
func TestVlessLinkRoundTrip(t *testing.T) {
	links := []string{
		// ws + tls
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&path=%2Fvless&host=cdn.example.com&fp=chrome#VLESS-01",
		// tcp 无 tls
		"vless://22222222-2222-2222-2222-222222222222@1.2.3.4:8080?encryption=none&type=tcp#vless-tcp",
		// flow + reality 风格
		"vless://33333333-3333-3333-3333-333333333333@5.6.7.8:443?encryption=none&security=reality&flow=xtls-rprx-vision&sni=www.apple.com&type=tcp&fp=chrome#vless-reality",
	}

	for _, link := range links {
		v, err := ParseVlessLink(link)
		if err != nil {
			t.Fatalf("ParseVlessLink(%s) failed: %v", link, err)
		}
		if v.TypeName() != "vless" {
			t.Errorf("type = %q, want vless", v.TypeName())
		}
		if v.UUID == "" || v.Server == "" || v.Port == 0 {
			t.Errorf("missing base fields: %+v", v.Base)
		}

		// 重新生成链接,关键字段必须保留
		regen := v.Link()
		v2, err := ParseVlessLink(regen)
		if err != nil {
			t.Fatalf("re-parse generated link %s failed: %v", regen, err)
		}
		if v2.UUID != v.UUID || v2.Server != v.Server || v2.Port != v.Port {
			t.Errorf("round-trip base mismatch: %+v vs %+v", v2.Base, v.Base)
		}
		if v2.TLS != v.TLS || v2.ServerName != v.ServerName {
			t.Errorf("round-trip tls mismatch: tls=%v sn=%q vs tls=%v sn=%q",
				v2.TLS, v2.ServerName, v.TLS, v.ServerName)
		}
		if v2.Flow != v.Flow || v2.Network != v.Network {
			t.Errorf("round-trip flow/network mismatch: flow=%q net=%q vs flow=%q net=%q",
				v2.Flow, v2.Network, v.Flow, v.Network)
		}
	}
}

// TestVlessParseWS 验证 ws 传输的参数解析
func TestVlessParseWS(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=tls&type=ws&path=%2Fabc&host=example.com&sni=example.com#node"
	v, err := ParseVlessLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if v.Network != "ws" {
		t.Errorf("network = %q, want ws", v.Network)
	}
	if v.WSPath != "/abc" {
		t.Errorf("ws-path = %q, want /abc", v.WSPath)
	}
	if v.Host != "example.com" {
		t.Errorf("host = %q, want example.com", v.Host)
	}
	if !v.TLS || v.ServerName != "example.com" {
		t.Errorf("tls = %v, sni = %q", v.TLS, v.ServerName)
	}
}

// TestVlessOutput 验证三端输出包含节点名与协议关键字
func TestVlessOutput(t *testing.T) {
	v := &Vless{
		Base:       Base{Name: "JP-01", Server: "example.com", Port: 443, Type: "vless", UDP: true},
		UUID:       "11111111-1111-1111-1111-111111111111",
		TLS:        true,
		Network:    "ws",
		WSPath:     "/vless",
		Host:       "cdn.example.com",
		ServerName: "cdn.example.com",
	}
	if s := v.ToClash(); !strings.Contains(s, `"type":"vless"`) || !strings.Contains(s, `"name":"JP-01"`) {
		t.Errorf("ToClash missing fields: %s", s)
	}
	if s := v.ToSurge(); !strings.Contains(s, "vless") || !strings.Contains(s, "JP-01") {
		t.Errorf("ToSurge missing fields: %s", s)
	}
	if s := v.ToLoon(); !strings.Contains(s, "vless") || !strings.Contains(s, "JP-01") {
		t.Errorf("ToLoon missing fields: %s", s)
	}
}

// TestGrepVlessLinkFromString 验证链接抓取
func TestGrepVlessLinkFromString(t *testing.T) {
	text := "some text vless://11111111-1111-1111-1111-111111111111@a.com:443?type=ws#n1 trailing vless://22222222-2222-2222-2222-222222222222@b.com:443?type=tcp#n2"
	links := GrepVlessLinkFromString(text)
	if len(links) != 2 {
		t.Fatalf("found %d links, want 2: %v", len(links), links)
	}
}

// TestVlessClashConfigUnmarshal 验证 clash 配置的 ws-opts 能映射到扁平字段
func TestVlessClashConfigUnmarshal(t *testing.T) {
	cfg := `{"name":"node","type":"vless","server":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","network":"ws","tls":true,"ws-opts":{"path":"/abc","headers":{"Host":"cdn.example.com"}}}`
	v := &Vless{}
	if err := json.Unmarshal([]byte(cfg), v); err != nil {
		t.Fatal(err)
	}
	if v.WSPath != "/abc" {
		t.Errorf("WSPath = %q, want /abc", v.WSPath)
	}
	if v.Host != "cdn.example.com" {
		t.Errorf("Host = %q, want cdn.example.com", v.Host)
	}
}

// TestToQuanX 验证各类型 ToQuanX 输出包含节点名与协议关键字
func TestToQuanX(t *testing.T) {
	proxies := []Proxy{
		&Shadowsocks{Base: Base{Name: "ss1", Server: "1.2.3.4", Port: 8388, Type: "ss"}, Password: "p", Cipher: "aes-256-gcm"},
		&Vmess{Base: Base{Name: "vm1", Server: "example.com", Port: 443, Type: "vmess"}, UUID: "11111111-1111-1111-1111-111111111111", Network: "ws", WSPath: "/v", TLS: true, ServerName: "cdn.example.com"},
		&Trojan{Base: Base{Name: "tr1", Server: "t.example.com", Port: 443, Type: "trojan"}, Password: "tp", SNI: "t.example.com"},
		&Vless{Base: Base{Name: "vl1", Server: "v.example.com", Port: 443, Type: "vless"}, UUID: "22222222-2222-2222-2222-222222222222", Network: "ws", WSPath: "/vl", TLS: true, Host: "cdn.example.com"},
	}
	for _, p := range proxies {
		out := p.ToQuanX()
		if !strings.Contains(out, "tag="+p.BaseInfo().Name) {
			t.Errorf("%s: ToQuanX missing tag: %s", p.TypeName(), out)
		}
		switch p.TypeName() {
		case "ss":
			if !strings.HasPrefix(out, "ss = ") {
				t.Errorf("ss prefix: %s", out)
			}
		case "vmess":
			if !strings.HasPrefix(out, "vmess = ") {
				t.Errorf("vmess prefix: %s", out)
			}
		case "trojan":
			if !strings.HasPrefix(out, "trojan = ") {
				t.Errorf("trojan prefix: %s", out)
			}
		case "vless":
			if !strings.HasPrefix(out, "vless = ") {
				t.Errorf("vless prefix: %s", out)
			}
		}
	}
}

// TestVlessReality 验证 reality 节点参数(pbk/sid/spiderX)解析与生成往返
func TestVlessReality(t *testing.T) {
	link := "vless://44444444-4444-4444-4444-444444444444@1.2.3.4:443?encryption=none&security=reality&pbk=REALITY_PUBLIC_KEY_ABC&sid=abcdef12&spiderX=%2F&flow=xtls-rprx-vision&sni=www.apple.com&fp=chrome&type=tcp#reality-node"
	v, err := ParseVlessLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if !v.TLS {
		t.Error("reality node should set TLS")
	}
	if v.RealityPublicKey != "REALITY_PUBLIC_KEY_ABC" {
		t.Errorf("pbk = %q", v.RealityPublicKey)
	}
	if v.RealityShortID != "abcdef12" {
		t.Errorf("sid = %q", v.RealityShortID)
	}
	if v.SpiderX != "/" {
		t.Errorf("spiderX = %q", v.SpiderX)
	}
	if v.ServerName != "www.apple.com" || v.Flow != "xtls-rprx-vision" {
		t.Errorf("sni=%q flow=%q", v.ServerName, v.Flow)
	}

	// 生成往返
	regen := v.Link()
	v2, err := ParseVlessLink(regen)
	if err != nil {
		t.Fatalf("re-parse failed: %v (%s)", err, regen)
	}
	if v2.RealityPublicKey != v.RealityPublicKey || v2.RealityShortID != v.RealityShortID || v2.SpiderX != v.SpiderX {
		t.Errorf("reality round-trip mismatch: %+v vs %+v", v2, v)
	}
}

// TestVlessGrpc 验证 grpc 传输参数(serviceName)解析与生成往返
func TestVlessGrpc(t *testing.T) {
	link := "vless://55555555-5555-5555-5555-555555555555@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=grpcsvc&fp=chrome#grpc-node"
	v, err := ParseVlessLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if v.Network != "grpc" {
		t.Errorf("network = %q, want grpc", v.Network)
	}
	if v.GrpcServiceName != "grpcsvc" {
		t.Errorf("grpc-service-name = %q, want grpcsvc", v.GrpcServiceName)
	}

	regen := v.Link()
	v2, err := ParseVlessLink(regen)
	if err != nil {
		t.Fatalf("re-parse failed: %v (%s)", err, regen)
	}
	if v2.Network != "grpc" || v2.GrpcServiceName != "grpcsvc" {
		t.Errorf("grpc round-trip mismatch: %+v", v2)
	}
}
