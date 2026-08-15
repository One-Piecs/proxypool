package proxy

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

// TestVlessToClashMapMihomo 验证 vless 的 ToClashMap 输出能被 mihomo adapter 正确解析，
// 这是健康检查/测速能识别 vless 节点的前提。
func TestVlessToClashMapMihomo(t *testing.T) {
	cases := []*Vless{
		{ // ws + tls
			Base:       Base{Name: "v1", Server: "example.com", Port: 443, Type: "vless", UDP: true},
			UUID:       "11111111-1111-1111-1111-111111111111",
			TLS:        true,
			Network:    "ws",
			WSPath:     "/vless",
			Host:       "cdn.example.com",
			ServerName: "cdn.example.com",
		},
		{ // tcp 无 tls
			Base:    Base{Name: "v2", Server: "1.2.3.4", Port: 8080, Type: "vless"},
			UUID:    "22222222-2222-2222-2222-222222222222",
			Network: "tcp",
		},
		{ // reality + flow
			Base:             Base{Name: "v3", Server: "5.6.7.8", Port: 443, Type: "vless"},
			UUID:             "33333333-3333-3333-3333-333333333333",
			TLS:              true,
			Flow:             "xtls-rprx-vision",
			Network:          "tcp",
			ServerName:       "www.apple.com",
			Fingerprint:      "chrome",
			RealityPublicKey: validRealityPubKey(t),
			RealityShortID:   "abcdef12",
		},
		{ // grpc + tls
			Base:            Base{Name: "v4", Server: "grpc.example.com", Port: 443, Type: "vless"},
			UUID:            "44444444-4444-4444-4444-444444444444",
			TLS:             true,
			Network:         "grpc",
			GrpcServiceName: "grpcsvc",
			ServerName:      "grpc.example.com",
		},
	}

	for _, v := range cases {
		m := ToClashMap(v)
		if m == nil {
			t.Fatalf("%s: ToClashMap returned nil", v.Name)
		}
		cp, err := adapter.ParseProxy(m)
		if err != nil {
			t.Fatalf("%s: mihomo ParseProxy failed: %v", v.Name, err)
		}
		if cp.Type() != C.Vless {
			t.Errorf("%s: type = %v, want Vless", v.Name, cp.Type())
		}
	}
}

// validRealityPubKey 生成一个 mihomo 能接受的合法 X25519 公钥（base64）
func validRealityPubKey(t *testing.T) string {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}
