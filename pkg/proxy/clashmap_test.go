package proxy

import (
	"encoding/json"
	"testing"
)

// TestToClashMap 验证 ToClashMap 与原先 String()→json.Unmarshal 的转换结果一致。
// 以 JSON 序列化对比：归一化 int/float64、[]string/[]interface{}、struct/map 等类型差异，
// 这正是 mihomo 旧路径实际接收到的形态，保证行为等价。
func TestToClashMap(t *testing.T) {
	proxies := []Proxy{
		&Shadowsocks{
			Base:       Base{Name: "ss1", Server: "1.2.3.4", Port: 8388, Type: "ss", Country: "JP", UDP: true},
			Password:   "pass123",
			Cipher:     "aes-256-gcm",
			Plugin:     "obfs",
			PluginOpts: map[string]interface{}{"mode": "http", "host": "example.com"},
		},
		&ShadowsocksR{
			Base:          Base{Name: "ssr1", Server: "5.6.7.8", Port: 443, Type: "ssr"},
			Password:      "p",
			Cipher:        "chacha20-ietf",
			Protocol:      "auth_aes128_sha1",
			ProtocolParam: "45063:param",
			Obfs:          "tls1.2_ticket_auth",
			ObfsParam:     "example.com",
			Group:         "g",
		},
		&Vmess{
			Base:           Base{Name: "vmess1", Server: "9.9.9.9", Port: 443, Type: "vmess"},
			UUID:           "00000000-0000-0000-0000-000000000000",
			AlterID:        0,
			Cipher:         "auto",
			Network:        "ws",
			WSPath:         "/path",
			ServerName:     "cdn.example.com",
			TLS:            true,
			SkipCertVerify: false,
		},
		&Trojan{
			Base:           Base{Name: "tr1", Server: "8.8.8.8", Port: 443, Type: "trojan"},
			Password:       "trojanpass",
			ALPN:           []string{"h2", "http/1.1"},
			SNI:            "trojan.example.com",
			SkipCertVerify: true,
			UDP:            true,
		},
	}

	for _, p := range proxies {
		// 旧方式：JSON 往返
		var oldMap map[string]interface{}
		if err := json.Unmarshal([]byte(p.String()), &oldMap); err != nil {
			t.Fatalf("%s: json round-trip failed: %v", p.TypeName(), err)
		}
		oldMap["port"] = int(oldMap["port"].(float64))
		if p.TypeName() == "vmess" {
			oldMap["alterId"] = int(oldMap["alterId"].(float64))
		}

		newMap := ToClashMap(p)
		if newMap == nil {
			t.Fatalf("%s: ToClashMap returned nil", p.TypeName())
		}

		oldJSON, _ := json.Marshal(oldMap)
		newJSON, _ := json.Marshal(newMap)
		if string(oldJSON) != string(newJSON) {
			t.Errorf("%s: map mismatch\nold=%s\nnew=%s", p.TypeName(), oldJSON, newJSON)
		}
	}
}
