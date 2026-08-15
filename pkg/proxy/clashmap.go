package proxy

import "encoding/json"

// ToClashMap 将代理转换为 mihomo adapter.ParseProxy 所需的配置 map。
// 替代原先 String() → json.Unmarshal 的往返转换：健康检查、测速、中转检测
// 会对每个代理调用一次，消除大批量检测时的 JSON 序列化/反序列化开销。
// 键名与空值省略规则与各结构体的 json tag 完全一致，保证与旧行为等价
// （mihomo 解码器按这些键读取，弱类型转换）。
func ToClashMap(p Proxy) map[string]interface{} {
	switch pp := p.(type) {
	case *Shadowsocks:
		m := clashBaseMap(pp.Base)
		m["password"] = pp.Password
		m["cipher"] = pp.Cipher
		if pp.Plugin != "" {
			m["plugin"] = pp.Plugin
		}
		if len(pp.PluginOpts) > 0 {
			m["plugin-opts"] = pp.PluginOpts
		}
		return m
	case *ShadowsocksR:
		m := clashBaseMap(pp.Base)
		m["password"] = pp.Password
		m["cipher"] = pp.Cipher
		m["protocol"] = pp.Protocol
		m["obfs"] = pp.Obfs
		if pp.ProtocolParam != "" {
			m["protocol-param"] = pp.ProtocolParam
		}
		if pp.ObfsParam != "" {
			m["obfs-param"] = pp.ObfsParam
		}
		if pp.Group != "" {
			m["group"] = pp.Group
		}
		return m
	case *Vmess:
		m := clashBaseMap(pp.Base)
		m["uuid"] = pp.UUID
		m["alterId"] = pp.AlterID
		m["cipher"] = pp.Cipher
		if pp.Network != "" {
			m["network"] = pp.Network
		}
		if pp.WSPath != "" {
			m["ws-path"] = pp.WSPath
		}
		if pp.ServerName != "" {
			m["servername"] = pp.ServerName
		}
		if len(pp.WSHeaders) > 0 {
			m["ws-headers"] = pp.WSHeaders
		}
		if pp.TLS {
			m["tls"] = pp.TLS
		}
		if pp.SkipCertVerify {
			m["skip-cert-verify"] = pp.SkipCertVerify
		}
		// 结构体字段不受 omitempty 影响，旧 JSON 行为总是包含；
		// 且 mihomo 解码器对非 map 的 struct 值会报错，需转成 map
		m["http-opts"] = clashStructToMap(pp.HTTPOpts)
		m["h2-opts"] = clashStructToMap(pp.HTTP2Opts)
		return m
	case *Trojan:
		m := clashBaseMap(pp.Base)
		m["password"] = pp.Password
		if pp.UDP {
			m["udp"] = pp.UDP
		}
		if len(pp.ALPN) > 0 {
			m["alpn"] = pp.ALPN
		}
		if pp.SNI != "" {
			m["sni"] = pp.SNI
		}
		if pp.SkipCertVerify {
			m["skip-cert-verify"] = pp.SkipCertVerify
		}
		return m
	case *Vless:
		m := clashBaseMap(pp.Base)
		m["uuid"] = pp.UUID
		if pp.UDP {
			m["udp"] = pp.UDP
		}
		network := pp.Network
		if network == "" {
			network = "tcp"
		}
		m["network"] = network
		if pp.TLS {
			m["tls"] = pp.TLS
		}
		if pp.ServerName != "" {
			m["servername"] = pp.ServerName
		}
		if pp.Fingerprint != "" {
			m["client-fingerprint"] = pp.Fingerprint
		}
		if pp.Flow != "" {
			m["flow"] = pp.Flow
		}
		if pp.SkipCertVerify {
			m["skip-cert-verify"] = pp.SkipCertVerify
		}
		switch network {
		case "ws":
			wsOpts := map[string]interface{}{"path": "/"}
			if pp.WSPath != "" {
				wsOpts["path"] = pp.WSPath
			}
			host := pp.Host
			if host == "" {
				host = pp.ServerName
			}
			if host != "" {
				wsOpts["headers"] = map[string]string{"Host": host}
			}
			m["ws-opts"] = wsOpts
		case "grpc":
			if pp.GrpcServiceName != "" {
				m["grpc-opts"] = map[string]interface{}{"grpc-service-name": pp.GrpcServiceName}
			}
		}
		// Reality 参数
		if pp.RealityPublicKey != "" {
			realityOpts := map[string]interface{}{"public-key": pp.RealityPublicKey}
			if pp.RealityShortID != "" {
				realityOpts["short-id"] = pp.RealityShortID
			}
			m["reality-opts"] = realityOpts
		}
		return m
	}
	return nil
}

// clashBaseMap 基础字段，country/udp/useable 遵循 omitempty 语义
func clashBaseMap(b Base) map[string]interface{} {
	m := map[string]interface{}{
		"name": b.Name, "server": b.Server, "port": b.Port, "type": b.Type,
	}
	if b.Country != "" {
		m["country"] = b.Country
	}
	if b.UDP {
		m["udp"] = b.UDP
	}
	if b.Useable {
		m["useable"] = b.Useable
	}
	return m
}

// clashStructToMap 将嵌套结构体转为 map（等价于旧路径 JSON 解码得到的形态）
func clashStructToMap(v any) map[string]interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]interface{}{}
	}
	return m
}
