package proxy

// IsTLS 判断代理是否使用 TLS 加密。
// trojan 协议本身必须走 TLS；vmess/vless 取决于 tls 标志。
func IsTLS(p Proxy) bool {
	switch pp := p.(type) {
	case *Vmess:
		return pp.TLS
	case *Vless:
		return pp.TLS
	case *Trojan:
		return true
	case *AnyTLS:
		return true
	}
	return false
}

// IsReality 判断代理是否使用 Reality 安全层（目前仅 vless 支持）。
func IsReality(p Proxy) bool {
	switch pp := p.(type) {
	case *Vless:
		return pp.RealityPublicKey != ""
	}
	return false
}
