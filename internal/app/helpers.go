package app

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/go-resty/resty/v2"
	"github.com/jinzhu/copier"
)

// bestNodeClient 共享的 resty 客户端：跳过 TLS 校验、统一 UA 与超时。
// resty.Client 并发安全，原先每个请求都 resty.New() 创建新客户端。
// 超时取 60s：订阅源常为海外慢站，原实现无超时（慢源会无限挂起），
// 30s 对部分源偏紧，60s 在防挂死与容错间取得平衡。
var bestNodeClient = resty.New().
	SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
	SetTimeout(60*time.Second).
	SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

// generatorKey 返回 Format 对应的 URL 生成器键名（未匹配返回空串）。
// 原先 5 个 SubNice* 函数各自内联一份 15 分支 switch，收敛为单一定义。
func generatorKey(f Format) string {
	switch {
	case f.Surge && f.Vmess:
		return "surge_vmess"
	case f.Surge && f.Trojan:
		return "surge_trojan"
	case f.Clash && f.Vmess:
		return "clash_vmess"
	case f.Clash && f.Trojan:
		return "clash_trojan"
	case f.Clash && f.Vless:
		return "clash_vless"
	case f.QuanX && f.Vmess:
		return "quanx_vmess"
	case f.QuanX && f.Trojan:
		return "quanx_trojan"
	case f.QuanX && f.Vless:
		return "quanx_vless"
	case f.Loon && f.Vmess:
		return "loon_vmess"
	case f.Loon && f.Trojan:
		return "loon_trojan"
	case f.Loon && f.Vless:
		return "loon_vless"
	case f.V2rayn && f.Vmess:
		return "v2rayn_vmess"
	case f.V2rayn && f.Trojan:
		return "v2rayn_trojan"
	case f.V2rayn && f.Vless:
		return "v2rayn_vless"
	}
	return ""
}

// 6 参数生成器：服务器地址直接取 ip
var urlGeneratorMap = map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, int){
	"surge_vmess":   genSurgeVmessUrl,
	"surge_trojan":  genSurgeTrojanUrl,
	"clash_vmess":   genClashVmessUrl,
	"clash_trojan":  genClashTrojanUrl,
	"clash_vless":   genClashVlessUrl,
	"quanx_vmess":   genQuanXVmessUrl,
	"quanx_trojan":  genQuanXTrojanUrl,
	"quanx_vless":   genQuanXVlessUrl,
	"loon_vmess":    genLoonVmessUrl,
	"loon_trojan":   genLoonTrojanUrl,
	"loon_vless":    genLoonVlessUrl,
	"v2rayn_vmess":  genV2raynVmessUrl,
	"v2rayn_trojan": genV2raynTrojanUrl,
	"v2rayn_vless":  genV2raynVlessUrl,
}

// 7 参数生成器：额外携带 nodeName（用于 SubNiceCfProxySub）
var urlGeneratorMap2 = map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, string, int){
	"surge_vmess":   genSurgeVmessUrl2,
	"surge_trojan":  genSurgeTrojanUrl2,
	"clash_vmess":   genClashVmessUrl2,
	"clash_trojan":  genClashTrojanUrl2,
	"clash_vless":   genClashVlessUrl2,
	"quanx_vmess":   genQuanXVmessUrl2,
	"quanx_trojan":  genQuanXTrojanUrl2,
	"quanx_vless":   genQuanXVlessUrl2,
	"loon_vmess":    genLoonVmessUrl2,
	"loon_trojan":   genLoonTrojanUrl2,
	"loon_vless":    genLoonVlessUrl2,
	"v2rayn_vmess":  genV2raynVmessUrl2,
	"v2rayn_trojan": genV2raynTrojanUrl2,
	"v2rayn_vless":  genV2raynVlessUrl2,
}

// trackDuration 记录函数执行耗时（配合 defer 使用）
func trackDuration(name string) func() {
	start := time.Now()
	return func() {
		log.Infoln("%s completed in %v", name, time.Since(start))
	}
}

// loadProxyInfo 复制代理配置信息（避免并发修改全局配置）
func loadProxyInfo() (config.ProxyInfo, error) {
	var proxyInfo config.ProxyInfo
	if err := copier.Copy(&proxyInfo, &config.Config().ProxyInfo); err != nil {
		log.Errorln("Failed to copy proxy info: %v", err)
		return nil, fmt.Errorf("proxy info copy error: %w", err)
	}
	return proxyInfo, nil
}

// writeOutputHeader 写入订阅头部（V2rayn 不需要头部）
func writeOutputHeader(buf *strings.Builder, f Format, ts string) {
	if !f.V2rayn {
		buf.WriteString("# " + ts + "\n")
		if f.Clash {
			buf.WriteString("proxies:\n")
		}
	}
}

// finishOutput 处理 V2rayn 的 base64 编码输出
func finishOutput(buf *strings.Builder, f Format) string {
	if f.V2rayn {
		return base64.StdEncoding.EncodeToString([]byte(buf.String()))
	}
	return buf.String()
}

// buildNodeOutput 生成以 ip 为节点地址的订阅输出（SubNiceCfProxyIp/Top20/Provider 共用）。
// 原先三个函数各约 90 行重复逻辑，收敛为单一实现。
func buildNodeOutput(nodes []string, f Format, proxyInfo config.ProxyInfo, distNodeCountry string, isIPV6 bool, port int) string {
	buf := strings.Builder{}
	buf.Grow(len(nodes) * 60)

	writeOutputHeader(&buf, f, time.Now().Format(time.RFC3339))

	country := geoIp.GeoIpDB.FindCountryIsoEmoji(distNodeCountry)
	generator := urlGeneratorMap[generatorKey(f)]

	for _, node := range nodes {
		if generator == nil {
			break
		}
		if isIPV6 && !IsIPv6(node) {
			continue
		}
		generator(&buf, proxyInfo, distNodeCountry, country, node, port)
	}
	return finishOutput(&buf, f)
}

// splitHostPort 拆分 host:port（正确处理 IPv6 方括号）
func splitHostPort(addr string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %s: %w", addr, err)
	}
	return host, p, nil
}

// normalizeAddr 为不含端口的地址补默认端口；已是 host:port 形式则原样返回。
// 相比原先手写 strings.Contains(ip, ":") 判断，正确处理了 IPv6（补方括号）。
func normalizeAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
}
