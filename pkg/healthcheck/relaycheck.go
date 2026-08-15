package healthcheck

import (
	"errors"
	"net"
	"time"

	"github.com/gammazero/workerpool"

	"github.com/metacubex/mihomo/adapter"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/proxy"
)

// RelayCheckWorkpool 检测代理是否经过中转/池化，结果写入 ProxyStats。
func RelayCheckWorkpool(proxies proxy.ProxyList) {
	pool := workerpool.New(500)
	progress := newProgress(len(proxies))

	log.Infoln("Relay Test ON")

	for _, p := range proxies {
		pp := p
		pool.Submit(func() {
			defer progress.inc()
			out, err := testRelay(pp)
			if err == nil && out != "" {
				statsLock.Lock()
				// Relay or pool
				if isRelay(pp.BaseInfo().Server, out) {
					if ps, ok := ProxyStats.Find(pp); ok {
						ps.UpdatePSOutIp(out)
						ps.Relay = true
					} else {
						ps = &Stat{
							Id:    pp.Identifier(),
							Relay: true,
							OutIp: out,
						}
						ProxyStats = append(ProxyStats, *ps)
					}
				} else { // is pool ip
					if ps, ok := ProxyStats.Find(pp); ok {
						ps.UpdatePSOutIp(out)
						ps.Pool = true
					} else {
						ps = &Stat{
							Id:    pp.Identifier(),
							Pool:  true,
							OutIp: out,
						}
						ProxyStats = append(ProxyStats, *ps)
					}
				}
				statsLock.Unlock()
			}
		})
	}

	pool.StopWait()
	log.Infoln("Relay Test Done")
}

// Get outbound relay ip
func testRelay(p proxy.Proxy) (outip string, err error) {
	pmap := proxy.ToClashMap(p)
	if pmap == nil {
		return "", errors.New("unsupported proxy type")
	}

	if p.TypeName() == "vmess" {
		if network, ok := pmap["network"]; ok && network.(string) == "h2" {
			return "", nil // todo 暂无方法测试h2的延迟，clash对于h2的connection会阻塞
		}
	}

	clashProxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return "", err
	}

	b, err := HTTPGetBodyViaProxyWithTime(clashProxy, "http://ipinfo.io/ip", time.Second*10)
	if err != nil {
		return "", err
	}

	if string(b) == p.BaseInfo().Server {
		return "", nil // not relay
	}

	address := net.ParseIP(string(b))
	if address == nil {
		return "", errors.New("error outbound ip format")
	}

	return string(b), nil
}

// Distinguish pool ip from relay. false for pool, true for relay
func isRelay(src string, out string) bool {
	ipv4Mask := net.CIDRMask(24, 32)
	ip1 := net.ParseIP(src)
	ip2 := net.ParseIP(out)

	return string(ip1.Mask(ipv4Mask)) != string(ip2.Mask(ipv4Mask))
}
