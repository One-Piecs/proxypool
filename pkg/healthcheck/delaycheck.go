package healthcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gammazero/workerpool"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/utils"

	"github.com/One-Piecs/proxypool/pkg/proxy"
)

var (
	defaultURLTestTimeout = time.Second * 5
	testURLs              = []string{
		"http://www.msftconnecttest.com/connecttest.txt",
		"http://captive.apple.com/hotspot-detect.html",
		"http://www.google.com/generate_204",
		"http://bing.com/generate_204",
		"http://play.googleapis.com/generate_204",
		"http://clients3.google.com/generate_204",
		"http://www.msftncsi.com/ncsi.txt",
		"http://edge-http.microsoft.com/captiveportal/generate_204",
		"http://www.apple.com/library/test/success.html",
		"http://apple-cloudkit.com/generate_204",
	}
	maxRetries = 2
)

// CleanBadProxiesWithWorkpool 对代理做延迟检测，返回可用（延迟非 0）的代理列表。
func CleanBadProxiesWithWorkpool(proxies []proxy.Proxy) (cproxies []proxy.Proxy) {
	pool := workerpool.New(500)
	c := make(chan *Stat)
	defer close(c)

	total := len(proxies)
	progress := newProgress(total)

	for _, p := range proxies {
		pp := p
		pool.Submit(func() {
			defer progress.inc()
			delay, err := testDelay(pp)
			if err == nil && delay != 0 {
				statsLock.Lock()
				var ps *Stat
				if ps, ok := ProxyStats.Find(pp); ok {
					ps.UpdatePSDelay(delay)
				} else {
					ps = &Stat{
						Id:    pp.Identifier(),
						Delay: delay,
					}
					ProxyStats = append(ProxyStats, *ps)
				}
				statsLock.Unlock()
				c <- ps
			}
		})
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		pool.StopWait()
		close(done)
	}()

	okMap := make(map[string]struct{})
	for { // Note: 无限循环，直到能读取到done
		select {
		case ps := <-c:
			if ps.Delay > 0 {
				okMap[ps.Id] = struct{}{}
			}
		case <-done:
			cproxies = make(proxy.ProxyList, 0, total)
			// check usable proxy
			for i := range proxies {
				if _, ok := okMap[proxies[i].Identifier()]; ok {
					cproxies = append(cproxies, proxies[i])
				}
			}
			return
		}
	}
}

// Return 0 for error
func testDelay(p proxy.Proxy) (delay uint16, err error) {
	pmap := make(map[string]interface{})
	err = json.Unmarshal([]byte(p.String()), &pmap)
	if err != nil {
		return 0, fmt.Errorf("解析代理配置失败: %w", err)
	}

	pmap["port"] = int(pmap["port"].(float64))
	if p.TypeName() == "vmess" {
		pmap["alterId"] = int(pmap["alterId"].(float64))
		if network, ok := pmap["network"]; ok && network.(string) == "h2" {
			return 0, fmt.Errorf("不支持h2协议的延迟测试")
		}
	}

	clashProxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return 0, fmt.Errorf("创建代理实例失败: %w", err)
	}

	expectedStatus, _ := utils.NewUnsignedRanges[uint16]("204")
	var lastErr error
	var successCount int
	var totalDelay uint16

	// 智能重试机制
	for retry := 0; retry <= maxRetries; retry++ {
		// 自适应超时：首次使用默认超时，之后递增50%
		timeout := defaultURLTestTimeout
		if retry > 0 {
			timeout = time.Duration(float64(timeout) * 1.5)
		}

		// 遍历所有测试URL
		for _, testURL := range testURLs {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			currentDelay, err := clashProxy.URLTest(ctx, testURL, expectedStatus)
			cancel()

			// 如果成功获取延迟
			if err == nil && currentDelay > 0 {
				successCount++
				totalDelay += currentDelay

				// 如果已经有足够的成功测试，返回平均延迟
				if successCount >= 2 {
					return totalDelay / uint16(successCount), nil
				}
				continue
			}

			// 记录错误
			lastErr = err
		}

		// 如果有部分成功的测试，返回平均延迟
		if successCount > 0 {
			return totalDelay / uint16(successCount), nil
		}

		// 如果是最后一次重试，返回错误
		if retry == maxRetries {
			return 0, fmt.Errorf("所有重试均失败: %v", lastErr)
		}
	}

	return 0, fmt.Errorf("测试失败: %v", lastErr)
}
