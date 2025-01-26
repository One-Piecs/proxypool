package healthcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	"github.com/gammazero/workerpool"
	"github.com/metacubex/mihomo/adapter"
)

var (
	openAITestURLs = []string{
		"https://chat.openai.com",
		"https://api.openai.com",
		"https://platform.openai.com",
	}
	openAITestTimeout = time.Second * 10
	openAIMaxRetries  = 2
)

func CheckWorkpool(proxies proxy.ProxyList) {
	pool := workerpool.New(500)
	m := sync.Mutex{}

	log.Infoln("ChatGPT Test ON")
	doneCount := 0
	total := len(proxies)

	for _, p := range proxies {
		pp := p
		pool.Submit(func() {
			ok, err := testOpenai(pp)
			if err == nil && ok {
				m.Lock()
				if ps, ok := ProxyStats.Find(pp); ok {
					ps.ChatGPT = true
				}
				m.Unlock()
			}
			doneCount++
			progress := float64(doneCount) * 100 / float64(total)
			fmt.Printf("\r\t[%5.1f%% DONE]", progress)
		})
	}

	pool.StopWait()
	fmt.Println()
}

var SupportCountry = []string{"AL", "DZ", "AD", "AO", "AG", "AR", "AM", "AU", "AT", "AZ", "BS", "BD", "BB", "BE", "BZ", "BJ", "BT", "BA", "BW", "BR", "BG", "BF", "CV", "CA", "CL", "CO", "KM", "CR", "HR", "CY", "DK", "DJ", "DM", "DO", "EC", "SV", "EE", "FJ", "FI", "FR", "GA", "GM", "GE", "DE", "GH", "GR", "GD", "GT", "GN", "GW", "GY", "HT", "HN", "HU", "IS", "IN", "ID", "IQ", "IE", "IL", "IT", "JM", "JP", "JO", "KZ", "KE", "KI", "KW", "KG", "LV", "LB", "LS", "LR", "LI", "LT", "LU", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MR", "MU", "MX", "MC", "MN", "ME", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NZ", "NI", "NE", "NG", "MK", "NO", "OM", "PK", "PW", "PA", "PG", "PE", "PH", "PL", "PT", "QA", "RO", "RW", "KN", "LC", "VC", "WS", "SM", "ST", "SN", "RS", "SC", "SL", "SG", "SK", "SI", "SB", "ZA", "ES", "LK", "SR", "SE", "CH", "TH", "TG", "TO", "TT", "TN", "TR", "TV", "UG", "AE", "US", "UY", "VU", "ZM", "BO", "BN", "CG", "CZ", "VA", "FM", "MD", "PS", "KR", "TW", "TZ", "TL", "GB"}

// Get openai
func testOpenai(p proxy.Proxy) (ok bool, err error) {
	pmap := make(map[string]interface{})
	err = json.Unmarshal([]byte(p.String()), &pmap)
	if err != nil {
		return false, fmt.Errorf("解析代理配置失败: %w", err)
	}

	pmap["port"] = int(pmap["port"].(float64))
	if p.TypeName() == "vmess" {
		pmap["alterId"] = int(pmap["alterId"].(float64))
		if network, ok := pmap["network"]; ok && network.(string) == "h2" {
			return false, errors.New("暂不支持 h2 协议测试")
		}
	}

	clashProxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return false, fmt.Errorf("创建代理客户端失败: %w", err)
	}

	// 智能重试机制
	var lastErr error
	for retry := 0; retry <= openAIMaxRetries; retry++ {
		// 自适应超时：首次使用默认超时，之后递增50%
		timeout := openAITestTimeout
		if retry > 0 {
			timeout = time.Duration(float64(timeout) * 1.5)
		}

		// 遍历所有测试URL
		for _, testURL := range openAITestURLs {
			b, err := HTTPGetBodyViaProxyWithTime(clashProxy, testURL, timeout)
			if err != nil {
				lastErr = err
				continue
			}

			if strings.Contains(string(b), "text/plain") {
				return false, errors.New("IP 已被 OpenAI 封禁")
			}

			// 检查 IP 归属地
			trace, err := HTTPGetBodyViaProxyWithTime(clashProxy, testURL+"/cdn-cgi/trace", timeout)
			if err != nil {
				lastErr = err
				continue
			}

			scanner := bufio.NewScanner(bytes.NewReader(trace))
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), "loc=") {
					if slices.Contains(SupportCountry, scanner.Text()[4:]) {
						return true, nil
					}
					break
				}
			}
		}

		// 如果是最后一次重试，返回错误
		if retry == openAIMaxRetries {
			if lastErr != nil {
				return false, fmt.Errorf("OpenAI 连接测试失败: %w", lastErr)
			}
			return false, errors.New("当前 IP 所在地区不支持访问 OpenAI")
		}

		// 非最后一次重试，等待一段时间后继续
		time.Sleep(time.Second * time.Duration(retry+1))
	}

	return false, lastErr
}
