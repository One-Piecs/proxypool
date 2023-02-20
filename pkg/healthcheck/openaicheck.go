package healthcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/Dreamacro/clash/adapter"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	"github.com/gammazero/workerpool"
)

func CheckWorkpool(proxies proxy.ProxyList) {
	pool := workerpool.New(500)

	log.Infoln("ChatGPT Test ON")
	doneCount := 0

	for _, p := range proxies {
		pp := p
		pool.Submit(func() {
			ok, err := testOpenai(pp)
			if err == nil && ok {
				if ps, ok := ProxyStats.Find(pp); ok {
					ps.ChatGPT = true
				}
			}
			doneCount++
			progress := float64(doneCount) * 100 / float64(len(proxies))
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
		return false, err
	}

	pmap["port"] = int(pmap["port"].(float64))
	if p.TypeName() == "vmess" {
		pmap["alterId"] = int(pmap["alterId"].(float64))
		if network, ok := pmap["network"]; ok && network.(string) == "h2" {
			return false, nil // todo 暂无方法测试h2的延迟，clash对于h2的connection会阻塞
		}
	}

	clashProxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return false, err
	}

	b, err := HTTPGetBodyViaProxyWithTime(clashProxy, "https://chat.openai.com/", time.Second*10)
	if err != nil {
		return false, err
	}

	if strings.Contains(string(b), "text/plain") {
		return false, errors.New("Your IP is BLOCKED!")
	}

	trace, err := HTTPGetBodyViaProxyWithTime(clashProxy, "https://chat.openai.com/cdn-cgi/trace", time.Second*10)
	if err != nil {
		return false, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(trace))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "loc=") {
			if slices.Contains(SupportCountry, scanner.Text()[4:]) {
				return true, nil
			}
		}
	}

	return false, errors.New("Not support OpenAI at this time")
}
