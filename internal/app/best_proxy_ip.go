package app

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/internal/cache"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/cdn"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/One-Piecs/proxypool/pkg/tool"
	"github.com/gammazero/workerpool"
	"github.com/go-resty/resty/v2"
	"github.com/jinzhu/copier"
)

type Format struct {
	Surge  bool
	Clash  bool
	QuanX  bool
	Loon   bool
	Vmess  bool
	Trojan bool
	Vless  bool
}

func CrawlBestNode() {
	urls := config.Config().SubIpUrl
	if len(urls) == 0 {
		log.Errorln("not found sub url")
		return
	}

	addrMap := sync.Map{}
	bestNodeList := make([]cache.BestNode, 0, 200)

	// 使用workerpool进行并发处理
	wp := workerpool.New(10) // 设置合适的并发数
	wg := &sync.WaitGroup{}
	var err error

	for _, _url := range urls {
		wg.Add(1)
		_url := _url // 创建副本避免闭包问题
		wp.Submit(func() {
			defer wg.Done()
			log.Infoln("Starting: %s", _url)

			// 添加重试机制
			for retries := 0; retries < 3; retries++ {
				resp, err := resty.New().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).R().
					SetQueryParams(map[string]string{
						"host":       "p.laibbb.top",
						"uuid":       "e4e08238-e42c-4288-8f67-e2994ec18c90",
						"pw":         "e4e08238",
						"path":       "/webhook",
						"edgetunnel": "cmliu",
					}).
					SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36").
					Get(_url)
				if err != nil {
					log.Errorln("resty.Get(): %s, retry: %d", err.Error(), retries)
					time.Sleep(time.Second * time.Duration(retries+1))
					continue
				}

				de64, err := base64.StdEncoding.DecodeString(resp.String())
				if err != nil {
					log.Errorln("url[%s] base64.StdEncoding.DecodeString(): %s, retry: %d", _url, err.Error(), retries)
					time.Sleep(time.Second * time.Duration(retries+1))
					continue
				}

				r := bufio.NewScanner(bytes.NewReader(de64))
				for r.Scan() {
					addr, err := ExtractHostPort(r.Text())
					if err != nil {
						log.Errorln("ExtractHostPort: %s", err.Error())
						continue
					}
					// 使用sync.Map进行去重
					addrMap.Store(addr, struct{}{})
				}
				break
			}
			log.Infoln("End: %s", _url)
		})
	}

	wg.Wait()
	wp.Stop()

	// 收集去重后的地址
	addrAll := make([]string, 0, 200)
	addrMap.Range(func(key, value interface{}) bool {
		addrAll = append(addrAll, key.(string))
		return true
	})

	log.Infoln("Total unique addresses: %d", len(addrAll))

	// Pre-process IPs for CDN check
	ipsToCheck := make([]string, 0)
	// Actually we just need a map of IP -> isCDN
	cdnMap := make(map[string]bool)

	for _, addr := range addrAll {
		// Extract IP logic duplicated from below, consider helper or just doing simple parse here
		// For simplicity, let's just do a quick parse or rely on the below loop.
		// But we want to do batch check BEFORE worker pool starts.

		ip := ""
		h := strings.Split(addr, "]:")
		if len(h) == 2 {
			ip = strings.ReplaceAll(h[0], "[", "")
		} else {
			h := strings.Split(addr, ":")
			if len(h) == 2 {
				ip = h[0]
			}
		}

		if ip != "" {
			// Priority 1: Check IP Ranges (Fastest, Local)
			if cdn.GlobalManager.IsCDN(ip) {
				cdnMap[ip] = true
				continue
			}

			// Priority 2: Check Local ASN DB (Fast, Local)
			if geoIp.IsCDN(ip) {
				cdnMap[ip] = true
				continue
			}

			// Priority 3: Online API (Slow, External) -> Add to batch list
			ipsToCheck = append(ipsToCheck, ip)
		}
	}

	if len(ipsToCheck) > 0 {
		log.Infoln("Checking ASN for %d IPs", len(ipsToCheck))
		asnResults, err := cdn.CheckIPsForCDN(ipsToCheck)
		if err != nil {
			log.Errorln("ASN check failed: %v", err)
		} else {
			for ip, isCDN := range asnResults {
				if isCDN {
					cdnMap[ip] = true
				}
			}
		}
	}

	// 使用workerpool处理IP检测
	wp = workerpool.New(20)
	mux := sync.Mutex{}

	for _, addr := range addrAll {
		addr := addr // 创建副本
		wp.Submit(func() {
			ip := ""
			port := 0
			h := strings.Split(addr, "]:")
			if len(h) == 2 {
				// ipv6
				ip = strings.ReplaceAll(h[0], "[", "")
				port, err = strconv.Atoi(h[1])
				if err != nil {
					log.Errorln("strconv.Atoi(h[1]): %s", err.Error())
					return
				}
			} else {
				// ipv4
				h := strings.Split(addr, ":")
				if len(h) != 2 {
					log.Errorln("invalid addr: %s", addr)
					return
				}
				ip = h[0]
				port, err = strconv.Atoi(h[1])
				if err != nil {
					log.Errorln("strconv.Atoi(h[1]): %s", err.Error())
					return
				}
			}

			if ip == "cf.090227.xyz" {
				return
			}

			_, country, err := geoIp.GeoIpDB.Find(ip)
			if err != nil {
				log.Errorln("GeoIP lookup failed for %s: %s", ip, err.Error())
				return
			}

			// Check if IP is CDN (using pre-calculated map)
			isCDN := cdnMap[ip]

			// 创建节点
			node := cache.BestNode{
				Ip:      ip,
				Port:    port,
				Country: country,
				CDN:     isCDN,
			}

			mux.Lock()
			bestNodeList = append(bestNodeList, node)
			mux.Unlock()

			log.Infoln("Node %s:%d added from %s", ip, port, country)
		})
	}

	wp.StopWait()

	// 按照国家名称、IP和端口多级排序
	sort.SliceStable(bestNodeList, func(i, j int) bool {
		// 首先按国家排序
		if bestNodeList[i].Country != bestNodeList[j].Country {
			return bestNodeList[i].Country < bestNodeList[j].Country
		}
		// 国家相同时按IP排序，使用TCP数值比较
		if bestNodeList[i].Ip != bestNodeList[j].Ip {
			// 如果是IPv4地址，使用数值比较
			ip1Parts := strings.Split(bestNodeList[i].Ip, ".")
			ip2Parts := strings.Split(bestNodeList[j].Ip, ".")
			if len(ip1Parts) == 4 && len(ip2Parts) == 4 {
				return ipToUint32(bestNodeList[i].Ip) < ipToUint32(bestNodeList[j].Ip)
			}
			// 对于IPv6或其他格式，保持字符串比较
			return bestNodeList[i].Ip < bestNodeList[j].Ip
		}
		// IP相同时按端口排序
		return bestNodeList[i].Port < bestNodeList[j].Port
	})

	cache.SetBestNodeList("bestNode", bestNodeList)
	cache.SetString("bestNodeLastUpdateTime", time.Now().Format(time.RFC3339))
	log.Infoln("Completed processing %d nodes", len(bestNodeList))
}

func SubNiceProxyIp(format string, distNodeCountry string, proxyCountryIsoCode string, limit int, random bool, isIPV6 bool, cdnFilter string) (s string, err error) {
	// 使用defer来记录函数执行时间
	start := time.Now()
	defer func() {
		log.Infoln("SubNiceProxyIp completed in %v", time.Since(start))
	}()

	// 检查格式并获取配置
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		log.Errorln("Format check failed: %v", err)
		return "", fmt.Errorf("format check error: %w", err)
	}

	// 获取并验证节点列表
	bestNodeList := cache.GetBestNodeList("bestNode")
	if len(bestNodeList) == 0 {
		log.Errorln("No best nodes found")
		return "", errors.New("not found best node list")
	}

	// 预分配buffer以提高性能
	buf := strings.Builder{}
	buf.Grow(len(bestNodeList) * 200) // 预估每个节点约200字节

	// 写入头部信息
	buf.WriteString("# " + cache.GetString("bestNodeLastUpdateTime") + "\n")
	if f.Clash {
		buf.WriteString("proxies:\n")
	}

	// 优化国家代码过滤
	var countryFilter map[string]struct{}
	if proxyCountryIsoCode != "" {
		countryFilter = make(map[string]struct{})
		for _, code := range strings.Split(proxyCountryIsoCode, ",") {
			countryFilter[code] = struct{}{}
		}
	}

	// 复制代理信息以避免并发问题
	var proxyInfo config.ProxyInfo
	if err := copier.Copy(&proxyInfo, &config.Config().ProxyInfo); err != nil {
		log.Errorln("Failed to copy proxy info: %v", err)
		return "", fmt.Errorf("proxy info copy error: %w", err)
	}

	// 使用函数映射来简化URL生成逻辑
	urlGenerators := map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, int){
		"surge_vmess":  genSurgeVmessUrl,
		"surge_trojan": genSurgeTrojanUrl,
		"clash_vmess":  genClashVmessUrl,
		"clash_trojan": genClashTrojanUrl,
		"clash_vless":  genClashVlessUrl,
		"quanx_vmess":  genQuanXVmessUrl,
		"quanx_trojan": genQuanXTrojanUrl,
		"quanx_vless":  genQuanXVlessUrl,
		"loon_vmess":   genLoonVmessUrl,
		"loon_trojan":  genLoonTrojanUrl,
		"loon_vless":   genLoonVlessUrl,
	}

	// 按国家分组节点
	countryNodes := make(map[string][]cache.BestNode)
	for _, node := range bestNodeList {
		// 优化的国家过滤逻辑
		if countryFilter != nil {
			matched := false
			for code := range countryFilter {
				if strings.Contains(node.Country, code) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		countryNodes[node.Country] = append(countryNodes[node.Country], node)
	}

	// 处理每个国家的节点，并应用limit限制
	for _, nodes := range countryNodes {
		// 如果random为true，随机打乱节点顺序
		if random {
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			r.Shuffle(len(nodes), func(i, j int) {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			})
		}

		nodeLimit := len(nodes)
		// 仅当limit大于0时才限制节点数量
		if limit > 0 && limit < nodeLimit {
			nodeLimit = limit
		}

		for i := 0; i < nodeLimit; i++ {
			node := nodes[i]

			// Filter based on cdnFilter
			if cdnFilter == "true" && !node.CDN {
				continue
			}
			if cdnFilter == "false" && node.CDN {
				continue
			}

			// 根据格式类型选择URL生成器
			var generator func(*strings.Builder, config.ProxyInfo, string, string, string, int)
			switch {
			case f.Surge && f.Vmess:
				generator = urlGenerators["surge_vmess"]
			case f.Surge && f.Trojan:
				generator = urlGenerators["surge_trojan"]
			case f.Clash && f.Vmess:
				generator = urlGenerators["clash_vmess"]
			case f.Clash && f.Trojan:
				generator = urlGenerators["clash_trojan"]
			case f.Clash && f.Vless:
				generator = urlGenerators["clash_vless"]
			case f.QuanX && f.Vmess:
				generator = urlGenerators["quanx_vmess"]
			case f.QuanX && f.Trojan:
				generator = urlGenerators["quanx_trojan"]
			case f.QuanX && f.Vless:
				generator = urlGenerators["quanx_vless"]
			case f.Loon && f.Vmess:
				generator = urlGenerators["loon_vmess"]
			case f.Loon && f.Trojan:
				generator = urlGenerators["loon_trojan"]
			case f.Loon && f.Vless:
				generator = urlGenerators["loon_vless"]
			}

			if generator != nil {
				if isIPV6 && !IsIPv6(node.Ip) {
					continue
				}
				generator(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			}
		}
	}

	return buf.String(), nil
}

func SubNiceCfProxyIp(format string, distNodeCountry string, isIPV6 bool) (s string, err error) {
	// 使用defer来记录函数执行时间
	start := time.Now()
	defer func() {
		log.Infoln("SubNiceCfProxyIp completed in %v", time.Since(start))
	}()

	// 检查格式并获取配置
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		log.Errorln("Format check failed: %v", err)
		return "", fmt.Errorf("format check error: %w", err)
	}

	// 获取 cf_best_ip list
	rawBestCfNodeList := config.Config().CfBestIp
	if len(rawBestCfNodeList) == 0 {
		log.Errorln("No best cf nodes found")
		return "", errors.New("not found best cf node list")
	}

	bestCfNodeList := make([]string, 0, len(rawBestCfNodeList))
	for _, node := range rawBestCfNodeList {
		if net.ParseIP(node) != nil {
			bestCfNodeList = append(bestCfNodeList, node)
			continue
		}

		// Try to resolve domain
		ips, err := net.LookupIP(node)
		if err != nil {
			log.Errorln("Failed to resolve domain %s: %v", node, err)
			continue
		}
		for _, ip := range ips {
			bestCfNodeList = append(bestCfNodeList, ip.String())
		}
	}

	if len(bestCfNodeList) == 0 {
		log.Errorln("No valid IPs found after resolution")
		return "", errors.New("no valid IPs found")
	}

	// 预分配buffer以提高性能
	buf := strings.Builder{}
	buf.Grow(len(bestCfNodeList) * 30) // 预估每个节点约30字节

	// 写入头部信息
	buf.WriteString("# " + time.Now().Format(time.RFC3339) + "\n")
	if f.Clash {
		buf.WriteString("proxies:\n")
	}

	// 复制代理信息以避免并发问题
	var proxyInfo config.ProxyInfo
	if err := copier.Copy(&proxyInfo, &config.Config().ProxyInfo); err != nil {
		log.Errorln("Failed to copy proxy info: %v", err)
		return "", fmt.Errorf("proxy info copy error: %w", err)
	}

	// 使用函数映射来简化URL生成逻辑
	urlGenerators := map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, int){
		"surge_vmess":  genSurgeVmessUrl,
		"surge_trojan": genSurgeTrojanUrl,
		"clash_vmess":  genClashVmessUrl,
		"clash_trojan": genClashTrojanUrl,
		"clash_vless":  genClashVlessUrl,
		"quanx_vmess":  genQuanXVmessUrl,
		"quanx_trojan": genQuanXTrojanUrl,
		"quanx_vless":  genQuanXVlessUrl,
		"loon_vmess":   genLoonVmessUrl,
		"loon_trojan":  genLoonTrojanUrl,
		"loon_vless":   genLoonVlessUrl,
	}

	// 处理每个国家的节点，并应用limit限制
	for _, node := range bestCfNodeList {
		// 根据格式类型选择URL生成器
		var generator func(*strings.Builder, config.ProxyInfo, string, string, string, int)
		switch {
		case f.Surge && f.Vmess:
			generator = urlGenerators["surge_vmess"]
		case f.Surge && f.Trojan:
			generator = urlGenerators["surge_trojan"]
		case f.Clash && f.Vmess:
			generator = urlGenerators["clash_vmess"]
		case f.Clash && f.Trojan:
			generator = urlGenerators["clash_trojan"]
		case f.Clash && f.Vless:
			generator = urlGenerators["clash_vless"]
		case f.QuanX && f.Vmess:
			generator = urlGenerators["quanx_vmess"]
		case f.QuanX && f.Trojan:
			generator = urlGenerators["quanx_trojan"]
		case f.QuanX && f.Vless:
			generator = urlGenerators["quanx_vless"]
		case f.Loon && f.Vmess:
			generator = urlGenerators["loon_vmess"]
		case f.Loon && f.Trojan:
			generator = urlGenerators["loon_trojan"]
		case f.Loon && f.Vless:
			generator = urlGenerators["loon_vless"]
		}

		country := geoIp.GeoIpDB.FindCountryIsoEmoji(distNodeCountry)

		if generator != nil {
			if isIPV6 && !IsIPv6(node) {
				continue
			}
			generator(&buf, proxyInfo, distNodeCountry, country, node, 443)
		}
	}

	return buf.String(), nil
}

// vps789 openapi
type CfIpTop20 struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Count   int    `json:"count"`
	Data    struct {
		Good []struct {
			Id              int     `json:"id"`
			VpsId           int     `json:"vpsId"`
			Ip              string  `json:"ip"`
			AvgLatency      int     `json:"avgLatency"`
			AvgPkgLostRate  float64 `json:"avgPkgLostRate"`
			YdLatency       int     `json:"ydLatency"`
			YdPkgLostRate   int     `json:"ydPkgLostRate"`
			LtLatency       int     `json:"ltLatency"`
			LtPkgLostRate   int     `json:"ltPkgLostRate"`
			DxLatency       int     `json:"dxLatency"`
			DxPkgLostRate   int     `json:"dxPkgLostRate"`
			Label           string  `json:"label"`
			CreatedTime     string  `json:"createdTime"`
			AvgScore        int     `json:"avgScore"`
			YdScore         int     `json:"ydScore"`
			DxScore         int     `json:"dxScore"`
			LtScore         int     `json:"ltScore"`
			HostProvider    string  `json:"hostProvider,omitempty"`
			LocationCountry string  `json:"locationCountry,omitempty"`
			LocationCity    string  `json:"locationCity,omitempty"`
		} `json:"good"`
	} `json:"data"`
}

// SubNiceCfProxyIpTop20 获取 https://vps789.com/openApi/cfIpTop20
func SubNiceCfProxyIpTop20(format string, distNodeCountry string, isConvertIp bool, isIPV6 bool) (s string, err error) {
	// 使用defer来记录函数执行时间
	start := time.Now()
	defer func() {
		log.Infoln("SubNiceCfProxyIp completed in %v", time.Since(start))
	}()

	// 检查格式并获取配置
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		log.Errorln("Format check failed: %v", err)
		return "", fmt.Errorf("format check error: %w", err)
	}

	// 获取 cf_top_ip list
	// bestCfNodeList := config.Config().CfBestIp
	// if len(bestCfNodeList) == 0 {
	// 	log.Errorln("No best cf nodes found")
	// 	return "", errors.New("not found best cf node list")
	// }

	resp, err := tool.GetHttpClient().Get("https://vps789.com/openApi/cfIpTop20")
	if err != nil {
		log.Errorln("get cfIpTop20 failed: %v", err)
		return "", fmt.Errorf("get cfIpTop20 failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("get cfIpTop20 readall: %v", err)
		return "", fmt.Errorf("get cfIpTop20 readall: %w", err)
	}
	var top20 CfIpTop20
	err = json.Unmarshal(body, &top20)
	if err != nil {
		log.Errorln("cfIpTop20 body json format: %v", err)
		return "", fmt.Errorf("cfIpTop20 body json format: %w", err)
	}
	bestCfNodeList := make([]string, 0, 20)
	for _, good := range top20.Data.Good {
		if isConvertIp {
			ips, err := net.LookupIP(good.Ip)
			if err != nil {
				return "", fmt.Errorf("DNS查询失败: %w", err)
			}
			for _, ip := range ips {
				bestCfNodeList = append(bestCfNodeList, ip.String())
			}
		} else {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
	}

	// 预分配buffer以提高性能
	buf := strings.Builder{}
	buf.Grow(len(bestCfNodeList) * 30) // 预估每个节点约30字节

	// 写入头部信息
	buf.WriteString("# " + time.Now().Format(time.RFC3339) + "\n")
	if f.Clash {
		buf.WriteString("proxies:\n")
	}

	// 复制代理信息以避免并发问题
	var proxyInfo config.ProxyInfo
	if err := copier.Copy(&proxyInfo, &config.Config().ProxyInfo); err != nil {
		log.Errorln("Failed to copy proxy info: %v", err)
		return "", fmt.Errorf("proxy info copy error: %w", err)
	}

	// 使用函数映射来简化URL生成逻辑
	urlGenerators := map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, int){
		"surge_vmess":  genSurgeVmessUrl,
		"surge_trojan": genSurgeTrojanUrl,
		"clash_vmess":  genClashVmessUrl,
		"clash_trojan": genClashTrojanUrl,
		"clash_vless":  genClashVlessUrl,
		"quanx_vmess":  genQuanXVmessUrl,
		"quanx_trojan": genQuanXTrojanUrl,
		"quanx_vless":  genQuanXVlessUrl,
		"loon_vmess":   genLoonVmessUrl,
		"loon_trojan":  genLoonTrojanUrl,
		"loon_vless":   genLoonVlessUrl,
	}

	// 处理每个国家的节点，并应用limit限制
	for _, node := range bestCfNodeList {
		// 根据格式类型选择URL生成器
		var generator func(*strings.Builder, config.ProxyInfo, string, string, string, int)
		switch {
		case f.Surge && f.Vmess:
			generator = urlGenerators["surge_vmess"]
		case f.Surge && f.Trojan:
			generator = urlGenerators["surge_trojan"]
		case f.Clash && f.Vmess:
			generator = urlGenerators["clash_vmess"]
		case f.Clash && f.Trojan:
			generator = urlGenerators["clash_trojan"]
		case f.Clash && f.Vless:
			generator = urlGenerators["clash_vless"]
		case f.QuanX && f.Vmess:
			generator = urlGenerators["quanx_vmess"]
		case f.QuanX && f.Trojan:
			generator = urlGenerators["quanx_trojan"]
		case f.QuanX && f.Vless:
			generator = urlGenerators["quanx_vless"]
		case f.Loon && f.Vmess:
			generator = urlGenerators["loon_vmess"]
		case f.Loon && f.Trojan:
			generator = urlGenerators["loon_trojan"]
		case f.Loon && f.Vless:
			generator = urlGenerators["loon_vless"]
		}

		country := geoIp.GeoIpDB.FindCountryIsoEmoji(distNodeCountry)

		if generator != nil {
			if isIPV6 && !IsIPv6(node) {
				continue
			}
			generator(&buf, proxyInfo, distNodeCountry, country, node, 443)
		}
	}

	return buf.String(), nil
}

type CfIpProvider struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Count   int    `json:"count"`
	Data    struct {
		CT []struct {
			Ip               string  `json:"ip"`
			YdLatencyAvg     float64 `json:"ydLatencyAvg"`
			YdPkgLostRateAvg float64 `json:"ydPkgLostRateAvg"`
			LtLatencyAvg     float64 `json:"ltLatencyAvg"`
			LtPkgLostRateAvg float64 `json:"ltPkgLostRateAvg"`
			DxLatencyAvg     float64 `json:"dxLatencyAvg"`
			DxPkgLostRateAvg float64 `json:"dxPkgLostRateAvg"`
			DownloadSpeed    int     `json:"downloadSpeed"`
			CreatedTime      string  `json:"createdTime"`
			AvgScore         int     `json:"avgScore"`
			YdScore          int     `json:"ydScore"`
			DxScore          int     `json:"dxScore"`
			LtScore          int     `json:"ltScore"`
		} `json:"CT"`
		CU []struct {
			Ip               string  `json:"ip"`
			YdLatencyAvg     float64 `json:"ydLatencyAvg"`
			YdPkgLostRateAvg float64 `json:"ydPkgLostRateAvg"`
			LtLatencyAvg     float64 `json:"ltLatencyAvg"`
			LtPkgLostRateAvg float64 `json:"ltPkgLostRateAvg"`
			DxLatencyAvg     float64 `json:"dxLatencyAvg"`
			DxPkgLostRateAvg float64 `json:"dxPkgLostRateAvg"`
			DownloadSpeed    int     `json:"downloadSpeed"`
			CreatedTime      string  `json:"createdTime"`
			AvgScore         int     `json:"avgScore"`
			YdScore          int     `json:"ydScore"`
			DxScore          int     `json:"dxScore"`
			LtScore          int     `json:"ltScore"`
		} `json:"CU"`
		CM []struct {
			Ip               string  `json:"ip"`
			YdLatencyAvg     float64 `json:"ydLatencyAvg"`
			YdPkgLostRateAvg float64 `json:"ydPkgLostRateAvg"`
			LtLatencyAvg     float64 `json:"ltLatencyAvg"`
			LtPkgLostRateAvg float64 `json:"ltPkgLostRateAvg"`
			DxLatencyAvg     float64 `json:"dxLatencyAvg"`
			DxPkgLostRateAvg float64 `json:"dxPkgLostRateAvg"`
			DownloadSpeed    int     `json:"downloadSpeed"`
			CreatedTime      string  `json:"createdTime"`
			AvgScore         int     `json:"avgScore"`
			YdScore          int     `json:"ydScore"`
			DxScore          int     `json:"dxScore"`
			LtScore          int     `json:"ltScore"`
		} `json:"CM"`
		AllAvg []struct {
			Ip               string  `json:"ip"`
			YdLatencyAvg     float64 `json:"ydLatencyAvg"`
			YdPkgLostRateAvg float64 `json:"ydPkgLostRateAvg"`
			LtLatencyAvg     float64 `json:"ltLatencyAvg"`
			LtPkgLostRateAvg float64 `json:"ltPkgLostRateAvg"`
			DxLatencyAvg     float64 `json:"dxLatencyAvg"`
			DxPkgLostRateAvg float64 `json:"dxPkgLostRateAvg"`
			DownloadSpeed    int     `json:"downloadSpeed"`
			CreatedTime      string  `json:"createdTime"`
			AvgScore         int     `json:"avgScore"`
			YdScore          int     `json:"ydScore"`
			DxScore          int     `json:"dxScore"`
			LtScore          int     `json:"ltScore"`
		} `json:"AllAvg"`
	} `json:"data"`
}

// SubNiceCfProxyIpProvider 获取 https://vps789.com/openApi/cfIpApi
func SubNiceCfProxyIpProvider(format string, isp string, distNodeCountry string, isIPV6 bool) (s string, err error) {
	// 使用defer来记录函数执行时间
	start := time.Now()
	defer func() {
		log.Infoln("SubNiceCfProxyIpProvider completed in %v", time.Since(start))
	}()

	// 检查格式并获取配置
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		log.Errorln("Format check failed: %v", err)
		return "", fmt.Errorf("format check error: %w", err)
	}

	// 获取 cf_top_ip list
	// bestCfNodeList := config.Config().CfBestIp
	// if len(bestCfNodeList) == 0 {
	// 	log.Errorln("No best cf nodes found")
	// 	return "", errors.New("not found best cf node list")
	// }

	resp, err := tool.GetHttpClient().Get("https://vps789.com/openApi/cfIpApi")
	if err != nil {
		log.Errorln("get cfIpApi failed: %v", err)
		return "", fmt.Errorf("get cfIpApi failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("get cfIpApi readall: %v", err)
		return "", fmt.Errorf("get cfIpApi readall: %w", err)
	}
	var provider CfIpProvider
	err = json.Unmarshal(body, &provider)
	if err != nil {
		log.Errorln("cfIpApi body json format: %v", err)
		return "", fmt.Errorf("cfIpApi body json format: %w", err)
	}
	bestCfNodeList := make([]string, 0, 20)

	switch isp {
	case "CT":
		for _, good := range provider.Data.CT {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
	case "CU":
		for _, good := range provider.Data.CU {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
	case "CM":
		for _, good := range provider.Data.CM {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
	default:
		for _, good := range provider.Data.CT {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
		for _, good := range provider.Data.CU {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
		for _, good := range provider.Data.CM {
			bestCfNodeList = append(bestCfNodeList, good.Ip)
		}
	}

	// 预分配buffer以提高性能
	buf := strings.Builder{}
	buf.Grow(len(bestCfNodeList) * 30) // 预估每个节点约30字节

	// 写入头部信息
	buf.WriteString("# " + time.Now().Format(time.RFC3339) + "\n")
	if f.Clash {
		buf.WriteString("proxies:\n")
	}

	// 复制代理信息以避免并发问题
	var proxyInfo config.ProxyInfo
	if err := copier.Copy(&proxyInfo, &config.Config().ProxyInfo); err != nil {
		log.Errorln("Failed to copy proxy info: %v", err)
		return "", fmt.Errorf("proxy info copy error: %w", err)
	}

	// 使用函数映射来简化URL生成逻辑
	urlGenerators := map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, int){
		"surge_vmess":  genSurgeVmessUrl,
		"surge_trojan": genSurgeTrojanUrl,
		"clash_vmess":  genClashVmessUrl,
		"clash_trojan": genClashTrojanUrl,
		"clash_vless":  genClashVlessUrl,
		"quanx_vmess":  genQuanXVmessUrl,
		"quanx_trojan": genQuanXTrojanUrl,
		"quanx_vless":  genQuanXVlessUrl,
		"loon_vmess":   genLoonVmessUrl,
		"loon_trojan":  genLoonTrojanUrl,
		"loon_vless":   genLoonVlessUrl,
	}

	// 处理每个国家的节点，并应用limit限制
	for _, node := range bestCfNodeList {
		// 根据格式类型选择URL生成器
		var generator func(*strings.Builder, config.ProxyInfo, string, string, string, int)
		switch {
		case f.Surge && f.Vmess:
			generator = urlGenerators["surge_vmess"]
		case f.Surge && f.Trojan:
			generator = urlGenerators["surge_trojan"]
		case f.Clash && f.Vmess:
			generator = urlGenerators["clash_vmess"]
		case f.Clash && f.Trojan:
			generator = urlGenerators["clash_trojan"]
		case f.Clash && f.Vless:
			generator = urlGenerators["clash_vless"]
		case f.QuanX && f.Vmess:
			generator = urlGenerators["quanx_vmess"]
		case f.QuanX && f.Trojan:
			generator = urlGenerators["quanx_trojan"]
		case f.QuanX && f.Vless:
			generator = urlGenerators["quanx_vless"]
		case f.Loon && f.Vmess:
			generator = urlGenerators["loon_vmess"]
		case f.Loon && f.Trojan:
			generator = urlGenerators["loon_trojan"]
		case f.Loon && f.Vless:
			generator = urlGenerators["loon_vless"]
		}

		country := geoIp.GeoIpDB.FindCountryIsoEmoji(distNodeCountry)

		if generator != nil {
			if isIPV6 && !IsIPv6(node) {
				continue
			}
			generator(&buf, proxyInfo, distNodeCountry, country, node, 443)
		}
	}

	return buf.String(), nil
}

type nodeBase struct {
	hostname string
	port     string
	fragment string
}

// SubNiceCfProxySub 从 cf sub 订阅连接替换为自己的 IP
func SubNiceCfProxySub(format string, sub string, distNodeCountry string, isIPV6 bool) (s string, err error) {
	// 使用defer来记录函数执行时间
	start := time.Now()
	defer func() {
		log.Infoln("SubNiceCfProxySub completed in %v", time.Since(start))
	}()

	// 检查格式并获取配置
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		log.Errorln("Format check failed: %v", err)
		return "", fmt.Errorf("format check error: %w", err)
	}

	resp, err := tool.GetHttpClient().Get(sub)
	if err != nil {
		log.Errorln("get cf sub failed: %v", err)
		return "", fmt.Errorf("get cf sub failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("get cfIpApi readall: %v", err)
		return "", fmt.Errorf("get cfIpApi readall: %w", err)
	}

	de64, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		log.Errorln("url[%s] base64.StdEncoding.DecodeString(): %s", sub, err.Error())
		return "", fmt.Errorf("url[%s] base64.StdEncoding.DecodeString(): %s", sub, err.Error())
	}

	addrMap := sync.Map{}

	r := bufio.NewScanner(bytes.NewReader(de64))
	for r.Scan() {
		parsedURL, err := url.Parse(r.Text())
		if err != nil {
			log.Errorln("url.Parse: %s", err.Error())
			continue
		}
		// 使用sync.Map进行去重
		addrMap.Store(nodeBase{parsedURL.Hostname(), parsedURL.Port(), parsedURL.Fragment}, struct{}{})
	}

	bestCfNodeList := make([]nodeBase, 0, 200)
	addrMap.Range(func(key, value interface{}) bool {
		bestCfNodeList = append(bestCfNodeList, key.(nodeBase))
		return true
	})

	// 预分配buffer以提高性能
	buf := strings.Builder{}
	buf.Grow(len(bestCfNodeList) * 30) // 预估每个节点约30字节

	// 写入头部信息
	buf.WriteString("# " + time.Now().Format(time.RFC3339) + "\n")
	if f.Clash {
		buf.WriteString("proxies:\n")
	}

	// 复制代理信息以避免并发问题
	var proxyInfo config.ProxyInfo
	if err := copier.Copy(&proxyInfo, &config.Config().ProxyInfo); err != nil {
		log.Errorln("Failed to copy proxy info: %v", err)
		return "", fmt.Errorf("proxy info copy error: %w", err)
	}

	// 使用函数映射来简化URL生成逻辑
	urlGenerators := map[string]func(*strings.Builder, config.ProxyInfo, string, string, string, string, int){
		"surge_vmess":  genSurgeVmessUrl2,
		"surge_trojan": genSurgeTrojanUrl2,
		"clash_vmess":  genClashVmessUrl2,
		"clash_trojan": genClashTrojanUrl2,
		"clash_vless":  genClashVlessUrl2,
		"quanx_vmess":  genQuanXVmessUrl2,
		"quanx_trojan": genQuanXTrojanUrl2,
		"quanx_vless":  genQuanXVlessUrl2,
		"loon_vmess":   genLoonVmessUrl2,
		"loon_trojan":  genLoonTrojanUrl2,
		"loon_vless":   genLoonVlessUrl2,
	}

	// 处理每个国家的节点，并应用limit限制
	for idx, node := range bestCfNodeList {
		// 根据格式类型选择URL生成器
		var generator func(*strings.Builder, config.ProxyInfo, string, string, string, string, int)
		switch {
		case f.Surge && f.Vmess:
			generator = urlGenerators["surge_vmess"]
		case f.Surge && f.Trojan:
			generator = urlGenerators["surge_trojan"]
		case f.Clash && f.Vmess:
			generator = urlGenerators["clash_vmess"]
		case f.Clash && f.Trojan:
			generator = urlGenerators["clash_trojan"]
		case f.Clash && f.Vless:
			generator = urlGenerators["clash_vless"]
		case f.QuanX && f.Vmess:
			generator = urlGenerators["quanx_vmess"]
		case f.QuanX && f.Trojan:
			generator = urlGenerators["quanx_trojan"]
		case f.QuanX && f.Vless:
			generator = urlGenerators["quanx_vless"]
		case f.Loon && f.Vmess:
			generator = urlGenerators["loon_vmess"]
		case f.Loon && f.Trojan:
			generator = urlGenerators["loon_trojan"]
		case f.Loon && f.Vless:
			generator = urlGenerators["loon_vless"]
		}

		country := geoIp.GeoIpDB.FindCountryIsoEmoji(distNodeCountry)

		port := 443
		if node.port != "" {
			port, err = strconv.Atoi(node.port)
			if err != nil {
				log.Errorln("Failed strconv.Atoi : %v", err)
				continue
			}
		}

		node.fragment = node.fragment + fmt.Sprintf(" %d", idx)

		if generator != nil {
			if isIPV6 && !IsIPv6(node.hostname) {
				continue
			}
			generator(&buf, proxyInfo, distNodeCountry, country, node.fragment, node.hostname, port)
		}
	}

	return buf.String(), nil
}

func filterIpCountry(filter []string, c string) bool {
	if len(filter) == 0 || filter[0] == "" {
		return true
	}
	for _, f := range filter {
		if strings.Contains(c, f) {
			return true
		}
	}

	return false
}

func checkFormat(format string, distNodeCountry string) (f Format, err error) {
	if strings.Contains(format, "surge") {
		f.Surge = true
	} else if strings.Contains(format, "clash") {
		f.Clash = true
	} else if strings.Contains(format, "quanx") {
		f.QuanX = true
	} else if strings.Contains(format, "loon") {
		f.Loon = true
	} else {
		return f, fmt.Errorf("invaild client format")
	}

	if _, ok := config.Config().ProxyInfo[distNodeCountry]; !ok {
		return f, fmt.Errorf("not found %s node", distNodeCountry)
	}

	if strings.Contains(format, "Vmess") {
		if _, ok := config.Config().ProxyInfo[distNodeCountry]["vmess"]; !ok {
			return f, fmt.Errorf("not found vaild vmess node")
		}
		f.Vmess = true
	} else if strings.Contains(format, "Trojan") {
		if _, ok := config.Config().ProxyInfo[distNodeCountry]["trojan"]; !ok {
			return f, fmt.Errorf("not found vaild trojan node")
		}
		f.Trojan = true
	} else if strings.Contains(format, "Vless") {
		if _, ok := config.Config().ProxyInfo[distNodeCountry]["vless"]; !ok {
			return f, fmt.Errorf("not found vaild vless node")
		}
		f.Vless = true
	} else {
		return f, fmt.Errorf("invaild node type")
	}
	return f, nil
}

func ExtractHostPort(link string) (addr string, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}

	return u.Host, nil
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func ipToUint32(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i := 0; i < 4; i++ {
		val, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0
		}
		result = result<<8 | uint32(val)
	}
	return result
}

func genSurgeVmessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s:%d = vmess, %-15s, %d, username=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v", vmess-aead=true, tls=true
`,
		country, ip, port, ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"]))
}

func genSurgeTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s:%d = trojan, %-15s, %d, password=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v"
`,
		country, ip, port, ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"]))
}

func genClashVlessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %s:%d", "type":"vless", "server":"%s", "port":%d, "uuid":"%v", "network":"ws", "tls":true, "udp":true, "sni":"%v", "client-fingerprint":"chrome", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, ip, port, ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"]))
}

func genClashVmessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %s:%d", "type":"vmess", "server":"%s", "port":%d, "uuid":"%v", "tls":true, "cipher":"none", "alterId":0, "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}, "servername":"%v"}
`,
		country, ip, port, ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"]))
}

func genClashTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, node_country, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %s:%d", "type":"trojan", "server":"%s", "port":%d, "password":"%v", "sni":"%v", "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, ip, port, ip, port,
		proxyInfo[node_country]["trojan"]["password"],
		proxyInfo[node_country]["trojan"]["host"],
		proxyInfo[node_country]["trojan"]["path"],
		proxyInfo[node_country]["trojan"]["host"]))
}

func genQuanXVlessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`vless = %s:%d, method=none, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-verification=false, tls-host=%s, fast-open=false, udp-relay=true, tag=%s %s:%d
`,
		ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["host"],
		country, ip, port))
}

func genQuanXVmessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`vmess = %s:%d, method=none, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-host=%s, aead=true, udp-relay=true, tag=%s %s:%d
`,
		ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		country, ip, port))
}

func genQuanXTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`trojan = %s:%d, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-host=%s, udp-relay=true, tag=%s %s:%d
`,
		ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		country, ip, port))
}

func genLoonVlessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s:%d = vless, %s, %d, "%s", transport=ws, path=%s, host=%s, udp=true, over-tls=true, sni=%s
`,
		country, ip, port,
		ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["host"],
	))
}

func genLoonVmessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s:%d = vmess, %s, %d, none, "%s", transport=ws, alterId=0, path=%s, host=%s, udp=true, over-tls=true, sni=%s
`,
		country, ip, port,
		ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"],
	))
}

func genLoonTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s:%d = trojan, %s, %d, "%s", transport=ws, sni=%s, path=%s, host=%s, udp=true
`,
		country, ip, port,
		ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"],
	))
}

func genSurgeVmessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s = vmess, %-15s, %d, username=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v", vmess-aead=true, tls=true
`,
		country, nodeName, ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"]))
}

func genSurgeTrojanUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s = trojan, %-15s, %d, password=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v"
`,
		country, nodeName, ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"]))
}

func genClashVlessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %s", "type":"vless", "server":"%s", "port":%d, "uuid":"%v", "network":"ws", "tls":true, "udp":true, "sni":"%v", "client-fingerprint":"chrome", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, nodeName, ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"]))
}

func genClashVmessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %s", "type":"vmess", "server":"%s", "port":%d, "uuid":"%v", "tls":true, "cipher":"none", "alterId":0, "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}, "servername":"%v"}
`,
		country, nodeName, ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"]))
}

func genClashTrojanUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, node_country, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %s", "type":"trojan", "server":"%s", "port":%d, "password":"%v", "sni":"%v", "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, nodeName, ip, port,
		proxyInfo[node_country]["trojan"]["password"],
		proxyInfo[node_country]["trojan"]["host"],
		proxyInfo[node_country]["trojan"]["path"],
		proxyInfo[node_country]["trojan"]["host"]))
}

func genQuanXVlessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`vless = %s:%d, method=none, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-verification=false, tls-host=%s, fast-open=false, udp-relay=true, tag=%s %s
`,
		ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["host"],
		country, nodeName))
}

func genQuanXVmessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`vmess = %s:%d, method=none, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-host=%s, aead=true, udp-relay=true, tag=%s %s
`,
		ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		country, nodeName))
}

func genQuanXTrojanUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`trojan = %s:%d, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-host=%s, udp-relay=true, tag=%s %s
`,
		ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		country, nodeName))
}

func genLoonVlessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s = vless, %s, %d, "%s", transport=ws, path=%s, host=%s, udp=true, over-tls=true, sni=%s
`,
		country, nodeName,
		ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["host"],
	))
}

func genLoonVmessUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s = vmess, %s, %d, none, "%s", transport=ws, alterId=0, path=%s, host=%s, udp=true, over-tls=true, sni=%s
`,
		country, nodeName,
		ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"],
	))
}

func genLoonTrojanUrl2(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, nodeName string, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %s = trojan, %s, %d, "%s", transport=ws, sni=%s, path=%s, host=%s, udp=true
`,
		country, nodeName,
		ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"],
	))
}

func IsIPv6(addr string) bool {
	ipv6Addr := net.ParseIP(addr)

	// 核心实现：
	//
	// 检查 IP 地址是否为 16 字节长，并且不能被 To4() 成功转换为 IPv4 地址。
	// 如果 To4() 返回非 nil，则表示它是 IPv4 或 IPv4-mapped IPv6 地址。
	// 只有当长度为 16 字节且 To4() 返回 nil 时，才是纯粹的 IPv6 地址。
	return len(ipv6Addr) == net.IPv6len && ipv6Addr.To4() == nil
}
