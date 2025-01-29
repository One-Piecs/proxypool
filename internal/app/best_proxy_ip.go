package app

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/internal/cache"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
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
				resp, err := resty.New().R().
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

			// 创建节点
			node := cache.BestNode{
				Ip:      ip,
				Port:    port,
				Country: country,
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
		// 国家相同时按IP排序
		if bestNodeList[i].Ip != bestNodeList[j].Ip {
			return bestNodeList[i].Ip < bestNodeList[j].Ip
		}
		// IP相同时按端口排序
		return bestNodeList[i].Port < bestNodeList[j].Port
	})

	cache.SetBestNodeList("bestNode", bestNodeList)
	cache.SetString("bestNodeLastUpdateTime", time.Now().Format(time.RFC3339))
	log.Infoln("Completed processing %d nodes", len(bestNodeList))
}

func SubNiceProxyIp(format string, distNodeCountry string, proxyCountryIsoCode string) (s string, err error) {
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

	// 处理每个节点
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
			generator(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
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
