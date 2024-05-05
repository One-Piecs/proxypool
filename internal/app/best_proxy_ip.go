package app

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jinzhu/copier"

	"github.com/One-Piecs/proxypool/internal/cache"

	"github.com/One-Piecs/proxypool/config"

	"github.com/One-Piecs/proxypool/pkg/geoIp"

	"github.com/One-Piecs/proxypool/log"
	"github.com/go-resty/resty/v2"
)

type Format struct {
	Surge  bool
	Clash  bool
	QuanX  bool
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

	addrAll := make([]string, 0, 200)

	bestNodeList := make([]cache.BestNode, 0, 200)

	chn := make(chan []string, len(urls))
	wg := &sync.WaitGroup{}

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			log.Infoln("Starting: %s", url)
			list := make([]string, 0, 100)

			resp, err := resty.New().R().
				SetQueryParams(map[string]string{
					"host":       "p.laibbb.top",
					"uuid":       "e4e08238-e42c-4288-8f67-e2994ec18c90",
					"path":       "/webhook",
					"edgetunnel": "cmliu",
				}).
				SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36").
				Get(url)
			if err != nil {
				log.Errorln("resty.Get(): %s", err.Error())
				chn <- list
				wg.Done()
				return
			}
			de64, err := base64.StdEncoding.DecodeString(resp.String())
			if err != nil {
				log.Errorln("url[%s] base64.StdEncoding.DecodeString(): %s", url, err.Error())
				chn <- list
				wg.Done()
				return
			}
			// fmt.Println(url, "\n", string(de64))
			r := bufio.NewScanner(bytes.NewReader(de64))

			for r.Scan() {
				addr, err := ExtractHostPort(r.Text())
				if err != nil {
					log.Errorln("ExtractHostPort: %s", err.Error())
					continue
				}
				list = append(list, addr)
			}

			chn <- list
			wg.Done()
			log.Infoln("End: %s", url)
		}(url)
	}

	wg.Wait()

	num := 0
	for addrs := range chn {
		num++
		addrAll = append(addrAll, addrs...)
		if num == len(urls) {
			close(chn)
			break
		}
	}

	addrAll = removeDuplicateElement(addrAll)
	var err error
	for _, addr := range addrAll {
		ip := ""
		port := 0
		h := strings.Split(addr, "]:")
		if len(h) == 2 {
			// ipv6
			ip = strings.ReplaceAll(h[0], "[", "")
			port, err = strconv.Atoi(h[1])
			if err != nil {
				log.Errorln("strconv.Atoi(h[1]): %s", err.Error())
				continue
			}
		} else {
			// ipv4
			h := strings.Split(addr, ":")
			if len(h) != 2 {
				log.Errorln("invalid addr: %s", addr)
				continue
			}
			ip = h[0]
			port, err = strconv.Atoi(h[1])
			if err != nil {
				log.Errorln("strconv.Atoi(h[1]): %s", err.Error())
				continue
			}
		}

		if ip == "cf.090227.xyz" {
			continue
		}

		_, country, err := geoIp.GeoIpDB.Find(ip)
		if err != nil {
			log.Errorln(err.Error())
			continue
		}

		bestNodeList = append(bestNodeList, cache.BestNode{
			Ip:      ip,
			Port:    port,
			Country: country,
		})
	}

	cache.SetBestNodeList("bestNode", bestNodeList)
	cache.SetString("bestNodeLastUpdateTime", time.Now().Format(time.RFC3339))
}

func SubNiceProxyIp(format string, distNodeCountry string, proxyCountryIsoCode string) (s string, err error) {
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		return "", err
	}

	bestNodeList := cache.GetBestNodeList("bestNode")
	if bestNodeList == nil || len(bestNodeList) == 0 {
		return "", errors.New("not found best node list")
	}

	buf := strings.Builder{}
	buf.WriteString("# " + cache.GetString("bestNodeLastUpdateTime") + "\n")

	switch format {
	case "surgeVmess", "surgeTrojan":
	case "quanxVmess", "quanxTrojan", "quanxVless":
	case "clashVmess", "clashTrojan", "clashVless":
		buf.WriteString("proxies:\n")
	default:
		return "", fmt.Errorf("invalid format: %s", format)
	}

	proxyCountryIsoCodeList := strings.Split(proxyCountryIsoCode, ",")

	var proxyInfo config.ProxyInfo

	_ = copier.Copy(&proxyInfo, &config.Config().ProxyInfo)

	for _, node := range bestNodeList {

		if !filterIpCountry(proxyCountryIsoCodeList, node.Country) {
			continue
		}

		if f.Surge {
			if f.Vmess {
				genSurgeVmessUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			} else if f.Trojan {
				genSurgeTrojanUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			}
		} else if f.Clash {
			if f.Vmess {
				genClashVmessUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			} else if f.Trojan {
				genClashTrojanUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			} else if f.Vless {
				genClashVlessUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			}
		} else if f.QuanX {
			if f.Vmess {
				genQuanXVmessUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			} else if f.Trojan {
				genQuanXTrojanUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			} else if f.Vless {
				genQuanXVlessUrl(&buf, proxyInfo, distNodeCountry, node.Country, node.Ip, node.Port)
			}
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
	buf.WriteString(fmt.Sprintf(`%s %-15s = vmess, %-15s, %d, username=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v", vmess-aead=true, tls=true
`,
		country, ip, ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"]))
}

func genSurgeTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %-15s = trojan, %-15s, %d, password=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v"
`,
		country, ip, ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"]))
}

func genClashVlessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %-15s", "type":"vless", "server":"%s", "port":%d, "uuid":"%v", "network":"ws", "tls":true, "udp":true, "sni":"%v", "client-fingerprint":"chrome", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, ip, ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"]))
}

func genClashVmessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %-15s", "type":"vmess", "server":"%s", "port":%d, "uuid":"%v", "tls":true, "cipher":"none", "alterId":0, "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}, "servername":"%v"}
`,
		country, ip, ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"]))
}

func genClashTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, node_country, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %-15.15s", "type":"trojan", "server":"%s", "port":%d, "password":"%v", "sni":"%v", "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, ip, ip, port,
		proxyInfo[node_country]["trojan"]["password"],
		proxyInfo[node_country]["trojan"]["host"],
		proxyInfo[node_country]["trojan"]["path"],
		proxyInfo[node_country]["trojan"]["host"]))
}

func genQuanXVlessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`vless = %s:%d, method=none, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-verification=false, tls-host=%s, fast-open=false, udp-relay=true, tag=%s %s
`,
		ip, port,
		proxyInfo[nodeCountry]["vless"]["uuid"],
		proxyInfo[nodeCountry]["vless"]["path"],
		proxyInfo[nodeCountry]["vless"]["host"],
		proxyInfo[nodeCountry]["vless"]["host"],
		country, ip))
}

func genQuanXVmessUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`vmess = %s:%d, method=chacha20-ietf-poly1305, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-host=%s, aead=true, udp-relay=true, tag=%s %s
`,
		ip, port,
		proxyInfo[nodeCountry]["vmess"]["uuid"],
		proxyInfo[nodeCountry]["vmess"]["path"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		proxyInfo[nodeCountry]["vmess"]["host"],
		country, ip))
}

func genQuanXTrojanUrl(buf *strings.Builder, proxyInfo config.ProxyInfo, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`trojan = %s:%d, password=%s, obfs=wss, obfs-uri=%s, obfs-host=%s, tls-host=%s, udp-relay=true, tag=%s %s 
`,
		ip, port,
		proxyInfo[nodeCountry]["trojan"]["password"],
		proxyInfo[nodeCountry]["trojan"]["path"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		proxyInfo[nodeCountry]["trojan"]["host"],
		country, ip))
}
