package app

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/One-Piecs/proxypool/config"

	"github.com/One-Piecs/proxypool/pkg/geoIp"

	"github.com/One-Piecs/proxypool/log"
	"github.com/go-resty/resty/v2"
)

type Format struct {
	Surge  bool
	Clash  bool
	Vmess  bool
	Trojan bool
	Vless  bool
}

func SubNiceProxyIp(format string, distNodeCountry string) (s string, err error) {
	f, err := checkFormat(format, distNodeCountry)
	if err != nil {
		return "", err
	}

	urls := config.Config.SubIpUrl
	if len(urls) == 0 {
		return "", fmt.Errorf("not found sub url")
	}

	addrAll := make([]string, 0, 100)

	chn := make(chan []string, len(urls))
	wg := &sync.WaitGroup{}

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			log.Infoln("Starting: %s", url)
			list := make([]string, 0, 100)

			resp, err := resty.New().R().
				SetQueryParams(map[string]string{
					"host":       "fake.com",
					"uuid":       "uuid",
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
				log.Errorln("base64.StdEncoding.DecodeString(): %s", err.Error())
				chn <- list
				wg.Done()
				return
			}
			// fmt.Println(url, "\n", string(de64))
			r := bufio.NewScanner(bytes.NewReader(de64))

			for r.Scan() {
				addr, err := ExtractHostPort2(r.Text())
				if err != nil {
					log.Errorln("ExtractHostPort2: %s", err.Error())
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

	buf := strings.Builder{}
	switch format {
	case "surgeVmess", "surgeTrojan":
		buf.WriteString("# " + time.Now().Format(time.RFC3339) + "\n")
	case "clashVmess", "clashTrojan", "clashVless":
		buf.WriteString("# " + time.Now().Format(time.RFC3339) + "\n")
		buf.WriteString("proxies:\n")
	default:
		return "", fmt.Errorf("invalid format: %s", format)
	}

	for _, addr := range addrAll {
		host := ""
		port := 0
		h := strings.Split(addr, "]:")
		if len(h) == 2 {
			// ipv6
			host = strings.ReplaceAll(h[0], "[", "")
			port, err = strconv.Atoi(h[1])
			if err != nil {
				log.Errorln("strconv.Atoi(h[1]): %s", err.Error())
				continue
			}
		} else {
			// ipv4
			h := strings.Split(addr, ":")
			host = h[0]
			port, err = strconv.Atoi(h[1])
			if err != nil {
				log.Errorln("strconv.Atoi(h[1]): %s", err.Error())
				continue
			}
		}

		if host == "cf.090227.xyz" {
			continue
		}

		_, country, err := geoIp.GeoIpDB.Find(host)
		if err != nil {
			log.Errorln(err.Error())
			continue
		}

		if f.Surge {
			if f.Vmess {
				genSurgeVmessUrl(&buf, distNodeCountry, country, host, port)
			} else if f.Trojan {
				genSurgeTrojanUrl(&buf, distNodeCountry, country, host, port)
			}
		} else if f.Clash {
			if f.Vmess {
				genClashVmessUrl(&buf, distNodeCountry, country, host, port)
			} else if f.Trojan {
				genClashTrojanUrl(&buf, distNodeCountry, country, host, port)
			} else if f.Vless {
				genClashVlessUrl(&buf, distNodeCountry, country, host, port)
			}
		}

	}

	return buf.String(), nil
}

func checkFormat(format string, distNodeCountry string) (f Format, err error) {
	err = config.Parse("")
	if err != nil {
		log.Errorln("[best_proxy_ip.go] config parse error: %s", err)
	}

	if strings.Contains(format, "surge") {
		f.Surge = true
	} else if strings.Contains(format, "clash") {
		f.Clash = true
	} else {
		return f, fmt.Errorf("invaild client format")
	}

	if _, ok := config.Config.ProxyInfo[distNodeCountry]; !ok {
		return f, fmt.Errorf("not found %s node", distNodeCountry)
	}

	if strings.Contains(format, "Vmess") {
		if _, ok := config.Config.ProxyInfo[distNodeCountry]["vmess"]; !ok {
			return f, fmt.Errorf("not found vaild vmess node")
		}
		f.Vmess = true
	} else if strings.Contains(format, "Trojan") {
		if _, ok := config.Config.ProxyInfo[distNodeCountry]["trojan"]; !ok {
			return f, fmt.Errorf("not found vaild trojan node")
		}
		f.Trojan = true
	} else if strings.Contains(format, "Vless") {
		if _, ok := config.Config.ProxyInfo[distNodeCountry]["vless"]; !ok {
			return f, fmt.Errorf("not found vaild vless node")
		}
		f.Vless = true
	} else {
		return f, fmt.Errorf("invaild node type")
	}
	return f, nil
}

func ExtractHostPort(link string) (host string, port int, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", 0, err
	}

	h := strings.Split(u.Host, "]:")
	if len(h) == 2 {
		// ipv6
		host = strings.ReplaceAll(h[0], "[", "")
		port, err = strconv.Atoi(h[1])
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	} else {
		// ipv4
		h := strings.Split(u.Host, ":")
		port, err = strconv.Atoi(h[1])
		if err != nil {
			return "", 0, err
		}
		return h[0], port, nil
	}
}

func ExtractHostPort2(link string) (addr string, err error) {
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

func genSurgeVmessUrl(buf *strings.Builder, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %-15s = vmess, %-15s, %d, username=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v", vmess-aead=true, tls=true
`,
		country, ip, ip, port,
		config.Config.ProxyInfo[nodeCountry]["vmess"]["uuid"],
		config.Config.ProxyInfo[nodeCountry]["vmess"]["host"],
		config.Config.ProxyInfo[nodeCountry]["vmess"]["path"],
		config.Config.ProxyInfo[nodeCountry]["vmess"]["host"]))
}

func genSurgeTrojanUrl(buf *strings.Builder, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`%s %-15s = trojan, %-15s, %d, password=%v, sni=%v, ws=true, ws-path=%v, ws-headers=Host:"%v"
`,
		country, ip, ip, port,
		config.Config.ProxyInfo[nodeCountry]["trojan"]["password"],
		config.Config.ProxyInfo[nodeCountry]["trojan"]["host"],
		config.Config.ProxyInfo[nodeCountry]["trojan"]["path"],
		config.Config.ProxyInfo[nodeCountry]["trojan"]["host"]))
}

func genClashVlessUrl(buf *strings.Builder, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %-15s", "type":"vless", "server":"%s", "port":%d, "uuid":"%v", "network":"ws", "tls":true, "udp":true, "sni":"%v", "client-fingerprint":"chrome", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, ip, ip, port,
		config.Config.ProxyInfo[nodeCountry]["vless"]["uuid"],
		config.Config.ProxyInfo[nodeCountry]["vless"]["host"],
		config.Config.ProxyInfo[nodeCountry]["vless"]["path"],
		config.Config.ProxyInfo[nodeCountry]["vless"]["host"]))
}

func genClashVmessUrl(buf *strings.Builder, nodeCountry, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %-15s", "type":"vmess", "server":"%s", "port":%d, "uuid":"%v", "tls":true, "cipher":"none", "alterId":0, "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}, "servername":"%v"}
`,
		country, ip, ip, port,
		config.Config.ProxyInfo[nodeCountry]["vmess"]["uuid"],
		config.Config.ProxyInfo[nodeCountry]["vmess"]["path"],
		config.Config.ProxyInfo[nodeCountry]["vmess"]["host"],
		config.Config.ProxyInfo[nodeCountry]["vmess"]["host"]))
}

func genClashTrojanUrl(buf *strings.Builder, node_country, country, ip string, port int) {
	buf.WriteString(fmt.Sprintf(`  - {"name":"%s %-15.15s", "type":"trojan", "server":"%s", "port":%d, "password":"%v", "sni":"%v", "network":"ws", "ws-opts":{"path":"%v", "headers":{"Host":"%v"}}}
`,
		country, ip, ip, port,
		config.Config.ProxyInfo[node_country]["trojan"]["password"],
		config.Config.ProxyInfo[node_country]["trojan"]["host"],
		config.Config.ProxyInfo[node_country]["trojan"]["path"],
		config.Config.ProxyInfo[node_country]["trojan"]["host"]))
}
