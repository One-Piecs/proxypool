package cdn

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/One-Piecs/proxypool/log"
)

type Manager struct {
	ranges []*net.IPNet
	mu     sync.RWMutex
}

var GlobalManager = &Manager{}

func (m *Manager) Update() {
	newRanges := make([]*net.IPNet, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex

	appendRanges := func(ranges []*net.IPNet) {
		mu.Lock()
		defer mu.Unlock()
		newRanges = append(newRanges, ranges...)
	}

	// 1. Cloudflare
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfUrls := []string{
			"https://www.cloudflare.com/ips-v4",
			"https://www.cloudflare.com/ips-v6",
		}
		for _, url := range cfUrls {
			cidrs, err := fetchTextCIDRs(url)
			if err != nil {
				log.Errorln("Failed to fetch CF CDN list from %s: %v", url, err)
				continue
			}
			appendRanges(cidrs)
		}
	}()

	// 2. AWS CloudFront
	wg.Add(1)
	go func() {
		defer wg.Done()
		cidrs, err := fetchAWS()
		if err != nil {
			log.Errorln("Failed to fetch AWS list: %v", err)
			return
		}
		appendRanges(cidrs)
	}()

	// 3. Google Cloud
	wg.Add(1)
	go func() {
		defer wg.Done()
		cidrs, err := fetchGoogle()
		if err != nil {
			log.Errorln("Failed to fetch Google list: %v", err)
			return
		}
		appendRanges(cidrs)
	}()

	// 4. Fastly
	wg.Add(1)
	go func() {
		defer wg.Done()
		cidrs, err := fetchFastly()
		if err != nil {
			log.Errorln("Failed to fetch Fastly list: %v", err)
			return
		}
		appendRanges(cidrs)
	}()

	// 5. Gcore
	wg.Add(1)
	go func() {
		defer wg.Done()
		cidrs, err := fetchGcore()
		if err != nil {
			log.Errorln("Failed to fetch Gcore list: %v", err)
			return
		}
		appendRanges(cidrs)
	}()

	wg.Wait()

	m.mu.Lock()
	m.ranges = newRanges
	m.mu.Unlock()
	log.Infoln("Updated CDN IP ranges, total count: %d", len(newRanges))
}

// Fetchers

// cdnClient 统一带超时的 HTTP 客户端：原实现裸 http.Get 无超时无重试，
// 网络受限环境（如无法直连 Google）会长时间挂起。
var cdnClient = &http.Client{Timeout: 15 * time.Second}

// httpGetWithRetry 带超时与一次重试的 GET 请求
func httpGetWithRetry(url string) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := cdnClient.Get(url)
		if err == nil {
			return resp, nil
		}
		if attempt >= 1 {
			return nil, err
		}
		time.Sleep(2 * time.Second)
	}
}

func fetchTextCIDRs(url string) ([]*net.IPNet, error) {
	resp, err := httpGetWithRetry(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cidrs []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		cidrs = append(cidrs, ipNet)
	}
	return cidrs, scanner.Err()
}

// AWS
type awsIPRanges struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
	} `json:"ipv6_prefixes"`
}

func fetchAWS() ([]*net.IPNet, error) {
	resp, err := httpGetWithRetry("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data awsIPRanges
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var cidrs []*net.IPNet
	for _, p := range data.Prefixes {
		_, ipNet, err := net.ParseCIDR(p.IPPrefix)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}
	for _, p := range data.IPv6Prefixes {
		_, ipNet, err := net.ParseCIDR(p.IPv6Prefix)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}
	return cidrs, nil
}

// Google
type googleIPRanges struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func fetchGoogle() ([]*net.IPNet, error) {
	resp, err := httpGetWithRetry("https://www.gstatic.com/ipranges/goog.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data googleIPRanges
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var cidrs []*net.IPNet
	for _, p := range data.Prefixes {
		if p.IPv4Prefix != "" {
			_, ipNet, err := net.ParseCIDR(p.IPv4Prefix)
			if err == nil {
				cidrs = append(cidrs, ipNet)
			}
		}
		if p.IPv6Prefix != "" {
			_, ipNet, err := net.ParseCIDR(p.IPv6Prefix)
			if err == nil {
				cidrs = append(cidrs, ipNet)
			}
		}
	}
	return cidrs, nil
}

// Fastly
type fastlyIPRanges struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
}

func fetchFastly() ([]*net.IPNet, error) {
	resp, err := httpGetWithRetry("https://api.fastly.com/public-ip-list")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data fastlyIPRanges
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var cidrs []*net.IPNet
	for _, ip := range data.Addresses {
		_, ipNet, err := net.ParseCIDR(ip)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}
	for _, ip := range data.IPv6Addresses {
		_, ipNet, err := net.ParseCIDR(ip)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}
	return cidrs, nil
}

// Gcore
type gcoreIPRanges struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
}

func fetchGcore() ([]*net.IPNet, error) {
	resp, err := httpGetWithRetry("https://api.gcore.com/cdn/public-ip-list")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data gcoreIPRanges
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	var cidrs []*net.IPNet
	for _, ip := range data.Addresses {
		_, ipNet, err := net.ParseCIDR(ip)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}
	for _, ip := range data.IPv6Addresses {
		_, ipNet, err := net.ParseCIDR(ip)
		if err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}
	return cidrs, nil
}

func (m *Manager) IsCDN(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, rangeNet := range m.ranges {
		if rangeNet.Contains(ip) {
			return true
		}
	}
	return false
}
