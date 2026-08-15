package config

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/One-Piecs/proxypool/pkg/tool"
	"gopkg.in/yaml.v3"
)

var configFilePath = "config.yaml"

type ConfigOptions struct {
	Domain                string   `json:"domain" yaml:"domain"`
	Port                  string   `json:"port" yaml:"port"`
	TLSEnable             bool     `json:"tls_enable" yaml:"tls_enable"`
	CertFile              string   `json:"cert_file" yaml:"cert_file"`
	KeyFile               string   `json:"key_file" yaml:"key_file"`
	DatabaseUrl           string   `json:"database_url" yaml:"database_url"`
	CrawlInterval         uint64   `json:"crawl-interval" yaml:"crawl-interval"`
	CFEmail               string   `json:"cf_email" yaml:"cf_email"`
	CFKey                 string   `json:"cf_key" yaml:"cf_key"`
	SourceFiles           []string `json:"source-files" yaml:"source-files"`
	SpeedTest             bool     `json:"speedtest" yaml:"speedtest"`
	SpeedTestInterval     uint64   `json:"speedtest-interval" yaml:"speedtest-interval"`
	SpeedCountryWhiteList string   `json:"speed-country-white-list" yaml:"speed-country-white-list"`
	Connection            int      `json:"connection" yaml:"connection"`
	Timeout               int      `json:"timeout" yaml:"timeout"`
	ActiveFrequency       uint16   `json:"active-frequency" yaml:"active-frequency" `
	ActiveInterval        uint64   `json:"active-interval" yaml:"active-interval"`
	ActiveMaxNumber       uint16   `json:"active-max-number" yaml:"active-max-number"`
	TgChannelProxyUrl     string   `json:"tg_channel_proxy_url" yaml:"tg_channel_proxy_url"`
	V2WsHeaderUserAgent   string   `json:"v2_ws_header_user_agent" yaml:"v2_ws_header_user_agent"`
	GeoipDbUrl            string   `json:"geoip_db_url" yaml:"geoip_db_url"`

	SubBestNodeInterval uint64    `json:"sub-best-node-interval" yaml:"sub-best-node-interval"`
	SubIpUrl            []string  `json:"sub_ip_url" yaml:"sub_ip_url"`
	ProxyInfo           ProxyInfo `json:"proxy_info" yaml:"proxy_info"`
	CfBestIp            []string  `json:"cf_best_ip" yaml:"cf_best_ip"`
}

var gCfg atomic.Value

// 配置解析缓存：避免每次请求都重新读取/解析配置文件。
// 本地文件按 mtime 判断是否变化（保留热更新能力）；
// http(s) 源按 TTL 刷新。所有调用点（cron、API、任务）统一受益。
const urlConfigTTL = 60 * time.Second

var (
	parseMu    sync.Mutex
	parsedInfo = make(map[string]parsedMeta)
)

type parsedMeta struct {
	mtime      time.Time // 本地文件修改时间
	validUntil time.Time // URL 源有效截止时间
}

// Config 配置
// var Config ConfigOptions
func Config() *ConfigOptions {
	if v := gCfg.Load(); v != nil {
		return v.(*ConfigOptions)
	}
	return &ConfigOptions{}
}

// isConfigFresh 判断配置是否仍有效（无需重新解析）
func isConfigFresh(path string) bool {
	info, ok := parsedInfo[path]
	if !ok {
		return false
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return time.Now().Before(info.validUntil)
	}
	st, err := os.Stat(path)
	if err != nil {
		return false // 文件不存在/不可读，重新解析（会再次报错）
	}
	return st.ModTime().Equal(info.mtime)
}

// recordParsed 记录本次解析后的配置有效性
func recordParsed(path string) {
	meta := parsedMeta{}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		meta.validUntil = time.Now().Add(urlConfigTTL)
	} else if st, err := os.Stat(path); err == nil {
		meta.mtime = st.ModTime()
	}
	parsedInfo[path] = meta
}

// Parse 解析配置文件，支持本地文件系统和网络链接。
// 配置源未变化时直接返回（不重复解析）。
func Parse(path string) error {
	if path == "" {
		path = configFilePath
	} else {
		configFilePath = path
	}

	parseMu.Lock()
	defer parseMu.Unlock()

	if isConfigFresh(path) {
		return nil
	}

	fileData, err := ReadFile(path)
	if err != nil {
		return err
	}
	cfg := ConfigOptions{}
	err = yaml.Unmarshal(fileData, &cfg)
	if err != nil {
		return err
	}

	// set default
	if cfg.Connection <= 0 {
		cfg.Connection = 5
	}
	if cfg.Port == "" {
		cfg.Port = "12580"
	}
	if cfg.CrawlInterval == 0 {
		cfg.CrawlInterval = 60
	}
	if cfg.SpeedTestInterval == 0 {
		cfg.SpeedTestInterval = 720
	}
	if cfg.ActiveInterval == 0 {
		cfg.ActiveInterval = 60
	}
	if cfg.ActiveFrequency == 0 {
		cfg.ActiveFrequency = 100
	}
	if cfg.ActiveMaxNumber == 0 {
		cfg.ActiveMaxNumber = 100
	}

	if cfg.V2WsHeaderUserAgent == "" {
		cfg.V2WsHeaderUserAgent = "user-agent:Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1"
	}

	if cfg.GeoipDbUrl == "" {
		cfg.GeoipDbUrl = "https://cdn.jsdelivr.net/gh/alecthw/mmdb_china_ip_list@release/"
	}

	if cfg.SubBestNodeInterval == 0 {
		cfg.SubBestNodeInterval = 60
	}

	// 部分配置环境变量优先
	if domain := os.Getenv("DOMAIN"); domain != "" {
		cfg.Domain = domain
	}
	if cfEmail := os.Getenv("CF_API_EMAIL"); cfEmail != "" {
		cfg.CFEmail = cfEmail
	}
	if cfKey := os.Getenv("CF_API_KEY"); cfKey != "" {
		cfg.CFKey = cfKey
	}

	gCfg.Store(&cfg)
	recordParsed(path)

	return nil
}

// 从本地文件或者http链接读取配置文件内容
func ReadFile(path string) ([]byte, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		resp, err := tool.GetHttpClient().Get(path)
		if err != nil {
			return nil, errors.New("config file http get fail")
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	return os.ReadFile(path)
}
