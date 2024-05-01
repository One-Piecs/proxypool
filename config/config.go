package config

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"github.com/One-Piecs/proxypool/pkg/tool"
	"github.com/ghodss/yaml"
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

	SubIpUrl  []string  `json:"sub_ip_url" yaml:"sub_ip_url"`
	ProxyInfo ProxyInfo `json:"proxy_info" yaml:"proxy_info"`
}

// Config 配置
var Config ConfigOptions

// Parse 解析配置文件，支持本地文件系统和网络链接
func Parse(path string) error {
	if path == "" {
		path = configFilePath
	} else {
		configFilePath = path
	}
	fileData, err := ReadFile(path)
	if err != nil {
		return err
	}
	Config = ConfigOptions{}
	err = yaml.Unmarshal(fileData, &Config)
	if err != nil {
		return err
	}

	// set default
	if Config.Connection <= 0 {
		Config.Connection = 5
	}
	if Config.Port == "" {
		Config.Port = "12580"
	}
	if Config.CrawlInterval == 0 {
		Config.CrawlInterval = 60
	}
	if Config.SpeedTestInterval == 0 {
		Config.SpeedTestInterval = 720
	}
	if Config.ActiveInterval == 0 {
		Config.ActiveInterval = 60
	}
	if Config.ActiveFrequency == 0 {
		Config.ActiveFrequency = 100
	}
	if Config.ActiveMaxNumber == 0 {
		Config.ActiveMaxNumber = 100
	}

	if Config.V2WsHeaderUserAgent == "" {
		Config.V2WsHeaderUserAgent = "user-agent:Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1"
	}

	if Config.GeoipDbUrl == "" {
		Config.GeoipDbUrl = "https://cdn.jsdelivr.net/gh/alecthw/mmdb_china_ip_list@release/"
	}

	// 部分配置环境变量优先
	if domain := os.Getenv("DOMAIN"); domain != "" {
		Config.Domain = domain
	}
	if cfEmail := os.Getenv("CF_API_EMAIL"); cfEmail != "" {
		Config.CFEmail = cfEmail
	}
	if cfKey := os.Getenv("CF_API_KEY"); cfKey != "" {
		Config.CFKey = cfKey
	}

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
		return ioutil.ReadAll(resp.Body)
	} else {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, err
		}
		return ioutil.ReadFile(path)
	}
}
