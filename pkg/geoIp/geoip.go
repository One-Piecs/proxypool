package geoIp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/log"

	"github.com/oschwald/geoip2-golang"
)

// 数据库文件路径（首次下载后落盘，重启免重复下载）
const (
	countryDBPath = "assets/Country.mmdb"
	versionPath   = "assets/version"
	asnDBPath     = "assets/GeoLite2-ASN.mmdb"
)

// maxminddb.Reader 的所有方法线程安全，可跨 goroutine 共享。
// 更新时通过 atomic 指针原子替换；旧 reader 延迟关闭，避免与进行中的查询冲突
// （查询为微秒级，closeDelay 足以覆盖）。
const closeDelay = 60 * time.Second

var (
	countryDB atomic.Pointer[geoip2.Reader]
	asnDB     atomic.Pointer[geoip2.Reader]

	// 下载与版本检查各自独立的带超时客户端（原实现裸 http.Client{} 无超时）
	downloadClient = &http.Client{Timeout: 30 * time.Second}
	versionClient  = &http.Client{Timeout: 10 * time.Second}
)

// GeoIpDBCurVersion 当前 Country 库版本号（用于页面展示）
var GeoIpDBCurVersion string

// GeoIP 地理位置查询器（保持对外 API 不变）
type GeoIP struct {
	emojiMap map[string]string
}

// GeoIpDB 全局地理位置查询器
var GeoIpDB GeoIP

// CountryEmoji flags.json 中的国家与 emoji 映射项
type CountryEmoji struct {
	Code  string `json:"code"`
	Emoji string `json:"emoji"`
}

// IPAPIResponse ip-api.com 查询响应
type IPAPIResponse struct {
	CountryCode string `json:"countryCode"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

// InitGeoIpDB 初始化数据库：
// 1. 本地已有 Country.mmdb 则直接加载（秒开），否则下载并落盘
// 2. 加载 emoji 映射
// 3. 初始化 ASN 库
func InitGeoIpDB() error {
	if err := loadCountryDB(); err != nil {
		return err
	}
	em, err := loadEmojiMap()
	if err != nil {
		return err
	}
	GeoIpDB.emojiMap = em
	InitGeoIpASNDB()
	return nil
}

// loadCountryDB 加载本地库；缺失时下载。
func loadCountryDB() error {
	if _, err := os.Stat(countryDBPath); err == nil {
		db, err := geoip2.Open(countryDBPath)
		if err != nil {
			return fmt.Errorf("open local country db: %w", err)
		}
		countryDB.Store(db)
		if v, err := os.ReadFile(versionPath); err == nil {
			GeoIpDBCurVersion = strings.TrimSpace(string(v))
		}
		log.Infoln("geoip: loaded local Country.mmdb (version: %s)", GeoIpDBCurVersion)
		return nil
	}

	log.Infoln("geoip: Country.mmdb not found, downloading...")
	return downloadCountryDB("")
}

// downloadCountryDB 下载 Country 库到临时文件后原子替换；knownVersion 为空时自行获取版本号。
func downloadCountryDB(knownVersion string) error {
	data, err := httpGet(config.Config().GeoipDbUrl+"Country.mmdb", downloadClient)
	if err != nil {
		return fmt.Errorf("download country db: %w", err)
	}
	if err := writeFileAtomic(countryDBPath, data); err != nil {
		return err
	}

	db, err := geoip2.Open(countryDBPath)
	if err != nil {
		return fmt.Errorf("open downloaded country db: %w", err)
	}
	old := countryDB.Swap(db)
	swapClose(old)

	if knownVersion == "" {
		if ver, err := httpGet(config.Config().GeoipDbUrl+"version", versionClient); err == nil {
			knownVersion = strings.TrimSpace(string(ver))
		} else {
			log.Warnln("geoip: fetch version failed: %v", err)
		}
	}
	if knownVersion != "" {
		GeoIpDBCurVersion = knownVersion
		_ = writeFileAtomic(versionPath, []byte(knownVersion))
	}
	log.Infoln("geoip: Country.mmdb downloaded (version: %s)", GeoIpDBCurVersion)
	return nil
}

// UpdateGeoIP 检查远程版本，有更新则下载替换（由 cron 每日调用）。
// 修复原实现：本地文件加载模式版本号为空导致永远跳过更新检查。
func UpdateGeoIP() {
	ver, err := httpGet(config.Config().GeoipDbUrl+"version", versionClient)
	if err != nil {
		log.Errorln("geoip: check version failed: %v", err)
		return
	}
	verStr := strings.TrimSpace(string(ver))
	if GeoIpDBCurVersion == verStr {
		return // 已是最新
	}

	log.Infoln("geoip: update available %s -> %s, downloading...", GeoIpDBCurVersion, verStr)
	if err := downloadCountryDB(verStr); err != nil {
		log.Errorln("geoip: update failed: %v", err)
	}
}

// swapClose 延迟关闭旧 reader，避免影响进行中的查询
func swapClose(old *geoip2.Reader) {
	if old == nil {
		return
	}
	time.AfterFunc(closeDelay, func() { _ = old.Close() })
}

// loadEmojiMap 加载国家 emoji 映射：优先本地文件，其次嵌入式 FS。
func loadEmojiMap() (map[string]string, error) {
	var flagsData []byte
	var err error
	if data, e := os.ReadFile("assets/flags.json"); e == nil {
		flagsData = data
	} else {
		flagsData, err = config.GeoIpFS.ReadFile("assets/flags.json")
		if err != nil {
			return nil, fmt.Errorf("read flags.json: %w", err)
		}
	}

	countryEmojiList := make([]CountryEmoji, 0)
	if err := json.Unmarshal(flagsData, &countryEmojiList); err != nil {
		return nil, fmt.Errorf("parse flags.json: %w", err)
	}
	emojiMap := make(map[string]string, len(countryEmojiList))
	for _, i := range countryEmojiList {
		emojiMap[i.Code] = i.Emoji
	}
	return emojiMap, nil
}

// Find ip info：入参为 IP 时直接解析，避免不必要的 DNS 查询
func (g GeoIP) Find(ipORdomain string) (ip, country string, err error) {
	parsed := net.ParseIP(ipORdomain)
	if parsed == nil {
		ips, err := net.LookupIP(ipORdomain)
		if err != nil {
			return "", "", err
		}
		parsed = ips[0]
	}
	ip = parsed.String()

	db := countryDB.Load()
	if db == nil {
		return ip, "", errors.New("geoip: country db not loaded")
	}

	record, err := db.City(parsed)
	if err != nil {
		return ip, "", err
	}

	countryIsoCode := record.Country.IsoCode
	if countryIsoCode == "" {
		return ip, "🏁 ZZ", nil
	}
	if emoji, found := g.emojiMap[countryIsoCode]; found {
		return ip, emoji + " " + countryIsoCode, nil
	}

	// Fallback to ip-api.com
	if code, err2 := FindFromIPAPI(ip); err2 == nil && code != "" {
		if emoji, found := g.emojiMap[code]; found {
			country = emoji + " " + code
			log.Infoln("Fallback to ip-api.com success: %s -> %s", ip, country)
			return
		}
	}
	return ip, "🏁 ZZ", nil
}

func (g GeoIP) FindCountryIsoEmoji(countryIsoCode string) string {
	return g.emojiMap[countryIsoCode]
}

// ip-api.com 免费版限速约 45 次/分钟：加 TTL 缓存（成功 24h、失败 5min）
// 并用互斥锁串行化查询，防止代理池大量 fallback 触发 429。
const (
	ipAPISuccessTTL = 24 * time.Hour
	ipAPIFailTTL    = 5 * time.Minute
	ipAPITimeout    = 5 * time.Second
)

type ipAPIEntry struct {
	code    string
	ok      bool
	expires time.Time
}

var (
	ipAPIMu    sync.Mutex
	ipAPICache = make(map[string]ipAPIEntry, 64)
)

// FindFromIPAPI 通过 ip-api.com 查询国家码（带缓存，原实现无超时无缓存）
func FindFromIPAPI(ip string) (countryCode string, err error) {
	ipAPIMu.Lock()
	defer ipAPIMu.Unlock()

	now := time.Now()
	if e, hit := ipAPICache[ip]; hit {
		if now.Before(e.expires) {
			if e.ok {
				return e.code, nil
			}
			return "", errors.New("ip-api.com query failed (cached)")
		}
		delete(ipAPICache, ip) // 惰性清理过期项
	}

	client := &http.Client{Timeout: ipAPITimeout}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,countryCode,message", ip))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ip-api.com status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var data IPAPIResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}

	if data.Status == "success" {
		ipAPICache[ip] = ipAPIEntry{code: data.CountryCode, ok: true, expires: now.Add(ipAPISuccessTTL)}
		return data.CountryCode, nil
	}
	ipAPICache[ip] = ipAPIEntry{ok: false, expires: now.Add(ipAPIFailTTL)}
	return "", fmt.Errorf("ip-api.com query failed: %s", data.Message)
}

// InitGeoIpASNDB 初始化 ASN 库：本地已有则直接加载（原实现每次启动全量下载）
func InitGeoIpASNDB() {
	if _, err := os.Stat(asnDBPath); err == nil {
		if db, err := geoip2.Open(asnDBPath); err == nil {
			asnDB.Store(db)
			log.Infoln("geoip: loaded local ASN DB")
			return
		}
	}
	UpdateGeoIpASNDB()
}

// UpdateGeoIpASNDB 下载 ASN 库并原子替换（由 cron 每日调用）
func UpdateGeoIpASNDB() {
	log.Infoln("Starting ASN DB update...")

	// 直接使用 GitHub Release 资产地址（原 git.io 短链不稳定，且已被 GitHub 停用）
	const asnDownloadURL = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
	data, err := httpGet(asnDownloadURL, downloadClient)
	if err != nil {
		log.Errorln("Failed to download ASN DB: %v", err)
	} else if err := writeFileAtomic(asnDBPath, data); err != nil {
		log.Errorln("Failed to write ASN DB: %v", err)
	} else {
		db, err := geoip2.Open(asnDBPath)
		if err != nil {
			log.Errorln("ASN DB reload failed: %v", err)
		} else {
			old := asnDB.Swap(db)
			swapClose(old)
			log.Infoln("ASN DB updated and reloaded successfully")
			return
		}
	}

	// 确保库已加载（启动时本地文件也缺失的情况）
	if asnDB.Load() == nil {
		if db, err := geoip2.Open(asnDBPath); err == nil {
			asnDB.Store(db)
			log.Infoln("ASN DB initial load success")
		} else {
			log.Infoln("ASN DB load failed (optional): %v", err)
		}
	}
}

// GetASN 返回 IP 的 ASN 组织名
func GetASN(ipStr string) (string, error) {
	db := asnDB.Load()
	if db == nil {
		return "", errors.New("ASN DB not loaded")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", errors.New("invalid IP")
	}
	record, err := db.ASN(ip)
	if err != nil {
		return "", err
	}
	return record.AutonomousSystemOrganization, nil
}

// cdnKeywordsUpper 判断 CDN 的关键词（大写预编译，避免循环内重复 ToUpper）
var cdnKeywordsUpper = []string{
	"CDN", "CONTENT DELIVERY", "EDGE", "ANYCAST", "CACHE",
	"AKAMAI", "INCAP", "STACKPATH", "BUNNY", "ZSCALER", "CLOUDFLARE", "FASTLY",
	"MICROSOFT", "AZURE", "AMAZON", "GOOGLE", "EDGIO", "EDGECAST", "LIMELIGHT",
	"CACHEFLY", "CDNETWORKS", "ARVANCLOUD", "TENCENT", "ALIBABA",
}

// IsCDN 基于本地 ASN 库判断 IP 是否属于 CDN
func IsCDN(ipStr string) bool {
	org, err := GetASN(ipStr)
	if err != nil {
		return false
	}
	orgUpper := strings.ToUpper(org)
	for _, kw := range cdnKeywordsUpper {
		if strings.Contains(orgUpper, kw) {
			return true
		}
	}
	return false
}

// httpGet 带超时与状态码检查的 GET 请求
func httpGet(url string, client *http.Client) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// writeFileAtomic 先写临时文件再原子重命名，避免进程中断留下半截文件
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
