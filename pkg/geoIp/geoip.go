package geoIp

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/log"

	// bingeoip "github.com/One-Piecs/proxypool/internal/bindata/geoip"

	"github.com/oschwald/geoip2-golang"
)

var GeoIpDB GeoIP

var GeoIpDBCurVersion string

func InitGeoIpDB() error {
	// geodb := "assets/GeoLite2-City.mmdb"
	// // 判断文件是否存在
	// _, err := os.Stat(geodb)
	// if err != nil && os.IsNotExist(err) {
	// 	err = bingeoip.RestoreAsset("", "assets/flags.json")
	// 	if err != nil {
	// 		panic(err)
	// 		return err
	// 	}
	// 	err = bingeoip.RestoreAsset("", "assets/GeoLite2-City.mmdb")
	// 	if err != nil {
	// 		log.Println("文件不存在，请自行下载 Geoip2 City库，并保存在", geodb)
	// 		panic(err)
	// 		return err
	// 	}
	// 	// GeoIpDB = NewGeoIP("assets/GeoLite2-City.mmdb", "assets/flags.json")
	// }

	// https://raw.githubusercontent.com/alecthw/mmdb_china_ip_list/release/Country.mmdb
	// http://www.ideame.top/mmdb/version
	GeoIpDB = NewGeoIP("assets/Country.mmdb", "assets/flags.json")
	InitGeoIpASNDB()
	return nil
}

func ReInitGeoIpDB() {
	db := GeoIpDB
	defer db.db.Close()

	// log.Println("更新Country.mmdb")
	GeoIpDB = NewGeoIP("assets/Country.mmdb", "assets/flags.json")
}

// GeoIP2
type GeoIP struct {
	db       *geoip2.Reader
	emojiMap map[string]string
}

type CountryEmoji struct {
	Code  string `json:"code"`
	Emoji string `json:"emoji"`
}

type IPAPIResponse struct {
	CountryCode string `json:"countryCode"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

// new geoip from db file
func NewGeoIP(geodb, flags string) (geoip GeoIP) {
	// 运行到这里时geodb只能为存在
	db, err := geoip2.Open(geodb)
	if err != nil {
		// log.Println(err)
		buf, err := GeoIpBinary(config.Config().GeoipDbUrl + "Country.mmdb")
		if err != nil {
			panic(err)
		}

		db, err = geoip2.FromBytes(buf)
		if err != nil {
			panic(err)
		}

		ver, err := GeoIpVersion(config.Config().GeoipDbUrl + "version")
		if err != nil {
			panic(err)
		}

		GeoIpDBCurVersion = ver

	}
	geoip.db = db

	var flagsData []byte
	_, err = os.Stat(flags)
	if err != nil && os.IsNotExist(err) {
		// log.Println("flags 文件不存在，请自行下载 flags.json，并保存在", flags)
		// os.Exit(1)
		flagsData, err = config.GeoIpFS.ReadFile(flags)
		if err != nil {
			panic(err)
		}

	} else {
		flagsData, err = os.ReadFile(flags)
		if err != nil {
			panic(err)
		}
	}

	countryEmojiList := make([]CountryEmoji, 0)
	err = json.Unmarshal(flagsData, &countryEmojiList)
	if err != nil {
		panic(err.Error())
	}

	emojiMap := make(map[string]string)
	for _, i := range countryEmojiList {
		emojiMap[i.Code] = i.Emoji
	}
	geoip.emojiMap = emojiMap

	return
}

func GeoIpBinary(url string) (data []byte, err error) {
	// Create client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("GeoIpBinary NewRequest Failure : ", err)
		return nil, err
	}

	// Fetch Request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("GeoIpBinary Failure : ", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Get Country.mmdb: %v", resp.StatusCode)
	}

	// Read Response Body
	return io.ReadAll(resp.Body)
}

func GeoIpVersion(url string) (version string, err error) {
	// Create client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("GeoIpBinary NewRequest Failure : ", err)
		return "", err
	}

	// Fetch Request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("GeoIpBinary Failure : ", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Get Country.mmdb: %v", resp.StatusCode)
	}

	// Read Response Body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

// new geoip from db file
func UpdateGeoIP() {
	if GeoIpDBCurVersion == "" {
		return
	}

	ver, err := GeoIpVersion(config.Config().GeoipDbUrl + "version")
	if err != nil {
		log.Errorln("GeoIpVersion: %v", err)
		return
	}
	if GeoIpDBCurVersion != ver {
		// log.Println(err)
		buf, err := GeoIpBinary(config.Config().GeoipDbUrl + "lite/Country.mmdb")
		if err != nil {
			log.Errorln("GeoIpBinary: %v", err)
			return
		}

		db, err := geoip2.FromBytes(buf)
		if err != nil {
			log.Errorln("geoip2 load GeoIpBinary: %v", err)
			return
		}

		oldDB := GeoIpDB.db
		defer oldDB.Close()

		GeoIpDB.db = db
		GeoIpDBCurVersion = ver
	}
}

// Find ip info
func (g GeoIP) Find(ipORdomain string) (ip, country string, err error) {
	ips, err := net.LookupIP(ipORdomain)
	if err != nil {
		return "", "", err
	}
	ip = ips[0].String()

	var record *geoip2.City
	record, err = g.db.City(ips[0])
	if err != nil {
		return
	}
	countryIsoCode := record.Country.IsoCode
	if countryIsoCode == "" {
		country = "🏁 ZZ"
	}
	emoji, found := g.emojiMap[countryIsoCode]
	if found {
		country = fmt.Sprintf("%v %v", emoji, countryIsoCode)
	} else {
		// Fallback to ip-api.com
		countryCode, err2 := FindFromIPAPI(ips[0].String())
		if err2 == nil && countryCode != "" {
			countryIsoCode = countryCode
			emoji, found = g.emojiMap[countryIsoCode]
			if found {
				country = fmt.Sprintf("%v %v", emoji, countryIsoCode)
				log.Infoln("Fallback to ip-api.com success: %s -> %s", ips[0].String(), country)
				return
			}
		}
		country = "🏁 ZZ"
	}
	return
}

func FindFromIPAPI(ip string) (countryCode string, err error) {
	resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,countryCode,message", ip))
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
		return data.CountryCode, nil
	}
	return "", fmt.Errorf("ip-api.com query failed: %s", data.Message)
}

func (g GeoIP) FindCountryIsoEmoji(countryIsoCode string) string {
	return g.emojiMap[countryIsoCode]
}

var GeoIpASNDB *geoip2.Reader

// UpdateGeoIpASNDB Force download daily
func UpdateGeoIpASNDB() {
	dbPath := "assets/GeoLite2-ASN.mmdb"
	downloadUrl := "https://git.io/GeoLite2-ASN.mmdb"

	log.Infoln("Starting daily ASN DB update...")

	resp, err := http.Get(downloadUrl)
	if err != nil {
		log.Errorln("Failed to download ASN DB: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(resp.Body)
			if err == nil {
				if err := os.WriteFile(dbPath, data, 0644); err == nil {
					log.Infoln("ASN DB downloaded and updated successfully")

					// Reload DB
					db, err := geoip2.Open(dbPath)
					if err != nil {
						log.Errorln("ASN DB reload failed: %v", err)
						return
					}

					if GeoIpASNDB != nil {
						GeoIpASNDB.Close()
					}
					GeoIpASNDB = db
					log.Infoln("ASN DB reloaded successfully")
				} else {
					log.Errorln("Failed to write ASN DB: %v", err)
				}
			} else {
				log.Errorln("Failed to read ASN DB body: %v", err)
			}
		} else {
			log.Errorln("Failed to download ASN DB, status: %d", resp.StatusCode)
		}
	}

	// Ensure DB is loaded if it wasn't already (e.g. startup)
	if GeoIpASNDB == nil {
		db, err := geoip2.Open(dbPath)
		if err != nil {
			log.Infoln("ASN DB load failed (optional): %v", err)
			return
		}
		GeoIpASNDB = db
		log.Infoln("ASN DB initial load success")
	}
}

func InitGeoIpASNDB() {
	UpdateGeoIpASNDB()
}

// GetASN returns the ASN organization for an IP
func GetASN(ipStr string) (string, error) {
	if GeoIpASNDB == nil {
		return "", fmt.Errorf("ASN DB not loaded")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP")
	}
	record, err := GeoIpASNDB.ASN(ip)
	if err != nil {
		return "", err
	}
	return record.AutonomousSystemOrganization, nil
}

// IsCDN checks if the IP belongs to a CDN based on local ASN DB
func IsCDN(ipStr string) bool {
	org, err := GetASN(ipStr)
	if err != nil {
		return false
	}

	// Keywords to detect CDN (same as in pkg/cdn/asn.go but for local check)
	keywords := []string{
		"CDN", "Content Delivery", "Edge", "Anycast", "Cache",
		"Akamai", "Incap", "Stackpath", "Bunny", "Zscaler", "Cloudflare", "Fastly",
		"Microsoft", "Azure", "Amazon", "Google", "Edgio", "Edgecast", "Limelight",
		"CacheFly", "CDNetworks", "ArvanCloud", "Tencent", "Alibaba",
	}

	orgUpper := strings.ToUpper(org)
	for _, kw := range keywords {
		if strings.Contains(orgUpper, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}
