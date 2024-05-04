package geoIp

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

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

// new geoip from db file
func NewGeoIP(geodb, flags string) (geoip GeoIP) {
	// 运行到这里时geodb只能为存在
	db, err := geoip2.Open(geodb)
	if err != nil {
		// log.Println(err)
		buf, err := GeoIpBinary(config.Config().GeoipDbUrl + "lite/Country.mmdb")
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
		flagsData, err = ioutil.ReadFile(flags)
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
	return ioutil.ReadAll(resp.Body)
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
	respBody, err := ioutil.ReadAll(resp.Body)
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
		country = "🏁 ZZ"
	}
	return
}
