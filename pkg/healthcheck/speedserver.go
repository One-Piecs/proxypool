package healthcheck

import (
	"bytes"
	"encoding/xml"
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

// speedtest.net config
type User struct {
	IP  string `xml:"ip,attr"`
	Lat string `xml:"lat,attr"`
	Lon string `xml:"lon,attr"`
	Isp string `xml:"isp,attr"`
}

// Users : for decode speedtest.net xml
type Users struct {
	Users []User `xml:"client"`
}

// fetchUserInfo with proxy connection
func fetchUserInfo(clashProxy C.Proxy) (user *User, err error) {
	url := "https://www.speedtest.net/speedtest-config.php"
	// config 接口走代理，用与服务器列表一致的超时，避免慢代理 5s 内取不完
	body, err := HTTPGetBodyViaProxyWithTime(clashProxy, url, serverListTimeout)
	if err != nil {
		return nil, errors.New("Get user to speedtest.net. :" + err.Error())
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	users := Users{}
	for {
		t, _ := decoder.Token()
		if t == nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			_ = decoder.DecodeElement(&users, &se)
		}
	}
	if users.Users == nil {
		// log.Println("Warning: Cannot fetch user information. http://www.speedtest.net/speedtest-config.php is temporarily unavailable.")
		return nil, errors.New("No user to speedtest.net. ")
	}
	return &users.Users[0], nil
}
