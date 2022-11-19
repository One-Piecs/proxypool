package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/pkg/tool"
)

var (
	ErrorNotVmessLink          = errors.New("not a correct vmess link")
	ErrorVmessPayloadParseFail = errors.New("vmess link payload parse failed")
)

type Vmess struct {
	Base
	UUID           string            `yaml:"uuid" json:"uuid"`
	AlterID        int               `yaml:"alterId" json:"alterId"`
	Cipher         string            `yaml:"cipher" json:"cipher"`
	Network        string            `yaml:"network,omitempty" json:"network,omitempty"`
	WSPath         string            `yaml:"ws-path,omitempty" json:"ws-path,omitempty"`
	ServerName     string            `yaml:"servername,omitempty" json:"servername,omitempty"`
	WSHeaders      map[string]string `yaml:"ws-headers,omitempty" json:"ws-headers,omitempty"`
	HTTPOpts       HTTPOptions       `yaml:"http-opts,omitempty" json:"http-opts,omitempty"`
	HTTP2Opts      HTTP2Options      `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
	TLS            bool              `yaml:"tls,omitempty" json:"tls,omitempty"`
	SkipCertVerify bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
}

type HTTPOptions struct {
	Method  string              `yaml:"method,omitempty" json:"method,omitempty"`
	Path    []string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers map[string][]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `yaml:"host,omitempty" json:"host,omitempty"`
	Path string   `yaml:"path,omitempty" json:"path,omitempty"` // 暂只处理一个Path
}

func (v Vmess) Identifier() string {
	return net.JoinHostPort(v.Server, strconv.Itoa(v.Port)) + v.Cipher + v.UUID
}

func (v Vmess) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

func (v Vmess) ToClash() string {
	{
		vvList := strings.Split(v.ServerName, ",")
		v.ServerName = vvList[0] // 只取第一个
		for k, vv := range v.WSHeaders {
			vvList := strings.Split(vv, ",")
			v.WSHeaders[k] = vvList[0] // 只取第一个

			// 去除 ‘/’ 保留域名
			if k == "host" || k == "HOST" {
				vvList = strings.Split(vvList[0], "/")
				v.WSHeaders[k] = vvList[0]
			}
		}
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return "  - " + string(data)
}

func (v Vmess) ToSurge() string {
	// node2 = vmess, server, port, username=, ws=true, ws-path=, ws-headers=
	if v.Network == "ws" {
		wsHeasers := ""
		for k, v := range v.WSHeaders {

			// surge head v 多组分割要注意 ':'  ','
			v = strings.ReplaceAll(v, "http://", "")
			v = strings.ReplaceAll(v, "https://", "")
			vv := strings.Split(v, ",")
			v = vv[0] // 只取第一个

			// 去除 ‘/’ 保留域名
			if k == "host" || k == "HOST" {
				vv = strings.Split(v, "/")
				v = vv[0]
			}

			if wsHeasers == "" {
				wsHeasers = k + ":" + v
			} else {
				wsHeasers += "|" + k + ":" + v
			}
		}

		wsPath := v.WSPath
		if v.WSPath == "" {
			wsPath = "/"
		}
		text := ""
		if v.AlterID != 0 {
			text = fmt.Sprintf("%s = vmess, %s, %d, username=%s, alterId=%d, ws=true, tls=%t, ws-path=%s, skip-cert-verify=%v",
				v.Name, v.Server, v.Port, v.UUID, v.AlterID, v.TLS, wsPath, v.SkipCertVerify)
		} else {
			text = fmt.Sprintf("%s = vmess, %s, %d, username=%s, vmess-aead=true, ws=true, tls=%t, ws-path=%s, skip-cert-verify=%v",
				v.Name, v.Server, v.Port, v.UUID, v.TLS, wsPath, v.SkipCertVerify)
		}

		if wsHeasers != "" {
			// text += ", ws-headers=" + wsHeasers
			text += fmt.Sprintf(`, ws-headers="%s|%s"`, wsHeasers, config.Config.V2WsHeaderUserAgent)
		} else {
			text += fmt.Sprintf(`, ws-headers="%s"`, config.Config.V2WsHeaderUserAgent)
		}
		return text
	} else {
		if v.AlterID != 0 {
			return fmt.Sprintf("%s = vmess, %s, %d, username=%s, alterId=%d, tls=%t, skip-cert-verify=%v",
				v.Name, v.Server, v.Port, v.UUID, v.AlterID, v.TLS, v.SkipCertVerify)
		} else {
			return fmt.Sprintf("%s = vmess, %s, %d, username=%s, vmess-aead=true, tls=%t, skip-cert-verify=%v",
				v.Name, v.Server, v.Port, v.UUID, v.TLS, v.SkipCertVerify)
		}
	}
}

func (v Vmess) ToLoon() string {
	// # 节点名称 = 协议，服务器地址，端口，加密方式，UUID，传输方式:(tcp/ws),path：websocket握手header中的path，host：websocket握手header中的path，over-tls:是否tls，tls-name：tls名字，skip-cert-verify：是否跳过证书校验（默认否）
	// 6 = vmess, 1.2.3.4, 10086, aes-128-gcm,"uuid",transport:ws,path:/,host:icloud.com,over-tls:true,tls-name:youtTlsServerName.com,skip-cert-verify:false
	// TODO: #vmess+tcp
	// # 节点名称 = 协议，服务器地址，端口，加密方式，UUID，传输方式:(tcp/ws),path：websocket握手header中的path，host：websocket握手header中的path，over-tls:是否tls，tls-name：tls名字，skip-cert-verify：是否跳过证书校验（默认否）
	// vmess1 = vmess,example.com,10086,aes-128-gcm,"52396e06-041a-4cc2-be5c-8525eb457809",transport=tcp,path=/,host=v3-dy-y.ixigua.com,over-tls:false
	// #vmess+tcp+tls
	// vmess2 = vmess,example.com,10086,aes-128-gcm,"52396e06-041a-4cc2-be5c-8525eb457809",transport=tcp,path=/,host=v3-dy-y.ixigua.com,over-tls=true,tls-name=example.com,skip-cert-verify=true
	// #vmess+ws
	// vmess3 = vmess,example.com,10086,aes-128-gcm,"52396e06-041a-4cc2-be5c-8525eb457809",transport=ws,path=/,host=v3-dy-y.ixigua.com,over-tls=false
	// #vmess+wss
	// vmess4 = vmess,example.com,10086,aes-128-gcm,"52396e06-041a-4cc2-be5c-8525eb457809",transport=ws,path=/,host=v3-dy-y.ixigua.com,over-tls=true,tls-name=example.com,skip-cert-verify=true
	var cipher string
	if v.Cipher == "auto" {
		cipher = "chacha20-ietf-poly1305"
	} else {
		cipher = v.Cipher
	}

	if v.Network == "ws" {
		text := fmt.Sprintf(`%s = vmess, %s, %d, %s, "%s", transport:%v, path:%s, over-tls:%v`,
			v.Name, v.Server, v.Port, cipher, v.UUID,
			v.Network, v.WSPath, v.TLS)
		if v.TLS {
			text += ", tls-name:" + v.Server
			text += fmt.Sprintf(", skip-cert-verify:%v", v.SkipCertVerify)
		}
		if v.WSHeaders["HOST"] != "" {
			// loon host v 多组分割要注意 ':'  ','
			vv := strings.ReplaceAll(v.WSHeaders["HOST"], "http://", "")
			vv = strings.ReplaceAll(vv, "https://", "")
			vvList := strings.Split(vv, ",")
			v.WSHeaders["HOST"] = vvList[0] // 只取第一个

			// 去除 ‘/’ 保留域名
			vvList = strings.Split(v.WSHeaders["HOST"], "/")
			v.WSHeaders["HOST"] = vvList[0]

			text += ", host:" + v.WSHeaders["HOST"]
		}
		return text
	} else {
		text := fmt.Sprintf(`%s = vmess, %s, %d, %s, "%s", transport:%v, path:%s, over-tls:%v`,
			v.Name, v.Server, v.Port, cipher, v.UUID,
			v.Network, v.WSPath, v.TLS)
		if v.TLS {
			text += fmt.Sprintf(", skip-cert-verify:%v", v.SkipCertVerify)
		}
		return text
	}
}

func (v Vmess) Clone() Proxy {
	return &v
}

func (v Vmess) Link() (link string) {
	vjv, err := json.Marshal(v.toLinkJson())
	if err != nil {
		return
	}
	return fmt.Sprintf("vmess://%s", tool.Base64EncodeBytes(vjv))
}

type vmessLinkJson struct {
	Add  string `json:"add"`
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Port int    `json:"port"`
	Id   string `json:"id"`
	Aid  string `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
}

func (v Vmess) toLinkJson() vmessLinkJson {
	vj := vmessLinkJson{
		Add:  v.Server,
		Ps:   v.Name,
		Port: v.Port,
		Id:   v.UUID,
		Aid:  strconv.Itoa(v.AlterID),
		Net:  v.Network,
		Path: v.WSPath,
		Host: v.ServerName,
		V:    "2",
	}
	if v.TLS {
		vj.Tls = "tls"
	}
	if host, ok := v.WSHeaders["HOST"]; ok && host != "" {
		vj.Host = host
	}
	return vj
}

func ParseVmessLink(link string) (*Vmess, error) {
	if !strings.HasPrefix(link, "vmess") {
		return nil, ErrorNotVmessLink
	}

	vmessmix := strings.SplitN(link, "://", 2)
	if len(vmessmix) < 2 {
		return nil, ErrorNotVmessLink
	}
	linkPayload := vmessmix[1]
	if strings.Contains(linkPayload, "?") {
		// 使用第二种解析方法 目测是Shadowrocket格式
		var infoPayloads []string
		if strings.Contains(linkPayload, "/?") {
			infoPayloads = strings.SplitN(linkPayload, "/?", 2)
		} else {
			infoPayloads = strings.SplitN(linkPayload, "?", 2)
		}
		if len(infoPayloads) < 2 {
			return nil, ErrorNotVmessLink
		}

		baseInfo, err := tool.Base64DecodeString(infoPayloads[0])
		if err != nil {
			return nil, ErrorVmessPayloadParseFail
		}
		baseInfoPath := strings.Split(baseInfo, ":")
		if len(baseInfoPath) < 3 {
			return nil, ErrorPathNotComplete
		}
		// base info
		cipher := baseInfoPath[0]
		mixInfo := strings.SplitN(baseInfoPath[1], "@", 2)
		if len(mixInfo) < 2 {
			return nil, ErrorVmessPayloadParseFail
		}
		uuid := mixInfo[0]
		server := mixInfo[1]
		portStr := baseInfoPath[2]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, ErrorVmessPayloadParseFail
		}

		moreInfo, _ := url.ParseQuery(infoPayloads[1])
		remarks := moreInfo.Get("remarks")

		// Transmission protocol
		wsHeaders := make(map[string]string)
		h2Opt := HTTP2Options{
			Host: make([]string, 0),
		}
		httpOpt := HTTPOptions{}

		// Network <- obfs=websocket
		obfs := moreInfo.Get("obfs")
		network := ""
		if obfs == "http" {
			httpOpt.Method = "GET" // 不知道Headers为空时会不会报错
		}
		if obfs == "websocket" {
			network = "ws"
		} else { // when http h2
			network = obfs
		}
		// HTTP Object: Host <- obfsParam=www.036452916.xyz
		host := moreInfo.Get("obfsParam")
		if host != "" {
			switch obfs {
			case "websocket":
				wsHeaders["Host"] = host
			case "h2":
				h2Opt.Host = append(h2Opt.Host, host)
			}
		}
		// HTTP Object: Path
		path := moreInfo.Get("path")
		if path == "" {
			path = "/"
		}
		switch obfs {
		case "h2":
			h2Opt.Path = path
			path = ""
		case "http":
			httpOpt.Path = append(httpOpt.Path, path)
			path = ""
		}

		tls := moreInfo.Get("tls") == "1"
		if obfs == "h2" {
			tls = true
		}
		// allowInsecure=1 Clash config unsuported
		// alterId=64
		aid := 0
		aidStr := moreInfo.Get("alterId")
		if aidStr != "" {
			aid, _ = strconv.Atoi(aidStr)
		}

		return &Vmess{
			Base: Base{
				Name:   remarks + "_" + strconv.Itoa(rand.Int()),
				Server: server,
				Port:   port,
				Type:   "vmess",
				UDP:    false,
			},
			UUID:           uuid,
			AlterID:        aid,
			Cipher:         cipher,
			TLS:            tls,
			Network:        network,
			HTTPOpts:       httpOpt,
			HTTP2Opts:      h2Opt,
			WSPath:         path,
			WSHeaders:      wsHeaders,
			SkipCertVerify: true,
			ServerName:     server,
		}, nil
	} else {
		// V2rayN ref: https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
		payload, err := tool.Base64DecodeString(linkPayload)
		if err != nil {
			return nil, ErrorVmessPayloadParseFail
		}
		vmessJson := vmessLinkJson{}
		jsonMap, err := str2jsonDynaUnmarshal(payload)
		if err != nil {
			return nil, err
		}
		vmessJson, err = mapStrInter2VmessLinkJson(jsonMap)
		if err != nil {
			return nil, err
		}

		alterId, err := strconv.Atoi(vmessJson.Aid)
		if err != nil {
			alterId = 0
		}
		tls := vmessJson.Tls == "tls"

		if vmessJson.Net == "h2" {
			tls = true
		}

		wsHeaders := make(map[string]string)
		h2Opt := HTTP2Options{}
		httpOpt := HTTPOptions{}

		if vmessJson.Net == "http" {
			httpOpt.Method = "GET" // 不知道Headers为空时会不会报错
		}

		if vmessJson.Host != "" {
			switch vmessJson.Net {
			case "h2":
				h2Opt.Host = append(h2Opt.Host, vmessJson.Host) // 不知道为空时会不会报错
			case "ws":
				wsHeaders["HOST"] = vmessJson.Host
			}
		}

		if vmessJson.Path == "" {
			vmessJson.Path = "/"
		}
		switch vmessJson.Net {
		case "h2":
			h2Opt.Path = vmessJson.Path
			vmessJson.Path = ""
		case "http":
			httpOpt.Path = append(httpOpt.Path, vmessJson.Path)
			vmessJson.Path = ""
		}

		return &Vmess{
			Base: Base{
				Name:   "",
				Server: vmessJson.Add,
				Port:   vmessJson.Port,
				Type:   "vmess",
				UDP:    false,
			},
			UUID:           vmessJson.Id,
			AlterID:        alterId,
			Cipher:         "auto",
			Network:        vmessJson.Net,
			HTTPOpts:       httpOpt,
			HTTP2Opts:      h2Opt,
			WSPath:         vmessJson.Path,
			WSHeaders:      wsHeaders,
			ServerName:     vmessJson.Host,
			TLS:            tls,
			SkipCertVerify: true,
		}, nil
	}
}

var vmessPlainRe = regexp.MustCompile("vmess://([A-Za-z0-9+/_?&=-])+")

func GrepVmessLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "vmess://")
	for _, text := range texts {
		results = append(results, vmessPlainRe.FindAllString("vmess://"+text, -1)...)
	}
	return results
}

func str2jsonDynaUnmarshal(s string) (jsn map[string]interface{}, err error) {
	var f interface{}
	err = json.Unmarshal([]byte(s), &f)
	if err != nil {
		return nil, err
	}
	jsn = f.(map[string]interface{}) // f is pointer point to map struct
	if jsn == nil {
		return nil, ErrorVmessPayloadParseFail
	}
	return jsn, err
}

func mapStrInter2VmessLinkJson(jsn map[string]interface{}) (vmessLinkJson, error) {
	vmess := vmessLinkJson{}
	var err error

	vmessVal := reflect.ValueOf(&vmess).Elem()
	for i := 0; i < vmessVal.NumField(); i++ {
		tags := vmessVal.Type().Field(i).Tag.Get("json")
		tag := strings.Split(tags, ",")
		if jsnVal, ok := jsn[strings.ToLower(tag[0])]; ok {
			if strings.ToLower(tag[0]) == "port" { // set int in port
				switch jsnVal := jsnVal.(type) {
				case float64:
					vmessVal.Field(i).SetInt(int64(jsnVal))
				case string: // Force Convert
					valInt, err := strconv.Atoi(jsnVal)
					if err != nil {
						valInt = 443
					}
					vmessVal.Field(i).SetInt(int64(valInt))
				default:
					vmessVal.Field(i).SetInt(443)
				}
			} else if strings.ToLower(tag[0]) == "ps" {
				continue
			} else { // set string in other fields
				switch jsnVal := jsnVal.(type) {
				case string:
					vmessVal.Field(i).SetString(jsnVal)
				default: // Force Convert
					vmessVal.Field(i).SetString(fmt.Sprintf("%v", jsnVal))
				}
			}
		}
	}
	return vmess, err
}
