package tool

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

const UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"

type HttpClient struct {
	*http.Client
}

var httpClient *HttpClient

var defaultClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxConnsPerHost:     500,
		MaxIdleConnsPerHost: 100,
		Proxy:               http.ProxyFromEnvironment,
	},
}

func init() {
	// httpClient = &HttpClient{http.DefaultClient}
	httpClient = &HttpClient{defaultClient}
	httpClient.Timeout = time.Second * 120
}

func GetHttpClient() *HttpClient {
	c := *httpClient
	return &c
}

func (c *HttpClient) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", UserAgent)
	return c.Do(req)
}

func (c *HttpClient) Post(url string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	// req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", UserAgent)
	return c.Do(req)
}
