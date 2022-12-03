package getter

import (
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/gammazero/workerpool"
	"gopkg.in/yaml.v3"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	"github.com/One-Piecs/proxypool/pkg/tool"
)

// Add key value pair to creatorMap(string → creator) in base.go
func init() {
	Register("nodelist", NewNodeList)
}

// NodeList is A Getter with an additional property
type NodeList struct {
	Url string
}

// Get() of NodeList is to implement Getter interface
func (s *NodeList) Get() proxy.ProxyList {
	resp, err := tool.GetHttpClient().Get(s.Url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	nodesString := strings.ReplaceAll(string(body), "\t", "")
	nodes := strings.Split(nodesString, "\n")
	// return StringArray2ProxyArray(nodes)

	wp := workerpool.New(250)
	m := sync.Mutex{}
	result := make(proxy.ProxyList, 0)

	for _, link := range nodes {
		link := link
		wp.Submit(func() {
			resp, err := tool.GetHttpClient().Get(link)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return
			}

			// clash
			conf := config{}
			err = yaml.Unmarshal(body, &conf)
			if err != nil {
				return
			}
			subResult := ClashProxy2ProxyArray(conf.Proxy)
			if len(subResult) > 0 {
				m.Lock()
				result = append(result, subResult...)
				m.Unlock()
			}

			// subscribe
			nodesString, err := tool.Base64DecodeString(string(body))
			if err != nil {
				return
			}
			nodesString = strings.ReplaceAll(nodesString, "\t", "")

			nodes := strings.Split(nodesString, "\n")
			subResult = StringArray2ProxyArray(nodes)
			if len(subResult) > 0 {
				m.Lock()
				result = append(result, subResult...)
				m.Unlock()
			}
		})

	}
	wp.StopWait()
	return result
}

// Get2Chan() of NodeList is to implement Getter interface. It gets proxies and send proxy to channel one by one
func (s *NodeList) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	nodes := s.Get()
	log.Infoln("STATISTIC: NodeList\tcost=%v\tcount=%d\turl=%s", time.Since(start), len(nodes), s.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func (s *NodeList) Get2Chan(pc chan proxy.Proxy) {
	nodes := s.Get()
	log.Infoln("STATISTIC: NodeList\tcount=%d\turl=%s", len(nodes), s.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func NewNodeList(options tool.Options) (getter Getter, err error) {
	urlInterface, found := options["url"]
	if found {
		url, err := AssertTypeStringNotNull(urlInterface)
		if err != nil {
			return nil, err
		}
		return &NodeList{
			Url: url,
		}, nil
	}
	return nil, ErrorUrlNotFound
}
