package healthcheck

import (
	"sort"
	"sync"

	"github.com/One-Piecs/proxypool/pkg/proxy"
)

// statsLock 保护全局 ProxyStats 的并发访问：
// 爬取管道（延迟/测速/中转/ChatGPT 检测）与 HTTP 请求（provider.preFilter）会并发读写。
var statsLock sync.RWMutex

// FindStat 并发安全地查找代理统计
func FindStat(p proxy.Proxy) (*Stat, bool) {
	statsLock.RLock()
	defer statsLock.RUnlock()
	return ProxyStats.Find(p)
}

// AppendStat 并发安全地追加代理统计
func AppendStat(s Stat) {
	statsLock.Lock()
	ProxyStats = append(ProxyStats, s)
	statsLock.Unlock()
}

// IncReqCount 并发安全地对代理的请求计数 +1，不存在则新建一条统计。
func IncReqCount(p proxy.Proxy) {
	statsLock.Lock()
	if ps, ok := ProxyStats.Find(p); ok {
		ps.ReqCount++
	} else {
		ProxyStats = append(ProxyStats, Stat{
			Id:       p.Identifier(),
			ReqCount: 1,
		})
	}
	statsLock.Unlock()
}

// InitSpeed 恢复历史测速结果到统计（启动从数据库加载时调用）。
// 同时置 SpeedExist，使 provider 的速度过滤与标签立即生效。
func InitSpeed(id string, speed float64) {
	if speed <= 0 {
		return
	}
	statsLock.Lock()
	for i := range ProxyStats {
		if ProxyStats[i].Id == id {
			ProxyStats[i].Speed = speed
			statsLock.Unlock()
			SpeedExist = true
			return
		}
	}
	ProxyStats = append(ProxyStats, Stat{Id: id, Speed: speed})
	statsLock.Unlock()
	SpeedExist = true
}

// Statistic for a proxy
type Stat struct {
	Speed    float64
	Delay    uint16
	ReqCount uint16
	Relay    bool
	Pool     bool
	ChatGPT  bool
	OutIp    string
	Id       string
}

// Statistic array for proxies
type StatList []Stat

// ProxyStats stores proxies' statistics
var ProxyStats StatList

func init() {
	ProxyStats = make(StatList, 0)
}

// Update speed for a Stat
func (ps *Stat) UpdatePSSpeed(speed float64) {
	if ps.Speed < 60 && ps.Speed != 0 {
		ps.Speed = 0.3*ps.Speed + 0.7*speed
	} else {
		ps.Speed = speed
	}
}

// Update delay for a Stat
func (ps *Stat) UpdatePSDelay(delay uint16) {
	ps.Delay = delay
}

// Update out ip for a Stat
func (ps *Stat) UpdatePSOutIp(outIp string) {
	ps.OutIp = outIp
}

// Count + 1 for a Stat
func (ps *Stat) UpdatePSCount() {
	ps.ReqCount++
}

// Find a proxy's Stat in StatList
func (psList StatList) Find(p proxy.Proxy) (*Stat, bool) {
	s := p.Identifier()
	for i := range psList {
		if psList[i].Id == s {
			return &psList[i], true
		}
	}
	return nil, false
}

// Return proxies that request count more than a given nubmer
func (psList StatList) ReqCountThan(n uint16, pl []proxy.Proxy, reset bool) []proxy.Proxy {
	statsLock.RLock()
	// 先构建 Id → 请求次数 的索引，将 O(n*m) 降为 O(n+m)
	countMap := make(map[string]uint16, len(psList))
	for j := range psList {
		countMap[psList[j].Id] = psList[j].ReqCount
	}
	statsLock.RUnlock()

	proxies := make([]proxy.Proxy, 0, len(pl))
	for _, p := range pl {
		if p == nil {
			continue
		}
		if countMap[p.Identifier()] > n {
			proxies = append(proxies, p)
		}
	}

	// reset request count
	if reset {
		statsLock.Lock()
		for i := range psList {
			psList[i].ReqCount = 0
		}
		statsLock.Unlock()
	}
	return proxies
}

// Sort proxies by speed. Notice that this returns the same pointer.
// 使用稳定的 sort.SliceStable 替代手写冒泡排序，将 O(n^2) 降为 O(n log n)。
func (psList StatList) SortProxiesBySpeed(proxies []proxy.Proxy) []proxy.Proxy {
	if ok := checkErrorProxies(proxies); !ok {
		return proxies
	}
	l := len(proxies)
	if l == 1 {
		return proxies
	}

	statsLock.RLock()
	// 预取每个代理的速度记录，避免在比较器中反复线性查找
	speedMap := make(map[string]float64, l)
	for _, p := range proxies {
		if ps, ok := psList.Find(p); ok {
			speedMap[p.Identifier()] = ps.Speed
		}
	}
	statsLock.RUnlock()

	// 排序规则：有测速记录的排前面（速度从大到小），无记录的排后面
	sort.SliceStable(proxies, func(i, j int) bool {
		si, oki := speedMap[proxies[i].Identifier()]
		sj, okj := speedMap[proxies[j].Identifier()]
		switch {
		case oki && okj:
			return si > sj
		case oki:
			return true
		default:
			return false
		}
	})
	return proxies
}
