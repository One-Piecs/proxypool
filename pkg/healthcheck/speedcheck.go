package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gammazero/workerpool"

	"github.com/metacubex/mihomo/adapter"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	C "github.com/metacubex/mihomo/constant"
)

var (
	SpeedTimeout = time.Second * 10
	SpeedExist   = false
)

// speedTestWithWorkpool 并发测速公共实现。
// newOnly=true 时仅测试尚未测速或速度为 0 的节点（首次/增量测速）。
func speedTestWithWorkpool(proxies []proxy.Proxy, conns int, newOnly bool) {
	SpeedExist = true
	if ok := checkErrorProxies(proxies); !ok {
		return
	}
	numWorker := conns
	if numWorker <= 0 {
		numWorker = 5
	}

	resultCount := 0
	progress := newProgress(len(proxies))

	log.Infoln("Speed Test ON")

	pool := workerpool.New(numWorker)
	for _, p := range proxies {
		pp := p
		pool.Submit(func() {
			defer progress.inc()

			if newOnly {
				// 仅在节点尚未测速或速度仍为 0 时测试
				statsLock.RLock()
				proxyStat, exists := ProxyStats.Find(pp)
				needTest := !exists || proxyStat.Speed == 0
				statsLock.RUnlock()
				if !needTest {
					return
				}
			}

			speed, err := ProxySpeedTest(pp)
			if err == nil && speed > 0 {
				statsLock.Lock()
				if proxyStat, ok := ProxyStats.Find(pp); ok {
					proxyStat.UpdatePSSpeed(speed)
				} else {
					ProxyStats = append(ProxyStats, Stat{
						Id:    pp.Identifier(),
						Speed: speed,
					})
				}
				resultCount++
				statsLock.Unlock()
			}
		})
	}
	pool.StopWait()
	log.Infoln("Speed Test Done. Speed results count: %d", resultCount)
}

// SpeedTestAllWithWorkpool tests speed of a group of proxies. Results are stored in ProxyStats
func SpeedTestAllWithWorkpool(proxies []proxy.Proxy, conns int) {
	speedTestWithWorkpool(proxies, conns, false)
}

// SpeedTestNewWithWorkpool tests speed of new proxies which is not in ProxyStats or
// whose speed is still 0. Then appended to ProxyStats.
func SpeedTestNewWithWorkpool(proxies []proxy.Proxy, conns int) {
	speedTestWithWorkpool(proxies, conns, true)
}

// ProxySpeedTest returns a speed result of a proxy. The speed result is like 20Mbit/s. -1 for error.
func ProxySpeedTest(p proxy.Proxy) (speedResult float64, err error) {
	// 增加测速国家白名单
	if len(config.Config().SpeedCountryWhiteList) != 0 {
		countryOk := false
		countries := strings.Split(config.Config().SpeedCountryWhiteList, ",")
		for _, c := range countries {
			if strings.Contains(p.BaseInfo().Name, c) {
				countryOk = true
				break
			}
		}

		if !countryOk {
			// 不在白名单内
			return 0, nil
		}
	}

	// convert to clash proxy struct（直接构造 map，避免 JSON 往返）
	pmap := proxy.ToClashMap(p)
	if pmap == nil {
		return -1, fmt.Errorf("unsupported proxy type: %s", p.TypeName())
	}

	if p.TypeName() == "vmess" {
		if network, ok := pmap["network"]; ok && network.(string) == "h2" {
			return 0, nil // todo 暂无方法测试h2的速度，clash对于h2的connection会阻塞
		}
	}

	clashProxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return -1, err
	}

	// start speedtest using speedtest.net
	var user *User
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		user, _ = fetchUserInfo(clashProxy)
	}()
	serverList, err := fetchServerList(clashProxy)
	if err != nil {
		return -1, err
	}

	// deal fetchUserInfo routine
	wg.Wait()

	if len(serverList.Servers) == 0 {
		return -1, errors.New("unexpected error when fetching serverlist: unexpected 0 server")
	}

	// Calculate distance
	if user != nil {
		for i := range serverList.Servers {
			server := serverList.Servers[i]
			sLat, _ := strconv.ParseFloat(server.Lat, 64)
			sLon, _ := strconv.ParseFloat(server.Lon, 64)
			uLat, _ := strconv.ParseFloat(user.Lat, 64)
			uLon, _ := strconv.ParseFloat(user.Lon, 64)
			server.Distance = distance(sLat, sLon, uLat, uLon)
		}
		// Sort by distance
		sort.Sort(ByDistance{serverList.Servers})
	} else {
		// 获取用户位置失败（config 接口被墙等），退化使用服务器列表前几个
		log.Debugln("fetchUserInfo failed, skip distance sort: %s", p.Identifier())
	}

	var targets Servers
	if len(serverList.Servers) >= 3 {
		targets = serverList.Servers[:3]
	} else {
		targets = serverList.Servers
	}

	// Test
	targets.StartTest(clashProxy)
	speedResult = targets.GetResult()

	return speedResult, nil
}

/* Test with SpeedTest.net */
// Download Size(MB)  0.245 0.5 1.125  2   5     8     12.5  18    24.5  32
var dlSizes = [...]int{350, 500, 750, 1000, 1500, 2000, 2500, 3000, 3500, 4000}

func pingTest(clashProxy C.Proxy, sURL string) time.Duration {
	pingURL := strings.Split(sURL, "/upload")[0] + "/latency.txt"

	l := time.Second * 10
	for i := 0; i < 2; i++ {
		sTime := time.Now()
		err := HTTPGetViaProxy(clashProxy, pingURL)
		fTime := time.Now()
		if err != nil {
			continue
		}
		if fTime.Sub(sTime) < l {
			l = fTime.Sub(sTime)
		}
	}
	return l / 2.0
}

// return a speed(Mbps)
func downloadTest(clashProxy C.Proxy, sURL string, latency time.Duration) float64 {
	dlURL := strings.Split(sURL, "/upload")[0]

	// Warming up
	sTime := time.Now()
	err := dlWarmUp(clashProxy, dlURL)
	fTime := time.Now()
	if err != nil {
		return 0
	}
	// 1.125MB for each request (750 * 750 * 2)
	wuSpeed := 1.125 * 8 * 2 / fTime.Sub(sTime.Add(latency)).Seconds()

	// Decide workload by warm up speed. Weight is the level of size.
	weight := 0
	if 10.0 < wuSpeed {
		weight = 5
	} else if 5 < wuSpeed {
		weight = 4
	} else if 2.5 < wuSpeed {
		weight = 3
	} else { // if too slow, skip main test to save time
		return wuSpeed
	}

	// Main speedtest
	dlSpeed := wuSpeed
	sTime = time.Now()
	err = downloadRequest(clashProxy, dlURL, weight)
	fTime = time.Now()
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		return dlSpeed // todo Incorrect Result
	}
	reqMB := dlSizes[weight] * dlSizes[weight] * 2 / 1000 / 1000
	dlSpeed = float64(reqMB) * 8 / fTime.Sub(sTime).Seconds()
	return dlSpeed
}

func dlWarmUp(clashProxy C.Proxy, dlURL string) error {
	size := dlSizes[2]
	url := dlURL + "/random" + strconv.Itoa(size) + "x" + strconv.Itoa(size) + ".jpg"
	err := HTTPGetBodyForSpeedTest(clashProxy, url, SpeedTimeout)
	if err != nil {
		return err
	}
	return nil
}

func downloadRequest(clashProxy C.Proxy, dlURL string, w int) error {
	size := dlSizes[w]
	url := dlURL + "/random" + strconv.Itoa(size) + "x" + strconv.Itoa(size) + ".jpg"
	err := HTTPGetBodyForSpeedTest(clashProxy, url, SpeedTimeout)
	if err != nil {
		return err
	}
	return nil
}
