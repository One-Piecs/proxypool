package api

import (
	"html/template"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/One-Piecs/proxypool/internal/cron"

	"github.com/arl/statsviz"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/One-Piecs/proxypool/pkg/provider"

	"github.com/One-Piecs/proxypool/internal/app"

	"github.com/One-Piecs/proxypool/config"
	appcache "github.com/One-Piecs/proxypool/internal/cache"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	"github.com/gin-contrib/cache"
	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	_ "github.com/heroku/x/hmetrics/onload"
)

var (
	version string
	router  *gin.Engine
)

func SetVersion(v string) {
	version = v
}

// serveProxyList 统一处理 /clash|/surge|/loon|/v2rayn/proxies 四个接口的逻辑：
// 解析公共筛选参数，无筛选时优先返回缓存，type=all 时使用全量代理。
func serveProxyList(c *gin.Context, cacheKey string, supportUnderlyingProxy bool, provide func(proxy.ProxyList, provider.Base) string) string {
	proxyTypes := c.DefaultQuery("type", "")
	proxyCountry := c.DefaultQuery("c", "")
	proxyNotCountry := c.DefaultQuery("nc", "")
	proxySpeed := c.DefaultQuery("speed", "")
	proxyFilter := c.DefaultQuery("filter", "")
	proxyUnderlyingProxy := c.DefaultQuery("underlyingproxy", "")

	noFilter := proxyTypes == "" && proxyCountry == "" && proxyNotCountry == "" &&
		proxySpeed == "" && proxyFilter == "" &&
		(!supportUnderlyingProxy || proxyUnderlyingProxy == "")

	base := provider.Base{
		Types:           proxyTypes,
		Country:         proxyCountry,
		NotCountry:      proxyNotCountry,
		Speed:           proxySpeed,
		Filter:          proxyFilter,
		UnderlyingProxy: proxyUnderlyingProxy,
	}

	if noFilter {
		// 命中缓存则直接返回；否则生成一次并缓存（测速后由任务刷新）
		if text := appcache.GetString(cacheKey); text != "" {
			return text
		}
		proxies := appcache.GetProxies("proxies")
		base.Proxies = &proxies
		text := provide(proxies, base)
		appcache.SetString(cacheKey, text)
		return text
	}

	// 根据Query筛选节点：type=all 使用全量节点，否则使用可用节点
	key := "proxies"
	if proxyTypes == "all" {
		key = "allproxies"
	}
	proxies := appcache.GetProxies(key)
	base.Proxies = &proxies
	return provide(proxies, base)
}

func setupRouter() {
	gin.SetMode(gin.ReleaseMode)
	router = gin.New()              // 没有任何中间件的路由
	temp, err := loadHTMLTemplate() // 加载html模板，模板源存放于html.go中的类似_assetsHtmlSurgeHtml的变量
	if err != nil {
		panic(err)
	}
	router.SetHTMLTemplate(temp) // 应用模板

	store := persistence.NewInMemoryStore(time.Minute)
	router.Use(gin.Recovery(), cache.SiteCache(store, time.Minute)) // 加上处理panic的中间件，防止遇到panic退出程序

	// router.Use(gin.Recovery())
	pprof.Register(router)

	// Create statsviz server.
	srv, _ := statsviz.NewServer(statsviz.Root("/debug/statsviz"))
	ws := srv.Ws()
	index := srv.Index()

	router.GET("/debug/statsviz/*filepath", func(context *gin.Context) {
		if context.Param("filepath") == "/ws" {
			ws(context.Writer, context.Request)
			return
		}
		index(context.Writer, context.Request)
	})

	// router.StaticFS("/static", http.FS(config.StaticFS))

	router.GET("/static/index.js", func(c *gin.Context) {
		c.Header("Content-Type", "text/javascript")
		data, _ := config.StaticFS.ReadFile("assets/static/index.js")
		c.String(200, string(data))
	})

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"domain":                      config.Config().Domain,
			"getters_count":               appcache.GettersCount,
			"all_proxies_count":           appcache.AllProxiesCount,
			"ss_proxies_count":            appcache.SSProxiesCount,
			"ssr_proxies_count":           appcache.SSRProxiesCount,
			"vmess_proxies_count":         appcache.VmessProxiesCount,
			"trojan_proxies_count":        appcache.TrojanProxiesCount,
			"useful_proxies_count":        appcache.UsefullProxiesCount,
			"useful_ss_proxies_count":     appcache.UsefullSSProxiesCount,
			"useful_ssr_proxies_count":    appcache.UsefullSSRProxiesCount,
			"useful_vmess_proxies_count":  appcache.UsefullVmessProxiesCount,
			"useful_trojan_proxies_count": appcache.UsefullTrojanProxiesCount,
			"last_crawl_time":             appcache.LastCrawlTime,
			"is_speed_test":               appcache.IsSpeedTest,
			"version":                     version,
			"geo_ip_db_version":           geoIp.GeoIpDBCurVersion,
		})
	})

	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	router.GET("/clash", func(c *gin.Context) {
		c.HTML(http.StatusOK, "clash.html", gin.H{
			"domain": config.Config().Domain,
			"port":   config.Config().Port,
		})
	})

	router.GET("/surge", func(c *gin.Context) {
		c.HTML(http.StatusOK, "surge.html", gin.H{
			"domain": config.Config().Domain,
		})
	})

	router.GET("/shadowrocket", func(c *gin.Context) {
		c.HTML(http.StatusOK, "shadowrocket.html", gin.H{
			"domain": config.Config().Domain,
		})
	})

	router.GET("/clash/config", func(c *gin.Context) {
		c.HTML(http.StatusOK, "clash-config.yaml", gin.H{
			"domain": config.Config().Domain,
		})
	})
	router.GET("/clash/localconfig", func(c *gin.Context) {
		c.HTML(http.StatusOK, "clash-config-local.yaml", gin.H{
			"port": config.Config().Port,
		})
	})

	router.GET("/surge/config", func(c *gin.Context) {
		c.HTML(http.StatusOK, "surge.conf", gin.H{
			"domain": config.Config().Domain,
		})
	})

	router.GET("/clash/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "clashproxies", false, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.Clash{Base: base}.Provide()
		})
		c.String(200, text)
	})
	router.GET("/surge/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "surgeproxies", true, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.Surge{Base: base}.Provide()
		})
		c.String(200, text)
	})

	router.GET("/loon/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "loonproxies", false, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.Loon{Base: base}.Provide()
		})
		c.String(200, text)
	})

	router.GET("/v2rayn/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "v2raynproxies", false, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.V2rayn{Base: base}.Provide()
		})
		c.String(200, text)
	})

	router.GET("/ss/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		ssSub := provider.SSSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "ss",
			},
		}
		c.String(200, ssSub.Provide())
	})
	router.GET("/ssr/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		ssrSub := provider.SSRSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "ssr",
			},
		}
		c.String(200, ssrSub.Provide())
	})
	router.GET("/vmess/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		vmessSub := provider.VmessSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "vmess",
			},
		}
		c.String(200, vmessSub.Provide())
	})
	router.GET("/sip002/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		sip002Sub := provider.SIP002Sub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "ss",
			},
		}
		c.String(200, sip002Sub.Provide())
	})
	router.GET("/trojan/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		trojanSub := provider.TrojanSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "trojan",
			},
		}
		c.String(200, trojanSub.Provide())
	})
	router.GET("/link/:id", func(c *gin.Context) {
		idx := c.Param("id")
		proxies := appcache.GetProxies("allproxies")
		id, err := strconv.Atoi(idx)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		if id >= proxies.Len() || id < 0 {
			c.String(500, "id out of range")
			return
		}
		c.String(200, proxies[id].Link())
	})

	router.GET("/task/crawl", func(c *gin.Context) {
		go func() {
			err := app.InitConfigAndGetters("")
			if err != nil {
				log.Errorln("config parse error: %s", err)
			}
			app.CrawlGo()
			app.Getters = nil
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/task/speedtest", func(c *gin.Context) {
		go func() {
			log.Infoln("Doing speed test task...")
			err := config.Parse("")
			if err != nil {
				log.Errorln("config parse error: %s", err)
			}
			pl := appcache.GetProxies("proxies")

			app.SpeedTest(pl)
			appcache.SetString("clashproxies", provider.Clash{
				Base: provider.Base{
					Proxies: &pl,
				},
			}.Provide()) // update static string provider
			appcache.SetString("surgeproxies", provider.Surge{
				Base: provider.Base{
					Proxies: &pl,
				},
			}.Provide())
			appcache.SetString("loonproxies", provider.Loon{
				Base: provider.Base{
					Proxies: &pl,
				},
			}.Provide())
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/task/updateGeoIP", func(c *gin.Context) {
		go func() {
			log.Infoln("Reloading GeoIP...")
			// geoIp.ReInitGeoIpDB()
			geoIp.UpdateGeoIP()
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/task/updateBestNode", func(c *gin.Context) {
		go func() {
			log.Infoln("updateBestNode...")
			cron.CrawlBestNodeTask()
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/bestProxyIp/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")
		distNodeCountry := c.Query("d")
		if distNodeCountry == "" {
			distNodeCountry = "JP"
		}
		// 获取并解析limit参数
		limitStr := c.Query("limit")
		limit := 0
		if limitStr != "" {
			limit, err = strconv.Atoi(limitStr)
			if err != nil {
				c.String(500, "invalid limit parameter")
				return
			}
		}
		// 获取并解析random参数
		random := false
		if c.Query("random") == "true" {
			random = true
		}

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		cdnFilter := c.Query("cdn")

		text, err := app.SubNiceProxyIp(format, distNodeCountry, c.Query("c"), limit, random, isIPV6, cdnFilter)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestCfProxyIp/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")
		distNodeCountry := c.Query("d")
		if distNodeCountry == "" {
			distNodeCountry = "JP"
		}

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		text, err := app.SubNiceCfProxyIp(format, distNodeCountry, isIPV6)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestCfProxyDomainTop20/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")
		distNodeCountry := c.Query("d")
		if distNodeCountry == "" {
			distNodeCountry = "JP"
		}

		isConvertIp := false
		if c.Query("ips") == "true" || c.Query("ips") == "1" {
			isConvertIp = true
		}

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		text, err := app.SubNiceCfProxyIpTop20(format, distNodeCountry, isConvertIp, isIPV6)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestCfProxyIpTop20/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")
		distNodeCountry := c.Query("d")
		if distNodeCountry == "" {
			distNodeCountry = "JP"
		}

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		text, err := app.SubNiceCfProxyIpTop20(format, distNodeCountry, true, isIPV6)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestCfProxyIpIsp/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")

		distNodeCountry := c.Query("d")
		if distNodeCountry == "" {
			distNodeCountry = "JP"
		}

		isp := c.Query("isp")

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		text, err := app.SubNiceCfProxyIpProvider(format, isp, distNodeCountry, isIPV6)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestCfProxySub/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")

		distNodeCountry := c.Query("d")
		if distNodeCountry == "" {
			distNodeCountry = "JP"
		}

		sub := c.Query("sub")

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		text, err := app.SubNiceCfProxySub(format, sub, distNodeCountry, isIPV6)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestIpKr/:format", func(c *gin.Context) {
		err := config.Parse("")
		if err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(500, err.Error())
			return
		}

		format := c.Param("format")
		// 获取并解析random参数
		random := false
		if c.Query("random") == "true" {
			random = true
		}

		isIPV6 := false
		if c.Query("ipv6") == "true" || c.Query("ipv6") == "1" {
			isIPV6 = true
		}

		text, err := app.SubNiceProxyIp(format, "KR", c.Query("c"), 0, random, isIPV6, c.Query("cdn"))
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})
}

func Run() {
	setupRouter()
	servePort := config.Config().Port
	envp := os.Getenv("PORT") // environment port for heroku app
	if envp != "" {
		servePort = envp
	}
	// Run on this server
	var err error
	if config.Config().TLSEnable {
		err = router.RunTLS(":"+servePort, config.Config().CertFile, config.Config().KeyFile)
	} else {
		err = router.Run(":" + servePort)
	}

	if err != nil {
		log.Errorln("router: Web server starting failed. Make sure your port %s has not been used. \n%s", servePort, err.Error())
	} else {
		log.Infoln("Proxypool is serving on port: %s", servePort)
	}
}

// 返回页面templates
func loadHTMLTemplate() (t *template.Template, err error) {
	t, err = template.New("").ParseFS(config.HtmlFs, "assets/html/*")
	return
}
