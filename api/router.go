package api

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/One-Piecs/proxypool/internal/app"

	"github.com/arl/statsviz"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/One-Piecs/proxypool/pkg/provider"

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

// cachedResponse 缓存的 HTTP 响应
//
// 注：gin-contrib/cache 的 SiteCache 只读不写（缓存永远不会被填充，等价于空操作），
// 此处实现一个可用的站点缓存：未命中时包装 ResponseWriter 记录响应，命中时直接回放。
type cachedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// cacheWriter 包装 gin.ResponseWriter，拦截响应写入以便缓存
//
// 注：gin-contrib/cache 的 SiteCache 只读不写（缓存永远不会被填充，等价于空操作），
// 此处实现一个可用的站点缓存：未命中时包装 ResponseWriter 记录响应，命中时直接回放。
type cacheWriter struct {
	gin.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *cacheWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *cacheWriter) WriteString(s string) (int, error) {
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

// siteCache 站点响应缓存中间件：
// 未命中时缓存 2xx 响应，命中时直接回放；
// 触发类/动态接口（/task/、/health、/link/、/debug/*）通过 skipPrefixes 跳过缓存。
func siteCache(store persistence.CacheStore, expire time.Duration, skipPrefixes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 带 random=true 的请求（/bestProxyIp 随机打乱节点顺序）不缓存，
		// 保证每次调用都重新随机，否则 1 分钟内会返回相同的排列
		if r := c.Query("random"); r == "true" || r == "1" {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		for _, p := range skipPrefixes {
			if strings.HasPrefix(path, p) {
				c.Next()
				return
			}
		}

		// 用 URL.RequestURI() 重建请求 URI（含 query）作为缓存 key：
		// 不依赖服务端填充的 RequestURI 字段，httptest 等场景也正确区分
		key := cache.CreateKey(c.Request.URL.RequestURI())
		var resp cachedResponse
		if err := store.Get(key, &resp); err == nil {
			// 命中缓存：回放状态码、响应头与响应体
			for k, vs := range resp.Header {
				for _, v := range vs {
					c.Header(k, v)
				}
			}
			c.Status(resp.Status)
			_, _ = c.Writer.Write(resp.Body)
			c.Abort()
			return
		}

		// 未命中：包装 writer 记录响应
		w := &cacheWriter{ResponseWriter: c.Writer, status: http.StatusOK}
		c.Writer = w
		c.Next()

		// 仅缓存成功的完整响应，避免缓存错误页与空响应
		if w.status >= 200 && w.status < 300 && w.body.Len() > 0 {
			_ = store.Set(key, cachedResponse{
				Status: w.status,
				Header: w.Header().Clone(),
				Body:   w.body.Bytes(),
			}, expire)
		}
	}
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
	proxyTLS := c.DefaultQuery("tls", "")
	proxyReality := c.DefaultQuery("reality", "")

	noFilter := proxyTypes == "" && proxyCountry == "" && proxyNotCountry == "" &&
		proxySpeed == "" && proxyFilter == "" && proxyTLS == "" && proxyReality == "" &&
		(!supportUnderlyingProxy || proxyUnderlyingProxy == "")

	base := provider.Base{
		Types:           proxyTypes,
		Country:         proxyCountry,
		NotCountry:      proxyNotCountry,
		Speed:           proxySpeed,
		Filter:          proxyFilter,
		UnderlyingProxy: proxyUnderlyingProxy,
		TLS:             proxyTLS,
		Reality:         proxyReality,
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

// subHandler 生成 /ss|/ssr|/vmess|/sip002|/trojan|/vless/sub 接口 handler，
// 支持 tls / reality 过滤参数（与 /proxies 接口一致）
func subHandler(types string, provide func(provider.Base) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		base := provider.Base{
			Proxies: &proxies,
			Types:   types,
			TLS:     c.Query("tls"),
			Reality: c.Query("reality"),
		}
		c.String(http.StatusOK, provide(base))
	}
}

// bestIPHandler 统一 /best* 接口的配置加载与错误处理。
// config.Parse 带 mtime 缓存，未变化时零开销。
func bestIPHandler(fn func(c *gin.Context) (string, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := config.Parse(""); err != nil {
			log.Errorln("config parse error: %s", err)
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		text, err := fn(c)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.String(http.StatusOK, text)
	}
}

// parseBestIPParams 解析 /best* 公共路径与查询参数
func parseBestIPParams(c *gin.Context) (format, distCountry string) {
	format = c.Param("format")
	distCountry = c.Query("d")
	if distCountry == "" {
		distCountry = "JP"
	}
	return
}

// isTrue 解析 "true"/"1" 布尔查询参数
func isTrue(v string) bool {
	return v == "true" || v == "1"
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
	// 站点响应缓存；触发类/动态接口跳过（/task/*、/health、/link/、/debug/*）
	router.Use(gin.Recovery(), siteCache(store, time.Minute,
		"/task/", "/health", "/link/", "/debug/statsviz", "/debug/pprof"))

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

	router.GET("/static/index.js", func(c *gin.Context) {
		c.Header("Content-Type", "text/javascript")
		data, _ := config.StaticFS.ReadFile("assets/static/index.js")
		c.String(http.StatusOK, string(data))
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
			"vless_proxies_count":         appcache.VlessProxiesCount,
			"useful_proxies_count":        appcache.UsefullProxiesCount,
			"useful_ss_proxies_count":     appcache.UsefullSSProxiesCount,
			"useful_ssr_proxies_count":    appcache.UsefullSSRProxiesCount,
			"useful_vmess_proxies_count":  appcache.UsefullVmessProxiesCount,
			"useful_trojan_proxies_count": appcache.UsefullTrojanProxiesCount,
			"useful_vless_proxies_count":  appcache.UsefullVlessProxiesCount,
			"anytls_proxies_count":        appcache.AnyTLSProxiesCount,
			"useful_anytls_proxies_count": appcache.UsefullAnyTLSProxiesCount,
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

	router.GET("/loon", func(c *gin.Context) {
		c.HTML(http.StatusOK, "loon.html", gin.H{
			"domain": config.Config().Domain,
		})
	})

	router.GET("/quanx", func(c *gin.Context) {
		c.HTML(http.StatusOK, "quanx.html", gin.H{
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
		c.String(http.StatusOK, text)
	})
	router.GET("/surge/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "surgeproxies", true, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.Surge{Base: base}.Provide()
		})
		c.String(http.StatusOK, text)
	})

	router.GET("/loon/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "loonproxies", false, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.Loon{Base: base}.Provide()
		})
		c.String(http.StatusOK, text)
	})

	router.GET("/v2rayn/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "v2raynproxies", false, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.V2rayn{Base: base}.Provide()
		})
		c.String(http.StatusOK, text)
	})

	router.GET("/quanx/proxies", func(c *gin.Context) {
		text := serveProxyList(c, "quanxproxies", false, func(proxies proxy.ProxyList, base provider.Base) string {
			return provider.QuanX{Base: base}.Provide()
		})
		c.String(http.StatusOK, text)
	})

	router.GET("/ss/sub", subHandler("ss", func(b provider.Base) string { return provider.SSSub{Base: b}.Provide() }))
	router.GET("/ssr/sub", subHandler("ssr", func(b provider.Base) string { return provider.SSRSub{Base: b}.Provide() }))
	router.GET("/vmess/sub", subHandler("vmess", func(b provider.Base) string { return provider.VmessSub{Base: b}.Provide() }))
	router.GET("/sip002/sub", subHandler("ss", func(b provider.Base) string { return provider.SIP002Sub{Base: b}.Provide() }))
	router.GET("/trojan/sub", subHandler("trojan", func(b provider.Base) string { return provider.TrojanSub{Base: b}.Provide() }))
	router.GET("/vless/sub", subHandler("vless", func(b provider.Base) string { return provider.VlessSub{Base: b}.Provide() }))

	router.GET("/link/:id", func(c *gin.Context) {
		proxies := appcache.GetProxies("allproxies")
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		if id >= proxies.Len() || id < 0 {
			c.String(http.StatusInternalServerError, "id out of range")
			return
		}
		c.String(http.StatusOK, proxies[id].Link())
	})

	// 任务接口：后台执行，任务实现（含互斥防并发与 GC）收敛在 internal/app
	router.GET("/task/crawl", func(c *gin.Context) {
		go app.CrawlTask()
		c.String(http.StatusOK, "ok")
	})
	router.GET("/task/speedtest", func(c *gin.Context) {
		go app.SpeedTestTask()
		c.String(http.StatusOK, "ok")
	})
	router.GET("/task/updateGeoIP", func(c *gin.Context) {
		go app.GeoIPTask()
		c.String(http.StatusOK, "ok")
	})
	router.GET("/task/updateBestNode", func(c *gin.Context) {
		go app.BestNodeTask()
		c.String(http.StatusOK, "ok")
	})

	router.GET("/bestProxyIp/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, distCountry := parseBestIPParams(c)
		limit := 0
		if s := c.Query("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				return "", errors.New("invalid limit parameter")
			}
			limit = n
		}
		return app.SubNiceProxyIp(format, distCountry, c.Query("c"), limit, isTrue(c.Query("random")), isTrue(c.Query("ipv6")), c.Query("cdn"))
	}))

	router.GET("/bestCfProxyIp/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, distCountry := parseBestIPParams(c)
		return app.SubNiceCfProxyIp(format, distCountry, isTrue(c.Query("ipv6")))
	}))

	router.GET("/bestCfProxyDomainTop20/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, distCountry := parseBestIPParams(c)
		return app.SubNiceCfProxyIpTop20(format, distCountry, isTrue(c.Query("ips")), isTrue(c.Query("ipv6")))
	}))

	router.GET("/bestCfProxyIpTop20/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, distCountry := parseBestIPParams(c)
		return app.SubNiceCfProxyIpTop20(format, distCountry, true, isTrue(c.Query("ipv6")))
	}))

	router.GET("/bestCfProxyIpIsp/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, distCountry := parseBestIPParams(c)
		return app.SubNiceCfProxyIpProvider(format, c.Query("isp"), distCountry, isTrue(c.Query("ipv6")))
	}))

	router.GET("/bestCfProxySub/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, distCountry := parseBestIPParams(c)
		return app.SubNiceCfProxySub(format, c.Query("sub"), distCountry, isTrue(c.Query("ipv6")))
	}))

	router.GET("/bestIpKr/:format", bestIPHandler(func(c *gin.Context) (string, error) {
		format, _ := parseBestIPParams(c)
		return app.SubNiceProxyIp(format, "KR", c.Query("c"), 0, isTrue(c.Query("random")), isTrue(c.Query("ipv6")), c.Query("cdn"))
	}))
}

func Run() {
	setupRouter()
	servePort := config.Config().Port
	// heroku 平台通过 PORT 环境变量指定端口（仅 heroku 生效，避免普通部署被环境变量覆盖）
	if envp := os.Getenv("PORT"); envp != "" && os.Getenv("DYNO") != "" {
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
