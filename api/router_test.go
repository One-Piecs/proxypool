package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-gonic/gin"
)

// TestSkipCache 验证：指定前缀路径不被缓存（触发类接口可重复执行），
// 其余路径被站点缓存命中（handler 只执行一次）。
func TestSkipCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := persistence.NewInMemoryStore(time.Minute)
	r.Use(siteCache(store, time.Minute, "/task/"))

	count := 0
	r.GET("/task/crawl", func(c *gin.Context) {
		count++
		c.String(http.StatusOK, "ok")
	})
	r.GET("/clash/proxies", func(c *gin.Context) {
		count++
		c.String(http.StatusOK, "cached")
	})

	get := func(path string) int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		r.ServeHTTP(w, req)
		return w.Code
	}

	// /task/ 不被缓存：两次请求 handler 都应执行
	if code := get("/task/crawl"); code != http.StatusOK {
		t.Fatalf("/task/crawl status = %d", code)
	}
	if code := get("/task/crawl"); code != http.StatusOK {
		t.Fatalf("/task/crawl status = %d", code)
	}
	if count != 2 {
		t.Errorf("/task/ should not be cached, handler ran %d times, want 2", count)
	}

	// 非跳过路径被缓存：两次请求 handler 只执行一次
	if code := get("/clash/proxies"); code != http.StatusOK {
		t.Fatalf("/clash/proxies status = %d", code)
	}
	if code := get("/clash/proxies"); code != http.StatusOK {
		t.Fatalf("/clash/proxies status = %d", code)
	}
	if count != 3 {
		t.Errorf("/clash/proxies should be cached, handler ran %d times, want 3", count)
	}

	// 带 random=true 的请求不缓存：两次请求 handler 都应执行
	r.GET("/bestProxyIp/clash", func(c *gin.Context) {
		count++
		c.String(http.StatusOK, "random-output")
	})
	if code := get("/bestProxyIp/clash?random=true"); code != http.StatusOK {
		t.Fatalf("/bestProxyIp?random=true status = %d", code)
	}
	if code := get("/bestProxyIp/clash?random=true"); code != http.StatusOK {
		t.Fatalf("/bestProxyIp?random=true status = %d", code)
	}
	if count != 5 {
		t.Errorf("random=true should bypass cache, handler ran %d times, want 5", count)
	}

	// 无 random 参数的同类请求仍被缓存：两次请求 handler 只执行一次
	if code := get("/bestProxyIp/clash"); code != http.StatusOK {
		t.Fatalf("/bestProxyIp/clash status = %d", code)
	}
	if code := get("/bestProxyIp/clash"); code != http.StatusOK {
		t.Fatalf("/bestProxyIp/clash status = %d", code)
	}
	if count != 6 {
		t.Errorf("/bestProxyIp/clash should be cached, handler ran %d times, want 6", count)
	}
}
