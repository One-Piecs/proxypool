package cache

import (
	"sync"

	"github.com/One-Piecs/proxypool/pkg/proxy"
)

// BestNode 最佳节点信息
type BestNode struct {
	Ip      string
	Port    int
	Country string
	CDN     bool
}

// cacheStore 一个简单的无过期时间的并发安全缓存，
// 替代已归档的 github.com/patrickmn/go-cache（所有 key 均使用 NoExpiration）。
type cacheStore struct {
	mu sync.RWMutex
	m  map[string]any
}

func newCacheStore() *cacheStore {
	return &cacheStore{m: make(map[string]any)}
}

func (s *cacheStore) Get(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	return v, ok
}

func (s *cacheStore) Set(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
}

var c = newCacheStore()

func GetProxies(key string) proxy.ProxyList {
	result, found := c.Get(key)
	if found {
		if pl, ok := result.(proxy.ProxyList); ok {
			return pl
		}
	}
	return nil
}

func SetProxies(key string, proxies proxy.ProxyList) {
	c.Set(key, proxies)
}

func SetString(key, value string) {
	c.Set(key, value)
}

func GetString(key string) string {
	result, found := c.Get(key)
	if found {
		if s, ok := result.(string); ok {
			return s
		}
	}
	return ""
}

func SetBestNodeList(key string, value []BestNode) {
	c.Set(key, value)
}

func GetBestNodeList(key string) (value []BestNode) {
	result, found := c.Get(key)
	if found {
		if v, ok := result.([]BestNode); ok {
			return v
		}
	}
	return nil
}
