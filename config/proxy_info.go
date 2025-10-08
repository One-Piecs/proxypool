package config

type (
	ProxyInfo map[string]ProxyType
	ProxyType map[string]map[string]interface{}
)
