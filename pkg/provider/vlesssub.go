package provider

import (
	"strings"

	"github.com/One-Piecs/proxypool/pkg/tool"
)

// VlessSub vless 订阅：base64 编码的 vless:// 链接列表
type VlessSub struct {
	Base
}

func (sub VlessSub) Provide() string {
	sub.Types = "vless"
	sub.preFilter()
	var resultBuilder strings.Builder
	for _, p := range *sub.Proxies {
		resultBuilder.WriteString(p.Link() + "\n")
	}
	return tool.Base64EncodeString(resultBuilder.String(), false)
}
