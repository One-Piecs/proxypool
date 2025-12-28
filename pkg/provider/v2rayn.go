package provider

import (
	"encoding/base64"
	"strings"
)

// V2rayn provides functions that make proxies support v2rayn client
type V2rayn struct {
	Base
}

// Provide of v2rayn generates providers for v2rayn configuration
func (v V2rayn) Provide() string {
	v.preFilter()

	var resultBuilder strings.Builder
	for _, p := range *v.Proxies {
		link := p.Link()
		if link != "" {
			resultBuilder.WriteString(link + "\n")
		}
	}
	return base64.StdEncoding.EncodeToString([]byte(resultBuilder.String()))
}
