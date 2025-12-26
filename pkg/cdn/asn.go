package cdn

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/One-Piecs/proxypool/log"
)

// IP-API.com batch endpoint
const ipApiBatchUrl = "http://ip-api.com/batch"

// Keywords to detect CDN
var cdKeywords = []string{
	"CDN", "Content Delivery", "Edge", "Anycast", "Cache",
	"Akamai", "Incap", "Stackpath", "Bunny", "Zscaler", "Cloudflare", "Fastly",
	"Microsoft", "Azure", "Amazon", "Google", "Edgio", "Edgecast", "Limelight",
	"CacheFly", "CDNetworks", "ArvanCloud", "Tencent", "Alibaba",
}

type IPAPIResponse struct {
	Query  string `json:"query"`
	Status string `json:"status"`
	ISP    string `json:"isp"`
	Org    string `json:"org"`
	AS     string `json:"as"`
}

// CheckIPsForCDN uses ip-api.com batch API to check if IPs are related to CDNs
// It limits requests to 100 IPs per batch.
func CheckIPsForCDN(ips []string) (map[string]bool, error) {
	results := make(map[string]bool)
	chunkSize := 100

	for i := 0; i < len(ips); i += chunkSize {
		end := i + chunkSize
		if end > len(ips) {
			end = len(ips)
		}

		batchIPs := ips[i:end]
		batchResults, err := fetchIPAPIBatch(batchIPs)
		if err != nil {
			log.Errorln("fetchIPAPIBatch failed: %v", err)
			continue
		}

		for ip, isCDN := range batchResults {
			results[ip] = isCDN
		}
	}
	return results, nil
}

func fetchIPAPIBatch(ips []string) (map[string]bool, error) {
	payload, err := json.Marshal(ips)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(ipApiBatchUrl, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResps []IPAPIResponse
	if err := json.Unmarshal(body, &apiResps); err != nil {
		return nil, err
	}

	results := make(map[string]bool)
	for _, info := range apiResps {
		results[info.Query] = isCDNInfo(info)
	}
	return results, nil
}

func isCDNInfo(info IPAPIResponse) bool {
	combined := strings.Join([]string{info.ISP, info.Org, info.AS}, " ")
	combined = strings.ToUpper(combined)

	for _, kw := range cdKeywords {
		if strings.Contains(combined, strings.ToUpper(kw)) {
			return true
		}
	}
	return false
}
