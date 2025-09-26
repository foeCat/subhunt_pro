package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	scanResults []ScanResult // 变量名和你代码中用的一致

)

func StartHTTPProbe(concurrency *int, dnsResults []DNSResult, timeout int) {
	var httpWG sync.WaitGroup
	httpSemaphore := make(chan struct{}, *concurrency)

	tempDNSResults := make([]DNSResult, len(dnsResults))
	copy(tempDNSResults, dnsResults)

	for _, dnsResult := range tempDNSResults {
		httpWG.Add(1)
		httpSemaphore <- struct{}{}

		go func(result DNSResult, to int) {
			defer httpWG.Done()
			defer func() { <-httpSemaphore }()

			// 进行HTTP/HTTPS探测
			httpStatus, httpsStatus, redirectURL := checkHTTP(result.Domain, to)
			isAccessible := (httpStatus >= 200 && httpStatus < 400) || (httpsStatus >= 200 && httpsStatus < 400)
			if isAccessible {
				statusInfo := make([]string, 0)
				if httpStatus > 0 {
					statusInfo = append(statusInfo, fmt.Sprintf("HTTP: %d", httpStatus))
				}
				if httpsStatus > 0 {
					statusInfo = append(statusInfo, fmt.Sprintf("HTTPS: %d", httpsStatus))
				}

				fmt.Printf("[可访问] %s", result.Domain)
				if len(statusInfo) > 0 {
					fmt.Printf(" -> [%s]", strings.Join(statusInfo, ", "))
				}
				if redirectURL != "" {
					fmt.Printf(" (重定向至: %s)", redirectURL)
				}
				fmt.Println()

				resultMutex.Lock()
				scanResults = append(scanResults, ScanResult{
					DNSResult:   result,
					HTTPStatus:  httpStatus,
					HTTPSStatus: httpsStatus,
					RedirectURL: redirectURL,
				})
				resultMutex.Unlock()

			}
			// 记录完整结果

		}(dnsResult, 5)

	}

}

func checkHTTP(domain string, timeoutSeconds int) (httpStatus, httpsStatus int, redirectURL string) {
	client := &http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 记录重定向URL但不跟随重定向
			redirectURL = req.URL.String()
			return http.ErrUseLastResponse
		},
	}
	httpsResp, err := client.Get(fmt.Sprintf("https://%s", domain))
	if err == nil {
		httpsStatus = httpsResp.StatusCode
		defer httpsResp.Body.Close() // 用 defer 确保响应体一定被关闭，避免资源泄漏
	}

	// 2. HTTP 请求：声明 httpResp 变量（首次声明用 :=）
	httpResp, err := client.Get(fmt.Sprintf("http://%s", domain)) // 现在 httpResp 已声明，不会报错
	if err == nil {
		httpStatus = httpResp.StatusCode
		defer httpResp.Body.Close()
	}

	// 3. 提取重定向 URL（用各自的响应变量判断，避免混淆）
	if redirectURL == "" {
		// 先检查 HTTPS 响应
		if (httpsStatus == http.StatusMovedPermanently || httpsStatus == http.StatusFound) && httpsResp != nil {
			redirectURL = httpsResp.Header.Get("Location")
		}
		// 再检查 HTTP 响应
		if (httpStatus == http.StatusMovedPermanently || httpStatus == http.StatusFound) && httpResp != nil {
			redirectURL = httpResp.Header.Get("Location")
		}
	}

	return httpStatus, httpsStatus, redirectURL

}
