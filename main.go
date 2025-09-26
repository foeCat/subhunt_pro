package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type DNSResult struct {
	Domain string
	IPs    []string
}

type ScanResult struct {
	DNSResult          // 嵌入 DNSResult 结构体，继承其字段
	HTTPStatus  int    `json:"http_status"`            // HTTP 请求状态码
	HTTPSStatus int    `json:"https_status"`           // HTTPS 请求状态码
	RedirectURL string `json:"redirect_url,omitempty"` // 重定向 URL（可选字段）
}

var (
	wg          sync.WaitGroup
	dnsResults  []DNSResult
	countMutex  sync.Mutex
	resultMutex sync.Mutex
)

func main() {
	domain := flag.String("domain", "bsuc.cn", "目标主域名 (必填)")
	wordlist := flag.String("wordlist", "D:/Cybersecurity_Tools/common_tools/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt", "子域名字典文件路径")
	concurrency := flag.Int("concurrency", 50, "并发请求数量")
	showIP := flag.Bool("show-ip", true, "显示子域名对应的IP地址")
	flag.Parse()

	// 验证必填参数
	if *domain == "" {
		fmt.Println("错误: 必须使用--domain选项指定目标域名")
		flag.Usage()
		os.Exit(1)
	}

	// 打开字典文件
	file, err := os.Open(*wordlist)
	if err != nil {
		fmt.Printf("无法打开字典文件: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	taskChan := make(chan string, *concurrency)

	foundCount := 0
	fmt.Printf("开始爆破子域名: %s\n", *domain)
	fmt.Printf("使用字典: %s\n", *wordlist)
	fmt.Printf("并发数: %d\n", *concurrency)
	fmt.Println("------------------------")

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(workerID int, mainDomain string) {
			defer wg.Done()             // 释放信号量
			for sub := range taskChan { // 组合成完整域名
				fullDomain := fmt.Sprintf("%s.%s", sub, mainDomain)

				// 尝试解析域名
				ips, err := resolveDomain(fullDomain)
				if err != nil {
					// 可以取消注释下面一行来显示解析失败的域名
					// fmt.Printf("[-] %s 解析失败: %v\n", fullDomain, err)
					continue
				}

				// 解析成功，输出结果
				countMutex.Lock()
				foundCount++
				countMutex.Unlock()

				if *showIP {
					fmt.Printf("[+] %s -> %s\n", fullDomain, ips)
				} else {
					fmt.Printf("[+] %s\n", fullDomain)
				}
				// 发送结果到结果通道

			}
		}(i, *domain)
	}

	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomain := scanner.Text()
			if subdomain != "" {
				taskChan <- subdomain
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("读取字典文件时出错: %v\n", err)
		}

		close(taskChan)

	}()

	wg.Wait()
	fmt.Println("------------------------")
	fmt.Printf("扫描完成，共发现 %d 个有效子域名\n", foundCount)

	var httpChoice string

	fmt.Print("\n是否对发现的子域名进行 HTTP/HTTPS 可访问性探测？(yes/no): ")
	fmt.Scanln(&httpChoice)
	if strings.ToLower(httpChoice) == "yes" || strings.ToLower(httpChoice) == "y" {
		fmt.Println("\n[HTTP探测] 开始对有效子域名进行 HTTP/HTTPS 探测...")
		StartHTTPProbe(concurrency, dnsResults, 5)
	}

}

func resolveDomain(domain string) (string, error) {
	timeout := 1 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 执行DNS解析
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err == nil && len(ips) > 0 {
		// 格式化IP地址列表
		ipStrs := make([]string, len(ips))
		for j, ip := range ips {
			ipStrs[j] = ip.String()
		}
		resultMutex.Lock()
		dnsResults = append(dnsResults, DNSResult{
			Domain: domain,
			IPs:    ipStrs,
		})
		resultMutex.Unlock()
		return fmt.Sprintf("%v", ipStrs), nil
	}
	return "", fmt.Errorf("无法解析域名: %s:%w", domain, err)
}
