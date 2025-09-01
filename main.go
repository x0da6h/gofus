package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version   = "1.0"
	buildDate = "2025-9-1"
	author    = "x0da6h\n"
)

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// 全局变量定义
var (
	dictPath        string
	targetURL       string
	urlListPath     string // URL列表文件路径
	proxyURL        string // 代理服务器URL
	client          *http.Client
	visited         sync.Map // 替换为sync.Map
	wg              sync.WaitGroup
	concurrent      int
	maxDepth        int   // 最大递归深度
	filterCodes     []int // 需要过滤的状态码
	matchCodes      []int // 需要匹配的状态码（只输出这些状态码）
	filterLengths   []int // 需要过滤的响应体大小
	filterCodeStr   string
	matchCodeStr    string // 匹配状态码参数字符串
	filterLengthStr string
	extensions      []string    // 需要扩展的文件后缀
	extensionStr    string      // 扩展后缀参数字符串
	showVersion     bool        // 显示版本信息
	ignoreBody      bool        // 忽略响应体内容，只获取响应头
	httpMethod      string      // HTTP请求方法
	timeout         int         // 请求超时时间（秒）
	customHeaders   headerFlags // 自定义请求头
	requestData     string      // POST请求体数据
	scannedCount    int64       // 已扫描数量
	errorCount      int64       // 错误计数
	totalWords      int         // 总字典条数
	outputMutex     sync.Mutex  // 用于同步输出，防止进度条被刷乱
	statusBarActive bool        // 进度条是否激活
	outputQueue     chan string
	outputDone      chan struct{}
)

const (
	green = "\033[32m"
	red   = "\033[31m"
	blue  = "\033[34m"
	cyan  = "\033[36m"
	redBg = "\033[41m"
	reset = "\033[0m"
)

func logo() {
	gofusLogo := `
   ██████╗   ██████╗  ███████╗ ██╗   ██╗ ███████╗
  ██╔════╝  ██╔═══██╗ ██╔════╝ ██║   ██║ ██╔════╝
  ██║ ████╗ ██║   ██║ ██████╗  ██║   ██║ ███████╗
  ██║   ██║ ██║   ██║ ██╔═══╝  ██║   ██║ ╚════██║
  ╚██████╔╝ ╚██████╔╝ ██║      ╚██████╔╝ ███████║
   ╚═════╝   ╚═════╝  ╚═╝       ╚═════╝  ╚══════╝

  gofus - Web递归FUZZ工具 | by x0da6h
`
	fmt.Print(gofusLogo)
}

func printConfigBox(lines []string) {
	maxWidth := 0
	for _, line := range lines {
		displayWidth := 0
		for _, r := range []rune(line) {
			if r > 127 { // 非 ASCII 字符（中文等）占两个位置
				displayWidth += 2
			} else {
				displayWidth += 1
			}
		}
		if displayWidth > maxWidth {
			maxWidth = displayWidth
		}
	}

	if maxWidth < 20 {
		maxWidth = 20
	}
	border := "*" + strings.Repeat("-", maxWidth+2) + "*"
	fmt.Println(border)
	for _, line := range lines {
		currentWidth := 0
		for _, r := range []rune(line) {
			if r > 127 { // 非 ASCII 字符（中文等）占两个位置
				currentWidth += 2
			} else {
				currentWidth += 1
			}
		}
		// 计算需要填充的空格数
		padding := maxWidth - currentWidth
		fmt.Printf("| %s%s |\n", line, strings.Repeat(" ", padding))
	}
	fmt.Println(border)
}

func printHelp() {
	logo()
	params := []struct {
		flag       string
		defaultVal string
		desc       string
	}{
		{"\t-h", "无", "\t显示当前帮助信息"},
		{"\t-v", "无", "\t显示工具版本信息"},
		{"\t-u", "<必填>", "\t目标URL (例：https://example.com 或 example.com)"},
		{"\t-U", "无", "\t目标URL列表文件 (每行一个URL，用于探活检测)"},
		{"\t-w", "<必填>", "\t路径字典文件 (支持#注释、自动忽略空行)"},
		{"\t-c", "20", "\t并发请求数 (建议20-50，防止触发目标限流)"},
		{"\t-d", "1", "\t最大递归深度 (1: 仅根路径，3: 支持3级子路径)"},
		{"\t-fc", "无", "\t过滤状态码 (例：-fc 404,403 不显示404/403)"},
		{"\t-mc", "无", "\t匹配状态码 (例：-mc 200,500 只显示200/500)"},
		{"\t-fs", "无", "\t过滤响应体大小 (例：-fs 800,1000 不显示大小800/1000的响应)"},
		{"\t-x", "无", "\t文件后缀扩展 (例：-x php,txt,bak)"},
		{"\t-ib", "无", "\t忽略响应体内容 (只获取响应头)"},
		{"\t-m", "GET", "\tHTTP请求方法 (支持: GET,POST,OPTIONS)"},
		{"\t-t", "1", "\t请求超时时间 (秒数，例：-t 5 设置5秒超时)"},
		{"\t-H", "无", "\t自定义请求头 (例：-H \"Name: Value\" 可多次使用)"},
		{"\t-data", "无", "\t请求体数据 (例：-data \"{user:admin}\")"},
		{"\t-proxy", "无", "\t代理服务器 (例：-proxy socks5://127.0.0.1:7890)"},
	}

	fmt.Println("\n选项说明:\n")
	for _, p := range params {
		fmt.Printf("  %-8s  默认值: %-8s  %s\n", p.flag, p.defaultVal, p.desc)
	}
	fmt.Println()
}

func printVersion() {
	logo()
	fmt.Printf("\n版本: %s\n", version)
	fmt.Printf("构建日期: %s\n", buildDate)
	fmt.Printf("作者: %s\n", author)
}

func init() {
	flag.BoolVar(&showVersion, "v", false, "显示版本信息")
	flag.StringVar(&dictPath, "w", "", "路径字典文件")
	flag.StringVar(&targetURL, "u", "", "目标URL地址")
	flag.StringVar(&urlListPath, "U", "", "URL列表文件路径")
	flag.IntVar(&concurrent, "c", 20, "并发数量")
	flag.IntVar(&maxDepth, "d", 1, "最大递归深度")
	flag.StringVar(&extensionStr, "x", "", "文件后缀扩展，用逗号分隔 (例如: php,txt,bak)")
	flag.StringVar(&httpMethod, "m", "GET", "HTTP请求方法 (支持: GET,POST,OPTIONS)")
	flag.IntVar(&timeout, "t", 3, "请求超时时间(秒)")
	flag.StringVar(&requestData, "data", "", "请求体数据")
	flag.StringVar(&filterCodeStr, "fc", "", "需要过滤的状态码，用逗号分隔 (例如: 404,403)")
	flag.StringVar(&matchCodeStr, "mc", "", "需要匹配的状态码，用逗号分隔 (例如: 200,500)")
	flag.StringVar(&filterLengthStr, "fs", "", "需要过滤的响应体大小，用逗号分隔 (例如: 1000,2000)")
	flag.BoolVar(&ignoreBody, "ib", false, "忽略响应体内容，只获取响应头")
	flag.Var(&customHeaders, "H", "自定义请求头 (例如: -H 'Name: Value')")
	flag.StringVar(&proxyURL, "proxy", "", "代理服务器地址 (支持HTTP、HTTPS、SOCKS4和SOCKS5，格式: http://127.0.0.1:7890 或 socks5://127.0.0.1:7890)")
	flag.Usage = printHelp
	flag.Parse()
	if showVersion {
		printVersion()
		os.Exit(0)
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		os.Exit(0)
	}

	if urlListPath != "" {
		if dictPath != "" {
			fmt.Printf("%s\n[ERROR] -U 和 -w 选项不能同时使用%s\n", red, reset)
			os.Exit(1)
		}
		if targetURL != "" {
			fmt.Printf("%s\n[ERROR] -U 和 -u 选项不能同时使用%s\n", red, reset)
			os.Exit(1)
		}
	} else {
		if dictPath == "" || targetURL == "" {
			fmt.Printf("%s\n[ERROR] 缺少必需参数 -u (目标URL) 和 -w (字典文件)%s\n", red, reset)
			fmt.Println("提示：执行 gofus -h 查看完整使用说明\n")
			os.Exit(1)
		}
	}

	filterCodes = parseFilterNumbers(filterCodeStr)
	matchCodes = parseFilterNumbers(matchCodeStr)
	filterLengths = parseFilterNumbers(filterLengthStr)
	extensions = parseExtensions(extensionStr)
	httpMethod = strings.ToUpper(httpMethod)
	if httpMethod != "GET" && httpMethod != "POST" && httpMethod != "OPTIONS" {
		fmt.Printf("%s\n[ERROR] 不支持的HTTP方法: %s，支持的方法: GET, POST, OPTIONS%s\n", red, httpMethod, reset)
		os.Exit(1)
	}

	if timeout < 1 || timeout > 300 {
		fmt.Printf("%s\n[ERROR] 超时时间不合理: %d秒，允许范围: 1-300秒%s\n", red, timeout, reset)
		os.Exit(1)
	}

	httpTransport := &http.Transport{
		MaxIdleConns:          50,               // 从100降低到50
		MaxIdleConnsPerHost:   10,               // 从20降低到10
		MaxConnsPerHost:       0,                // 不限制每个主机的最大连接数
		TLSHandshakeTimeout:   3 * time.Second,  // 降低TLS握手超时时间以加快连接速度
		ResponseHeaderTimeout: 5 * time.Second,  // 降低响应头超时时间以加快结果返回
		ExpectContinueTimeout: 1 * time.Second,  // 降低Expect-Continue超时以加快请求处理
		IdleConnTimeout:       90 * time.Second, // 增加空闲连接超时时间
		ForceAttemptHTTP2:     false,            // 禁用HTTP/2，解决Adobe等网站的stream error问题
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,             // 跳过TLS证书验证
			MinVersion:         tls.VersionTLS12, // 设置最低TLS版本
			MaxVersion:         tls.VersionTLS13, // 设置最高TLS版本
			CipherSuites: []uint16{ // 配置支持的密码套件
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384}, // 曲线偏好设置
		},
	}

	if proxyURL != "" {
		proxyURLObj, err := neturl.Parse(proxyURL)
		if err != nil {
			fmt.Printf("%s\n[ERROR] 无效的代理URL格式: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		protocol := strings.ToLower(proxyURLObj.Scheme)
		if protocol != "http" && protocol != "https" && protocol != "socks5" && protocol != "socks4" {
			fmt.Printf("%s\n[ERROR] 不支持的代理协议: %s，仅支持: http, https, socks4, socks5%s\n", red, protocol, reset)
			os.Exit(1)
		}
		httpTransport.Proxy = http.ProxyURL(proxyURLObj)
	}

	client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second, // 使用用户指定的超时时间
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: httpTransport,
	}

	if urlListPath == "" && targetURL != "" {
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}
		if !strings.HasSuffix(targetURL, "/") {
			targetURL += "/"
		}
	}
}

func parseFilterNumbers(filterStr string) []int {
	var result []int
	if filterStr == "" {
		return result
	}
	parts := strings.Split(filterStr, ",")
	for _, part := range parts {
		num, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			result = append(result, num)
		}
	}
	return result
}

func parseExtensions(extStr string) []string {
	var result []string
	if extStr == "" {
		return result
	}
	parts := strings.Split(extStr, ",")
	for _, part := range parts {
		ext := strings.TrimSpace(part)
		if ext != "" {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			result = append(result, ext)
		}
	}
	return result
}

func applyCustomHeaders(req *http.Request, headers []string) {
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" {
				req.Header.Set(key, value)
			}
		}
	}
}

func isFilteredCode(code int) bool {
	for _, c := range filterCodes {
		if code == c {
			return true
		}
	}
	return false
}

func isMatchedCode(code int) bool {
	if len(matchCodes) == 0 {
		return true
	}
	for _, c := range matchCodes {
		if code == c {
			return true
		}
	}
	return false
}

func isFilteredLength(length int) bool {
	for _, l := range filterLengths {
		if length == l {
			return true
		}
	}
	return false
}

func formatIntArray(arr []int) string {
	if len(arr) == 0 {
		return "[]"
	}
	strs := make([]string, len(arr))
	for i, v := range arr {
		strs[i] = strconv.Itoa(v)
	}
	return "[" + strings.Join(strs, ",") + "]"
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if len(path) > 0 && strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "//") {
		path = path[:len(path)-1]
	}
	return path
}

func formatExtensionArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	cleanExts := make([]string, len(arr))
	for i, ext := range arr {
		if strings.HasPrefix(ext, ".") {
			cleanExts[i] = ext[1:]
		} else {
			cleanExts[i] = ext
		}
	}
	return "[" + strings.Join(cleanExts, ",") + "]"
}

func main() {
	logo()
	var configLines []string
	var words []string
	var urls []string

	if urlListPath != "" {
		var err error
		urls, err = readURLList(urlListPath)
		if err != nil {
			fmt.Printf("%s【错误】读取URL列表失败: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		totalWords = len(urls)
		configLines = []string{
			fmt.Sprintf("#URL文件    : %s", urlListPath),
			fmt.Sprintf("#URL数量    : %d", len(urls)),
			fmt.Sprintf("#并发数量   : %d", concurrent),
			fmt.Sprintf("#HTTP方法   : %s", httpMethod),
			fmt.Sprintf("#超时时间   : %d秒", timeout),
		}
		if proxyURL != "" {
			configLines = append(configLines, fmt.Sprintf("#代理设置   : %s", proxyURL))
		}
	} else {
		var err error
		words, err = readDictionary(dictPath)
		if err != nil {
			fmt.Printf("%s【错误】读取字典失败: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		totalWords = len(words)
		configLines = []string{
			fmt.Sprintf("#目标URL     : %s", targetURL),
			fmt.Sprintf("#字典文件    : %s", dictPath),
			fmt.Sprintf("#字典加载    : %d", len(words)),
			fmt.Sprintf("#并发数量    : %d", concurrent),
			fmt.Sprintf("#最大深度    : %d", maxDepth),
			fmt.Sprintf("#HTTP方法    : %s", httpMethod),
			fmt.Sprintf("#超时时间    : %d秒", timeout),
		}

		if proxyURL != "" {
			configLines = append(configLines, fmt.Sprintf("#代理设置    : %s", proxyURL))
		}
	}

	if len(filterLengths) > 0 {
		configLines = append(configLines, fmt.Sprintf("#过滤大小    : %s", formatIntArray(filterLengths)))
	}
	if len(filterCodes) > 0 {
		configLines = append(configLines, fmt.Sprintf("#过滤状态码  : %s", formatIntArray(filterCodes)))
	}
	if len(matchCodes) > 0 {
		configLines = append(configLines, fmt.Sprintf("#匹配状态码  : %s", formatIntArray(matchCodes)))
	}
	if len(extensions) > 0 && urlListPath == "" {
		configLines = append(configLines, fmt.Sprintf("#扩展后缀    : %s", formatExtensionArray(extensions)))
	}
	if ignoreBody {
		configLines = append(configLines, "#忽略响应体  : 开启")
	}
	if len(customHeaders) > 0 {
		configLines = append(configLines, fmt.Sprintf("#自定义请求头  : %d个", len(customHeaders)))
	}
	if requestData != "" {
		configLines = append(configLines, "#请求体数据  : 已设置")
	}

	printConfigBox(configLines)
	outputQueue = make(chan string, 100) // 缓冲100个消息
	outputDone = make(chan struct{})
	startOutputProcessor()
	setupSignalHandler()
	statusBarActive = true
	startStatusBarUpdater()
	fmt.Printf("\n") // 预留进度条行
	semaphore := make(chan struct{}, concurrent)
	if urlListPath != "" {
		probeURLList(urls)
	} else {
		scanPath(targetURL, words, semaphore, 1)
	}
	wg.Wait()
	close(outputQueue)
	close(outputDone)
	time.Sleep(100 * time.Millisecond)
	statusBarActive = false
	fmt.Fprint(os.Stderr, "\r\033[K\n")
	if urlListPath != "" {
		totalScanned := atomic.LoadInt64(&scannedCount)
		totalErrors := atomic.LoadInt64(&errorCount)
		totalSuccess := totalScanned - totalErrors
		fmt.Printf("%s[+] 探活完成! 总计扫描: %d 个URL，成功: %d 个，错误: %d 个%s\n",
			green, totalScanned, totalSuccess, totalErrors, reset)
	} else {
		fmt.Printf("%s[+] 扫描完成! 总计扫描: %d 个路径，错误: %d 个%s\n",
			green, atomic.LoadInt64(&scannedCount), atomic.LoadInt64(&errorCount), reset)
	}
}

func readFileLines(path string, processLine func(line string) (string, bool)) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var results []string
	resultMap := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			processedLine, shouldInclude := processLine(line)
			if shouldInclude {
				normalizedLine := normalizePath(processedLine)
				if !resultMap[normalizedLine] {
					resultMap[normalizedLine] = true
					results = append(results, processedLine)
				}
			}
		}
	}
	return results, scanner.Err()
}

// 从HTML内容中提取网页标题
func extractTitle(htmlContent string) string {
	// 修改正则表达式以支持带有属性的title标签，并忽略大小写
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(htmlContent)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func readDictionary(path string) ([]string, error) {
	var allWords []string
	wordMap := make(map[string]bool)

	dictWords, err := readFileLines(path, func(line string) (string, bool) {
		return line, true
	})
	if err != nil {
		return nil, err
	}

	for _, word := range dictWords {
		normalizedWord := normalizePath(word)
		if !wordMap[normalizedWord] {
			wordMap[normalizedWord] = true
			allWords = append(allWords, word)
		}
		if len(extensions) > 0 && !hasFileExtension(word) {
			for _, ext := range extensions {
				extWord := word + ext
				normalizedExtWord := normalizePath(extWord)
				if !wordMap[normalizedExtWord] {
					wordMap[normalizedExtWord] = true
					allWords = append(allWords, extWord)
				}
			}
		}
	}

	return allWords, nil
}

func readURLList(path string) ([]string, error) {
	return readFileLines(path, func(line string) (string, bool) {
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}
		return line, true
	})
}

func hasFileExtension(path string) bool {
	lastSlashIndex := strings.LastIndex(path, "/")
	filename := path
	if lastSlashIndex >= 0 {
		filename = path[lastSlashIndex+1:]
	}
	dotIndex := strings.LastIndex(filename, ".")
	return dotIndex > 0 && dotIndex < len(filename)-1
}

// 处理HTTP请求并返回响应信息
func sendHTTPRequest(targetURL string, method string, depth int, isURLListMode bool) {
	var requestBody io.Reader
	if requestData != "" {
		requestBody = strings.NewReader(requestData + "\n\n")
	}

	// 创建HTTP请求
	req, err := http.NewRequest(method, targetURL, requestBody)
	if err != nil {
		handleRequestError(targetURL, fmt.Errorf("request error: %v", err))
		return
	}

	// 设置请求头，模拟浏览器
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	applyCustomHeaders(req, customHeaders)

	// 发送请求并处理重试逻辑
	var resp *http.Response
	const maxRetries = 2
	retryCount := 0
	retryableErrors := []string{"timeout", "deadline exceeded", "TLS handshake timeout", "connection reset"}

	for retryCount <= maxRetries {
		resp, err = client.Do(req)
		if err == nil {
			break // 请求成功，退出重试循环
		}

		isRetryable := false
		for _, retryErr := range retryableErrors {
			if strings.Contains(err.Error(), retryErr) {
				isRetryable = true
				break
			}
		}

		if !isRetryable || retryCount == maxRetries {
			handleRequestError(targetURL, err)
			return
		}

		retryCount++
		time.Sleep(time.Duration(retryCount*100) * time.Millisecond) // 指数退避
	}

	defer resp.Body.Close()
	atomic.AddInt64(&scannedCount, 1)

	if isURLListMode {
		if !isFilteredCode(resp.StatusCode) && isMatchedCode(resp.StatusCode) {
			contentLength := int(resp.ContentLength)
			title := ""
			var bodyBytes []byte
			var err error

			// 读取并解压响应体
			bodyBytes, err = readAndDecompressBody(resp)
			if err == nil {
				contentLength = len(bodyBytes)
				// 提取网页标题 - 放宽Content-Type检查，尝试从所有响应中提取标题
				title = extractTitle(string(bodyBytes))
			} else {
				contentLength = 0
			}

			formatSize := func(size int) string {
				if size == 0 {
					return fmt.Sprintf("%s%d%s", redBg, size, reset)
				}
				return fmt.Sprintf("%d", size)
			}

			// 构建标题部分
			titlePart := ""
			if title != "" {
				titlePart = ", 标题: " + title
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				printResult(fmt.Sprintf("[%s%d%s] %s \t[大小: %s%s]", green, resp.StatusCode, reset, targetURL, formatSize(contentLength), titlePart))
			} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")

				if location != "" {
					redirectURL := location
					if strings.HasPrefix(redirectURL, "//") {
						baseURL, _ := neturl.Parse(targetURL)
						redirectURL = baseURL.Scheme + ":" + redirectURL
					} else if !strings.HasPrefix(redirectURL, "http://") && !strings.HasPrefix(redirectURL, "https://") {
						baseURL, _ := neturl.Parse(targetURL)
						redirectURLObj, err := baseURL.Parse(location)
						if err == nil {
							redirectURL = redirectURLObj.String()
						}
					}

					// 使用followRedirects函数跟踪完整的重定向链
					finalURL, finalTitle, finalSize, err := followRedirects(redirectURL, 5) // 设置最大5次重定向
					if err != nil {
						// 如果跟踪重定向失败，使用原始逻辑
						redirectTitlePart := ""
						if title != "" {
							redirectTitlePart = ", 标题: " + title
						}
						printResult(fmt.Sprintf("[%s%d%s] %s -> %s \t[大小: %s%s] [跟踪重定向失败: %v]", blue, resp.StatusCode, reset, targetURL, redirectURL, formatSize(contentLength), redirectTitlePart, err))
					} else {
						// 成功跟踪重定向链，显示最终URL、标题和大小
						finalTitlePart := ""
						if finalTitle != "" {
							finalTitlePart = ", 标题: " + finalTitle
						}
						printResult(fmt.Sprintf("[%s%d%s] %s -> %s \t[最终大小: %s%s]", blue, resp.StatusCode, reset, targetURL, finalURL, formatSize(finalSize), finalTitlePart))
					}
				} else {
					printResult(fmt.Sprintf("[%s%d%s] %s \t[大小: %s%s]", blue, resp.StatusCode, reset, targetURL, formatSize(contentLength), titlePart))
				}
			} else if resp.StatusCode >= 400 {
				printResult(fmt.Sprintf("[%s%d%s] %s \t[大小: %s%s]", red, resp.StatusCode, reset, targetURL, formatSize(contentLength), titlePart))
			} else {
				printResult(fmt.Sprintf("[%d] %s \t[大小: %s%s]", resp.StatusCode, targetURL, formatSize(contentLength), titlePart))
			}
		}
		return
	}

	contentLength := int(resp.ContentLength)
	if contentLength < 0 {
		contentLength = 0
	}

	canDescend := false
	if depth < maxDepth {
		parts := strings.Split(targetURL, "/")
		word := parts[len(parts)-1]
		if len(parts) > 1 && parts[len(parts)-2] != "" {
			word = parts[len(parts)-2]
		}

		if strings.HasSuffix(word, "/") {
			canDescend = resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect ||
				resp.StatusCode == http.StatusPermanentRedirect
		} else {
			if resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect ||
				resp.StatusCode == http.StatusPermanentRedirect {
				canDescend = true
			} else if resp.StatusCode == http.StatusOK { // 200状态码且没有文件后缀名，应该递归
				dotIndex := strings.LastIndex(word, ".")
				if dotIndex == -1 || dotIndex == len(word)-1 {
					canDescend = true
				}
			}
		}
	}

	if !isFilteredCode(resp.StatusCode) && !isFilteredLength(contentLength) && isMatchedCode(resp.StatusCode) {
		var outputFormat string
		if ignoreBody {
			outputFormat = "[深度: %d]"
		} else {
			outputFormat = "[深度: %d, 大小: %d]"
		}

		if resp.StatusCode == http.StatusOK {
			if ignoreBody {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					green, resp.StatusCode, reset, targetURL, depth))
			} else {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					green, resp.StatusCode, reset, targetURL, depth, contentLength))
			}
		} else if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
			if ignoreBody {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					blue, resp.StatusCode, reset, targetURL, depth))
			} else {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					blue, resp.StatusCode, reset, targetURL, depth, contentLength))
			}
		} else {
			if ignoreBody {
				printResult(fmt.Sprintf("[%d] %s\t"+outputFormat,
					resp.StatusCode, targetURL, depth))
			} else {
				printResult(fmt.Sprintf("[%d] %s\t"+outputFormat,
					resp.StatusCode, targetURL, depth, contentLength))
			}
		}
	}

	if depth < maxDepth && canDescend {
		nextBase := targetURL
		if !strings.HasSuffix(nextBase, "/") {
			nextBase += "/"
		}
		words, err := readDictionary(dictPath)
		if err == nil {
			semaphore := make(chan struct{}, concurrent)
			scanPath(nextBase, words, semaphore, depth+1)
		}
	}
}

// 读取并解压HTTP响应体
func readAndDecompressBody(resp *http.Response) ([]byte, error) {
	// 获取Content-Encoding头
	contentEncoding := resp.Header.Get("Content-Encoding")

	// 根据Content-Encoding选择合适的读取器
	var reader io.Reader = resp.Body

	if strings.Contains(contentEncoding, "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	// 读取解压后的内容
	return io.ReadAll(reader)
}

// followRedirects 跟踪完整的重定向链，返回最终URL、标题和大小
func followRedirects(initialURL string, maxRedirects int) (string, string, int, error) {
	currentURL := initialURL
	redirectCount := 0

	// 避免重定向循环
	visitedRedirects := make(map[string]bool)

	for redirectCount < maxRedirects {
		// 检查是否陷入重定向循环
		if visitedRedirects[currentURL] {
			return currentURL, "", 0, fmt.Errorf("检测到重定向循环")
		}
		visitedRedirects[currentURL] = true

		// 创建GET请求
		getReq, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return currentURL, "", 0, err
		}

		// 设置请求头
		getReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
		getReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		getReq.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		getReq.Header.Set("Accept-Encoding", "gzip, deflate, br")
		getReq.Header.Set("Connection", "keep-alive")
		getReq.Header.Set("Upgrade-Insecure-Requests", "1")
		applyCustomHeaders(getReq, customHeaders)

		// 发送请求
		getResp, err := client.Do(getReq)
		if err != nil {
			return currentURL, "", 0, err
		}

		// 检查是否是重定向状态码
		if getResp.StatusCode >= 300 && getResp.StatusCode < 400 {
			location := getResp.Header.Get("Location")
			getResp.Body.Close()

			if location == "" {
				// 没有Location头，结束重定向
				break
			}

			// 处理相对URL
			nextURL := location
			if strings.HasPrefix(nextURL, "//") {
				baseURL, _ := neturl.Parse(currentURL)
				nextURL = baseURL.Scheme + ":" + nextURL
			} else if !strings.HasPrefix(nextURL, "http://") && !strings.HasPrefix(nextURL, "https://") {
				baseURL, _ := neturl.Parse(currentURL)
				redirectURLObj, err := baseURL.Parse(location)
				if err == nil {
					nextURL = redirectURLObj.String()
				}
			}

			currentURL = nextURL
			redirectCount++
		} else {
			// 非重定向状态码，读取响应体获取标题和大小
			body, err := readAndDecompressBody(getResp)
			getResp.Body.Close()

			if err != nil {
				return currentURL, "", 0, err
			}

			title := extractTitle(string(body))
			size := len(body)

			return currentURL, title, size, nil
		}
	}

	// 达到最大重定向次数或遇到其他情况，返回当前状态
	getReq, err := http.NewRequest("GET", currentURL, nil)
	if err != nil {
		return currentURL, "", 0, err
	}

	getReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	getReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	applyCustomHeaders(getReq, customHeaders)

	getResp, err := client.Do(getReq)
	if err != nil {
		return currentURL, "", 0, err
	}

	body, err := readAndDecompressBody(getResp)
	getResp.Body.Close()

	if err != nil {
		return currentURL, "", 0, err
	}

	title := extractTitle(string(body))
	size := len(body)

	return currentURL, title, size, nil
}

func probeURLList(urls []string) {
	semaphore := make(chan struct{}, concurrent)
	processedURLs := make(map[string]bool)
	domainGroups := make(map[string][]string)

	for _, u := range urls {
		normalizedURL := normalizePath(u)
		if processedURLs[normalizedURL] {
			continue
		}
		processedURLs[normalizedURL] = true
		parsedURL, err := neturl.Parse(normalizedURL)
		if err != nil {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-semaphore }()
				sendHTTPRequest(u, httpMethod, 0, true)
			}(u)
			continue
		}
		domain := parsedURL.Hostname()
		domainGroups[domain] = append(domainGroups[domain], u)
	}

	for _, urlsInDomain := range domainGroups {
		for _, currentURL := range urlsInDomain {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-semaphore }()
				sendHTTPRequest(u, httpMethod, 0, true)
			}(currentURL)
		}
	}
	wg.Wait()
}

func scanPath(basePath string, words []string, semaphore chan struct{}, depth int) {
	normalizedPath := normalizePath(basePath)
	// 使用sync.Map的LoadOrStore方法检查并标记为已访问
	if _, loaded := visited.LoadOrStore(normalizedPath, true); loaded {
		return
	}

	if depth > maxDepth {
		return
	}

	for _, word := range words {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(word string, currentDepth int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			testPath(basePath, word, words, semaphore, currentDepth)
		}(word, depth)
	}
}

func testPath(basePath, word string, words []string, semaphore chan struct{}, depth int) {
	fullPath := basePath + word
	requestMethod := httpMethod
	if ignoreBody && httpMethod == "GET" {
		requestMethod = "HEAD"
	}
	sendHTTPRequest(fullPath, requestMethod, depth, false)
}

func startOutputProcessor() {
	go func() {
		for {
			select {
			case message := <-outputQueue:
				if message == "" {
					return
				}
				outputMutex.Lock()
				if statusBarActive {
					fmt.Fprint(os.Stderr, "\r\033[K")
				}
				fmt.Printf("%s\n", message)
				outputMutex.Unlock()
			case <-outputDone:
				return
			}
		}
	}()
}

func printResult(message string) {
	select {
	case outputQueue <- message:
	default:
		outputMutex.Lock()
		if statusBarActive {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		fmt.Printf("%s\n", message)
		outputMutex.Unlock()
	}
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		statusBarActive = false
		fmt.Fprint(os.Stderr, "\r\033[K\n")
		fmt.Printf("%s[!] 扫描已终止 (Ctrl+C)%s\n", red, reset)
		fmt.Printf("%s[+] 已扫描: %d/%d (%.1f%%), 错误: %d%s\n",
			cyan, atomic.LoadInt64(&scannedCount), totalWords,
			float64(atomic.LoadInt64(&scannedCount))/float64(totalWords)*100,
			atomic.LoadInt64(&errorCount), reset)
		os.Exit(0)
	}()
}
func updateStatusBar() {
	if !statusBarActive {
		return
	}
	scanned := atomic.LoadInt64(&scannedCount)
	errors := atomic.LoadInt64(&errorCount)
	progressLine := fmt.Sprintf("\r%s%.1f%% | 已扫描: %d/%d | 错误: %d%s ",
		green,
		float64(scanned)/float64(totalWords)*100,
		scanned, totalWords,
		errors,
		reset)
	fmt.Fprint(os.Stderr, progressLine)
}

func startStatusBarUpdater() {
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond) // 降低到500ms更新一次，减少闪烁
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				updateStatusBar()
			}
		}
	}()
}

func handleRequestError(targetURL string, err error) {
	atomic.AddInt64(&scannedCount, 1)
	atomic.AddInt64(&errorCount, 1)
	var errorMsg string
	if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
		errorMsg = fmt.Sprintf("[%sTimeout%s] %s", red, reset, targetURL)
	} else if strings.Contains(err.Error(), "tls") {
		errorMsg = fmt.Sprintf("[%sTLS错误%s] %s - %v", red, reset, targetURL, err)
	} else if strings.Contains(err.Error(), "connection refused") {
		errorMsg = fmt.Sprintf("[%s连接拒绝%s] %s", red, reset, targetURL)
	} else if strings.Contains(err.Error(), "no such host") {
		errorMsg = fmt.Sprintf("[%sDNS解析失败%s] %s", red, reset, targetURL)
	} else if strings.Contains(err.Error(), "network is unreachable") {
		errorMsg = fmt.Sprintf("[%s网络不可达%s] %s", red, reset, targetURL)
	} else if strings.Contains(err.Error(), "request error") {
		errorMsg = fmt.Sprintf("%s[请求错误] %s: %v%s", red, targetURL, err, reset)
	} else {
		errorMsg = fmt.Sprintf("[%s网络错误%s] %s - %v", red, reset, targetURL, err)
	}
	printResult(errorMsg)
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
