package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// 版本信息
const (
	version   = "1.0.0"
	buildDate = "2025-8-31"
	author    = "x0da6h"
)

// 自定义类型用于处理多个字符串值
type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

var (
	dictPath    string
	targetURL   string
	urlListPath string // URL列表文件路径
	proxyURL    string // 代理服务器URL
	client      *http.Client
	visited     = struct {
		sync.RWMutex
		m map[string]bool
	}{m: make(map[string]bool)}
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

	// 扫描状态统计
	scannedCount    int64      // 已扫描数量
	errorCount      int64      // 错误计数
	totalWords      int        // 总字典条数
	outputMutex     sync.Mutex // 用于同步输出，防止进度条被刷乱
	statusBarActive bool       // 进度条是否激活

	// 输出队列机制
	outputQueue chan string
	outputDone  chan struct{}
)

// ANSI颜色控制码
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

// 新增：打印配置信息框（根据内容自动调整宽度）
func printConfigBox(lines []string) {
	// 计算最大内容宽度（考虑中文字符的显示宽度）
	maxWidth := 0
	for _, line := range lines {
		// 计算实际显示宽度（中文字符占两个位置）
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

	// 不设置最小宽度，让配置框根据内容自动调整（保持紧凑）
	// 只在内容宽度低于20时才设置最小宽度
	if maxWidth < 20 {
		maxWidth = 20
	}

	// 生成上边框
	borderTop := "*" + strings.Repeat("-", maxWidth+2) + "*"
	borderBottom := "*" + strings.Repeat("-", maxWidth+2) + "*"

	// 打印边框和内容
	fmt.Println(borderTop)
	for _, line := range lines {
		// 计算当前行的显示宽度
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
	fmt.Println(borderBottom)
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

	// 打印参数列表
	fmt.Println("\n选项说明:\n")
	for _, p := range params {
		fmt.Printf("  %-8s  默认值: %-8s  %s\n", p.flag, p.defaultVal, p.desc)
	}
}

// 打印版本信息
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
	flag.IntVar(&timeout, "t", 1, "请求超时时间(秒)")
	flag.StringVar(&requestData, "data", "", "请求体数据")
	flag.StringVar(&filterCodeStr, "fc", "", "需要过滤的状态码，用逗号分隔 (例如: 404,403)")
	flag.StringVar(&matchCodeStr, "mc", "", "需要匹配的状态码，用逗号分隔 (例如: 200,500)")
	flag.StringVar(&filterLengthStr, "fs", "", "需要过滤的响应体大小，用逗号分隔 (例如: 1000,2000)")
	flag.BoolVar(&ignoreBody, "ib", false, "忽略响应体内容，只获取响应头")
	flag.Var(&customHeaders, "H", "自定义请求头 (例如: -H 'Name: Value')")
	flag.StringVar(&proxyURL, "proxy", "", "代理服务器地址 (支持HTTP、HTTPS、SOCKS4和SOCKS5，格式: http://127.0.0.1:7890 或 socks5://127.0.0.1:7890)")

	flag.Usage = printHelp
	flag.Parse()
	// 处理版本参数
	if showVersion {
		printVersion()
		os.Exit(0)
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		os.Exit(0)
	}

	if urlListPath != "" {
		// URL列表模式：只需要URL列表文件
		if dictPath != "" {
			fmt.Printf("%s\n[ERROR] -U 和 -w 选项不能同时使用%s\n", red, reset)
			os.Exit(1)
		}
		if targetURL != "" {
			fmt.Printf("%s\n[ERROR] -U 和 -u 选项不能同时使用%s\n", red, reset)
			os.Exit(1)
		}
	} else {
		// 正常扫描模式：需要URL和字典文件
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

	// 验证HTTP方法是否有效
	httpMethod = strings.ToUpper(httpMethod)
	if httpMethod != "GET" && httpMethod != "POST" && httpMethod != "OPTIONS" {
		fmt.Printf("%s\n[ERROR] 不支持的HTTP方法: %s，支持的方法: GET, POST, OPTIONS%s\n", red, httpMethod, reset)
		os.Exit(1)
	}

	// 验证超时时间是否合理
	if timeout < 1 || timeout > 300 {
		fmt.Printf("%s\n[ERROR] 超时时间不合理: %d秒，允许范围: 1-300秒%s\n", red, timeout, reset)
		os.Exit(1)
	}

	// 请求体数据可用于任何HTTP方法（符合FUZZ工具的设计理念）

	// 创建HTTP传输对象
	// 创建HTTP传输对象
	httpTransport := &http.Transport{
		// 优化连接池设置
		MaxIdleConns:          100,             // 增加最大空闲连接数
		MaxIdleConnsPerHost:   20,              // 每个主机的最大空闲连接数
		MaxConnsPerHost:       0,               // 不限制每个主机的最大连接数
		TLSHandshakeTimeout:   3 * time.Second, // 降低TLS握手超时时间(从5秒到3秒)以加快连接速度
		ResponseHeaderTimeout: 5 * time.Second, // 降低响应头超时时间(从10秒到5秒)以加快结果返回
		// HTTP客户端在发送带有Expect: 100-continue头的请求时，等待服务器响应的最长时间为2秒
		// 这个机制用于在发送大请求体前先询问服务器是否愿意接受请求，避免浪费带宽
		ExpectContinueTimeout: 1 * time.Second,  // 降低Expect-Continue超时(从2秒到1秒)以加快请求处理
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

	// 如果设置了代理，配置代理
	if proxyURL != "" {
		proxyURLObj, err := neturl.Parse(proxyURL)
		if err != nil {
			fmt.Printf("%s\n[ERROR] 无效的代理URL格式: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		// 验证代理协议类型
		protocol := strings.ToLower(proxyURLObj.Scheme)
		if protocol != "http" && protocol != "https" && protocol != "socks5" && protocol != "socks4" {
			fmt.Printf("%s\n[ERROR] 不支持的代理协议: %s，仅支持: http, https, socks4, socks5%s\n", red, protocol, reset)
			os.Exit(1)
		}
		httpTransport.Proxy = http.ProxyURL(proxyURLObj)
	}

	// 创建HTTP客户端
	client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second, // 使用用户指定的超时时间
		// 允许最多10次重定向，但在URL列表模式下特殊处理
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 默认不自动跟随重定向，但在URL列表模式下会特殊处理
			return http.ErrUseLastResponse
		},
		Transport: httpTransport,
	}

	// 只在非URL列表模式下处理目标URL
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

// 新增：解析文件扩展名
func parseExtensions(extStr string) []string {
	var result []string
	if extStr == "" {
		return result
	}
	parts := strings.Split(extStr, ",")
	for _, part := range parts {
		ext := strings.TrimSpace(part)
		if ext != "" {
			// 确保扩展名以.开头
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			result = append(result, ext)
		}
	}
	return result
}

// 新增：解析请求头并应用到请求上
func applyCustomHeaders(req *http.Request, headers []string) {
	for _, header := range headers {
		// 解析 "Name: Value" 格式
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

// 新增：检查状态码是否在匹配列表中
func isMatchedCode(code int) bool {
	// 如果没有设置匹配列表，则匹配所有状态码
	if len(matchCodes) == 0 {
		return true
	}
	// 检查状态码是否在匹配列表中
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

// 新增：格式化整数数组为逗号分隔的字符串
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

// 新增：路径规范化函数，用于去重
func normalizePath(path string) string {
	// 去除末尾的斜杠，使/123和/123/视为同一个路径
	path = strings.TrimSpace(path)
	if len(path) > 0 && strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "//") {
		path = path[:len(path)-1]
	}
	return path
}

// 新增：格式化扩展名数组为逗号分隔的字符串（去掉句号前缀）
func formatExtensionArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	// 去掉每个扩展名的句号前缀
	cleanExts := make([]string, len(arr))
	for i, ext := range arr {
		if strings.HasPrefix(ext, ".") {
			cleanExts[i] = ext[1:] // 去掉句号
		} else {
			cleanExts[i] = ext
		}
	}
	return "[" + strings.Join(cleanExts, ",") + "]"
}

func main() {
	logo()

	// 准备配置信息
	var configLines []string
	var words []string
	var urls []string

	if urlListPath != "" {
		// URL列表模式
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

		// 只有在设置了代理时才显示代理设置行
		if proxyURL != "" {
			configLines = append(configLines, fmt.Sprintf("#代理设置   : %s", proxyURL))
		}
	} else {
		// 正常扫描模式
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

		// 只有在设置了代理时才显示代理设置行
		if proxyURL != "" {
			configLines = append(configLines, fmt.Sprintf("#代理设置    : %s", proxyURL))
		}
	}

	// 添加可选的过滤信息
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

	// 打印格式化的配置框
	printConfigBox(configLines)

	// 初始化输出队列
	outputQueue = make(chan string, 100) // 缓冲100个消息
	outputDone = make(chan struct{})

	// 启动输出处理协程
	startOutputProcessor()

	// 设置信号处理器
	setupSignalHandler()

	// 启用状态行进度条（固定在底部）
	statusBarActive = true

	// 启动状态行更新器
	startStatusBarUpdater()

	// 为状态栏预留空间（在底部预留1行）
	fmt.Printf("\n") // 预留进度条行

	semaphore := make(chan struct{}, concurrent)
	// 根据模式执行不同的扫描逻辑
	if urlListPath != "" {
		// URL列表探活模式
		probeURLList(urls)
	} else {
		// 正常扫描模式
		scanPath(targetURL, words, semaphore, 1)
	}
	wg.Wait()

	// 关闭输出队列
	close(outputQueue)
	close(outputDone)

	// 等待一下让所有输出完成
	time.Sleep(100 * time.Millisecond)

	// 禁用进度条
	statusBarActive = false

	// 按照项目规范清除进度条：使用fmt.Fprint(os.Stderr, "\r\033[K\n")
	fmt.Fprint(os.Stderr, "\r\033[K\n")

	// 扫描完成后显示最终统计
	if urlListPath != "" {
		totalScanned := atomic.LoadInt64(&scannedCount)
		totalErrors := atomic.LoadInt64(&errorCount)
		totalSuccess := totalScanned - totalErrors
		fmt.Printf("%s[+] 探活完成! 总计扫描: %d 个URL，成功: %d 个，错误: %d 个%s\n",
			green, totalScanned, totalSuccess, totalErrors, reset)
	} else {
		fmt.Printf("%s[+] 扫描完成! 总计扫描: %d 个路径，错误: %d 个%s\n\n",
			green, atomic.LoadInt64(&scannedCount), atomic.LoadInt64(&errorCount), reset)
	}
}

func readDictionary(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var words []string
	wordMap := make(map[string]bool) // 用于去重
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			// 原始词条
			normalizedWord := normalizePath(word)
			if !wordMap[normalizedWord] {
				wordMap[normalizedWord] = true
				words = append(words, word)
			}

			// 如果指定了扩展名，且该词条没有扩展名，则添加扩展名版本
			if len(extensions) > 0 && !hasFileExtension(word) {
				for _, ext := range extensions {
					extWord := word + ext
					normalizedExtWord := normalizePath(extWord)
					if !wordMap[normalizedExtWord] {
						wordMap[normalizedExtWord] = true
						words = append(words, extWord)
					}
				}
			}
		}
	}
	return words, scanner.Err()
}

// 新增：读取URL列表文件（带去重功能）
func readURLList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var urls []string
	urlMap := make(map[string]bool) // 用于去重
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" && !strings.HasPrefix(url, "#") {
			// 确保 URL 有协议前缀
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			// 规范化URL并去重
			normalizedURL := normalizePath(url)
			if !urlMap[normalizedURL] {
				urlMap[normalizedURL] = true
				urls = append(urls, url)
			}
		}
	}
	return urls, scanner.Err()
}

// 新增：检查路径是否已有文件扩展名
func hasFileExtension(path string) bool {
	// 获取最后一个斜杠后的部分
	lastSlashIndex := strings.LastIndex(path, "/")
	filename := path
	if lastSlashIndex >= 0 {
		filename = path[lastSlashIndex+1:]
	}

	// 检查是否有有意义的扩展名（点后面有字符）
	dotIndex := strings.LastIndex(filename, ".")
	return dotIndex > 0 && dotIndex < len(filename)-1
}

// 统一的HTTP请求函数，支持重试机制
func sendHTTPRequest(targetURL string, method string, depth int, isURLListMode bool) {
	// 创建请求体（支持任何HTTP方法）
	var requestBody io.Reader
	if requestData != "" {
		// 在请求体末尾添加两个换行符，确保请求格式完整
		requestBody = strings.NewReader(requestData + "\n\n")
	}

	// 创建自定义HTTP请求，设置User-Agent
	req, err := http.NewRequest(method, targetURL, requestBody)
	if err != nil {
		// 增加扫描计数和错误计数
		atomic.AddInt64(&scannedCount, 1)
		atomic.AddInt64(&errorCount, 1)
		printResult(fmt.Sprintf("%s[请求错误] %s: %v%s", red, targetURL, err, reset))
		return
	}

	// 优化请求头以更好地模拟浏览器
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// 应用自定义请求头
	applyCustomHeaders(req, customHeaders)

	// 添加简单的重试机制
	var resp *http.Response
	const maxRetries = 2
	retryCount := 0
	retryableErrors := []string{"timeout", "deadline exceeded", "TLS handshake timeout", "connection reset"}

	for retryCount <= maxRetries {
		resp, err = client.Do(req)
		if err == nil {
			break // 请求成功，退出重试循环
		}

		// 检查错误是否可重试
		isRetryable := false
		for _, retryErr := range retryableErrors {
			if strings.Contains(err.Error(), retryErr) {
				isRetryable = true
				break
			}
		}

		// 如果不可重试或者已经达到最大重试次数，则报告错误
		if !isRetryable || retryCount == maxRetries {
			// 增加扫描计数和错误计数
			atomic.AddInt64(&scannedCount, 1)
			atomic.AddInt64(&errorCount, 1)

			// 显示详细的错误信息
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
				printResult(fmt.Sprintf("[%sTimeout%s] %s", red, reset, targetURL))
			} else if strings.Contains(err.Error(), "tls") {
				printResult(fmt.Sprintf("[%sTLS错误%s] %s - %v", red, reset, targetURL, err))
			} else if strings.Contains(err.Error(), "connection refused") {
				printResult(fmt.Sprintf("[%s连接拒绝%s] %s", red, reset, targetURL))
			} else if strings.Contains(err.Error(), "no such host") {
				printResult(fmt.Sprintf("[%sDNS解析失败%s] %s", red, reset, targetURL))
			} else if strings.Contains(err.Error(), "network is unreachable") {
				printResult(fmt.Sprintf("[%s网络不可达%s] %s", red, reset, targetURL))
			} else {
				// 其他未知错误
				printResult(fmt.Sprintf("[%s网络错误%s] %s - %v", red, reset, targetURL, err))
			}
			return
		}

		// 可重试的错误，等待一段时间后重试
		retryCount++
		time.Sleep(time.Duration(retryCount*100) * time.Millisecond) // 指数退避
	}

	defer resp.Body.Close()

	// 更新扫描计数
	atomic.AddInt64(&scannedCount, 1)

	// 如果是URL列表模式，直接处理结果
	if isURLListMode {
		// 只在未被过滤且匹配指定状态码时才输出结果
		if !isFilteredCode(resp.StatusCode) && isMatchedCode(resp.StatusCode) {
			// 获取响应体大小
			// 先尝试使用Content-Length
			contentLength := int(resp.ContentLength)
			if contentLength < 0 {
				// 如果Content-Length不可用，实际读取响应体计算大小
				bodyBytes, err := io.ReadAll(resp.Body)
				if err == nil {
					contentLength = len(bodyBytes)
				} else {
					contentLength = 0
				}
				// 重新包装响应体以便后续处理
				resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// 格式化响应体大小，当大小为0时使用红色背景
			formatSize := func(size int) string {
				if size == 0 {
					return fmt.Sprintf("%s%d%s", redBg, size, reset)
				}
				return fmt.Sprintf("%d", size)
			}

			// 根据状态码选择颜色输出
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// 2xx状态码：绿色
				printResult(fmt.Sprintf("[%s%d%s] %s [响应体大小: %s]", green, resp.StatusCode, reset, targetURL, formatSize(contentLength)))
			} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				// 3xx状态码：蓝色
				location := resp.Header.Get("Location")
				if location != "" {
					// 如果有Location头，显示重定向目标和跳转后的响应体大小
					redirectSize := 0
					// 对于重定向，获取跳转后的响应体大小
					redirectURL := location
					// 处理不同类型的不完整URL
					if strings.HasPrefix(redirectURL, "//") {
						// 协议相对URL (//example.com/path)
						baseURL, _ := neturl.Parse(targetURL)
						redirectURL = baseURL.Scheme + ":" + redirectURL
					} else if !strings.HasPrefix(redirectURL, "http://") && !strings.HasPrefix(redirectURL, "https://") {
						// 相对URL，需要补全
						baseURL, _ := neturl.Parse(targetURL)
						redirectURLObj, err := baseURL.Parse(location)
						if err == nil {
							redirectURL = redirectURLObj.String()
						}
					}

					// 发送HEAD请求获取重定向URL的响应体大小
					redirectReq, err := http.NewRequest("HEAD", redirectURL, nil)
					if err == nil {
						redirectReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
						redirectResp, err := client.Do(redirectReq)
						if err == nil {
							redirectSize = int(redirectResp.ContentLength)
							if redirectSize < 0 {
								// 如果Content-Length不可用，使用GET请求实际读取响应体
								getReq, err := http.NewRequest("GET", redirectURL, nil)
								if err == nil {
									getReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
									getResp, err := client.Do(getReq)
									if err == nil {
										bodyBytes, err := io.ReadAll(getResp.Body)
										if err == nil {
											redirectSize = len(bodyBytes)
										}
										getResp.Body.Close()
									}
								}
							}
							redirectResp.Body.Close()
						}
					}

					printResult(fmt.Sprintf("[%s%d%s] %s -> %s [响应体大小: %s]", blue, resp.StatusCode, reset, targetURL, redirectURL, formatSize(redirectSize)))
				} else {
					printResult(fmt.Sprintf("[%s%d%s] %s [响应体大小: %s]", blue, resp.StatusCode, reset, targetURL, formatSize(contentLength)))
				}
			} else if resp.StatusCode >= 400 {
				// 4xx和5xx状态码：红色
				printResult(fmt.Sprintf("[%s%d%s] %s [响应体大小: %s]", red, resp.StatusCode, reset, targetURL, formatSize(contentLength)))
			} else {
				// 其他状态码：默认颜色
				printResult(fmt.Sprintf("[%d] %s [响应体大小: %s]", resp.StatusCode, targetURL, formatSize(contentLength)))
			}
		}
		return
	}

	// 对于非URL列表模式（正常扫描模式），需要处理递归逻辑
	contentLength := int(resp.ContentLength)
	if contentLength < 0 {
		contentLength = 0
	}

	// 先判断是否为可递归目录（不受过滤影响）
	canDescend := false
	if depth < maxDepth {
		// 从URL中提取最后一部分作为word
		parts := strings.Split(targetURL, "/")
		word := parts[len(parts)-1]
		if len(parts) > 1 && parts[len(parts)-2] != "" {
			word = parts[len(parts)-2]
		}

		// 情况1：字典词以'/'结尾，通常表示目录
		if strings.HasSuffix(word, "/") {
			canDescend = resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect ||
				resp.StatusCode == http.StatusPermanentRedirect
		} else {
			// 情况2：未以'/'结尾，但返回了重定向（常见：/a -> /a/）
			if resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusFound ||
				resp.StatusCode == http.StatusTemporaryRedirect ||
				resp.StatusCode == http.StatusPermanentRedirect {
				canDescend = true
			} else if resp.StatusCode == http.StatusOK {
				// 情况3：200状态码且没有文件后缀名，应该递归
				// 检查是否有文件后缀名（包含点且后面有字母或数字）
				dotIndex := strings.LastIndex(word, ".")
				if dotIndex == -1 || dotIndex == len(word)-1 {
					// 没有点或点在最后，认为是目录
					canDescend = true
				}
			}
		}
	}

	// 只在未被过滤且匹配指定状态码时才输出结果
	if !isFilteredCode(resp.StatusCode) && !isFilteredLength(contentLength) && isMatchedCode(resp.StatusCode) {
		// 根据是否使用-ib选项决定输出格式
		var outputFormat string
		if ignoreBody {
			// 使用-ib选项时，不显示大小信息
			outputFormat = "[深度: %d]"
		} else {
			// 正常模式显示深度和大小
			outputFormat = "[深度: %d, 大小: %d]"
		}

		// 根据状态码选择颜色输出
		if resp.StatusCode == http.StatusOK {
			// 200状态码：绿色
			if ignoreBody {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					green, resp.StatusCode, reset, targetURL, depth))
			} else {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					green, resp.StatusCode, reset, targetURL, depth, contentLength))
			}
		} else if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
			// 301和302状态码：蓝色
			if ignoreBody {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					blue, resp.StatusCode, reset, targetURL, depth))
			} else {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					blue, resp.StatusCode, reset, targetURL, depth, contentLength))
			}
		} else {
			// 其他状态码：默认颜色
			if ignoreBody {
				printResult(fmt.Sprintf("[%d] %s\t"+outputFormat,
					resp.StatusCode, targetURL, depth))
			} else {
				printResult(fmt.Sprintf("[%d] %s\t"+outputFormat,
					resp.StatusCode, targetURL, depth, contentLength))
			}
		}
	}

	// 递归扫描逻辑（不受过滤影响）
	if depth < maxDepth && canDescend {
		nextBase := targetURL
		if !strings.HasSuffix(nextBase, "/") {
			nextBase += "/"
		}
		// 获取字典文件内容
		words, err := readDictionary(dictPath)
		if err == nil {
			semaphore := make(chan struct{}, concurrent)
			scanPath(nextBase, words, semaphore, depth+1)
		}
	}
}

// URL列表探活函数，使用域名分组来优化并发性能
func probeURLList(urls []string) {
	semaphore := make(chan struct{}, concurrent)
	processedURLs := make(map[string]bool) // 用于扫描时去重

	// 按域名分组，避免对同一域名同时发起过多请求
	domainGroups := make(map[string][]string)

	for _, u := range urls {
		normalizedURL := normalizePath(u)
		if processedURLs[normalizedURL] {
			continue
		}
		processedURLs[normalizedURL] = true

		// 提取域名
		parsedURL, err := neturl.Parse(normalizedURL)
		if err != nil {
			// 无法解析的URL直接处理
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

	// 为每个域名组启动goroutine，控制对同一域名的并发请求
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
	// 规范化路径以确保去重正确工作
	normalizedPath := normalizePath(basePath)
	visited.Lock()
	if visited.m[normalizedPath] {
		visited.Unlock()
		return
	}
	visited.m[normalizedPath] = true
	visited.Unlock()

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

	// 根据用户选项决定HTTP方法
	requestMethod := httpMethod
	if ignoreBody && httpMethod == "GET" {
		// 如果启用-ib且使用GET方法，则改为HEAD方法
		requestMethod = "HEAD"
	}

	sendHTTPRequest(fullPath, requestMethod, depth, false)
}

// 新增：输出处理协程
func startOutputProcessor() {
	go func() {
		for {
			select {
			case message := <-outputQueue:
				if message == "" {
					return // 空消息表示结束
				}
				// 安全的结果输出：临时清除进度条→输出结果→让进度条自然恢复
				outputMutex.Lock()
				if statusBarActive {
					// 清除当前进度条
					fmt.Fprint(os.Stderr, "\r\033[K")
				}
				// 输出结果到stdout
				fmt.Printf("%s\n", message)
				outputMutex.Unlock()
			case <-outputDone:
				return
			}
		}
	}()
}

// 新增：打印结果（保护进度条不被干扰）
func printResult(message string) {
	// 使用输出队列确保所有结果都能显示
	select {
	case outputQueue <- message:
		// 成功发送到队列
	default:
		// 队列满了，直接输出
		outputMutex.Lock()
		if statusBarActive {
			// 清除当前进度条
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		// 输出结果到stdout
		fmt.Printf("%s\n", message)
		outputMutex.Unlock()
	}
}

// 设置信号处理器 (Ctrl+C直接终止)
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		statusBarActive = false

		// 按照项目规范清除进度条
		fmt.Fprint(os.Stderr, "\r\033[K\n")

		// 显示暂停信息
		fmt.Printf("%s[!] 扫描已终止 (Ctrl+C)%s\n", red, reset)
		fmt.Printf("%s[+] 已扫描: %d/%d (%.1f%%), 错误: %d%s\n",
			cyan, atomic.LoadInt64(&scannedCount), totalWords,
			float64(atomic.LoadInt64(&scannedCount))/float64(totalWords)*100,
			atomic.LoadInt64(&errorCount), reset)
		os.Exit(0)
	}()
}

// 固定状态行进度条更新
func updateStatusBar() {
	if !statusBarActive {
		return
	}

	scanned := atomic.LoadInt64(&scannedCount)
	errors := atomic.LoadInt64(&errorCount)

	// 使用简单的\r回车符实现就地更新，移除复杂的ANSI光标控制
	progressLine := fmt.Sprintf("\r%s%.1f%% | 已扫描: %d/%d | 错误: %d%s ",
		green,
		float64(scanned)/float64(totalWords)*100,
		scanned, totalWords,
		errors,
		reset)

	// 输出进度信息到stderr
	fmt.Fprint(os.Stderr, progressLine)
}

// 新增：启动状态栏更新协程
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
