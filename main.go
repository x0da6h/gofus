package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	buildDate = "2025-8-29"
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
	dictPath  string
	targetURL string
	client    *http.Client
	visited   = struct {
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

	// 新增：扫描状态统计
	scannedCount    int64     // 已扫描数量
	errorCount      int64     // 错误计数
	totalWords      int       // 总字典条数
	isPaused        int32     // 是否暂停 (0: 运行中, 1: 暂停)
	requestRate     int64     // 请求速率 (每秒请求数)
	lastRequestTime time.Time // 上次请求时间
	rateMutex       sync.RWMutex
	statusMutex     sync.Mutex
	outputMutex     sync.Mutex // 用于同步输出，防止进度条被刷乱
	statusBarActive bool       // 进度条是否激活

	// 新增：输出队列机制
	outputQueue chan string
	outputDone  chan struct{}
)

// ANSI颜色控制码
const (
	green = "\033[32m"
	red   = "\033[31m"
	blue  = "\033[34m"
	cyan  = "\033[36m"
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

	// 确保最小宽度
	if maxWidth < 30 {
		maxWidth = 30
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
		{"-h", "无", "	显示当前帮助信息"},
		{"-v", "无", "	显示工具版本信息"},
		{"-u", "<必填>", "	目标URL (例：https://example.com 或 example.com)"},
		{"-w", "<必填>", "	路径字典文件 (支持#注释、自动忽略空行)"},
		{"-c", "10", "	并发请求数 (建议10-50，防止触发目标限流)"},
		{"-d", "1", "	最大递归深度 (1: 仅根路径，3: 支持3级子路径)"},
		{"-fc", "无", "	过滤状态码 (逗号分隔，例：-fc 404,403 不显示404/403)"},
		{"-mc", "无", "	匹配状态码 (逗号分隔，例：-mc 200,500 只显示200/500)"},
		{"-fs", "无", "	过滤响应体大小 (逗号分隔，例：-fs 1000 不显示大小1000的响应)"},
		{"-x", "无", "	文件后缀扩展 (逗号分隔，例：-x php,txt,bak)"},
		{"-ib", "无", "	忽略响应体内容 (只获取响应头)"},
		{"-m", "GET", "	HTTP请求方法 (支持: GET,POST,OPTIONS)"},
		{"-t", "1", "	请求超时时间 (秒数，例：-t 5 设置5秒超时)"},
		{"-H", "无", "	自定义请求头 (例：-H \"Name: Value\" 可多次使用)"},
		{"--data", "无", "	请求体数据 (例：--data \"{user:admin}\")"},
	}

	// 打印参数列表
	fmt.Println("\n选项说明:\n")
	for _, p := range params {
		fmt.Printf("  %-6s  默认值: %-8s  %s\n", p.flag, p.defaultVal, p.desc)
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
	flag.IntVar(&concurrent, "c", 10, "并发数量")
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

	if dictPath == "" || targetURL == "" {
		fmt.Printf("%s\n[ERROR] 缺少必需参数 -u (目标URL) 和 -w (字典文件)%s\n", red, reset)
		fmt.Println("提示：执行 gofus -h 查看完整使用说明\n")
		os.Exit(1)
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

	client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second, // 使用用户指定的超时时间
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSHandshakeTimeout:   time.Duration(timeout/2) * time.Second, // TLS握手超时设为总超时的一半
			ResponseHeaderTimeout: time.Duration(timeout/3) * time.Second, // 响应头超时设为总超时的三分之一
			ExpectContinueTimeout: 5 * time.Second,                        // Expect-Continue超时
			IdleConnTimeout:       30 * time.Second,                       // 空闲连接超时
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过TLS证书验证
			},
		},
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
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

// 新增：格式化字符串数组为逗号分隔的字符串
func formatStringArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	return "[" + strings.Join(arr, ",") + "]"
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
	configLines := []string{
		fmt.Sprintf("#目标URL    : %s", targetURL),
		fmt.Sprintf("#字典文件   : %s", dictPath),
		fmt.Sprintf("#并发数量   : %d", concurrent),
		fmt.Sprintf("#最大深度   : %d", maxDepth),
		fmt.Sprintf("#HTTP方法   : %s", httpMethod),
		fmt.Sprintf("#超时时间   : %d秒", timeout),
	}

	// 添加可选的过滤信息
	if len(filterLengths) > 0 {
		configLines = append(configLines, fmt.Sprintf("#过滤大小   : %s", formatIntArray(filterLengths)))
	}
	if len(filterCodes) > 0 {
		configLines = append(configLines, fmt.Sprintf("#过滤状态码 : %s", formatIntArray(filterCodes)))
	}
	if len(matchCodes) > 0 {
		configLines = append(configLines, fmt.Sprintf("#匹配状态码 : %s", formatIntArray(matchCodes)))
	}
	if len(extensions) > 0 {
		configLines = append(configLines, fmt.Sprintf("#扩展后缀   : %s", formatExtensionArray(extensions)))
	}
	if ignoreBody {
		configLines = append(configLines, "#忽略响应体 : 开启")
	}
	if len(customHeaders) > 0 {
		configLines = append(configLines, fmt.Sprintf("#自定义请求头 : %d个", len(customHeaders)))
	}
	if requestData != "" {
		configLines = append(configLines, "#请求体数据 : 已设置")
	}

	// 读取字典并添加加载信息
	words, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("%s【错误】读取字典失败: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	totalWords = len(words)
	configLines = append(configLines, fmt.Sprintf("#字典加载   : %d", len(words)))

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
	scanPath(targetURL, words, semaphore, 1)
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
	fmt.Printf("%s[+] 扫描完成! 总计扫描: %d 个路径，错误: %d 个%s\n", green, atomic.LoadInt64(&scannedCount), atomic.LoadInt64(&errorCount), reset)
}

func readDictionary(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			// 原始词条
			words = append(words, word)

			// 如果指定了扩展名，且该词条没有扩展名，则添加扩展名版本
			if len(extensions) > 0 && !hasFileExtension(word) {
				for _, ext := range extensions {
					words = append(words, word+ext)
				}
			}
		}
	}
	return words, scanner.Err()
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

func scanPath(basePath string, words []string, semaphore chan struct{}, depth int) {
	visited.Lock()
	if visited.m[basePath] {
		visited.Unlock()
		return
	}
	visited.m[basePath] = true
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
	// 检查是否暂停
	if atomic.LoadInt32(&isPaused) == 1 {
		return
	}

	fullPath := basePath + word

	// 根据用户选项决定HTTP方法
	requestMethod := httpMethod
	if ignoreBody && httpMethod == "GET" {
		// 如果启用-ib且使用GET方法，则改为HEAD方法
		requestMethod = "HEAD"
	}

	// 创建请求体（支持任何HTTP方法）
	var requestBody io.Reader
	if requestData != "" {
		// 在请求体末尾添加两个换行符，确保请求格式完整
		requestBody = strings.NewReader(requestData + "\n\n")
	}

	// 创建自定义HTTP请求，设置User-Agent
	req, err := http.NewRequest(requestMethod, fullPath, requestBody)
	if err != nil {
		// 增加错误计数
		atomic.AddInt64(&errorCount, 1)
		printResult(fmt.Sprintf("%s[请求错误] %s: %v%s", red, fullPath, err, reset))
		return
	}

	// 设置User-Agent为gofus
	req.Header.Set("User-Agent", "gofus/1.0")

	// 应用自定义请求头
	applyCustomHeaders(req, customHeaders)

	resp, err := client.Do(req)
	if err != nil {
		// 增加错误计数
		atomic.AddInt64(&errorCount, 1)

		// 使用printResult函数输出错误信息
		if strings.Contains(err.Error(), "timeout") {
			printResult(fmt.Sprintf("%s[超时] %s%s", red, fullPath, reset))
		} else if strings.Contains(err.Error(), "tls") {
			printResult(fmt.Sprintf("%s[TLS错误] %s: %v%s", red, fullPath, err, reset))
		} else if strings.Contains(err.Error(), "connection refused") {
			printResult(fmt.Sprintf("%s[连接拒绝] %s%s", red, fullPath, reset))
		}
		return
	}
	defer resp.Body.Close()

	// 更新扫描计数
	atomic.AddInt64(&scannedCount, 1)

	// 更新请求速率 - 使用基于时间窗口的速率计算
	rateMutex.Lock()
	now := time.Now()
	if !lastRequestTime.IsZero() {
		elapsed := now.Sub(lastRequestTime).Seconds()
		if elapsed > 0 {
			// 计算瞬时速率
			instantRate := int64(1 / elapsed)
			// 使用加权平均来平滑速率变化
			currentRate := atomic.LoadInt64(&requestRate)
			if currentRate == 0 {
				atomic.StoreInt64(&requestRate, instantRate)
			} else {
				// 加权平均：新速率占30%，旧速率占70%
				newRate := int64(float64(currentRate)*0.7 + float64(instantRate)*0.3)
				atomic.StoreInt64(&requestRate, newRate)
			}
		}
	}
	lastRequestTime = now
	rateMutex.Unlock()

	contentLength := int(resp.ContentLength)
	if contentLength < 0 {
		contentLength = 0
	}

	// 先判断是否为可递归目录（不受过滤影响）
	canDescend := false
	if depth < maxDepth {
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
				lastSlashIndex := strings.LastIndex(word, "/")
				filename := word
				if lastSlashIndex >= 0 {
					filename = word[lastSlashIndex+1:]
				}
				// 如果没有文件后缀名（没有点或点后面没有内容），则认为是目录
				dotIndex := strings.LastIndex(filename, ".")
				if dotIndex == -1 || dotIndex == len(filename)-1 {
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
					green, resp.StatusCode, reset, fullPath, depth))
			} else {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					green, resp.StatusCode, reset, fullPath, depth, contentLength))
			}
		} else if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
			// 301和302状态码：蓝色
			if ignoreBody {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					blue, resp.StatusCode, reset, fullPath, depth))
			} else {
				printResult(fmt.Sprintf("[%s%d%s] %s\t"+outputFormat,
					blue, resp.StatusCode, reset, fullPath, depth, contentLength))
			}
		} else {
			// 其他状态码：默认颜色
			if ignoreBody {
				printResult(fmt.Sprintf("[%d] %s\t"+outputFormat,
					resp.StatusCode, fullPath, depth))
			} else {
				printResult(fmt.Sprintf("[%d] %s\t"+outputFormat,
					resp.StatusCode, fullPath, depth, contentLength))
			}
		}
	}

	// 递归扫描逻辑（不受过滤影响）
	if depth < maxDepth && canDescend {
		nextBase := fullPath
		if !strings.HasSuffix(nextBase, "/") {
			nextBase += "/"
		}
		scanPath(nextBase, words, semaphore, depth+1)
	}
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

// 新增：设置信号处理器 (Ctrl+C直接终止)
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		atomic.StoreInt32(&isPaused, 1)
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

// 新增：格式化速率 (类似ffuf的速率显示)
func formatRate(rate int64) string {
	if rate >= 1000 {
		return fmt.Sprintf("%.1fk", float64(rate)/1000)
	}
	return fmt.Sprintf("%d", rate)
}

// 新增：固定状态行进度条更新
func updateStatusBar() {
	if !statusBarActive {
		return
	}

	statusMutex.Lock()
	defer statusMutex.Unlock()

	// 检查是否暂停
	if atomic.LoadInt32(&isPaused) == 1 {
		return
	}

	scanned := atomic.LoadInt64(&scannedCount)
	errors := atomic.LoadInt64(&errorCount)
	rate := atomic.LoadInt64(&requestRate)

	// 使用简单的\r回车符实现就地更新，移除复杂的ANSI光标控制
	progressLine := fmt.Sprintf("\r%s%.1f%% | 速率: %s req/sec | 已扫描: %d/%d | 错误: %d%s ",
		green,
		float64(scanned)/float64(totalWords)*100,
		formatRate(rate),
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
				if atomic.LoadInt32(&isPaused) == 0 {
					updateStatusBar()
				}
			}
		}
	}()
}
