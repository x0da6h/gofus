package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
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
	filterLengths   []int // 需要过滤的响应体长度
	filterCodeStr   string
	filterLengthStr string

	// 新增：扫描状态统计
	scannedCount    int64     // 已扫描数量
	errorCount      int64     // 错误计数
	totalWords      int       // 总字典条数
	startTime       time.Time // 开始时间
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
	green   = "\033[32m"
	red     = "\033[31m"
	blue    = "\033[34m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
	reset   = "\033[0m"

	// 进度条字符
	progressChar = "█"
	emptyChar    = "░"
)

func logo() {
	gofusLogo := `
   ██████╗   ██████╗  ███████╗ ██╗   ██╗ ███████╗
  ██╔════╝  ██╔═══██╗ ██╔════╝ ██║   ██║ ██╔════╝
  ██║ ████╗ ██║   ██║ ██████╗  ██║   ██║ ███████╗
  ██║   ██║ ██║   ██║ ██╔═══╝  ██║   ██║ ╚════██║
  ╚██████╔╝ ╚██████╔╝ ██║      ╚██████╔╝ ███████║
   ╚═════╝   ╚═════╝  ╚═╝       ╚═════╝  ╚══════╝

  gofus - WEB路径递归扫描工具 | by x0da6h
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
		{"-h", "无", " 显示当前帮助信息"},
		{"-u", "<必填>", "目标URL (例：https://example.com 或 example.com)"},
		{"-w", "<必填>", "路径字典文件 (支持#注释、自动忽略空行)"},
		{"-c", "10", "  并发请求数 (建议10-50，防止触发目标限流)"},
		{"-d", "1", "  最大递归深度 (1: 仅根路径，3: 支持3级子路径)"},
		{"-fc", "无", " 过滤状态码 (逗号分隔，例：-fc 404,403 不显示404/403)"},
		{"-fl", "无", " 过滤响应长度 (逗号分隔，例：-fl 1000 不显示长度1000的响应)"},
	}

	// 打印参数列表
	fmt.Println("\n选项说明:")
	for _, p := range params {
		fmt.Printf("  %-6s  默认值: %-8s  %s\n", p.flag, p.defaultVal, p.desc)
	}
}

func init() {
	// 1. 定义命令行参数
	flag.StringVar(&dictPath, "w", "", "路径字典文件")
	flag.StringVar(&targetURL, "u", "", "目标URL地址")
	flag.IntVar(&concurrent, "c", 10, "并发数量")
	flag.IntVar(&maxDepth, "d", 1, "最大递归深度")
	flag.StringVar(&filterCodeStr, "fc", "", "需要过滤的状态码，用逗号分隔 (例如: 404,403)")
	flag.StringVar(&filterLengthStr, "fl", "", "需要过滤的响应体长度，用逗号分隔 (例如: 1000,2000)")

	flag.Usage = printHelp

	flag.Parse()

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		os.Exit(0)
	}

	if dictPath == "" || targetURL == "" {
		fmt.Printf("%s\n【ERROR】缺少必需参数 -u (目标URL) 和 -w (字典文件)%s\n", red, reset)
		fmt.Println("提示：执行 gofus -h 查看完整使用说明\n")
		os.Exit(1)
	}

	filterCodes = parseFilterNumbers(filterCodeStr)
	filterLengths = parseFilterNumbers(filterLengthStr)

	client = &http.Client{
		Timeout: 30 * time.Second, // 增加超时时间到30秒
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSHandshakeTimeout:   15 * time.Second, // TLS握手超时
			ResponseHeaderTimeout: 10 * time.Second, // 响应头超时
			ExpectContinueTimeout: 5 * time.Second,  // Expect-Continue超时
			IdleConnTimeout:       30 * time.Second, // 空闲连接超时
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

func isFilteredCode(code int) bool {
	for _, c := range filterCodes {
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

func main() {
	logo()

	// 准备配置信息
	configLines := []string{
		fmt.Sprintf("#目标URL    : %s", targetURL),
		fmt.Sprintf("#字典文件   : %s", dictPath),
		fmt.Sprintf("#并发数量   : %d", concurrent),
		fmt.Sprintf("#最大深度   : %d", maxDepth),
	}

	// 添加可选的过滤信息
	if len(filterCodes) > 0 {
		configLines = append(configLines, fmt.Sprintf("#过滤状态码 : %v", filterCodes))
	}
	if len(filterLengths) > 0 {
		configLines = append(configLines, fmt.Sprintf("#过滤长度   : %v", filterLengths))
	}

	// 读取字典并添加加载信息
	words, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("%s【错误】读取字典失败: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	// 设置总字典条数
	totalWords = len(words)

	// 添加字典加载信息
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
			words = append(words, word)
		}
	}
	return words, scanner.Err()
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

	resp, err := client.Get(fullPath)
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
			}
		}
	}

	// 只在未被过滤时才输出结果
	if !isFilteredCode(resp.StatusCode) && !isFilteredLength(contentLength) {
		// 根据状态码和是否可递归选择颜色输出
		if resp.StatusCode == http.StatusOK {
			// 200状态码：绿色
			printResult(fmt.Sprintf("[%s%d%s] %s (深度: %d, 长度: %d)",
				green, resp.StatusCode, reset, fullPath, depth, contentLength))
		} else if resp.StatusCode == http.StatusMovedPermanently || canDescend {
			// 301状态码或可递归目录：蓝色
			printResult(fmt.Sprintf("[%s%d%s] %s (深度: %d, 长度: %d)",
				blue, resp.StatusCode, reset, fullPath, depth, contentLength))
		} else {
			// 其他状态码：默认颜色
			printResult(fmt.Sprintf("[%d] %s (深度: %d, 长度: %d)",
				resp.StatusCode, fullPath, depth, contentLength))
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

// 新增：清除进度条
func clearProgressBar() {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	fmt.Print("\033[A") // 上移到进度条位置
	fmt.Print("\033[K") // 清除整行
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

// 新增：清除状态行
func clearStatusLine() {
	fmt.Print("\r")
	fmt.Print(strings.Repeat(" ", 120))
	fmt.Print("\r")
}

// 新增：移动光标到上一行并清除
func moveUpAndClear() {
	fmt.Print("\033[A")                 // 向上移动一行
	fmt.Print("\r")                     // 回到行首
	fmt.Print(strings.Repeat(" ", 120)) // 清空整行
	fmt.Print("\r")                     // 回到行首
}

// 新增：绘制进度条 (类似gobuster的进度条)
func drawProgressBar(current, total int64, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}

	percentage := float64(current) / float64(total)
	filled := int(float64(width) * percentage)

	bar := strings.Repeat("█", filled)
	bar += strings.Repeat("░", width-filled)

	return bar
}

// 新增：格式化时间 (类似ffuf的时间显示)
func formatDuration(d time.Duration) string {
	if d.Hours() >= 24 {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%dd %dh", days, hours)
	} else if d.Hours() >= 1 {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh %dm", hours, minutes)
	} else if d.Minutes() >= 1 {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
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

	// 更精确的光标控制，防止输出泄露
	fmt.Print("\033[s")       // 保存当前光标位置
	fmt.Print("\033[1000;1H") // 移动到屏幕最后一行
	fmt.Print("\033[2K")      // 清除整行（包括行首和行尾）
	fmt.Print("\033[1G")      // 移动到行首

	// 构建固定格式的进度信息，使用固定宽度确保数字位置稳定
	progressLine := fmt.Sprintf("%s%.1f%% | 速率: %s req/sec | 已扫描: %d/%d | 错误: %d%s",
		green,
		float64(scanned)/float64(totalWords)*100,
		formatRate(rate),
		scanned, totalWords,
		errors,
		reset)

	// 输出进度信息
	fmt.Print(progressLine)
	fmt.Print("\033[u") // 恢复光标位置
}

// 新增：格式化百分比
func formatPercentage(current, total int64) string {
	if total == 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(current)/float64(total)*100)
}

// 新增：启动状态栏更新协程
func startStatusBarUpdater() {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond) // 降低到500ms更新一次，减少闪烁
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
