package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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
	wg            sync.WaitGroup
	concurrent    int
	maxDepth      int   // 最大递归深度
	filterCodes   []int // 需要过滤的状态码
	filterLengths []int // 需要过滤的响应体长度
	// 全局变量：接收命令行参数（移到此处避免编译警告）
	filterCodeStr   string
	filterLengthStr string
)

// ANSI颜色控制码
const (
	green = "\033[32m" // 绿色文本（Logo、200响应码高亮）
	reset = "\033[0m"  // 重置文本颜色
)

// 自定义帮助函数：显示gofus Logo + 美观的参数说明
func printHelp() {
	gofusLogo := fmt.Sprintf(`%s


  ██████╗   ██████╗  ███████╗ ██╗   ██╗ ███████╗
 ██╔════╝  ██╔═══██╗ ██╔════╝ ██║   ██║ ██╔════╝
 ██║  ███╗ ██║   ██║ █████╗   ██║   ██║ ███████╗
 ██║   ██║ ██║   ██║ ██╔══╝   ██║   ██║ ╚════██║
 ╚██████╔╝ ╚██████╔╝ ██║      ╚██████╔╝ ███████║
  ╚═════╝   ╚═════╝  ╚═╝       ╚═════╝  ╚══════╝


  gofus - WEB路径递归扫描工具 | by x0da6h
%s`, green, reset)

	// 输出Logo + 工具简介
	fmt.Println(gofusLogo)
	// 格式化参数说明（左对齐参数，右对齐默认值，排版整齐）
	params := []struct {
		flag       string
		defaultVal string
		desc       string
	}{
		{"-h", "无", " 显示当前帮助信息"},
		{"-u", "<必填>", "目标URL（例：https://example.com 或 example.com）"},
		{"-w", "<必填>", "路径字典文件（支持#注释、自动忽略空行）"},
		{"-c", "10", "  并发请求数（建议10-50，防止触发目标限流）"},
		{"-d", "3", "  最大递归深度（1=仅根路径，3=支持3级子路径）"},
		{"-fc", "无", " 过滤状态码（逗号分隔，例：-fc 404,403 不显示404/403）"},
		{"-fl", "无", " 过滤响应长度（逗号分隔，例：-fl 1000 不显示长度1000的响应）"},
	}

	// 打印参数列表
	fmt.Println("------------------------------【参数说明】------------------------------\n")
	for _, p := range params {
		fmt.Printf("  %-6s  默认值: %-8s  %s\n", p.flag, p.defaultVal, p.desc)
	}
}

func init() {
	// 1. 定义命令行参数
	flag.StringVar(&dictPath, "w", "", "路径字典文件")
	flag.StringVar(&targetURL, "u", "", "目标URL地址")
	flag.IntVar(&concurrent, "c", 10, "并发数量")
	flag.IntVar(&maxDepth, "d", 3, "最大递归深度")
	flag.StringVar(&filterCodeStr, "fc", "", "需要过滤的状态码，用逗号分隔 (例如: 404,403)")
	flag.StringVar(&filterLengthStr, "fl", "", "需要过滤的响应体长度，用逗号分隔 (例如: 1000,2000)")

	// 2. 重写flag.Usage：让-h显示自定义帮助（含Logo）
	flag.Usage = printHelp

	// 3. 解析参数
	flag.Parse()

	// 4. 特殊处理：仅输入-h时，显示帮助后直接退出（不检查必填参数）
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		os.Exit(0)
	}

	// 5. 检查必填参数（非-h场景）
	if dictPath == "" || targetURL == "" {
		fmt.Printf("%s\n【ERROR】缺少必需参数 -u (目标URL) 和 -w (字典文件)%s\n", green, reset)
		fmt.Println("提示：执行 gofus -h 查看完整使用说明\n")
		os.Exit(1)
	}

	// 6. 解析过滤参数（状态码、响应长度）
	filterCodes = parseFilterNumbers(filterCodeStr)
	filterLengths = parseFilterNumbers(filterLengthStr)

	// 7. 初始化HTTP客户端（10秒超时，不跟随重定向）
	client = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 8. 处理URL格式（补全http/https前缀 + 末尾/）
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}
}

// 解析过滤参数为整数切片（支持逗号分隔，自动忽略无效值）
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

// 检查状态码是否需要被过滤
func isFilteredCode(code int) bool {
	for _, c := range filterCodes {
		if code == c {
			return true
		}
	}
	return false
}

// 检查响应长度是否需要被过滤
func isFilteredLength(length int) bool {
	for _, l := range filterLengths {
		if length == l {
			return true
		}
	}
	return false
}

func main() {
	// 打印扫描配置（清晰展示用户当前设置）
	fmt.Printf("%s【扫描配置】%s\n", green, reset)
	fmt.Printf("  目标URL    : %s\n", targetURL)
	fmt.Printf("  字典文件   : %s\n", dictPath)
	fmt.Printf("  并发数量   : %d\n", concurrent)
	fmt.Printf("  最大深度   : %d\n", maxDepth)
	if len(filterCodes) > 0 {
		fmt.Printf("  过滤状态码 : %v\n", filterCodes)
	}
	if len(filterLengths) > 0 {
		fmt.Printf("  过滤长度   : %v\n", filterLengths)
	}

	// 读取字典文件
	words, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("%s【错误】读取字典失败: %v%s\n", green, err, reset)
		os.Exit(1)
	}
	fmt.Printf("\n【字典加载完成】共加载 %d 个有效路径\n\n", len(words))

	// 初始化并发控制，启动扫描（初始深度1）
	semaphore := make(chan struct{}, concurrent)
	scanPath(targetURL, words, semaphore, 1)
	wg.Wait()

	fmt.Printf("%s\n【扫描结束】%s\n", green, reset)
}

// 读取字典文件（忽略空行和#注释）
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

// 扫描指定基础路径下的字典路径（带深度控制）
func scanPath(basePath string, words []string, semaphore chan struct{}, depth int) {
	// 避免重复扫描同一路径
	visited.Lock()
	if visited.m[basePath] {
		visited.Unlock()
		return
	}
	visited.m[basePath] = true
	visited.Unlock()

	// 超过最大深度则停止递归
	if depth > maxDepth {
		return
	}

	// 并发扫描每个字典路径
	for _, word := range words {
		wg.Add(1)
		semaphore <- struct{}{} // 并发控制：信号量满时阻塞

		// 启动协程扫描，传递当前深度
		go func(word string, currentDepth int) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量
			testPath(basePath, word, words, semaphore, currentDepth)
		}(word, depth)
	}
}

// 测试单个路径的有效性（含递归触发逻辑）
func testPath(basePath, word string, words []string, semaphore chan struct{}, depth int) {
	fullPath := basePath + word
	// 发送Get请求（获取响应体长度）
	resp, err := client.Get(fullPath)
	if err != nil {
		return // 忽略错误（不打印ERROR）
	}
	defer resp.Body.Close()

	// 获取响应体长度（ContentLength为-1时表示长度未知，按0处理）
	contentLength := int(resp.ContentLength)
	if contentLength < 0 {
		contentLength = 0
	}

	// 过滤逻辑：状态码/长度在过滤列表则不输出
	if isFilteredCode(resp.StatusCode) || isFilteredLength(contentLength) {
		return
	}

	// 输出结果：200响应码绿色高亮，其他默认颜色
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%s[%d] %s (深度: %d, 长度: %d)%s\n",
			green, resp.StatusCode, fullPath, depth, contentLength, reset)
	} else {
		fmt.Printf("[%d] %s (深度: %d, 长度: %d)\n",
			resp.StatusCode, fullPath, depth, contentLength)
	}

	// 触发递归：有效目录（200/301/302 + 路径以/结尾）且未达最大深度
	if depth < maxDepth &&
		(resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusFound) &&
		strings.HasSuffix(word, "/") {

		// 补全路径末尾的/（避免重复拼接）
		if !strings.HasSuffix(fullPath, "/") {
			fullPath += "/"
		}
		scanPath(fullPath, words, semaphore, depth+1) // 递归扫描子路径
	}
}
