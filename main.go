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
	wg              sync.WaitGroup
	concurrent      int
	maxDepth        int   // 最大递归深度
	filterCodes     []int // 需要过滤的状态码
	filterLengths   []int // 需要过滤的响应体长度
	filterCodeStr   string
	filterLengthStr string
)

// ANSI颜色控制码
const (
	green  = "\033[32m"
	red    = "\033[31m"
	blue   = "\033[34m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

// 自定义帮助函数：显示gofus Logo + 美观的参数说明
func printHelp() {
	gofusLogo := fmt.Sprintf(`%s

  ██████╗   ██████╗  ███████╗ ██╗   ██╗ ███████╗
 ██╔════╝  ██╔═══██╗ ██╔════╝ ██║   ██║ ██╔════╝
 ██║ ████╗ ██║   ██║ ██████╗  ██║   ██║ ███████╗
 ██║   ██║ ██║   ██║ ██╔═══╝  ██║   ██║ ╚════██║
 ╚██████╔╝ ╚██████╔╝ ██║      ╚██████╔╝ ███████║
  ╚═════╝   ╚═════╝  ╚═╝       ╚═════╝  ╚══════╝

  gofus - WEB路径递归扫描工具 | by x0da6h
%s`, green, reset)

	fmt.Println(gofusLogo)
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
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
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
	fmt.Printf("%s\n------------------------------【扫描配置】------------------------------%s\n", yellow, reset)
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

	words, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("%s【错误】读取字典失败: %v%s\n", green, err, reset)
		os.Exit(1)
	}
	fmt.Printf("\n【字典加载完成】共加载 %d 个有效路径\n\n", len(words))

	semaphore := make(chan struct{}, concurrent)
	scanPath(targetURL, words, semaphore, 1)
	wg.Wait()

	fmt.Printf("%s------------------------------【扫描结束】------------------------------%s\n", yellow, reset)
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
	fullPath := basePath + word
	resp, err := client.Get(fullPath)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	contentLength := int(resp.ContentLength)
	if contentLength < 0 {
		contentLength = 0
	}
	if isFilteredCode(resp.StatusCode) || isFilteredLength(contentLength) {
		return
	}

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%s[%d] %s (深度: %d, 长度: %d)%s\n",
			green, resp.StatusCode, fullPath, depth, contentLength, reset)
	} else {
		fmt.Printf("[%d] %s (深度: %d, 长度: %d)\n",
			resp.StatusCode, fullPath, depth, contentLength)
	}

	if depth < maxDepth {
		shouldDescend := false
		nextBase := fullPath

		// 情况1：字典词以'/'结尾，通常表示目录
		if strings.HasSuffix(word, "/") {
			shouldDescend = resp.StatusCode == http.StatusOK ||
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
				shouldDescend = true
				if !strings.HasSuffix(nextBase, "/") {
					nextBase += "/"
				}
			}
		}

		if shouldDescend {
			if !strings.HasSuffix(nextBase, "/") {
				nextBase += "/"
			}
			scanPath(nextBase, words, semaphore, depth+1)
		}
	}
}
