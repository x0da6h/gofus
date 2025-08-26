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
)

func init() {
	// 添加命令行参数
	flag.StringVar(&dictPath, "w", "", "路径字典文件")
	flag.StringVar(&targetURL, "u", "", "目标URL地址")
	flag.IntVar(&concurrent, "c", 10, "并发数量")
	flag.IntVar(&maxDepth, "d", 3, "最大递归深度")
	flag.StringVar(&filterCodeStr, "fc", "", "需要过滤的状态码，用逗号分隔 (例如: 404,403)")
	flag.StringVar(&filterLengthStr, "fl", "", "需要过滤的响应体长度，用逗号分隔 (例如: 1000,2000)")
	flag.Parse()

	if dictPath == "" || targetURL == "" {
		fmt.Println("必须指定字典文件(-w)和目标URL(-u)")
		flag.Usage()
		os.Exit(1)
	}

	// 解析过滤状态码
	filterCodes = parseFilterNumbers(filterCodeStr)
	// 解析过滤长度
	filterLengths = parseFilterNumbers(filterLengthStr)

	// 初始化HTTP客户端
	client = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 处理URL格式
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}
}

// 解析过滤参数为整数切片
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
	fmt.Printf("开始扫描目标: %s\n", targetURL)
	fmt.Printf("使用字典: %s\n", dictPath)
	fmt.Printf("并发数量: %d\n", concurrent)
	fmt.Printf("最大递归深度: %d\n", maxDepth)

	if len(filterCodes) > 0 {
		fmt.Printf("过滤状态码: %v\n", filterCodes)
	}
	if len(filterLengths) > 0 {
		fmt.Printf("过滤响应长度: %v\n", filterLengths)
	}

	words, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("读取字典失败: %v\n", err) // 字典读取失败属于致命错误，仍需提示
		os.Exit(1)
	}

	fmt.Printf("从字典中加载了 %d 个路径\n\n", len(words))

	// 初始深度为1
	semaphore := make(chan struct{}, concurrent)
	scanPath(targetURL, words, semaphore, 1)
	wg.Wait()
	fmt.Println("\n扫描完成")
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

	// 如果当前深度超过最大深度则停止
	if depth > maxDepth {
		return
	}

	for _, word := range words {
		wg.Add(1)
		semaphore <- struct{}{}

		// 传递当前深度到下一级
		go func(word string, currentDepth int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			testPath(basePath, word, words, semaphore, currentDepth)
		}(word, depth)
	}
}

func testPath(basePath, word string, words []string, semaphore chan struct{}, depth int) {
	fullPath := basePath + word
	resp, err := client.Get(fullPath) // 使用Get方法以便获取响应体长度
	if err != nil {
		// 移除错误信息打印，发生错误时直接返回
		return
	}
	defer resp.Body.Close()

	// 获取响应体长度
	contentLength := int(resp.ContentLength)

	// 检查是否需要过滤
	if isFilteredCode(resp.StatusCode) {
		return
	}
	if isFilteredLength(contentLength) {
		return
	}

	// 输出结果，包含响应体长度
	fmt.Printf("[%d] %s (深度: %d, 长度: %d)\n",
		resp.StatusCode, fullPath, depth, contentLength)

	// 只有当深度小于最大深度时才继续递归
	if depth < maxDepth &&
		(resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusFound) &&
		strings.HasSuffix(word, "/") {

		if !strings.HasSuffix(fullPath, "/") {
			fullPath += "/"
		}
		// 递归时深度+1
		scanPath(fullPath, words, semaphore, depth+1)
	}
}

// 新增全局变量用于接收命令行参数
var (
	filterCodeStr   string
	filterLengthStr string
)
