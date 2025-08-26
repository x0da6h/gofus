package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	dictPath  string
	targetURL string
	client    = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向，以便查看301/302状态
		},
	}
	visited = struct {
		sync.RWMutex
		m map[string]bool
	}{m: make(map[string]bool)}
	wg         sync.WaitGroup
	concurrent int
)

func init() {
	// 解析命令行参数
	flag.StringVar(&dictPath, "w", "", "路径字典文件")
	flag.StringVar(&targetURL, "u", "", "目标URL地址")
	flag.IntVar(&concurrent, "c", 10, "并发数量")
	flag.Parse()

	// 验证参数
	if dictPath == "" || targetURL == "" {
		fmt.Println("必须指定字典文件(-w)和目标URL(-u)")
		flag.Usage()
		os.Exit(1)
	}

	// 确保URL格式正确
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	// 确保URL以/结尾，方便路径拼接
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}
}

func main() {
	fmt.Printf("开始扫描目标: %s\n", targetURL)
	fmt.Printf("使用字典: %s\n", dictPath)
	fmt.Printf("并发数量: %d\n\n", concurrent)

	// 读取字典文件
	words, err := readDictionary(dictPath)
	if err != nil {
		fmt.Printf("读取字典失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("从字典中加载了 %d 个路径\n", len(words))

	// 创建信号量控制并发
	semaphore := make(chan struct{}, concurrent)

	// 开始扫描根路径
	scanPath(targetURL, words, semaphore)

	// 等待所有扫描完成
	wg.Wait()
	fmt.Println("\n扫描完成")
}

// 读取字典文件内容
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
		if word != "" && !strings.HasPrefix(word, "#") { // 忽略空行和注释行
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

// 扫描指定路径下的所有可能路径
func scanPath(basePath string, words []string, semaphore chan struct{}) {
	visited.Lock()
	if visited.m[basePath] {
		visited.Unlock()
		return
	}
	visited.m[basePath] = true
	visited.Unlock()

	for _, word := range words {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(word string) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量
			testPath(basePath, word, words, semaphore)
		}(word)
	}
}

// 测试单个路径是否存在
func testPath(basePath, word string, words []string, semaphore chan struct{}) {
	fullPath := basePath + word
	resp, err := client.Head(fullPath)
	if err != nil {
		// 忽略连接错误，可能是网络问题或服务器拒绝连接
		return
	}
	defer resp.Body.Close()

	// 打印找到的有效路径和状态码
	if resp.StatusCode != http.StatusNotFound {
		fmt.Printf("[%d] %s\n", resp.StatusCode, fullPath)
	}

	// 如果是目录或重定向，进行递归扫描
	if (resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusMovedPermanently ||
		resp.StatusCode == http.StatusFound) &&
		strings.HasSuffix(word, "/") {

		// 确保路径以/结尾
		if !strings.HasSuffix(fullPath, "/") {
			fullPath += "/"
		}
		scanPath(fullPath, words, semaphore)
	}
}
