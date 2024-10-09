package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"regexp"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

var (
	successPrint = color.New(color.FgGreen, color.Bold).PrintfFunc()
	infoPrint    = color.New(color.FgCyan, color.Bold).PrintfFunc()
	warnPrint    = color.New(color.FgYellow, color.Bold).PrintfFunc()
	errorPrint   = color.New(color.FgRed, color.Bold).PrintfFunc()
)

var sensitivePatterns = []*regexp.Regexp{
	// AWS
	regexp.MustCompile(`(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	
	// API Keys & Tokens
	regexp.MustCompile(`(?i)api[_-]?key['\"][:\s]+['\"]([^'\"]+)['\"]`),
	regexp.MustCompile(`(?i)token['\"][:\s]+['\"]([^'\"]+)['\"]`),
	regexp.MustCompile(`(?i)auth['\"][:\s]+['\"]([^'\"]+)['\"]`),
	regexp.MustCompile(`(?i)secret['\"][:\s]+['\"]([^'\"]+)['\"]`),
	
	// // Endpoints & URLs
	// regexp.MustCompile(`(?i)(https?:\/\/[^\s<>\"\']+(\/[^\s<>\"\']*)?)`),
	// regexp.MustCompile(`(?i)\/api\/[a-zA-Z0-9\/_-]+`),
	
	// Credentials
	regexp.MustCompile(`(?i)password['\"][:\s]+['\"]([^'\"]+)['\"]`),
	regexp.MustCompile(`(?i)username['\"][:\s]+['\"]([^'\"]+)['\"]`),
	
	// Private Keys
	regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)private.?key['\"][:\s]+['\"]([^'\"]+)['\"]`),
	
	// // Internal Paths
	// regexp.MustCompile(`(?i)(\/[a-zA-Z0-9_-]+)+\.(php|jsp|asp|aspx|html|js|py|rb)`),
	
	// Database Strings
	regexp.MustCompile(`(?i)mongodb(\+srv)?:\/\/[^\s<>"']+`),
	regexp.MustCompile(`(?i)mysql:\/\/[^\s<>"']+`),
	
	// S3 Buckets
	regexp.MustCompile(`(?i)[\w\-\.]+\.s3\.[\w\-\.]+\.amazonaws\.com`),
	
	// JWT Tokens
	regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
}

func main() {
	printBanner()

	// Initialize output directory
	if err := os.MkdirAll("output", 0755); err != nil {
		errorPrint("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	infoPrint("Do you have existing waybackurls and katana files? (y/n): ")
	var useExisting string
	fmt.Scanln(&useExisting)

	var waybackFile, katanaFile string
	var domain string

	if strings.ToLower(useExisting) == "y" {
		infoPrint("Enter path to waybackurls file: ")
		fmt.Scanln(&waybackFile)
		infoPrint("Enter path to katana file: ")
		fmt.Scanln(&katanaFile)
	} else {
		infoPrint("Enter domain name: ")
		fmt.Scanln(&domain)
		
		infoPrint("Enter number of threads: ")
		var threads string
		fmt.Scanln(&threads)

		waybackFile = fmt.Sprintf("output/waybackurls_%s.txt", domain)
		katanaFile = fmt.Sprintf("output/katana_%s.txt", domain)
		
		successPrint("\nRunning waybackurls on %s\n", domain)
		if err := runWaybackurls(domain, waybackFile); err != nil {
			warnPrint("Waybackurls error: %v\n", err)
		}
		
		successPrint("\nRunning katana on %s\n", domain)
		if err := runKatana(domain, katanaFile, threads); err != nil {
			warnPrint("Katana error: %v\n", err)
		}
	}

	jsFile := fmt.Sprintf("output/jsfiles_%s.txt", strings.ReplaceAll(domain, ".", "_"))
	successPrint("\nExtracting JavaScript files...\n")
	extractJSFiles(waybackFile, katanaFile, jsFile)

	successPrint("\nScanning JavaScript files for sensitive information...\n")
	scanJSFiles(jsFile)
}

func printBanner() {
	banner := color.New(color.FgMagenta, color.Bold).SprintFunc()(
		`
╔═══════════════════════════════════════╗
║     		   KeyHound                 ║
║     Created with ♥ by elit3pwner      ║    
╚═══════════════════════════════════════╝
`)
	fmt.Println(banner)
}

func runWaybackurls(domain, output string) error {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo %s | waybackurls > %s", domain, output))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Running waybackurls..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				bar.Add(1)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	err := cmd.Run()
	done <- true
	bar.Finish()

	if err != nil {
		return fmt.Errorf("waybackurls error: %v, stderr: %s", err, stderr.String())
	}

	return nil
}

func runKatana(domain, output, threads string) error {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

	args := []string{"-u", domain, "-o", output}
	if threads != "" {
		args = append(args, "-c", threads)
	}

	cmd := exec.Command("katana", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Running katana..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				bar.Add(1)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	err := cmd.Run()
	done <- true
	bar.Finish()

	if err != nil {
		return fmt.Errorf("katana error: %v, stderr: %s", err, stderr.String())
	}

	return nil
}

func extractJSFiles(waybackFile, katanaFile, outputFile string) {
	urls := make(map[string]bool)
	
	files := []string{waybackFile, katanaFile}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			warnPrint("Error opening %s: %v\n", file, err)
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			url := scanner.Text()
			if strings.HasSuffix(strings.ToLower(url), ".js") {
				urls[url] = true
			}
		}
	}

	f, err := os.Create(outputFile)
	if err != nil {
		errorPrint("Error creating output file: %v\n", err)
		return
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for url := range urls {
		writer.WriteString(url + "\n")
	}
	writer.Flush()

	successPrint("Found %d unique JavaScript files\n", len(urls))
}

func scanJSFiles(jsFile string) {
	f, err := os.Open(jsFile)
	if err != nil {
		errorPrint("Error opening JS file: %v\n", err)
		return
	}
	defer f.Close()

	outputFile := "output/sensitive_findings.txt"
	out, err := os.Create(outputFile)
	if err != nil {
		errorPrint("Error creating output file: %v\n", err)
		return
	}
	defer out.Close()

	scanner := bufio.NewScanner(f)
	var urls []string
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	bar := progressbar.Default(int64(len(urls)), "Scanning JavaScript files")
	
	var wg sync.WaitGroup
	results := make(chan string, 1000)
	semaphore := make(chan struct{}, 10) // Limit concurrent requests

	go func() {
		writer := bufio.NewWriter(out)
		defer writer.Flush()
		for result := range results {
			writer.WriteString(result + "\n")
		}
	}()

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			scanURL(url, results)
			<-semaphore // Release
			bar.Add(1)
		}(url)
	}

	wg.Wait()
	close(results)
	successPrint("\nScan complete! Results saved to %s\n", outputFile)
}

func scanURL(url string, results chan<- string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	content := string(body)
	for _, pattern := range sensitivePatterns {
		if matches := pattern.FindAllString(content, -1); matches != nil {
			for _, match := range matches {
				results <- fmt.Sprintf("URL: %s\nPattern: %s\nMatch: %s\n---", url, pattern.String(), match)
			}
		}
	}
}

func init() {
	color.NoColor = false
}
