package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aakamshpm/susfilter/susfilter"
)

func main() {
	const urlCount uint = 10000
	const falsePositiveRate float32 = 0.01

	bf := susfilter.New(10000, 0.01)

	maliciousURLs := []string{
		"https://malware-site.com",
		"https://phishing-login.com",
		"https://trojan-download.ru",
		"https://ransomware-attack.org",
		"https://spam-central.net",
	}

	for _, url := range maliciousURLs {
		bf.Add(url)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: urlchecker <url>")
		fmt.Println("Example: urlchecker https://malware-site.com")
		os.Exit(1)
	}

	checkUrl := os.Args[1]

	if bf.MightContain(checkUrl) {
		if isActuallyMalicious(checkUrl, maliciousURLs) {
			fmt.Printf("CONFIRMED: %s is in the malicious URL database\n", checkUrl)
		} else {
			fmt.Printf("FALSE POSITIVE: %s might be malicious (false positive rate ~1%%)\n", checkUrl)
		}
	} else {
		fmt.Printf("SAFE: %s is definitely NOT in the malicious URL database\n", checkUrl)
	}
}

func isActuallyMalicious(url string, maliciousURLs []string) bool {
	for _, m := range maliciousURLs {
		if strings.EqualFold(url, m) {
			return true
		}
	}
	return false
}
