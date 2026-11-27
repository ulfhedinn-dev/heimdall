// Command smoke runs a single real Trivy scan through Heimdall's scanner and
// prints a severity summary. Usage: go run ./hack/smoke <image-ref>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ulfhedinn-dev/heimdall/internal/scanner"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: smoke <image-ref>")
		os.Exit(2)
	}
	s := scanner.NewTrivyScanner()
	if dir := os.Getenv("TRIVY_CACHE_DIR"); dir != "" {
		s.CacheDir = dir
	}
	start := time.Now()
	rep, err := s.Scan(context.Background(), scanner.Request{ImageRef: os.Args[1], Timeout: 10 * time.Minute})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}
	raw, _ := json.Marshal(rep.Findings)
	fmt.Printf("findings JSON size: %d KiB\n", len(raw)/1024)
	c, h, m, l, u := scanner.Summarize(rep.Findings)
	fmt.Printf("%s: %d findings (critical=%d high=%d medium=%d low=%d unknown=%d) db=%s trivy=%s in %s\n",
		rep.ImageRef, len(rep.Findings), c, h, m, l, u, rep.VulnDBVersion, rep.ScannerVersion, time.Since(start).Round(time.Second))
}
