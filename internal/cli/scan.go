package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target URL for SQL injection vulnerabilities",
	Long: `Scan performs SQL injection detection against the specified target URL.
It tests all discovered parameters using the configured techniques.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

// parseCookieString parses a cookie header string (e.g., "name1=val1; name2=val2")
// into a map of name->value pairs.
func parseCookieString(raw string) map[string]string {
	cookies := make(map[string]string)
	if raw == "" {
		return cookies
	}
	pairs := strings.Split(raw, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			cookies[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return cookies
}

// parseHeaders parses header strings (e.g., "X-Custom: value") into a map.
func parseHeaders(rawHeaders []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range rawHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func runScan(cmd *cobra.Command, args []string) error {
	// Legal disclaimer banner
	fmt.Println("[!] Legal disclaimer: Usage of sqleech for attacking targets without prior mutual consent is illegal.")

	// 1. Get URL from --url flag (required)
	targetURL, _ := cmd.Flags().GetString("url")
	if targetURL == "" {
		return fmt.Errorf("target URL is required (use --url or -u)")
	}

	// 2. Read all flags
	method, _ := cmd.Flags().GetString("method")
	data, _ := cmd.Flags().GetString("data")
	cookieStr, _ := cmd.Flags().GetString("cookie")
	rawHeaders, _ := cmd.Flags().GetStringArray("header")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	forceSSL, _ := cmd.Flags().GetBool("force-ssl")
	randomAgent, _ := cmd.Flags().GetBool("random-agent")
	verbose, _ := cmd.Flags().GetInt("verbose")

	// If --force-ssl, ensure URL uses https://
	if forceSSL {
		targetURL = strings.Replace(targetURL, "http://", "https://", 1)
		if !strings.HasPrefix(targetURL, "https://") {
			targetURL = "https://" + targetURL
		}
	}

	// If --data is set and method is still default GET, switch to POST
	if data != "" && method == "GET" {
		method = "POST"
	}

	// Parse headers and cookies
	headers := parseHeaders(rawHeaders)
	cookies := parseCookieString(cookieStr)

	// 3. Build transport.ClientOptions from flags
	clientOpts := transport.ClientOptions{
		Timeout:         timeout,
		ProxyURL:        proxyURL,
		FollowRedirects: true,
		RandomUserAgent: randomAgent,
	}

	// 4. Create transport.Client
	client, err := transport.NewClient(clientOpts)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// 5. Build engine.ScanTarget from flags
	target := engine.ScanTarget{
		URL:     targetURL,
		Method:  method,
		Headers: headers,
		Body:    data,
		Cookies: cookies,
	}

	// Set Content-Type for POST data if not explicitly provided via headers
	if data != "" {
		if _, hasContentType := headers["Content-Type"]; !hasContentType {
			target.ContentType = "application/x-www-form-urlencoded"
		}
	}

	// 6. Setup context with signal handling (CTRL+C)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if verbose > 0 {
		fmt.Printf("[*] Target URL: %s\n", targetURL)
		fmt.Printf("[*] Method: %s\n", method)
		if proxyURL != "" {
			fmt.Printf("[*] Proxy: %s\n", proxyURL)
		}
	}

	// 7. Run scan pipeline
	// For now, perform a basic connectivity check using the transport client.
	// The full scanner integration (engine.Scanner) will be added in a later issue.
	fmt.Printf("[*] Starting scan against: %s\n", targetURL)

	testReq := &transport.Request{
		URL:     targetURL,
		Method:  method,
		Headers: headers,
		Body:    data,
		Cookies: cookies,
	}
	if target.ContentType != "" {
		testReq.ContentType = target.ContentType
	}

	resp, err := client.Do(ctx, testReq)
	if err != nil {
		return fmt.Errorf("connectivity check failed: %w", err)
	}

	fmt.Printf("[*] Connection successful: HTTP %d (%s, %d bytes)\n",
		resp.StatusCode, resp.Duration, len(resp.Body))

	// 8. Report results (placeholder - reporter will be integrated later)
	_ = target // will be used by engine.Scanner in a future issue

	fmt.Println("[*] Scan pipeline setup complete. Full scan engine integration pending.")
	fmt.Printf("[*] Scan finished.\n")

	return nil
}
