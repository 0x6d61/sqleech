package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// Version information (set by build flags)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "sqleech",
	Short: "Next-generation SQL injection testing tool",
	Long: `sqleech - Next-generation SQL injection testing tool

A high-performance, concurrent SQL injection detection and exploitation tool
written in Go. Designed for authorized penetration testing only.

WARNING: Use this tool only against systems you have explicit permission to test.
Unauthorized access to computer systems is illegal.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Target flags
	rootCmd.PersistentFlags().StringP("url", "u", "", "Target URL (e.g., http://target.com/page?id=1)")
	rootCmd.PersistentFlags().String("method", "GET", "HTTP method (GET, POST, PUT, etc.)")
	rootCmd.PersistentFlags().StringP("data", "d", "", "POST data (e.g., id=1&name=test)")
	rootCmd.PersistentFlags().String("cookie", "", "Cookie string (e.g., PHPSESSID=abc123)")
	rootCmd.PersistentFlags().StringArrayP("header", "H", nil, "Extra header (repeatable, e.g., -H 'X-Custom: value')")

	// Connection flags
	rootCmd.PersistentFlags().String("proxy", "", "Proxy URL (http://host:port or socks5://host:port)")
	rootCmd.PersistentFlags().Int("threads", 10, "Number of concurrent threads")
	rootCmd.PersistentFlags().Duration("timeout", 30*time.Second, "Request timeout")

	// Output flags
	rootCmd.PersistentFlags().IntP("verbose", "v", 0, "Verbosity level (0-3)")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output file path")
	rootCmd.PersistentFlags().StringP("format", "f", "text", "Output format (text, json)")

	// Scan options
	rootCmd.PersistentFlags().String("dbms", "", "Force DBMS type (MySQL, PostgreSQL)")
	rootCmd.PersistentFlags().String("technique", "", "Techniques to use (B=Boolean, E=Error, comma-separated)")
	rootCmd.PersistentFlags().Bool("force-ssl", false, "Force HTTPS")
	rootCmd.PersistentFlags().Bool("random-agent", false, "Use random User-Agent")
	rootCmd.PersistentFlags().Bool("force-test", false, "Test all parameters even if heuristics say safe")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sqleech %s (commit: %s, built: %s)\n", version, commit, date)
	},
}
