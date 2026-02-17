package cli

import (
	"fmt"

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
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sqleech %s (commit: %s, built: %s)\n", version, commit, date)
	},
}
