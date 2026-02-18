package report

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/0x6d61/sqleech/internal/engine"
)

const (
	doubleLine = "\u2550" // ═
	singleLine = "\u2500" // ─
	lineWidth  = 50
)

// TextReporter outputs plain terminal text.
type TextReporter struct {
	// Verbose controls detail level: 0=results only, 1=+scan info, 2=+details, 3=debug.
	Verbose int
}

// Format returns "text".
func (r *TextReporter) Format() string {
	return "text"
}

// Generate writes formatted scan results to w.
func (r *TextReporter) Generate(ctx context.Context, result *engine.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b := &strings.Builder{}

	// Header
	doubleBar := strings.Repeat(doubleLine, lineWidth)
	singleBar := strings.Repeat(singleLine, lineWidth)

	fmt.Fprintln(b, doubleBar)
	fmt.Fprintln(b, "sqleech - SQL Injection Scanner Results")
	fmt.Fprintln(b, doubleBar)

	// Target info
	fmt.Fprintf(b, "Target: %s\n", result.Target.URL)
	fmt.Fprintf(b, "Method: %s\n", result.Target.Method)

	if result.DBMS != "" {
		dbmsInfo := result.DBMS
		if result.DBMSVersion != "" {
			dbmsInfo += " " + result.DBMSVersion
		}
		fmt.Fprintf(b, "DBMS:   %s\n", dbmsInfo)
	}

	duration := result.EndTime.Sub(result.StartTime)
	fmt.Fprintf(b, "Duration: %.1fs\n", duration.Seconds())
	fmt.Fprintf(b, "Requests: %d\n", result.RequestCount)

	// Vulnerabilities
	if len(result.Vulnerabilities) == 0 {
		fmt.Fprintln(b, singleBar)
		fmt.Fprintln(b, "No vulnerabilities found.")
	} else {
		for _, vuln := range result.Vulnerabilities {
			fmt.Fprintln(b, singleBar)
			fmt.Fprintf(b, "[%s] SQL Injection Found!\n", vuln.Severity.String())
			fmt.Fprintf(b, "  Parameter:  %s (%s)\n", vuln.Parameter.Name, vuln.Parameter.Location.String())
			fmt.Fprintf(b, "  Technique:  %s\n", vuln.Technique)
			fmt.Fprintf(b, "  DBMS:       %s\n", vuln.DBMS)
			fmt.Fprintf(b, "  Payload:    %s\n", vuln.Payload)
			fmt.Fprintf(b, "  Confidence: %.0f%%\n", vuln.Confidence*100)
			fmt.Fprintf(b, "  Evidence:   %s\n", vuln.Evidence)
		}
	}

	// Errors section
	if len(result.Errors) > 0 {
		fmt.Fprintln(b, singleBar)
		fmt.Fprintln(b, "Errors:")
		for _, e := range result.Errors {
			fmt.Fprintf(b, "  - %s\n", e.Error())
		}
	}

	// Summary
	fmt.Fprintln(b, doubleBar)
	vulnCount := len(result.Vulnerabilities)
	paramCount := countAffectedParameters(result.Vulnerabilities)
	fmt.Fprintf(b, "Summary: %d vulnerabilities found in %d parameter(s)\n", vulnCount, paramCount)
	fmt.Fprintln(b, doubleBar)

	_, err := io.WriteString(w, b.String())
	return err
}

// countAffectedParameters counts distinct parameters that have vulnerabilities.
func countAffectedParameters(vulns []engine.Vulnerability) int {
	seen := make(map[string]struct{})
	for _, v := range vulns {
		key := v.Parameter.Name + ":" + v.Parameter.Location.String()
		seen[key] = struct{}{}
	}
	return len(seen)
}
