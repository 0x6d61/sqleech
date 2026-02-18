package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/sqleech/internal/engine"
)

// newTestScanResult creates a realistic ScanResult for testing.
func newTestScanResult() *engine.ScanResult {
	start := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	end := start.Add(12*time.Second + 300*time.Millisecond)
	return &engine.ScanResult{
		Target: engine.ScanTarget{
			URL:    "http://example.com/page?id=1",
			Method: "GET",
			Parameters: []engine.Parameter{
				{
					Name:     "id",
					Value:    "1",
					Location: engine.LocationQuery,
					Type:     engine.TypeInteger,
				},
			},
		},
		Vulnerabilities: []engine.Vulnerability{
			{
				Parameter: engine.Parameter{
					Name:     "id",
					Value:    "1",
					Location: engine.LocationQuery,
					Type:     engine.TypeInteger,
				},
				Technique:  "error-based",
				DBMS:       "MySQL",
				Payload:    "1' AND extractvalue(1,concat(0x7e,(@@version)))-- -",
				Confidence: 0.95,
				Severity:   engine.SeverityCritical,
				Evidence:   "XPATH syntax error: '~8.0.32~'",
				Injectable: true,
			},
			{
				Parameter: engine.Parameter{
					Name:     "id",
					Value:    "1",
					Location: engine.LocationQuery,
					Type:     engine.TypeInteger,
				},
				Technique:  "boolean-blind",
				DBMS:       "MySQL",
				Payload:    "1' AND 1=1-- -",
				Confidence: 0.85,
				Severity:   engine.SeverityHigh,
				Evidence:   "Response difference detected",
				Injectable: true,
			},
		},
		DBMS:         "MySQL",
		DBMSVersion:  "8.0.32",
		StartTime:    start,
		EndTime:      end,
		RequestCount: 147,
		Errors:       nil,
	}
}

// newEmptyScanResult creates a ScanResult with no vulnerabilities.
func newEmptyScanResult() *engine.ScanResult {
	start := time.Date(2026, 2, 18, 10, 0, 0, 0, time.UTC)
	end := start.Add(5 * time.Second)
	return &engine.ScanResult{
		Target: engine.ScanTarget{
			URL:    "http://example.com/safe?name=test",
			Method: "GET",
			Parameters: []engine.Parameter{
				{
					Name:     "name",
					Value:    "test",
					Location: engine.LocationQuery,
					Type:     engine.TypeString,
				},
			},
		},
		Vulnerabilities: nil,
		DBMS:            "",
		DBMSVersion:     "",
		StartTime:       start,
		EndTime:         end,
		RequestCount:    42,
		Errors:          nil,
	}
}

func TestTextReporter_Format(t *testing.T) {
	r := &TextReporter{}
	if got := r.Format(); got != "text" {
		t.Errorf("Format() = %q, want %q", got, "text")
	}
}

func TestTextReporter_Generate_WithVulnerabilities(t *testing.T) {
	r := &TextReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	// Check header
	if !strings.Contains(output, "sqleech") {
		t.Error("output should contain tool name 'sqleech'")
	}
	if !strings.Contains(output, "SQL Injection Scanner Results") {
		t.Error("output should contain 'SQL Injection Scanner Results'")
	}

	// Check target info
	if !strings.Contains(output, "http://example.com/page?id=1") {
		t.Error("output should contain target URL")
	}
	if !strings.Contains(output, "GET") {
		t.Error("output should contain HTTP method")
	}
	if !strings.Contains(output, "MySQL") {
		t.Error("output should contain DBMS name")
	}

	// Check vulnerability details
	if !strings.Contains(output, "CRITICAL") {
		t.Error("output should contain severity 'CRITICAL'")
	}
	if !strings.Contains(output, "id") {
		t.Error("output should contain parameter name 'id'")
	}
	if !strings.Contains(output, "query") {
		t.Error("output should contain parameter location 'query'")
	}
	if !strings.Contains(output, "error-based") {
		t.Error("output should contain technique 'error-based'")
	}
	if !strings.Contains(output, "boolean-blind") {
		t.Error("output should contain technique 'boolean-blind'")
	}
	if !strings.Contains(output, "1' AND extractvalue") {
		t.Error("output should contain payload")
	}
	if !strings.Contains(output, "95%") {
		t.Error("output should contain confidence percentage")
	}
	if !strings.Contains(output, "XPATH syntax error") {
		t.Error("output should contain evidence")
	}
}

func TestTextReporter_Generate_NoVulnerabilities(t *testing.T) {
	r := &TextReporter{}
	result := newEmptyScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "No vulnerabilities found") {
		t.Error("output should indicate no vulnerabilities found")
	}
}

func TestTextReporter_Generate_Summary(t *testing.T) {
	r := &TextReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	// Check summary line
	if !strings.Contains(output, "2 vulnerabilities") {
		t.Errorf("output should contain '2 vulnerabilities', got:\n%s", output)
	}
	if !strings.Contains(output, "1 parameter") {
		t.Errorf("output should contain '1 parameter', got:\n%s", output)
	}
}

func TestTextReporter_Generate_Duration(t *testing.T) {
	r := &TextReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "12.3s") {
		t.Errorf("output should contain duration '12.3s', got:\n%s", output)
	}
	if !strings.Contains(output, "147") {
		t.Errorf("output should contain request count '147', got:\n%s", output)
	}
}

func TestTextReporter_Generate_BoxDrawing(t *testing.T) {
	r := &TextReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	// Check for box-drawing characters
	if !strings.Contains(output, "\u2550") { // ═
		t.Error("output should contain double-line box-drawing character (═)")
	}
	if !strings.Contains(output, "\u2500") { // ─
		t.Error("output should contain single-line box-drawing character (─)")
	}
}

func TestTextReporter_Generate_ContextCancelled(t *testing.T) {
	r := &TextReporter{}
	result := newTestScanResult()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	err := r.Generate(ctx, result, &buf)
	if err == nil {
		t.Error("Generate() should return error when context is cancelled")
	}
}

func TestTextReporter_Generate_Errors(t *testing.T) {
	r := &TextReporter{}
	result := newTestScanResult()
	result.Errors = []error{
		context.DeadlineExceeded,
	}

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Errors") || !strings.Contains(output, "context deadline exceeded") {
		t.Errorf("output should contain errors section, got:\n%s", output)
	}
}
