package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/0x6d61/sqleech/internal/engine"
)

func TestJSONReporter_Format(t *testing.T) {
	r := &JSONReporter{}
	if got := r.Format(); got != "json" {
		t.Errorf("Format() = %q, want %q", got, "json")
	}
}

func TestJSONReporter_Generate_Valid(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Verify the output is valid JSON
	var raw json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Errorf("output is not valid JSON: %v\noutput:\n%s", err, buf.String())
	}
}

func TestJSONReporter_Generate_SchemaVersion(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	version, ok := output["schema_version"]
	if !ok {
		t.Fatal("output missing 'schema_version' field")
	}
	if version != "1.0" {
		t.Errorf("schema_version = %v, want %q", version, "1.0")
	}

	tool, ok := output["tool"]
	if !ok {
		t.Fatal("output missing 'tool' field")
	}
	if tool != "sqleech" {
		t.Errorf("tool = %v, want %q", tool, "sqleech")
	}
}

func TestJSONReporter_Generate_Vulnerabilities(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(output.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(output.Vulnerabilities))
	}

	v := output.Vulnerabilities[0]
	if v.Parameter.Name != "id" {
		t.Errorf("vulnerability[0].parameter.name = %q, want %q", v.Parameter.Name, "id")
	}
	if v.Parameter.Location != "query" {
		t.Errorf("vulnerability[0].parameter.location = %q, want %q", v.Parameter.Location, "query")
	}
	if v.Technique != "error-based" {
		t.Errorf("vulnerability[0].technique = %q, want %q", v.Technique, "error-based")
	}
	if v.DBMS != "MySQL" {
		t.Errorf("vulnerability[0].dbms = %q, want %q", v.DBMS, "MySQL")
	}
	if v.Confidence != 0.95 {
		t.Errorf("vulnerability[0].confidence = %v, want %v", v.Confidence, 0.95)
	}
	if v.Severity != "CRITICAL" {
		t.Errorf("vulnerability[0].severity = %q, want %q", v.Severity, "CRITICAL")
	}
	if v.Evidence != "XPATH syntax error: '~8.0.32~'" {
		t.Errorf("vulnerability[0].evidence = %q, want %q", v.Evidence, "XPATH syntax error: '~8.0.32~'")
	}
}

func TestJSONReporter_Generate_NoVulnerabilities(t *testing.T) {
	r := &JSONReporter{}
	result := newEmptyScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if output.Vulnerabilities == nil {
		t.Fatal("vulnerabilities should be empty array, not null")
	}
	if len(output.Vulnerabilities) != 0 {
		t.Errorf("got %d vulnerabilities, want 0", len(output.Vulnerabilities))
	}
}

func TestJSONReporter_Generate_Summary(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if output.Summary.TotalVulnerabilities != 2 {
		t.Errorf("summary.total_vulnerabilities = %d, want 2", output.Summary.TotalVulnerabilities)
	}
	if output.Summary.AffectedParameters != 1 {
		t.Errorf("summary.affected_parameters = %d, want 1", output.Summary.AffectedParameters)
	}
}

func TestJSONReporter_Generate_Target(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if output.Target.URL != "http://example.com/page?id=1" {
		t.Errorf("target.url = %q, want %q", output.Target.URL, "http://example.com/page?id=1")
	}
	if output.Target.Method != "GET" {
		t.Errorf("target.method = %q, want %q", output.Target.Method, "GET")
	}
}

func TestJSONReporter_Generate_DBMS(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if output.DBMS == nil {
		t.Fatal("dbms should not be nil when DBMS is detected")
	}
	if output.DBMS.Name != "MySQL" {
		t.Errorf("dbms.name = %q, want %q", output.DBMS.Name, "MySQL")
	}
	if output.DBMS.Version != "8.0.32" {
		t.Errorf("dbms.version = %q, want %q", output.DBMS.Version, "8.0.32")
	}
}

func TestJSONReporter_Generate_DBMSOmitted(t *testing.T) {
	r := &JSONReporter{}
	result := newEmptyScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if _, ok := raw["dbms"]; ok {
		t.Error("dbms field should be omitted when DBMS is not detected")
	}
}

func TestJSONReporter_Generate_Scan(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if output.Scan.TotalRequests != 147 {
		t.Errorf("scan.total_requests = %d, want 147", output.Scan.TotalRequests)
	}
	// Duration should be approximately 12.3 seconds
	if output.Scan.DurationSeconds < 12.0 || output.Scan.DurationSeconds > 13.0 {
		t.Errorf("scan.duration_seconds = %v, want ~12.3", output.Scan.DurationSeconds)
	}
}

func TestJSONReporter_Generate_PrettyPrint(t *testing.T) {
	r := &JSONReporter{Compact: false}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	// Pretty-printed JSON should contain newlines and indentation
	if !containsNewlineAndIndent(output) {
		t.Error("pretty-printed JSON should contain newlines and indentation")
	}
}

func TestJSONReporter_Generate_Compact(t *testing.T) {
	r := &JSONReporter{Compact: true}
	result := newTestScanResult()

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	// Compact JSON should not contain pretty-printing indentation
	lines := splitLines(output)
	// Compact JSON should be a single line (or at most very few lines)
	if len(lines) > 2 {
		t.Errorf("compact JSON should be minimal lines, got %d lines", len(lines))
	}
}

func TestJSONReporter_Generate_ContextCancelled(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	err := r.Generate(ctx, result, &buf)
	if err == nil {
		t.Error("Generate() should return error when context is cancelled")
	}
}

func TestJSONReporter_Generate_Errors(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()
	result.Errors = []error{
		context.DeadlineExceeded,
	}

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(output.Errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(output.Errors))
	}
	if output.Errors[0] != "context deadline exceeded" {
		t.Errorf("errors[0] = %q, want %q", output.Errors[0], "context deadline exceeded")
	}
}

func TestJSONReporter_Generate_MultipleParameters(t *testing.T) {
	r := &JSONReporter{}
	result := newTestScanResult()
	// Add a vulnerability on a different parameter
	result.Vulnerabilities = append(result.Vulnerabilities, engine.Vulnerability{
		Parameter: engine.Parameter{
			Name:     "name",
			Value:    "test",
			Location: engine.LocationBody,
			Type:     engine.TypeString,
		},
		Technique:  "error-based",
		DBMS:       "MySQL",
		Payload:    "test' OR 1=1-- -",
		Confidence: 0.90,
		Severity:   engine.SeverityCritical,
		Evidence:   "SQL syntax error",
		Injectable: true,
	})

	var buf bytes.Buffer
	err := r.Generate(context.Background(), result, &buf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if output.Summary.TotalVulnerabilities != 3 {
		t.Errorf("summary.total_vulnerabilities = %d, want 3", output.Summary.TotalVulnerabilities)
	}
	if output.Summary.AffectedParameters != 2 {
		t.Errorf("summary.affected_parameters = %d, want 2", output.Summary.AffectedParameters)
	}
}

// containsNewlineAndIndent checks if the string has indentation.
func containsNewlineAndIndent(s string) bool {
	lines := splitLines(s)
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			return true
		}
	}
	return false
}

// splitLines splits a string into lines, removing empty trailing lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range bytes.Split([]byte(s), []byte("\n")) {
		trimmed := bytes.TrimRight(line, "\r")
		lines = append(lines, string(trimmed))
	}
	// Remove trailing empty lines
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
