package report

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/0x6d61/sqleech/internal/engine"
)

// JSONReporter outputs structured JSON.
type JSONReporter struct {
	// Compact outputs single-line JSON when true (no indentation).
	Compact bool
}

// Format returns "json".
func (r *JSONReporter) Format() string {
	return "json"
}

// jsonOutput is the top-level JSON structure.
type jsonOutput struct {
	SchemaVersion   string     `json:"schema_version"`
	Tool            string     `json:"tool"`
	Target          jsonTarget `json:"target"`
	DBMS            *jsonDBMS  `json:"dbms,omitempty"`
	Scan            jsonScan   `json:"scan"`
	Vulnerabilities []jsonVuln `json:"vulnerabilities"`
	Summary         jsonSummary `json:"summary"`
	Errors          []string   `json:"errors,omitempty"`
}

// jsonTarget represents the scan target in JSON.
type jsonTarget struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// jsonDBMS represents the detected DBMS in JSON.
type jsonDBMS struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// jsonScan represents scan metadata in JSON.
type jsonScan struct {
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	DurationSeconds float64   `json:"duration_seconds"`
	TotalRequests   int64     `json:"total_requests"`
}

// jsonVuln represents a vulnerability in JSON.
type jsonVuln struct {
	Parameter  jsonParam `json:"parameter"`
	Technique  string    `json:"technique"`
	DBMS       string    `json:"dbms"`
	Payload    string    `json:"payload"`
	Confidence float64   `json:"confidence"`
	Severity   string    `json:"severity"`
	Evidence   string    `json:"evidence"`
}

// jsonParam represents a parameter in JSON.
type jsonParam struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Type     string `json:"type"`
}

// jsonSummary represents the summary in JSON.
type jsonSummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	AffectedParameters   int `json:"affected_parameters"`
}

// paramTypeString converts a ParameterType to a human-readable string.
func paramTypeString(t engine.ParameterType) string {
	switch t {
	case engine.TypeInteger:
		return "integer"
	case engine.TypeFloat:
		return "float"
	default:
		return "string"
	}
}

// Generate writes JSON scan results to w.
func (r *JSONReporter) Generate(ctx context.Context, result *engine.ScanResult, w io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	duration := result.EndTime.Sub(result.StartTime)

	output := jsonOutput{
		SchemaVersion: "1.0",
		Tool:          "sqleech",
		Target: jsonTarget{
			URL:    result.Target.URL,
			Method: result.Target.Method,
		},
		Scan: jsonScan{
			StartTime:       result.StartTime,
			EndTime:         result.EndTime,
			DurationSeconds: duration.Seconds(),
			TotalRequests:   result.RequestCount,
		},
		Vulnerabilities: make([]jsonVuln, 0, len(result.Vulnerabilities)),
		Summary: jsonSummary{
			TotalVulnerabilities: len(result.Vulnerabilities),
			AffectedParameters:  countAffectedParameters(result.Vulnerabilities),
		},
	}

	// DBMS (omitted if not detected)
	if result.DBMS != "" {
		output.DBMS = &jsonDBMS{
			Name:    result.DBMS,
			Version: result.DBMSVersion,
		}
	}

	// Vulnerabilities
	for _, v := range result.Vulnerabilities {
		output.Vulnerabilities = append(output.Vulnerabilities, jsonVuln{
			Parameter: jsonParam{
				Name:     v.Parameter.Name,
				Location: v.Parameter.Location.String(),
				Type:     paramTypeString(v.Parameter.Type),
			},
			Technique:  v.Technique,
			DBMS:       v.DBMS,
			Payload:    v.Payload,
			Confidence: v.Confidence,
			Severity:   v.Severity.String(),
			Evidence:   v.Evidence,
		})
	}

	// Errors
	if len(result.Errors) > 0 {
		output.Errors = make([]string, len(result.Errors))
		for i, e := range result.Errors {
			output.Errors[i] = e.Error()
		}
	}

	enc := json.NewEncoder(w)
	if !r.Compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(output)
}
