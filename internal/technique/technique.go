// Package technique defines the interface for SQL injection detection
// and exploitation techniques (error-based, boolean-based, time-based, etc.).
package technique

import (
	"context"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/payload"
	"github.com/0x6d61/sqleech/internal/transport"
)

// Technique defines a SQL injection detection and exploitation method.
type Technique interface {
	// Name returns the human-readable name of the technique (e.g., "error-based").
	Name() string

	// Priority returns the execution priority. Lower values are tried first.
	// Error=1, Boolean=2, Time=3, Union=4.
	Priority() int

	// Detect tests whether a parameter is injectable using this technique.
	Detect(ctx context.Context, req *InjectionRequest) (*DetectionResult, error)

	// Extract retrieves the value of a SQL expression using this technique.
	Extract(ctx context.Context, req *ExtractionRequest) (*ExtractionResult, error)
}

// InjectionRequest contains everything needed to test an injection point.
type InjectionRequest struct {
	Target    *engine.ScanTarget
	Parameter *engine.Parameter
	Baseline  *transport.Response
	DBMS      string // Hint from fingerprinting; empty means unknown
	Client    transport.Client
}

// DetectionResult indicates whether injection was detected.
type DetectionResult struct {
	Injectable bool
	Confidence float64
	Technique  string
	Payload    *payload.Payload
	Evidence   string
}

// ExtractionRequest asks to extract a specific SQL expression's value.
type ExtractionRequest struct {
	InjectionRequest
	Query string // SQL expression to evaluate, e.g., "@@version"
}

// ExtractionResult contains extracted data.
type ExtractionResult struct {
	Value    string
	Partial  bool
	Requests int
}
