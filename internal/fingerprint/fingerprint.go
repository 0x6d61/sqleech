// Package fingerprint provides DBMS identification through behavioral probing.
// It sends targeted payloads that exploit DBMS-specific syntax differences
// to determine which database engine backs a target application.
package fingerprint

import (
	"context"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

// DBMSInfo contains identified DBMS information.
type DBMSInfo struct {
	Name       string  // "MySQL", "PostgreSQL"
	Version    string  // e.g., "8.0.32"
	Banner     string  // Raw version string
	Confidence float64 // 0.0 - 1.0
}

// Fingerprinter identifies a specific DBMS.
type Fingerprinter interface {
	// DBMS returns the name of the DBMS this fingerprinter targets.
	DBMS() string

	// Fingerprint attempts to identify the target DBMS by sending
	// behavioural probes and analysing the responses.
	Fingerprint(ctx context.Context, req *FingerprintRequest) (*FingerprintResult, error)
}

// FingerprintRequest contains data needed for fingerprinting.
type FingerprintRequest struct {
	Target    *engine.ScanTarget
	Parameter *engine.Parameter
	Baseline  *transport.Response
	Client    transport.Client
}

// FingerprintResult is the outcome of a DBMS identification attempt.
type FingerprintResult struct {
	Identified bool
	DBMS       string
	Version    string
	Confidence float64
	Banner     string
}
