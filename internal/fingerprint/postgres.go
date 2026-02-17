package fingerprint

import (
	"context"

	"github.com/0x6d61/sqleech/internal/detector"
)

// PostgreSQLFingerprinter identifies PostgreSQL backends through behavioural probing.
type PostgreSQLFingerprinter struct{}

// DBMS returns the name of the target DBMS.
func (p *PostgreSQLFingerprinter) DBMS() string {
	return "PostgreSQL"
}

// Fingerprint performs multiple checks to identify a PostgreSQL backend:
//  1. Error signatures  - looks for PostgreSQL-specific error patterns in a quote probe
//  2. Behavioral test   - pg_sleep(0) accepted (PostgreSQL-specific function)
//  3. Syntax test       - ::int cast syntax (PostgreSQL-specific)
//  4. Function test     - CURRENT_SETTING('server_version') (PostgreSQL-specific)
//
// Confidence scoring:
//   - Error signature match:         0.7
//   - pg_sleep(0) accepted:          +0.1
//   - ::int cast works:              +0.1
//   - CURRENT_SETTING test works:    +0.1
func (p *PostgreSQLFingerprinter) Fingerprint(ctx context.Context, req *FingerprintRequest) (*FingerprintResult, error) {
	result := &FingerprintResult{
		DBMS: "PostgreSQL",
	}

	var confidence float64

	// --- Check 1: Error signatures via a quote probe ---
	quotePayload := req.Parameter.Value + "'"
	quoteResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, quotePayload)
	if err != nil {
		return nil, err
	}

	sqlErrors := detector.FindSQLErrors(quoteResp.Body)
	if matches, ok := sqlErrors["PostgreSQL"]; ok && len(matches) > 0 {
		confidence += 0.7
	}

	// --- Check 2: pg_sleep(0) behavioral test ---
	sleepPayload := req.Parameter.Value + " AND pg_sleep(0) IS NOT NULL-- -"
	sleepResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, sleepPayload)
	if err != nil {
		return nil, err
	}

	if responseSimilar(req.Baseline, sleepResp) {
		confidence += 0.1
	}

	// --- Check 3: ::int cast syntax test (PostgreSQL-specific) ---
	castPayload := req.Parameter.Value + "::int"
	castResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, castPayload)
	if err != nil {
		return nil, err
	}

	if responseSimilar(req.Baseline, castResp) {
		confidence += 0.1
	}

	// --- Check 4: CURRENT_SETTING function test (PostgreSQL-specific) ---
	settingPayload := req.Parameter.Value + " AND CURRENT_SETTING('server_version') IS NOT NULL-- -"
	settingResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, settingPayload)
	if err != nil {
		return nil, err
	}

	if responseSimilar(req.Baseline, settingResp) {
		confidence += 0.1
	}

	// Cap confidence at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	result.Confidence = confidence
	result.Identified = confidence >= 0.7

	return result, nil
}
