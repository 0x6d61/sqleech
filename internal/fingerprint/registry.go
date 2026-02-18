package fingerprint

import "context"

// Registry manages all available fingerprinters and runs them to identify
// the DBMS backing a target application.
type Registry struct {
	fingerprinters []Fingerprinter
}

// NewRegistry creates a registry with all built-in fingerprinters.
func NewRegistry() *Registry {
	return &Registry{
		fingerprinters: []Fingerprinter{
			&MySQLFingerprinter{},
			&PostgreSQLFingerprinter{},
			&mssqlFingerprinter{},
		},
	}
}

// Identify runs all registered fingerprinters and returns the best match.
// It returns nil if no fingerprinter identifies the target with sufficient
// confidence.
func (r *Registry) Identify(ctx context.Context, req *FingerprintRequest) (*DBMSInfo, error) {
	var best *FingerprintResult

	for _, fp := range r.fingerprinters {
		result, err := fp.Fingerprint(ctx, req)
		if err != nil {
			return nil, err
		}

		if result == nil || !result.Identified {
			continue
		}

		if best == nil || result.Confidence > best.Confidence {
			best = result
		}
	}

	if best == nil {
		return nil, nil
	}

	return &DBMSInfo{
		Name:       best.DBMS,
		Version:    best.Version,
		Banner:     best.Banner,
		Confidence: best.Confidence,
	}, nil
}

// supportedDBMS lists DBMS names that can be identified via error signatures.
// "Generic" is intentionally excluded as it does not identify a specific DBMS.
var supportedDBMS = []string{"MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"}

// IdentifyFromErrors uses error signatures from a heuristic scan to identify
// the DBMS without sending additional requests. This is a fast path that
// leverages the error messages already collected by the heuristic detector.
//
// It returns nil if no specific DBMS can be determined.
func IdentifyFromErrors(errorSignatures map[string][]string) *DBMSInfo {
	if len(errorSignatures) == 0 {
		return nil
	}

	var bestDBMS string
	var bestCount int

	for _, name := range supportedDBMS {
		matches, ok := errorSignatures[name]
		if !ok || len(matches) == 0 {
			continue
		}

		if len(matches) > bestCount {
			bestCount = len(matches)
			bestDBMS = name
		}
	}

	if bestDBMS == "" {
		return nil
	}

	return &DBMSInfo{
		Name:       bestDBMS,
		Confidence: 0.7,
	}
}
