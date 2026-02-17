// Package engine provides the core scan orchestration pipeline.
package engine

import "time"

// ScanTarget represents a single target to scan.
type ScanTarget struct {
	URL         string
	Method      string
	Headers     map[string]string
	Body        string
	ContentType string
	Cookies     map[string]string
	Parameters  []Parameter
}

// Parameter represents a single injectable parameter.
type Parameter struct {
	Name     string
	Value    string
	Location ParameterLocation
	Type     ParameterType
}

// ParameterLocation indicates where a parameter appears in the request.
type ParameterLocation int

const (
	LocationQuery ParameterLocation = iota
	LocationBody
	LocationHeader
	LocationCookie
	LocationPath
	LocationJSON
	LocationGraphQL
	LocationXML
	LocationMultipart
)

// String returns a human-readable name for the location.
func (l ParameterLocation) String() string {
	names := [...]string{
		"query", "body", "header", "cookie", "path",
		"json", "graphql", "xml", "multipart",
	}
	if int(l) < len(names) {
		return names[l]
	}
	return "unknown"
}

// ParameterType indicates the inferred data type of a parameter.
type ParameterType int

const (
	TypeString ParameterType = iota
	TypeInteger
	TypeFloat
)

// Severity represents the severity level of a vulnerability.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

// String returns the severity name.
func (s Severity) String() string {
	names := [...]string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	if int(s) < len(names) {
		return names[s]
	}
	return "UNKNOWN"
}

// ScanResult holds the complete result of a scan.
type ScanResult struct {
	Target          ScanTarget
	Vulnerabilities []Vulnerability
	DBMS            string
	DBMSVersion     string
	StartTime       time.Time
	EndTime         time.Time
	RequestCount    int64
	Errors          []error
}

// Vulnerability represents a confirmed SQL injection point.
type Vulnerability struct {
	Parameter  Parameter
	Technique  string
	DBMS       string
	Payload    string
	Confidence float64
	Severity   Severity
	Evidence   string
	Injectable bool
}
