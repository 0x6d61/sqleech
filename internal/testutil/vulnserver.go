// Package testutil provides test utilities including a mock vulnerable web
// server for integration testing of the sqleech SQL injection scanner.
//
// SECURITY NOTE: This package is for testing only. The mock server
// intentionally simulates SQL-injectable endpoints. All user-derived
// values embedded in responses are HTML-escaped via html/template.
package testutil

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// mockVersionMySQL is the fake MySQL version returned by the mock server.
const mockVersionMySQL = "8.0.32"

// mockVersionPostgreSQL is the fake PostgreSQL version returned by the mock server.
const mockVersionPostgreSQL = "PostgreSQL 15.3"

// timebasedSleepCap is the maximum simulated delay for time-based handlers.
// Kept short (1s) to keep integration tests fast.
const timebasedSleepCap = 1 * time.Second

// sleepSecondsPattern extracts the seconds argument from SLEEP(n) or PG_SLEEP(n).
var sleepSecondsPattern = regexp.MustCompile(`(?i)(?:PG_)?SLEEP\((\d+)\)`)

// Response templates using html/template for safe HTML rendering.
// Templates with {{.}} safely escape any dynamic data passed to them.
// Templates without interpolation render static content only.
var tmplMap = template.Must(template.New("").Parse(`
{{define "mysql-xpath-error"}}<html><body><h1>Error</h1><p>XPATH syntax error: '~` + mockVersionMySQL + `~'</p></body></html>{{end}}
{{define "mysql-syntax-error"}}<html><body><h1>Error</h1><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{{.}}'</p></body></html>{{end}}
{{define "mysql-normal"}}<html><body><h1>Products</h1><p>Product: Widget (ID: 1)</p></body></html>{{end}}
{{define "mysql-false"}}<html><body><h1>Products</h1><p>No results found.</p></body></html>{{end}}
{{define "pg-cast-error"}}<html><body><h1>Error</h1><p>invalid input syntax for type integer: "` + mockVersionPostgreSQL + `"</p></body></html>{{end}}
{{define "pg-syntax-error"}}<html><body><h1>Error</h1><p>ERROR: syntax error at or near "{{.}}"</p></body></html>{{end}}
{{define "pg-normal"}}<html><body><h1>Users</h1><p>User: admin (ID: 1)</p></body></html>{{end}}
{{define "pg-false"}}<html><body><h1>Users</h1><p>No user found.</p></body></html>{{end}}
{{define "bool-normal"}}<html><body><h1>Store</h1><p>Welcome! Your item: Widget</p></body></html>{{end}}
{{define "bool-false"}}<html><body><h1>Store</h1><p>No items found.</p></body></html>{{end}}
{{define "multi-normal"}}<html><body><h1>Results</h1><p>Item: Widget (ID: 1, Name: default)</p></body></html>{{end}}
{{define "multi-false"}}<html><body><h1>Results</h1><p>No results found.</p></body></html>{{end}}
{{define "post-normal"}}<html><body><h1>Login</h1><p>Welcome back, admin!</p></body></html>{{end}}
{{define "post-false"}}<html><body><h1>Login</h1><p>Login failed. Invalid credentials.</p></body></html>{{end}}
{{define "post-error"}}<html><body><h1>Error</h1><p>You have an error in your SQL syntax</p></body></html>{{end}}
{{define "safe"}}<html><body><h1>Product</h1><p>Product details for item 42</p></body></html>{{end}}
{{define "timebased-normal"}}<html><body><h1>Results</h1><p>Record found.</p></body></html>{{end}}
`))

// asciiSubstringPattern extracts position and comparison value from boolean
// blind probes like: ASCII(SUBSTRING(...,<pos>,1))><value>
var asciiSubstringPattern = regexp.MustCompile(`(?i)ASCII\(SUBSTRING\([^,]+,(\d+),1\)\)\s*>\s*(\d+)`)

// lengthPattern extracts the comparison value from LENGTH probes like:
// LENGTH(...)><value>  -- supports nested parentheses up to one level deep.
var lengthPattern = regexp.MustCompile(`(?i)LENGTH\((?:[^()]*\([^)]*\))*[^)]*\)\s*>\s*(\d+)`)

// NewVulnServer creates a mock HTTP server simulating a vulnerable web
// application. The server handles multiple endpoints that simulate different
// types of SQL injection vulnerabilities. The returned *httptest.Server
// should be closed after use.
func NewVulnServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/vuln/error-mysql", handleErrorMySQL)
	mux.HandleFunc("/vuln/error-postgres", handleErrorPostgres)
	mux.HandleFunc("/vuln/boolean", handleBoolean)
	mux.HandleFunc("/vuln/safe", handleSafe)
	mux.HandleFunc("/vuln/multi", handleMulti)
	mux.HandleFunc("/vuln/post", handlePost)
	mux.HandleFunc("/vuln/timebased-mysql", handleTimeBasedMySQL)
	mux.HandleFunc("/vuln/timebased-postgres", handleTimeBasedPostgres)

	return httptest.NewServer(mux)
}

// execTemplate renders a named template with optional data to the ResponseWriter.
func execTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	tmplMap.ExecuteTemplate(w, name, data) //nolint:errcheck
}

// handleErrorMySQL simulates a MySQL error-based injectable endpoint.
//
// GET /vuln/error-mysql?id=X
//   - Normal: returns HTML with "Product: Widget (ID: 1)"
//   - If X contains "'": returns MySQL syntax error
//   - If X contains "extractvalue": returns XPATH error with version
//   - If X contains "updatexml": returns XPATH error with version
//   - If X contains "AND 1=1" or "1=1": returns normal page
//   - If X contains "AND 1=2" or "1=2" (but not "1=1"): returns "No results found."
//   - If X contains "SLEEP": returns normal page (no actual delay)
func handleErrorMySQL(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	switch {
	case containsCI(id, "extractvalue") || containsCI(id, "updatexml"):
		execTemplate(w, "mysql-xpath-error", nil)
	case strings.Contains(id, "'"):
		execTemplate(w, "mysql-syntax-error", id)
	case containsCI(id, "AND 1=2") || containsFalseCondition(id):
		execTemplate(w, "mysql-false", nil)
	case containsCI(id, "AND 1=1") || containsTrueCondition(id):
		execTemplate(w, "mysql-normal", nil)
	case containsCI(id, "SLEEP"):
		execTemplate(w, "mysql-normal", nil)
	default:
		execTemplate(w, "mysql-normal", nil)
	}
}

// handleErrorPostgres simulates a PostgreSQL error-based injectable endpoint.
//
// GET /vuln/error-postgres?id=X
//   - Normal: returns HTML with "User: admin (ID: 1)"
//   - If X contains "'": returns PostgreSQL syntax error
//   - If X contains "CAST(": returns invalid input syntax error with version
//   - If X contains "AND 1=1": returns normal page
//   - If X contains "AND 1=2": returns different page
//   - If X contains "pg_sleep": returns normal page
func handleErrorPostgres(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	switch {
	case containsCI(id, "CAST("):
		execTemplate(w, "pg-cast-error", nil)
	case strings.Contains(id, "'"):
		execTemplate(w, "pg-syntax-error", id)
	case containsCI(id, "AND 1=2") || containsFalseCondition(id):
		execTemplate(w, "pg-false", nil)
	case containsCI(id, "AND 1=1") || containsTrueCondition(id):
		execTemplate(w, "pg-normal", nil)
	case containsCI(id, "pg_sleep"):
		execTemplate(w, "pg-normal", nil)
	default:
		execTemplate(w, "pg-normal", nil)
	}
}

// handleBoolean simulates a boolean-blind injectable endpoint.
//
// GET /vuln/boolean?id=X
//   - Normal: returns "Welcome! Your item: Widget"
//   - If X contains "AND 1=1": same as normal
//   - If X contains "AND 1=2": returns "No items found."
//   - If X contains "ASCII(SUBSTRING": evaluates against mock version data
//   - If X contains "LENGTH": compares against length of mock version
func handleBoolean(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	switch {
	case containsCI(id, "ASCII(SUBSTRING"):
		if evaluateASCIISubstring(id, mockVersionMySQL) {
			execTemplate(w, "bool-normal", nil)
		} else {
			execTemplate(w, "bool-false", nil)
		}
	case containsCI(id, "LENGTH("):
		if evaluateLength(id, mockVersionMySQL) {
			execTemplate(w, "bool-normal", nil)
		} else {
			execTemplate(w, "bool-false", nil)
		}
	case containsCI(id, "AND 1=2") || containsFalseCondition(id):
		execTemplate(w, "bool-false", nil)
	case containsCI(id, "AND 1=1") || containsTrueCondition(id):
		execTemplate(w, "bool-normal", nil)
	default:
		execTemplate(w, "bool-normal", nil)
	}
}

// handleSafe simulates a non-injectable endpoint. It always returns the
// same page regardless of input -- the parameter is not interpolated into SQL.
//
// GET /vuln/safe?id=X
func handleSafe(w http.ResponseWriter, _ *http.Request) {
	execTemplate(w, "safe", nil)
}

// handleMulti simulates an endpoint with multiple parameters where only
// "id" is injectable (MySQL error-based) and "name" is not.
//
// GET /vuln/multi?id=X&name=Y
func handleMulti(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	// Only id affects the response; name is ignored in SQL context.
	switch {
	case containsCI(id, "extractvalue") || containsCI(id, "updatexml"):
		execTemplate(w, "mysql-xpath-error", nil)
	case strings.Contains(id, "'"):
		execTemplate(w, "mysql-syntax-error", id)
	case containsCI(id, "AND 1=2") || containsFalseCondition(id):
		execTemplate(w, "multi-false", nil)
	case containsCI(id, "AND 1=1") || containsTrueCondition(id):
		execTemplate(w, "multi-normal", nil)
	default:
		execTemplate(w, "multi-normal", nil)
	}
}

// handlePost simulates a POST endpoint where the "username" body parameter
// is injectable via boolean-blind technique.
//
// POST /vuln/post
// Body: username=X&password=Y (application/x-www-form-urlencoded)
func handlePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")

	switch {
	case containsCI(username, "ASCII(SUBSTRING"):
		if evaluateASCIISubstring(username, mockVersionMySQL) {
			execTemplate(w, "post-normal", nil)
		} else {
			execTemplate(w, "post-false", nil)
		}
	case containsCI(username, "LENGTH("):
		if evaluateLength(username, mockVersionMySQL) {
			execTemplate(w, "post-normal", nil)
		} else {
			execTemplate(w, "post-false", nil)
		}
	case containsCI(username, "AND 1=2") || containsFalseCondition(username):
		execTemplate(w, "post-false", nil)
	case containsCI(username, "AND 1=1") || containsTrueCondition(username):
		execTemplate(w, "post-normal", nil)
	case strings.Contains(username, "'"):
		// Single quote causes a SQL error, which looks different from normal
		execTemplate(w, "post-error", nil)
	default:
		execTemplate(w, "post-normal", nil)
	}
}

// --------------------------------------------------------------------------
// Helper functions
// --------------------------------------------------------------------------

// containsCI performs a case-insensitive contains check.
func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(substr))
}

// containsTrueCondition checks for quoted true conditions like '1'='1'.
func containsTrueCondition(s string) bool {
	return strings.Contains(s, "'1'='1")
}

// containsFalseCondition checks for quoted false conditions like '1'='2'.
func containsFalseCondition(s string) bool {
	return strings.Contains(s, "'1'='2")
}

// evaluateASCIISubstring evaluates an ASCII(SUBSTRING(...,pos,1))>val probe
// against the mock data. Returns true if the ASCII value of the character at
// the given position is greater than the comparison value.
func evaluateASCIISubstring(input, mockData string) bool {
	matches := asciiSubstringPattern.FindStringSubmatch(input)
	if len(matches) < 3 {
		return false
	}

	pos, err := strconv.Atoi(matches[1])
	if err != nil || pos < 1 || pos > len(mockData) {
		return false
	}

	cmpVal, err := strconv.Atoi(matches[2])
	if err != nil {
		return false
	}

	charVal := int(mockData[pos-1])
	return charVal > cmpVal
}

// evaluateLength evaluates a LENGTH(...)>val probe against the mock data.
// Returns true if the length of the mock data is greater than the comparison value.
func evaluateLength(input, mockData string) bool {
	matches := lengthPattern.FindStringSubmatch(input)
	if len(matches) < 2 {
		return false
	}

	cmpVal, err := strconv.Atoi(matches[1])
	if err != nil {
		return false
	}

	return len(mockData) > cmpVal
}

// shouldTimebasedSleep returns true when the payload should cause a DB sleep,
// mirroring real DBMS behaviour:
//   - IF(1=1,SLEEP(n),0)   → true condition  → sleep
//   - IF(1=2,SLEEP(n),0)   → false condition → no sleep
//   - CASE WHEN (1=1) THEN (SELECT 1 FROM PG_SLEEP(n)) ELSE 1 END → sleep
//   - CASE WHEN (1=2) THEN (SELECT 1 FROM PG_SLEEP(n)) ELSE 1 END → no sleep
func shouldTimebasedSleep(payload string) (seconds int, ok bool) {
	matches := sleepSecondsPattern.FindStringSubmatch(payload)
	if len(matches) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(matches[1])
	if err != nil || n <= 0 {
		return 0, false
	}

	upper := strings.ToUpper(payload)
	hasSleep := strings.Contains(upper, "SLEEP(")
	isTrueCond := strings.Contains(upper, "1=1")
	isFalseCond := strings.Contains(upper, "1=2")

	// Sleep only when the condition is TRUE (contains 1=1, not only 1=2).
	if hasSleep && isTrueCond && !isFalseCond {
		return n, true
	}
	return 0, false
}

// handleTimeBasedMySQL simulates a MySQL time-based blind injectable endpoint.
//
// GET /vuln/timebased-mysql?id=X
//   - TRUE condition (1=1 + SLEEP): sleeps min(n, cap) seconds
//   - FALSE condition (1=2 + SLEEP): responds immediately (no sleep)
//
// This matches real MySQL IF(condition, SLEEP(n), 0) evaluation semantics.
func handleTimeBasedMySQL(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	if n, ok := shouldTimebasedSleep(id); ok {
		d := time.Duration(n) * time.Second
		if d > timebasedSleepCap {
			d = timebasedSleepCap
		}
		time.Sleep(d)
	}

	execTemplate(w, "timebased-normal", nil)
}

// handleTimeBasedPostgres simulates a PostgreSQL time-based blind injectable endpoint.
//
// GET /vuln/timebased-postgres?id=X
//   - TRUE condition: sleeps min(n, cap) seconds
//   - FALSE condition: responds immediately
func handleTimeBasedPostgres(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	if n, ok := shouldTimebasedSleep(id); ok {
		d := time.Duration(n) * time.Second
		if d > timebasedSleepCap {
			d = timebasedSleepCap
		}
		time.Sleep(d)
	}

	execTemplate(w, "timebased-normal", nil)
}
