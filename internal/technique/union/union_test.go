package union

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --------------------------------------------------------------------------
// Mock server helpers
// --------------------------------------------------------------------------

const (
	mockVersion = "8.0.32-MySQL"
	mockNumCols = 2 // Simulated query returns 2 columns (id, name)
)

// testTmpl holds templates for the mock server. Using html/template ensures
// any user-derived integers/strings are safely HTML-escaped.
var testTmpl = template.Must(template.New("").Parse(`
{{define "union-order-error"}}<html><body><h1>Error</h1><p>Unknown column '{{.}}' in 'order clause'</p></body></html>{{end}}
{{define "union-normal"}}<html><body><h1>Products</h1><p>ID: 1 | Name: Widget</p></body></html>{{end}}
{{define "union-sentinel"}}<html><body><h1>Products</h1><p>ID: 1 | Name: ` + sentinel + `</p></body></html>{{end}}
{{define "union-injected"}}<html><body><h1>Products</h1><p>ID: 1 | Name: ~` + mockVersion + `~</p></body></html>{{end}}
{{define "static"}}<html><body><h1>Static Page</h1><p>Content here.</p></body></html>{{end}}
`))

func execTestTmpl(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	testTmpl.ExecuteTemplate(w, name, data) //nolint:errcheck
}

// newUnionMockServer creates a 2-column mock server that:
//   - Accepts ORDER BY 1 and ORDER BY 2 normally.
//   - Returns an "Unknown column" error for ORDER BY 3+.
//   - Returns the sentinel in the response body when UNION SELECT contains the sentinel.
//   - Returns ~mockVersion~ in the response body for any other UNION SELECT injection.
func newUnionMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		upper := strings.ToUpper(id)

		// ORDER BY N detection
		if n, ok := parseOrderByN(upper); ok {
			if n > mockNumCols {
				execTestTmpl(w, "union-order-error", n)
				return
			}
			execTestTmpl(w, "union-normal", nil)
			return
		}

		// UNION SELECT detection
		if strings.Contains(upper, "UNION") && strings.Contains(upper, "SELECT") {
			if strings.Contains(id, sentinel) {
				execTestTmpl(w, "union-sentinel", nil)
				return
			}
			execTestTmpl(w, "union-injected", nil)
			return
		}

		// Normal response
		execTestTmpl(w, "union-normal", nil)
	}))
}

// newStaticServer creates a mock server that returns the same page regardless
// of the input — simulating a non-injectable endpoint.
func newStaticServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		execTestTmpl(w, "static", nil)
	}))
}

// parseOrderByN extracts N from "ORDER BY N" in an upper-case string.
// Returns (0, false) if no ORDER BY clause is found.
func parseOrderByN(upper string) (int, bool) {
	const token = "ORDER BY"
	idx := strings.Index(upper, token)
	if idx == -1 {
		return 0, false
	}
	rest := strings.TrimSpace(upper[idx+len(token):])
	var n int
	if _, err := fmt.Sscan(rest, &n); err != nil {
		return 0, false
	}
	return n, true
}

// newTestClient returns a real HTTP transport client for unit tests.
func newTestClient(t *testing.T) transport.Client {
	t.Helper()
	c, err := transport.NewClient(transport.ClientOptions{})
	if err != nil {
		t.Fatalf("transport.NewClient: %v", err)
	}
	return c
}

// newTestRequest builds an InjectionRequest with baseline response for the given server.
func newTestRequest(t *testing.T, srv *httptest.Server, client transport.Client) *technique.InjectionRequest {
	t.Helper()
	target := &engine.ScanTarget{
		URL:    srv.URL + "/search?id=1",
		Method: "GET",
	}
	param := &engine.Parameter{
		Name:     "id",
		Value:    "1",
		Location: engine.LocationQuery,
		Type:     engine.TypeInteger,
	}
	baseline, err := client.Do(context.Background(), buildProbeRequest(target, param, "1"))
	if err != nil {
		t.Fatalf("getting baseline: %v", err)
	}
	return &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		DBMS:      "MySQL",
		Client:    client,
	}
}

// --------------------------------------------------------------------------
// Core technique tests
// --------------------------------------------------------------------------

func TestUnion_Name(t *testing.T) {
	u := New()
	if u.Name() != "union-based" {
		t.Errorf("Name() = %q, want 'union-based'", u.Name())
	}
}

func TestUnion_Priority(t *testing.T) {
	u := New()
	if u.Priority() != 4 {
		t.Errorf("Priority() = %d, want 4", u.Priority())
	}
}

func TestUnion_Detect_MySQL_Injectable(t *testing.T) {
	srv := newUnionMockServer()
	defer srv.Close()

	client := newTestClient(t)
	req := newTestRequest(t, srv, client)

	u := New()
	result, err := u.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !result.Injectable {
		t.Error("expected Injectable=true")
	}
	if result.Technique != "union-based" {
		t.Errorf("Technique=%q, want 'union-based'", result.Technique)
	}
	if result.Confidence < 0.8 {
		t.Errorf("Confidence=%f, want >=0.8", result.Confidence)
	}
	if result.Evidence == "" {
		t.Error("expected non-empty Evidence")
	}
	if result.Payload == nil {
		t.Error("expected non-nil Payload")
	}
}

func TestUnion_Detect_NotInjectable(t *testing.T) {
	srv := newStaticServer()
	defer srv.Close()

	client := newTestClient(t)
	req := newTestRequest(t, srv, client)

	u := New()
	result, err := u.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Injectable {
		t.Error("expected Injectable=false for static endpoint")
	}
}

func TestUnion_Detect_ContextCancelled(t *testing.T) {
	srv := newUnionMockServer()
	defer srv.Close()

	client := newTestClient(t)
	req := newTestRequest(t, srv, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	u := New()
	_, err := u.Detect(ctx, req)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestUnion_Extract_MySQL(t *testing.T) {
	srv := newUnionMockServer()
	defer srv.Close()

	client := newTestClient(t)
	injReq := newTestRequest(t, srv, client)

	u := New()
	result, err := u.Extract(context.Background(), &technique.ExtractionRequest{
		InjectionRequest: *injReq,
		Query:            "@@version",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if result.Value == "" {
		t.Error("expected non-empty extracted value")
	}
	if !strings.Contains(result.Value, "8.0.32") {
		t.Errorf("extracted value = %q, want to contain '8.0.32'", result.Value)
	}
}

func TestUnion_Extract_Empty_NonInjectable(t *testing.T) {
	srv := newStaticServer()
	defer srv.Close()

	client := newTestClient(t)
	req := newTestRequest(t, srv, client)

	u := New()
	result, err := u.Extract(context.Background(), &technique.ExtractionRequest{
		InjectionRequest: *req,
		Query:            "@@version",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	// Non-injectable endpoint: value should be empty (no marker found)
	if result.Value != "" {
		t.Errorf("expected empty value for non-injectable endpoint, got %q", result.Value)
	}
}

// --------------------------------------------------------------------------
// Helper function tests
// --------------------------------------------------------------------------

func TestBuildColumnList_StrColFirst(t *testing.T) {
	d := findDBMS("MySQL")
	got := buildColumnList(3, 0, "'test'", d)
	if got != "'test',NULL,NULL" {
		t.Errorf("buildColumnList = %q, want \"'test',NULL,NULL\"", got)
	}
}

func TestBuildColumnList_StrColMiddle(t *testing.T) {
	d := findDBMS("MySQL")
	got := buildColumnList(3, 1, "'test'", d)
	if got != "NULL,'test',NULL" {
		t.Errorf("buildColumnList = %q, want \"NULL,'test',NULL\"", got)
	}
}

func TestBuildColumnList_StrColLast(t *testing.T) {
	d := findDBMS("MySQL")
	got := buildColumnList(3, 2, "'test'", d)
	if got != "NULL,NULL,'test'" {
		t.Errorf("buildColumnList = %q, want \"NULL,NULL,'test'\"", got)
	}
}

func TestBuildColumnList_OutOfRange(t *testing.T) {
	d := findDBMS("MySQL")
	got := buildColumnList(2, 5, "'test'", d)
	// strCol 5 is out of range for colCount 2 → all NULLs
	if got != "NULL,NULL" {
		t.Errorf("buildColumnList (out of range) = %q, want \"NULL,NULL\"", got)
	}
}

func TestWrapQueryWithMarker_MySQL(t *testing.T) {
	d := findDBMS("MySQL")
	got := wrapQueryWithMarker(d, "@@version")
	want := "CONCAT(CHAR(126),(@@version),CHAR(126))"
	if got != want {
		t.Errorf("wrapQueryWithMarker(MySQL) = %q, want %q", got, want)
	}
}

func TestWrapQueryWithMarker_PostgreSQL(t *testing.T) {
	d := findDBMS("PostgreSQL")
	got := wrapQueryWithMarker(d, "version()")
	want := "chr(126)||(version())||chr(126)"
	if got != want {
		t.Errorf("wrapQueryWithMarker(PostgreSQL) = %q, want %q", got, want)
	}
}

func TestWrapQueryWithMarker_MSSQL(t *testing.T) {
	d := findDBMS("MSSQL")
	got := wrapQueryWithMarker(d, "@@version")
	want := "CHAR(126)+CAST((@@version) AS NVARCHAR(MAX))+CHAR(126)"
	if got != want {
		t.Errorf("wrapQueryWithMarker(MSSQL) = %q, want %q", got, want)
	}
}

func TestParseMarkedValue(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{"hello ~extracted_value~ world", "extracted_value"},
		{"no markers here", ""},
		{"~only_open", ""},
		{"~a~b~c~", "a"},
		{"~~", ""},
		{"prefix~MySQL 8.0.32~suffix", "MySQL 8.0.32"},
	}
	for _, c := range cases {
		got := parseMarkedValue(c.body)
		if got != c.want {
			t.Errorf("parseMarkedValue(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestIsOrderByError_LengthRatio(t *testing.T) {
	baseline := []byte("<html><body><h1>Normal</h1><p>Widget item with many words in the description</p></body></html>")
	// Short error page (< 40% of baseline length)
	short := []byte("<p>Err</p>")
	if !isOrderByError(baseline, short) {
		t.Error("expected short response to be detected as ORDER BY error")
	}
}

func TestIsOrderByError_Keyword(t *testing.T) {
	baseline := []byte("<html><body><p>Normal</p></body></html>")
	errPage := []byte("<html><body><p>Unknown column '3' in 'order clause'</p></body></html>")
	if !isOrderByError(baseline, errPage) {
		t.Error("expected 'unknown column' keyword to be detected as ORDER BY error")
	}
}

func TestIsOrderByError_Normal(t *testing.T) {
	baseline := []byte("<html><body><h1>Products</h1><p>ID: 1 | Name: Widget</p></body></html>")
	normal := []byte("<html><body><h1>Products</h1><p>ID: 1 | Name: Widget</p></body></html>")
	if isOrderByError(baseline, normal) {
		t.Error("expected identical response NOT to be detected as ORDER BY error")
	}
}

func TestBuildProbeStr(t *testing.T) {
	bp := boundaryPair{prefix: "'", suffix: "-- -"}
	got := buildProbeStr("1", bp, "ORDER BY 1")
	want := "1' ORDER BY 1 -- -"
	if got != want {
		t.Errorf("buildProbeStr = %q, want %q", got, want)
	}
}
