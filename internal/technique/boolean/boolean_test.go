package boolean

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

// simulatedVersion is the "database version" used by the mock server.
const simulatedVersion = "8.0.32"

// newMockServer creates a test server that simulates boolean-blind behavior.
// - /vuln?id=X: evaluates injected AND conditions against a simulated DB.
// - /safe?id=X: always returns the same page regardless of injection.
func newMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		id := r.URL.Query().Get("id")

		switch path {
		case "/vuln":
			if evaluateCondition(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "Welcome! Item found.")
			} else {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "No results.")
			}
		case "/safe":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Welcome! Item found.")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Not Found")
		}
	}))
}

// evaluateCondition parses the injected id parameter and determines whether
// the simulated boolean condition is TRUE or FALSE.
func evaluateCondition(id string) bool {
	// Strip comment suffixes commonly appended by the injector.
	id = stripComment(id)
	id = strings.TrimSpace(id)

	// Check for AND 1=2 (always false)
	if strings.Contains(id, "AND 1=2") {
		return false
	}
	// Check for AND 1=1 (always true)
	if strings.Contains(id, "AND 1=1") {
		return true
	}
	// Check for AND '1'='2' (string false)
	if strings.Contains(id, "AND '1'='2") {
		return false
	}
	// Check for AND '1'='1' (string true)
	if strings.Contains(id, "AND '1'='1") {
		return true
	}

	// Handle LENGTH(...) = N or LENGTH(...) > N
	if m := regexp.MustCompile(`LENGTH\(\((.+?)\)\)\s*=\s*(\d+)`).FindStringSubmatch(id); m != nil {
		n, _ := strconv.Atoi(m[2])
		return len(simulatedVersion) == n
	}
	if m := regexp.MustCompile(`LENGTH\(\((.+?)\)\)\s*>\s*(\d+)`).FindStringSubmatch(id); m != nil {
		n, _ := strconv.Atoi(m[2])
		return len(simulatedVersion) > n
	}

	// Handle ASCII(SUBSTRING(..., pos, 1)) > N
	if m := regexp.MustCompile(`ASCII\(SUBSTRING\(\((.+?)\),(\d+),1\)\)\s*>\s*(\d+)`).FindStringSubmatch(id); m != nil {
		pos, _ := strconv.Atoi(m[2])
		threshold, _ := strconv.Atoi(m[3])
		if pos >= 1 && pos <= len(simulatedVersion) {
			ch := int(simulatedVersion[pos-1])
			return ch > threshold
		}
		return false
	}

	// Default: no condition found; treat as original value → true page
	return true
}

// stripComment removes SQL comment sequences from the end of a string.
func stripComment(s string) string {
	// Remove "-- -", "-- ", or "#" suffix
	if idx := strings.Index(s, "-- "); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "#"); idx != -1 {
		s = s[:idx]
	}
	return s
}

// newTestClient creates a transport.Client backed by the given test server.
func newTestClient(t *testing.T, server *httptest.Server) transport.Client {
	t.Helper()
	client, err := transport.NewClient(transport.ClientOptions{
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("creating transport client: %v", err)
	}
	return client
}

// getBaseline sends a request to the given URL and returns the response as a baseline.
func getBaseline(t *testing.T, client transport.Client, baseURL, path, paramName, paramValue string) *transport.Response {
	t.Helper()
	u, err := url.Parse(baseURL + path)
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}
	q := u.Query()
	q.Set(paramName, paramValue)
	u.RawQuery = q.Encode()

	req := &transport.Request{
		Method: "GET",
		URL:    u.String(),
	}
	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("baseline request: %v", err)
	}
	return resp
}

func TestBooleanBlind_Name(t *testing.T) {
	b := New()
	if got := b.Name(); got != "boolean-blind" {
		t.Errorf("Name() = %q, want %q", got, "boolean-blind")
	}
}

func TestBooleanBlind_Priority(t *testing.T) {
	b := New()
	if got := b.Priority(); got != 2 {
		t.Errorf("Priority() = %d, want %d", got, 2)
	}
}

func TestBooleanBlind_DetectInjectable(t *testing.T) {
	server := newMockServer()
	defer server.Close()

	client := newTestClient(t, server)
	baseline := getBaseline(t, client, server.URL, "/vuln", "id", "1")

	target := &engine.ScanTarget{
		URL:    server.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	b := New()
	result, err := b.Detect(context.Background(), &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		DBMS:      "MySQL",
		Client:    client,
	})
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if !result.Injectable {
		t.Error("Detect() Injectable = false, want true")
	}
	if result.Confidence <= 0 {
		t.Error("Detect() Confidence should be > 0")
	}
	if result.Technique != "boolean-blind" {
		t.Errorf("Detect() Technique = %q, want %q", result.Technique, "boolean-blind")
	}
}

func TestBooleanBlind_DetectNotInjectable(t *testing.T) {
	server := newMockServer()
	defer server.Close()

	client := newTestClient(t, server)
	baseline := getBaseline(t, client, server.URL, "/safe", "id", "1")

	target := &engine.ScanTarget{
		URL:    server.URL + "/safe?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	b := New()
	result, err := b.Detect(context.Background(), &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		DBMS:      "MySQL",
		Client:    client,
	})
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Injectable {
		t.Error("Detect() Injectable = true, want false for safe endpoint")
	}
}

func TestBooleanBlind_DetectStringParam(t *testing.T) {
	// Build a mock server that handles string-type injection with single-quote prefix.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("name")
		id = stripComment(id)
		id = strings.TrimSpace(id)

		// For string parameters, the injected payload will have a quote prefix.
		// e.g., name=alice' AND '1'='1  or  name=alice' AND 1=1 -- -
		if strings.Contains(id, "AND 1=2") || strings.Contains(id, "AND '1'='2") {
			fmt.Fprint(w, "No results.")
			return
		}
		if strings.Contains(id, "AND 1=1") || strings.Contains(id, "AND '1'='1") {
			fmt.Fprint(w, "Welcome! User found.")
			return
		}
		// Default: original value
		fmt.Fprint(w, "Welcome! User found.")
	}))
	defer server.Close()

	client := newTestClient(t, server)
	baseline := getBaseline(t, client, server.URL, "/", "name", "alice")

	target := &engine.ScanTarget{
		URL:    server.URL + "/?name=alice",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "name", Value: "alice", Location: engine.LocationQuery, Type: engine.TypeString},
		},
	}
	param := &target.Parameters[0]

	b := New()
	result, err := b.Detect(context.Background(), &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		DBMS:      "MySQL",
		Client:    client,
	})
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if !result.Injectable {
		t.Error("Detect() Injectable = false, want true for string parameter")
	}
}

func TestBooleanBlind_ExtractVersion(t *testing.T) {
	server := newMockServer()
	defer server.Close()

	client := newTestClient(t, server)
	baseline := getBaseline(t, client, server.URL, "/vuln", "id", "1")

	target := &engine.ScanTarget{
		URL:    server.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	b := New()
	result, err := b.Extract(context.Background(), &technique.ExtractionRequest{
		InjectionRequest: technique.InjectionRequest{
			Target:    target,
			Parameter: param,
			Baseline:  baseline,
			DBMS:      "MySQL",
			Client:    client,
		},
		Query: "@@version",
	})
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if result.Value != simulatedVersion {
		t.Errorf("Extract() Value = %q, want %q", result.Value, simulatedVersion)
	}
	if result.Requests == 0 {
		t.Error("Extract() Requests should be > 0")
	}
}

func TestBooleanBlind_ExtractLength(t *testing.T) {
	server := newMockServer()
	defer server.Close()

	client := newTestClient(t, server)
	baseline := getBaseline(t, client, server.URL, "/vuln", "id", "1")

	target := &engine.ScanTarget{
		URL:    server.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	b := New()
	d := findDBMS("MySQL")
	if d == nil {
		t.Fatal("DBMS registry returned nil for MySQL")
	}

	length, requests, err := b.extractLength(context.Background(), &technique.ExtractionRequest{
		InjectionRequest: technique.InjectionRequest{
			Target:    target,
			Parameter: param,
			Baseline:  baseline,
			DBMS:      "MySQL",
			Client:    client,
		},
		Query: "@@version",
	}, d, "", "-- -")
	if err != nil {
		t.Fatalf("extractLength() error: %v", err)
	}

	expectedLen := len(simulatedVersion) // "8.0.32" = 5
	if length != expectedLen {
		t.Errorf("extractLength() = %d, want %d", length, expectedLen)
	}
	if requests == 0 {
		t.Error("extractLength() requests should be > 0")
	}
}

func TestBooleanBlind_ExtractChar(t *testing.T) {
	server := newMockServer()
	defer server.Close()

	client := newTestClient(t, server)
	baseline := getBaseline(t, client, server.URL, "/vuln", "id", "1")

	target := &engine.ScanTarget{
		URL:    server.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	b := New()
	d := findDBMS("MySQL")
	if d == nil {
		t.Fatal("DBMS registry returned nil for MySQL")
	}

	// Test extracting each character of "8.0.32"
	for i, expected := range simulatedVersion {
		pos := i + 1 // 1-based position
		ch, requests, err := b.extractChar(context.Background(), &technique.ExtractionRequest{
			InjectionRequest: technique.InjectionRequest{
				Target:    target,
				Parameter: param,
				Baseline:  baseline,
				DBMS:      "MySQL",
				Client:    client,
			},
			Query: "@@version",
		}, d, pos, "", "-- -")
		if err != nil {
			t.Fatalf("extractChar(pos=%d) error: %v", pos, err)
		}

		if ch != byte(expected) {
			t.Errorf("extractChar(pos=%d) = %c (%d), want %c (%d)", pos, ch, ch, expected, expected)
		}
		if requests == 0 {
			t.Errorf("extractChar(pos=%d) requests should be > 0", pos)
		}
	}
}
