package timebased

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --------------------------------------------------------------------------
// Mock transport client
// --------------------------------------------------------------------------

// mockTimeClient simulates time-based injection by adding artificial delays
// when a sleep-triggering payload is detected in the request URL or body.
// This avoids real network calls and keeps unit tests fast.
type mockTimeClient struct {
	// simulatedDelay is the artificial delay added for sleep payloads.
	simulatedDelay time.Duration
	// requests counts total requests sent.
	requests int64
}

// containsSleepPayload returns true when the request carries a payload that
// should trigger a database sleep (TRUE condition with SLEEP/PG_SLEEP).
//
// The input may be URL-encoded, so it is decoded before matching.
func containsSleepPayload(s string) bool {
	// URL-decode to handle query-parameter encoding (SLEEP%28 → SLEEP().
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		decoded = s
	}
	upper := strings.ToUpper(decoded)

	// MySQL: IF(1=1,SLEEP(n),0)
	// PostgreSQL: CASE WHEN (1=1) THEN (SELECT 1 FROM PG_SLEEP(n))
	//
	// We detect the TRUE-condition variants (contains "1=1" with sleep call).
	// False-condition variants contain "1=2" and must NOT be delayed.
	hasSleep := strings.Contains(upper, "SLEEP(") || strings.Contains(upper, "PG_SLEEP(")
	isTrueCondition := strings.Contains(upper, "1=1")
	isFalseCondition := strings.Contains(upper, "1=2")

	return hasSleep && isTrueCondition && !isFalseCondition
}

func (c *mockTimeClient) Do(ctx context.Context, req *transport.Request) (*transport.Response, error) {
	start := time.Now()

	if containsSleepPayload(req.URL + req.Body) {
		select {
		case <-time.After(c.simulatedDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	duration := time.Since(start)
	c.requests++

	return &transport.Response{
		StatusCode: 200,
		Body:       []byte("<html><body><p>Product: Widget</p></body></html>"),
		Duration:   duration,
	}, nil
}

func (c *mockTimeClient) SetProxy(_ string) error { return nil }
func (c *mockTimeClient) SetRateLimit(_ float64)  {}
func (c *mockTimeClient) Stats() *transport.TransportStats {
	return &transport.TransportStats{TotalRequests: c.requests}
}

// mockInjectionRequest builds a minimal InjectionRequest for testing.
func mockInjectionRequest(client transport.Client) *technique.InjectionRequest {
	baseline := &transport.Response{
		StatusCode: 200,
		Body:       []byte("<html><body><p>Product: Widget</p></body></html>"),
		Duration:   2 * time.Millisecond,
	}
	return &technique.InjectionRequest{
		Target: &engine.ScanTarget{
			URL:    "http://example.test/vuln?id=1",
			Method: "GET",
		},
		Parameter: &engine.Parameter{
			Name:     "id",
			Value:    "1",
			Location: engine.LocationQuery,
			Type:     engine.TypeInteger,
		},
		Baseline: baseline,
		DBMS:     "MySQL",
		Client:   client,
	}
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

func TestTimeBased_Name(t *testing.T) {
	tech := New()
	if tech.Name() != "time-based" {
		t.Errorf("Name() = %q, want 'time-based'", tech.Name())
	}
}

func TestTimeBased_Priority(t *testing.T) {
	tech := New()
	if tech.Priority() != 3 {
		t.Errorf("Priority() = %d, want 3", tech.Priority())
	}
}

func TestTimeBased_Detect_Injectable_MySQL(t *testing.T) {
	// Use 1s sleep with 0.3 tolerance → threshold ≈ 300ms.
	// Mock client delays 500ms for sleep payloads → 500ms > 300ms → detected.
	tech := NewWithConfig(1, 0.3)
	client := &mockTimeClient{simulatedDelay: 500 * time.Millisecond}

	req := mockInjectionRequest(client)
	req.DBMS = "MySQL"

	ctx := context.Background()
	result, err := tech.Detect(ctx, req)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if !result.Injectable {
		t.Error("expected Injectable=true for time-delayed endpoint")
	}
	if result.Technique != "time-based" {
		t.Errorf("Technique = %q, want 'time-based'", result.Technique)
	}
	if result.Confidence == 0 {
		t.Error("expected non-zero Confidence")
	}
	if result.Evidence == "" {
		t.Error("expected non-empty Evidence")
	}
	if result.Payload == nil {
		t.Error("expected non-nil Payload")
	}
	t.Logf("evidence: %s", result.Evidence)
}

func TestTimeBased_Detect_Injectable_PostgreSQL(t *testing.T) {
	tech := NewWithConfig(1, 0.3)
	client := &mockTimeClient{simulatedDelay: 500 * time.Millisecond}

	req := mockInjectionRequest(client)
	req.DBMS = "PostgreSQL"

	ctx := context.Background()
	result, err := tech.Detect(ctx, req)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if !result.Injectable {
		t.Error("expected Injectable=true for PostgreSQL time-delayed endpoint")
	}
	t.Logf("payload: %v, evidence: %s", result.Payload, result.Evidence)
}

func TestTimeBased_Detect_Safe(t *testing.T) {
	// Mock client that never delays — simulates a non-injectable endpoint.
	tech := NewWithConfig(1, 0.3)
	client := &mockTimeClient{simulatedDelay: 0}

	req := mockInjectionRequest(client)

	ctx := context.Background()
	result, err := tech.Detect(ctx, req)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if result.Injectable {
		t.Error("expected Injectable=false for non-delaying endpoint")
	}
}

func TestTimeBased_Detect_ContextCancellation(t *testing.T) {
	tech := NewWithConfig(5, 0.7)
	// Use a long delay so the test is driven by context cancellation.
	client := &mockTimeClient{simulatedDelay: 10 * time.Second}

	req := mockInjectionRequest(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	_, err := tech.Detect(ctx, req)
	elapsed := time.Since(start)

	// Should return quickly, not wait for the sleep.
	if elapsed > 3*time.Second {
		t.Errorf("cancelled Detect took too long: %v", elapsed)
	}
	_ = err // error or nil is acceptable after cancellation
}

func TestTimeBased_SleepPayloadFor_MySQL(t *testing.T) {
	d := findDBMS("MySQL")
	payload := sleepPayloadFor(d, "1=1", 5)
	if !strings.Contains(payload, "IF(") {
		t.Errorf("MySQL sleep payload missing IF(): %s", payload)
	}
	if !strings.Contains(strings.ToUpper(payload), "SLEEP(5)") {
		t.Errorf("MySQL sleep payload missing SLEEP(5): %s", payload)
	}
}

func TestTimeBased_SleepPayloadFor_PostgreSQL(t *testing.T) {
	d := findDBMS("PostgreSQL")
	payload := sleepPayloadFor(d, "1=1", 5)
	if !strings.Contains(strings.ToUpper(payload), "PG_SLEEP(5)") {
		t.Errorf("PostgreSQL sleep payload missing PG_SLEEP(5): %s", payload)
	}
	if !strings.Contains(strings.ToUpper(payload), "CASE WHEN") {
		t.Errorf("PostgreSQL sleep payload missing CASE WHEN: %s", payload)
	}
}

func TestTimeBased_SleepPayloadFor_FalseCondition_MySQL(t *testing.T) {
	d := findDBMS("MySQL")
	payload := sleepPayloadFor(d, "1=2", 5)
	// False condition: IF(1=2, SLEEP(5), 0) → should not trigger in mock
	if !strings.Contains(payload, "1=2") {
		t.Errorf("false-condition payload missing '1=2': %s", payload)
	}
}
