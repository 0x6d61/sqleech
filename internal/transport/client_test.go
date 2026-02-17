package transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper: create a default test client
// ---------------------------------------------------------------------------

func newTestClient(t *testing.T) *DefaultClient {
	t.Helper()
	c, err := NewClient(ClientOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// ---------------------------------------------------------------------------
// Basic GET
// ---------------------------------------------------------------------------

func TestBasicGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()

	c := newTestClient(t)
	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL + "/test",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.BodyString() != "hello world" {
		t.Errorf("Body = %q, want %q", resp.BodyString(), "hello world")
	}
}

// ---------------------------------------------------------------------------
// POST with body
// ---------------------------------------------------------------------------

func TestPOSTWithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t)
	resp, err := c.Do(context.Background(), &Request{
		Method:      "POST",
		URL:         srv.URL + "/submit",
		Body:        `{"key":"value"}`,
		ContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.BodyString() != `{"key":"value"}` {
		t.Errorf("Body = %q", resp.BodyString())
	}
}

// ---------------------------------------------------------------------------
// Custom headers and cookies
// ---------------------------------------------------------------------------

func TestCustomHeadersAndCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check custom header
		if got := r.Header.Get("X-Custom"); got != "test-value" {
			t.Errorf("X-Custom header = %q, want %q", got, "test-value")
		}
		// Check cookie
		cookie, err := r.Cookie("session")
		if err != nil {
			t.Errorf("cookie 'session' not found: %v", err)
		} else if cookie.Value != "abc123" {
			t.Errorf("session cookie = %q, want %q", cookie.Value, "abc123")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	_, err := c.Do(context.Background(), &Request{
		Method:  "GET",
		URL:     srv.URL,
		Headers: map[string]string{"X-Custom": "test-value"},
		Cookies: map[string]string{"session": "abc123"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Response timing measurement
// ---------------------------------------------------------------------------

func TestResponseTimingMeasurement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", resp.Duration)
	}
	if resp.Duration < 40*time.Millisecond {
		t.Errorf("Duration = %v, expected at least ~50ms", resp.Duration)
	}
}

// ---------------------------------------------------------------------------
// Redirect following
// ---------------------------------------------------------------------------

func TestRedirectFollowing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "final page")
	}))
	defer srv.Close()

	// Follow redirects
	c, _ := NewClient(ClientOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: true,
	})
	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL + "/redirect",
	})
	if err != nil {
		t.Fatalf("Do (follow): %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("follow: StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.BodyString() != "final page" {
		t.Errorf("follow: Body = %q, want %q", resp.BodyString(), "final page")
	}
	if !strings.HasSuffix(resp.URL, "/final") {
		t.Errorf("follow: URL = %q, want suffix /final", resp.URL)
	}
}

func TestRedirectNotFollowing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "final page")
	}))
	defer srv.Close()

	// Do NOT follow redirects
	c, _ := NewClient(ClientOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: false,
	})
	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL + "/redirect",
	})
	if err != nil {
		t.Fatalf("Do (no-follow): %v", err)
	}
	if resp.StatusCode != 302 {
		t.Errorf("no-follow: StatusCode = %d, want 302", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Per-request redirect override
// ---------------------------------------------------------------------------

func TestPerRequestRedirectOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "final page")
	}))
	defer srv.Close()

	// Client follows redirects, but per-request says no.
	c, _ := NewClient(ClientOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: true,
	})
	noFollow := false
	resp, err := c.Do(context.Background(), &Request{
		Method:          "GET",
		URL:             srv.URL + "/redirect",
		FollowRedirects: &noFollow,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Errorf("StatusCode = %d, want 302", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Proxy configuration (test setting, not actual proxy)
// ---------------------------------------------------------------------------

func TestSetProxy(t *testing.T) {
	c := newTestClient(t)
	err := c.SetProxy("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	// Setting an invalid URL should error.
	err = c.SetProxy("://bad-url")
	if err == nil {
		t.Error("SetProxy with invalid URL should return error")
	}
}

// ---------------------------------------------------------------------------
// Status code handling
// ---------------------------------------------------------------------------

func TestStatusCodeHandling(t *testing.T) {
	codes := []int{200, 302, 403, 404, 500}
	for _, code := range codes {
		code := code
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()

			c, _ := NewClient(ClientOptions{
				Timeout:         5 * time.Second,
				FollowRedirects: false, // don't follow 302
			})
			resp, err := c.Do(context.Background(), &Request{
				Method: "GET",
				URL:    srv.URL,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if resp.StatusCode != code {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Timeout handling
// ---------------------------------------------------------------------------

func TestTimeoutHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewClient(ClientOptions{
		Timeout: 100 * time.Millisecond,
	})
	_, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Per-request timeout override
// ---------------------------------------------------------------------------

func TestPerRequestTimeoutOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Client has 5s timeout, but per-request overrides to 100ms.
	c, _ := NewClient(ClientOptions{
		Timeout: 5 * time.Second,
	})
	_, err := c.Do(context.Background(), &Request{
		Method:  "GET",
		URL:     srv.URL,
		Timeout: 100 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected timeout error from per-request override, got nil")
	}
}

// ---------------------------------------------------------------------------
// Stats tracking
// ---------------------------------------------------------------------------

func TestStatsTracking(t *testing.T) {
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	for i := 0; i < 5; i++ {
		_, err := c.Do(context.Background(), &Request{
			Method: "GET",
			URL:    srv.URL,
		})
		if err != nil {
			t.Fatalf("Do #%d: %v", i, err)
		}
	}

	stats := c.Stats()
	if stats.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", stats.TotalRequests)
	}
	if stats.AvgDuration <= 0 {
		t.Errorf("AvgDuration = %v, want > 0", stats.AvgDuration)
	}
	if stats.TotalDuration <= 0 {
		t.Errorf("TotalDuration = %v, want > 0", stats.TotalDuration)
	}
}

// ---------------------------------------------------------------------------
// TLS InsecureSkipVerify option
// ---------------------------------------------------------------------------

func TestTLSInsecureSkipVerifyOption(t *testing.T) {
	// Just verify that the option can be set without error.
	c, err := NewClient(ClientOptions{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewClient with InsecureSkipVerify: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
}

// ---------------------------------------------------------------------------
// TLS InsecureSkipVerify actually works with self-signed cert
// ---------------------------------------------------------------------------

func TestTLSInsecureSkipVerifyWithHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure")
	}))
	defer srv.Close()

	// Without InsecureSkipVerify, connection to self-signed cert should fail
	cStrict, _ := NewClient(ClientOptions{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: false,
	})
	_, err := cStrict.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err == nil {
		t.Error("expected TLS error with strict verification, got nil")
	}

	// With InsecureSkipVerify, it should succeed
	cInsecure, _ := NewClient(ClientOptions{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
	})
	resp, err := cInsecure.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("Do with InsecureSkipVerify: %v", err)
	}
	if resp.BodyString() != "secure" {
		t.Errorf("Body = %q, want %q", resp.BodyString(), "secure")
	}
}

// ---------------------------------------------------------------------------
// Request Clone
// ---------------------------------------------------------------------------

func TestRequestClone(t *testing.T) {
	orig := &Request{
		Method:      "POST",
		URL:         "http://example.com/test",
		Headers:     map[string]string{"X-Foo": "bar"},
		Body:        "original body",
		ContentType: "text/plain",
		Cookies:     map[string]string{"session": "abc"},
		Timeout:     3 * time.Second,
	}

	clone := orig.Clone()

	// Verify values match
	if clone.Method != orig.Method {
		t.Errorf("clone.Method = %q, want %q", clone.Method, orig.Method)
	}
	if clone.URL != orig.URL {
		t.Errorf("clone.URL = %q, want %q", clone.URL, orig.URL)
	}
	if clone.Body != orig.Body {
		t.Errorf("clone.Body = %q, want %q", clone.Body, orig.Body)
	}
	if clone.ContentType != orig.ContentType {
		t.Errorf("clone.ContentType = %q, want %q", clone.ContentType, orig.ContentType)
	}
	if clone.Timeout != orig.Timeout {
		t.Errorf("clone.Timeout = %v, want %v", clone.Timeout, orig.Timeout)
	}

	// Verify deep copy: mutating clone's maps should not affect original
	clone.Headers["X-Foo"] = "changed"
	if orig.Headers["X-Foo"] != "bar" {
		t.Error("modifying clone.Headers affected original")
	}

	clone.Cookies["session"] = "changed"
	if orig.Cookies["session"] != "abc" {
		t.Error("modifying clone.Cookies affected original")
	}
}

func TestRequestCloneNilMaps(t *testing.T) {
	orig := &Request{
		Method: "GET",
		URL:    "http://example.com",
	}
	clone := orig.Clone()
	if clone.Headers != nil {
		t.Error("clone.Headers should be nil when original is nil")
	}
	if clone.Cookies != nil {
		t.Error("clone.Cookies should be nil when original is nil")
	}
}

func TestRequestCloneFollowRedirects(t *testing.T) {
	val := true
	orig := &Request{
		Method:          "GET",
		URL:             "http://example.com",
		FollowRedirects: &val,
	}
	clone := orig.Clone()
	if clone.FollowRedirects == nil {
		t.Fatal("clone.FollowRedirects should not be nil")
	}
	if *clone.FollowRedirects != true {
		t.Error("clone.FollowRedirects value mismatch")
	}
	// Verify deep copy of the pointer
	*clone.FollowRedirects = false
	if *orig.FollowRedirects != true {
		t.Error("modifying clone.FollowRedirects affected original")
	}
}

// ---------------------------------------------------------------------------
// Random User-Agent header
// ---------------------------------------------------------------------------

func TestRandomUserAgentHeader(t *testing.T) {
	var receivedUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewClient(ClientOptions{
		Timeout:        5 * time.Second,
		RandomUserAgent: true,
	})
	_, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if receivedUA == "" {
		t.Error("User-Agent header was empty")
	}
	// It should not be Go's default User-Agent
	if strings.HasPrefix(receivedUA, "Go-http-client") {
		t.Errorf("User-Agent = %q, should be randomized", receivedUA)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func TestSetRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	c.SetRateLimit(10) // 10 RPS

	start := time.Now()
	for i := 0; i < 5; i++ {
		_, err := c.Do(context.Background(), &Request{
			Method: "GET",
			URL:    srv.URL,
		})
		if err != nil {
			t.Fatalf("Do #%d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// At 10 RPS, 5 requests should take at least ~400ms (first is immediate, then 4 waits of ~100ms).
	// We use a conservative threshold.
	if elapsed < 300*time.Millisecond {
		t.Errorf("5 requests at 10 RPS took %v, expected at least ~400ms", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := c.Do(ctx, &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err == nil {
		t.Error("expected context cancellation error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Client interface satisfaction
// ---------------------------------------------------------------------------

func TestClientInterfaceSatisfaction(t *testing.T) {
	var _ Client = (*DefaultClient)(nil)
}

// ---------------------------------------------------------------------------
// Content-Type header set for POST
// ---------------------------------------------------------------------------

func TestContentTypeHeader(t *testing.T) {
	var receivedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	_, err := c.Do(context.Background(), &Request{
		Method:      "POST",
		URL:         srv.URL,
		Body:        "data",
		ContentType: "application/x-www-form-urlencoded",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if receivedCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want %q", receivedCT, "application/x-www-form-urlencoded")
	}
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

func TestResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Server", "sqleech-test")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t)
	resp, err := c.Do(context.Background(), &Request{
		Method: "GET",
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := resp.Headers.Get("X-Server"); got != "sqleech-test" {
		t.Errorf("X-Server header = %q, want %q", got, "sqleech-test")
	}
}
