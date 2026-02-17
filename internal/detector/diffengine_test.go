package detector

import (
	"math"
	"strings"
	"testing"
)

// --- Ratio tests ---

func TestRatio_IdenticalResponses(t *testing.T) {
	engine := NewDiffEngine()
	body := []byte("<html><body><h1>Hello World</h1></body></html>")

	ratio := engine.Ratio(body, body)
	if ratio != 1.0 {
		t.Errorf("Ratio of identical bodies = %f, want 1.0", ratio)
	}
}

func TestRatio_CompletelyDifferent(t *testing.T) {
	engine := NewDiffEngine()
	a := []byte("aaaaaaaaaa")
	b := []byte("bbbbbbbbbb")

	ratio := engine.Ratio(a, b)
	if ratio > 0.2 {
		t.Errorf("Ratio of completely different bodies = %f, want close to 0.0", ratio)
	}
}

func TestRatio_BothEmpty(t *testing.T) {
	engine := NewDiffEngine()
	ratio := engine.Ratio([]byte{}, []byte{})
	if ratio != 1.0 {
		t.Errorf("Ratio of both empty bodies = %f, want 1.0", ratio)
	}
}

func TestRatio_OneEmpty(t *testing.T) {
	engine := NewDiffEngine()
	body := []byte("some content")

	ratio := engine.Ratio(body, []byte{})
	if ratio != 0.0 {
		t.Errorf("Ratio with one empty body = %f, want 0.0", ratio)
	}

	ratio = engine.Ratio([]byte{}, body)
	if ratio != 0.0 {
		t.Errorf("Ratio with one empty body (reversed) = %f, want 0.0", ratio)
	}
}

func TestRatio_MinorDifference(t *testing.T) {
	engine := NewDiffEngine()
	a := []byte(`<html>
<body>
<h1>Search Results</h1>
<p>Found 10 results for your query.</p>
<div class="result">Result 1</div>
<div class="result">Result 2</div>
<div class="result">Result 3</div>
</body>
</html>`)
	b := []byte(`<html>
<body>
<h1>Search Results</h1>
<p>Found 9 results for your query.</p>
<div class="result">Result 1</div>
<div class="result">Result 2</div>
<div class="result">Result 3</div>
</body>
</html>`)

	ratio := engine.Ratio(a, b)
	if ratio < 0.8 {
		t.Errorf("Ratio with minor difference = %f, want > 0.8", ratio)
	}
	if ratio >= 1.0 {
		t.Errorf("Ratio with minor difference = %f, want < 1.0", ratio)
	}
}

func TestRatio_DynamicContentStripping(t *testing.T) {
	engine := NewDiffEngine()
	// Two responses that differ only in session ID and timestamp
	a := []byte(`<html>
<body>
<input type="hidden" name="csrf_token" value="abc123def456">
<p>Session: sess_aaaaaaaaaaaa</p>
<p>Time: 2024-01-15T10:30:00Z</p>
<p>Welcome to the page</p>
</body>
</html>`)
	b := []byte(`<html>
<body>
<input type="hidden" name="csrf_token" value="xyz789ghi012">
<p>Session: sess_bbbbbbbbbbbb</p>
<p>Time: 2024-01-15T10:31:05Z</p>
<p>Welcome to the page</p>
</body>
</html>`)

	ratio := engine.Ratio(a, b)
	if ratio < 0.7 {
		t.Errorf("Ratio with only dynamic content differences = %f, want > 0.7", ratio)
	}
}

func TestRatio_NilInputs(t *testing.T) {
	engine := NewDiffEngine()

	ratio := engine.Ratio(nil, nil)
	if ratio != 1.0 {
		t.Errorf("Ratio of nil, nil = %f, want 1.0", ratio)
	}

	ratio = engine.Ratio(nil, []byte("content"))
	if ratio != 0.0 {
		t.Errorf("Ratio of nil, content = %f, want 0.0", ratio)
	}

	ratio = engine.Ratio([]byte("content"), nil)
	if ratio != 0.0 {
		t.Errorf("Ratio of content, nil = %f, want 0.0", ratio)
	}
}

// --- IsDifferent tests ---

func TestIsDifferent_IdenticalBelowThreshold(t *testing.T) {
	engine := NewDiffEngine()
	body := []byte("same content")

	if engine.IsDifferent(body, body, 0.9) {
		t.Error("identical bodies should not be different at threshold 0.9")
	}
}

func TestIsDifferent_DifferentAboveThreshold(t *testing.T) {
	engine := NewDiffEngine()
	a := []byte("completely different content here")
	b := []byte("nothing in common with the above text")

	if !engine.IsDifferent(a, b, 0.9) {
		t.Error("very different bodies should be detected as different at threshold 0.9")
	}
}

func TestIsDifferent_ThresholdBoundary(t *testing.T) {
	engine := NewDiffEngine()
	// Bodies with moderate similarity
	a := []byte("Hello World! This is a test page.")
	b := []byte("Hello World! This is a different page.")

	ratio := engine.Ratio(a, b)

	// At a threshold lower than the ratio, should NOT be different
	if engine.IsDifferent(a, b, ratio-0.1) {
		t.Errorf("bodies with ratio %f should not be different at threshold %f", ratio, ratio-0.1)
	}

	// At a threshold higher than the ratio, SHOULD be different
	if !engine.IsDifferent(a, b, ratio+0.1) {
		t.Errorf("bodies with ratio %f should be different at threshold %f", ratio, ratio+0.1)
	}
}

// --- DiffDetails tests ---

func TestDiffDetails_StatusCodeChange(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("OK"),
		ContentLength: 2,
	}
	b := &ResponseData{
		StatusCode:    500,
		Headers:       map[string][]string{},
		Body:          []byte("Internal Server Error"),
		ContentLength: 21,
	}

	result := engine.DiffDetails(a, b)
	if !result.StatusCodeChanged {
		t.Error("expected StatusCodeChanged to be true")
	}
}

func TestDiffDetails_StatusCodeSame(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("OK"),
		ContentLength: 2,
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("Also OK"),
		ContentLength: 7,
	}

	result := engine.DiffDetails(a, b)
	if result.StatusCodeChanged {
		t.Error("expected StatusCodeChanged to be false")
	}
}

func TestDiffDetails_ContentLengthDelta(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("short"),
		ContentLength: 5,
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("much longer response body content"),
		ContentLength: 32,
	}

	result := engine.DiffDetails(a, b)
	expectedDelta := int64(32 - 5)
	if result.ContentLengthDelta != expectedDelta {
		t.Errorf("ContentLengthDelta = %d, want %d", result.ContentLengthDelta, expectedDelta)
	}
}

func TestDiffDetails_BodyRatio(t *testing.T) {
	engine := NewDiffEngine()
	body := []byte("same body content")
	a := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          body,
		ContentLength: int64(len(body)),
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          body,
		ContentLength: int64(len(body)),
	}

	result := engine.DiffDetails(a, b)
	if result.BodyRatio != 1.0 {
		t.Errorf("BodyRatio = %f, want 1.0", result.BodyRatio)
	}
}

func TestDiffDetails_HeaderDiffs(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Type": {"text/html"},
			"X-Custom":     {"value1"},
		},
		Body:          []byte("body"),
		ContentLength: 4,
	}
	b := &ResponseData{
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Type": {"text/html"},
			"X-Custom":     {"value2"},
		},
		Body:          []byte("body"),
		ContentLength: 4,
	}

	result := engine.DiffDetails(a, b)
	if len(result.HeaderDiffs) == 0 {
		t.Fatal("expected header diffs to be detected")
	}
	diff, ok := result.HeaderDiffs["X-Custom"]
	if !ok {
		t.Fatal("expected X-Custom header diff")
	}
	if diff[0] != "value1" || diff[1] != "value2" {
		t.Errorf("X-Custom diff = %v, want [value1, value2]", diff)
	}
}

func TestDiffDetails_HeaderDiffs_NoChange(t *testing.T) {
	engine := NewDiffEngine()
	headers := map[string][]string{
		"Content-Type": {"text/html"},
		"X-Custom":     {"same-value"},
	}
	a := &ResponseData{
		StatusCode:    200,
		Headers:       headers,
		Body:          []byte("body"),
		ContentLength: 4,
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       headers,
		Body:          []byte("body"),
		ContentLength: 4,
	}

	result := engine.DiffDetails(a, b)
	if len(result.HeaderDiffs) != 0 {
		t.Errorf("expected no header diffs, got %v", result.HeaderDiffs)
	}
}

func TestDiffDetails_SQLErrorKeywords(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("<html><body>Normal page content</body></html>"),
		ContentLength: 44,
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("<html><body>You have an error in your SQL syntax; check the manual</body></html>"),
		ContentLength: 79,
	}

	result := engine.DiffDetails(a, b)
	if len(result.KeywordMatches) == 0 {
		t.Error("expected SQL error keywords to be detected")
	}

	found := false
	for _, kw := range result.KeywordMatches {
		if strings.Contains(kw, "MySQL") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MySQL keyword match, got %v", result.KeywordMatches)
	}
}

func TestDiffDetails_NoSQLErrors(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("Normal content"),
		ContentLength: 14,
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("Also normal content"),
		ContentLength: 19,
	}

	result := engine.DiffDetails(a, b)
	if len(result.KeywordMatches) != 0 {
		t.Errorf("expected no keyword matches, got %v", result.KeywordMatches)
	}
}

// --- NewDiffEngine tests ---

func TestNewDiffEngine_HasDefaultPatterns(t *testing.T) {
	engine := NewDiffEngine()
	if len(engine.DynamicPatterns) == 0 {
		t.Error("expected NewDiffEngine to have default dynamic patterns")
	}
}

// --- Large response performance test ---

func TestRatio_LargeResponse(t *testing.T) {
	engine := NewDiffEngine()

	// Generate a large response (~100KB)
	var builder strings.Builder
	for i := 0; i < 1000; i++ {
		builder.WriteString("<div class=\"item\">Item number ")
		builder.WriteString(strings.Repeat("x", 100))
		builder.WriteString("</div>\n")
	}
	baseBody := builder.String()
	a := []byte(baseBody)

	// Create slightly modified version
	b := []byte(strings.Replace(baseBody, "Item number", "Item count", 1))

	ratio := engine.Ratio(a, b)
	if ratio < 0.9 {
		t.Errorf("Ratio of large bodies with small difference = %f, want > 0.9", ratio)
	}
}

// --- Edge case tests ---

func TestRatio_SingleCharacterDiff(t *testing.T) {
	engine := NewDiffEngine()
	a := []byte("a")
	b := []byte("b")

	ratio := engine.Ratio(a, b)
	if ratio < 0.0 || ratio > 1.0 {
		t.Errorf("Ratio should be between 0.0 and 1.0, got %f", ratio)
	}
}

func TestRatio_ReturnsBetweenZeroAndOne(t *testing.T) {
	engine := NewDiffEngine()
	testCases := []struct {
		name string
		a    []byte
		b    []byte
	}{
		{"identical", []byte("same"), []byte("same")},
		{"different", []byte("aaa"), []byte("bbb")},
		{"partial", []byte("hello world"), []byte("hello earth")},
		{"empty-empty", []byte{}, []byte{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ratio := engine.Ratio(tc.a, tc.b)
			if ratio < 0.0 || ratio > 1.0 {
				t.Errorf("Ratio(%q, %q) = %f, want between 0.0 and 1.0", tc.a, tc.b, ratio)
			}
		})
	}
}

func TestRatio_Symmetry(t *testing.T) {
	engine := NewDiffEngine()
	a := []byte("hello world test content")
	b := []byte("hello earth different content")

	ratioAB := engine.Ratio(a, b)
	ratioBA := engine.Ratio(b, a)

	if math.Abs(ratioAB-ratioBA) > 0.001 {
		t.Errorf("Ratio should be symmetric: Ratio(a,b)=%f, Ratio(b,a)=%f", ratioAB, ratioBA)
	}
}

func TestDiffDetails_NilResponseData(t *testing.T) {
	engine := NewDiffEngine()

	// Both nil should not panic
	result := engine.DiffDetails(nil, nil)
	if result == nil {
		t.Error("DiffDetails should return a non-nil result even with nil inputs")
	}
}

func TestDiffDetails_HeaderMissingInOne(t *testing.T) {
	engine := NewDiffEngine()
	a := &ResponseData{
		StatusCode: 200,
		Headers: map[string][]string{
			"X-Custom": {"value1"},
		},
		Body:          []byte("body"),
		ContentLength: 4,
	}
	b := &ResponseData{
		StatusCode:    200,
		Headers:       map[string][]string{},
		Body:          []byte("body"),
		ContentLength: 4,
	}

	result := engine.DiffDetails(a, b)
	if len(result.HeaderDiffs) == 0 {
		t.Error("expected header diff when header is missing in one response")
	}
	diff, ok := result.HeaderDiffs["X-Custom"]
	if !ok {
		t.Fatal("expected X-Custom to be in HeaderDiffs")
	}
	if diff[0] != "value1" || diff[1] != "" {
		t.Errorf("expected diff [value1, ''], got %v", diff)
	}
}
