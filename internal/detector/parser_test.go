package detector

import (
	"testing"

	"github.com/0x6d61/sqleech/internal/engine"
)

// --- InferType tests ---

func TestInferType_Integer(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"1"},
		{"42"},
		{"-3"},
		{"0"},
		{"999999"},
		{"-0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := InferType(tt.input)
			if got != engine.TypeInteger {
				t.Errorf("InferType(%q) = %d, want TypeInteger (%d)", tt.input, got, engine.TypeInteger)
			}
		})
	}
}

func TestInferType_Float(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"1.5"},
		{"-3.14"},
		{"0.0"},
		{"100.001"},
		{"-0.5"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := InferType(tt.input)
			if got != engine.TypeFloat {
				t.Errorf("InferType(%q) = %d, want TypeFloat (%d)", tt.input, got, engine.TypeFloat)
			}
		})
	}
}

func TestInferType_String(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"hello"},
		{"1abc"},
		{""},
		{"abc123"},
		{"1.2.3"},
		{"--1"},
		{"1."},
		{".5"},
		{"hello world"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := InferType(tt.input)
			if got != engine.TypeString {
				t.Errorf("InferType(%q) = %d, want TypeString (%d)", tt.input, got, engine.TypeString)
			}
		})
	}
}

// --- ParseURLParameters tests ---

func TestParseURLParameters_Simple(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?id=1&name=test")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationQuery, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationQuery, engine.TypeString)
}

func TestParseURLParameters_NoParams(t *testing.T) {
	params := ParseURLParameters("http://example.com/page")
	if len(params) != 0 {
		t.Fatalf("expected 0 params, got %d", len(params))
	}
}

func TestParseURLParameters_EmptyValues(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?id=&name=")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "", engine.LocationQuery, engine.TypeString)
	assertParam(t, params, "name", "", engine.LocationQuery, engine.TypeString)
}

func TestParseURLParameters_NoValue(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?id")
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	assertParam(t, params, "id", "", engine.LocationQuery, engine.TypeString)
}

func TestParseURLParameters_URLEncodedPlus(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?q=hello+world")
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	assertParam(t, params, "q", "hello world", engine.LocationQuery, engine.TypeString)
}

func TestParseURLParameters_URLEncodedPercent(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?q=hello%20world")
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	assertParam(t, params, "q", "hello world", engine.LocationQuery, engine.TypeString)
}

func TestParseURLParameters_MultipleValuesSameName(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?id=1&id=2")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	// Both should be present with name "id"
	count := 0
	for _, p := range params {
		if p.Name == "id" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 params named 'id', got %d", count)
	}
	// Check values
	values := map[string]bool{}
	for _, p := range params {
		if p.Name == "id" {
			values[p.Value] = true
		}
	}
	if !values["1"] || !values["2"] {
		t.Errorf("expected values '1' and '2', got %v", values)
	}
}

func TestParseURLParameters_WithFragment(t *testing.T) {
	params := ParseURLParameters("http://example.com/page?id=1#section")
	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationQuery, engine.TypeInteger)
}

// --- ParseBodyParameters tests ---

func TestParseBodyParameters_FormURLEncoded(t *testing.T) {
	params := ParseBodyParameters("id=1&name=test", "application/x-www-form-urlencoded")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationBody, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationBody, engine.TypeString)
}

func TestParseBodyParameters_ComplexBody(t *testing.T) {
	params := ParseBodyParameters("user=admin&pass=test%40123&role=user", "application/x-www-form-urlencoded")
	if len(params) != 3 {
		t.Fatalf("expected 3 params, got %d", len(params))
	}
	assertParam(t, params, "user", "admin", engine.LocationBody, engine.TypeString)
	assertParam(t, params, "pass", "test@123", engine.LocationBody, engine.TypeString)
	assertParam(t, params, "role", "user", engine.LocationBody, engine.TypeString)
}

func TestParseBodyParameters_EmptyBody(t *testing.T) {
	params := ParseBodyParameters("", "application/x-www-form-urlencoded")
	if len(params) != 0 {
		t.Fatalf("expected 0 params, got %d", len(params))
	}
}

func TestParseBodyParameters_EmptyContentType(t *testing.T) {
	// When content type is empty, should still attempt form parsing
	params := ParseBodyParameters("id=1&name=test", "")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationBody, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationBody, engine.TypeString)
}

func TestParseBodyParameters_UnsupportedContentType(t *testing.T) {
	// JSON and other types are not yet supported; should return empty
	params := ParseBodyParameters(`{"id": 1}`, "application/json")
	if len(params) != 0 {
		t.Fatalf("expected 0 params for unsupported content type, got %d", len(params))
	}
}

func TestParseBodyParameters_ContentTypeWithCharset(t *testing.T) {
	params := ParseBodyParameters("id=1&name=test", "application/x-www-form-urlencoded; charset=utf-8")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationBody, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationBody, engine.TypeString)
}

// --- ParseParameters tests (combined) ---

func TestParseParameters_QueryOnly(t *testing.T) {
	params := ParseParameters("http://example.com/page?id=1&name=test", "", "")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationQuery, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationQuery, engine.TypeString)
}

func TestParseParameters_BodyOnly(t *testing.T) {
	params := ParseParameters("http://example.com/page", "id=1&name=test", "application/x-www-form-urlencoded")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationBody, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationBody, engine.TypeString)
}

func TestParseParameters_MixedQueryAndBody(t *testing.T) {
	params := ParseParameters(
		"http://example.com/page?id=1",
		"name=test",
		"application/x-www-form-urlencoded",
	)
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	assertParam(t, params, "id", "1", engine.LocationQuery, engine.TypeInteger)
	assertParam(t, params, "name", "test", engine.LocationBody, engine.TypeString)
}

func TestParseParameters_NoParams(t *testing.T) {
	params := ParseParameters("http://example.com/page", "", "")
	if len(params) != 0 {
		t.Fatalf("expected 0 params, got %d", len(params))
	}
}

func TestParseParameters_AllTypes(t *testing.T) {
	params := ParseParameters(
		"http://example.com/page?int=42&float=3.14&str=hello",
		"",
		"",
	)
	if len(params) != 3 {
		t.Fatalf("expected 3 params, got %d", len(params))
	}
	assertParam(t, params, "int", "42", engine.LocationQuery, engine.TypeInteger)
	assertParam(t, params, "float", "3.14", engine.LocationQuery, engine.TypeFloat)
	assertParam(t, params, "str", "hello", engine.LocationQuery, engine.TypeString)
}

// --- Test helper ---

func assertParam(t *testing.T, params []engine.Parameter, name, value string, location engine.ParameterLocation, ptype engine.ParameterType) {
	t.Helper()
	for _, p := range params {
		if p.Name == name && p.Value == value {
			if p.Location != location {
				t.Errorf("param %q: location = %v, want %v", name, p.Location, location)
			}
			if p.Type != ptype {
				t.Errorf("param %q: type = %d, want %d", name, p.Type, ptype)
			}
			return
		}
	}
	t.Errorf("param Name=%q Value=%q not found in %+v", name, value, params)
}
