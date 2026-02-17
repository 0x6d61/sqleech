package engine

import (
	"testing"
)

func TestParameterLocationString(t *testing.T) {
	tests := []struct {
		loc  ParameterLocation
		want string
	}{
		{LocationQuery, "query"},
		{LocationBody, "body"},
		{LocationHeader, "header"},
		{LocationCookie, "cookie"},
		{LocationJSON, "json"},
	}
	for _, tt := range tests {
		if got := tt.loc.String(); got != tt.want {
			t.Errorf("ParameterLocation(%d).String() = %q, want %q", tt.loc, got, tt.want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestScanTargetDefaults(t *testing.T) {
	target := ScanTarget{
		URL:    "http://example.com/page?id=1",
		Method: "GET",
	}
	if target.URL != "http://example.com/page?id=1" {
		t.Error("URL not set correctly")
	}
	if target.Method != "GET" {
		t.Error("Method not set correctly")
	}
}
