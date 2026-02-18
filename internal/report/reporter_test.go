package report

import (
	"testing"
)

func TestNew_Text(t *testing.T) {
	r, err := New("text")
	if err != nil {
		t.Fatalf("New(\"text\") returned error: %v", err)
	}
	if r == nil {
		t.Fatal("New(\"text\") returned nil reporter")
	}
	if _, ok := r.(*TextReporter); !ok {
		t.Errorf("New(\"text\") returned %T, want *TextReporter", r)
	}
	if r.Format() != "text" {
		t.Errorf("Format() = %q, want %q", r.Format(), "text")
	}
}

func TestNew_JSON(t *testing.T) {
	r, err := New("json")
	if err != nil {
		t.Fatalf("New(\"json\") returned error: %v", err)
	}
	if r == nil {
		t.Fatal("New(\"json\") returned nil reporter")
	}
	if _, ok := r.(*JSONReporter); !ok {
		t.Errorf("New(\"json\") returned %T, want *JSONReporter", r)
	}
	if r.Format() != "json" {
		t.Errorf("Format() = %q, want %q", r.Format(), "json")
	}
}

func TestNew_Invalid(t *testing.T) {
	r, err := New("xml")
	if err == nil {
		t.Fatal("New(\"xml\") should return error for unsupported format")
	}
	if r != nil {
		t.Errorf("New(\"xml\") returned non-nil reporter: %v", r)
	}
}

func TestNew_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input      string
		wantFormat string
	}{
		{"TEXT", "text"},
		{"Text", "text"},
		{"JSON", "json"},
		{"Json", "json"},
	}
	for _, tt := range tests {
		r, err := New(tt.input)
		if err != nil {
			t.Errorf("New(%q) returned error: %v", tt.input, err)
			continue
		}
		if r.Format() != tt.wantFormat {
			t.Errorf("New(%q).Format() = %q, want %q", tt.input, r.Format(), tt.wantFormat)
		}
	}
}
