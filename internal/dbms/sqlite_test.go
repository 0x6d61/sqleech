package dbms

import (
	"strings"
	"testing"
)

func TestSQLite_Name(t *testing.T) {
	s := &SQLite{}
	if s.Name() != "SQLite" {
		t.Errorf("Name() = %q, want 'SQLite'", s.Name())
	}
}

func TestSQLite_Concatenate(t *testing.T) {
	s := &SQLite{}
	got := s.Concatenate("a", "b", "c")
	if got != "a||b||c" {
		t.Errorf("Concatenate() = %q, want 'a||b||c'", got)
	}
}

func TestSQLite_Substring(t *testing.T) {
	s := &SQLite{}
	got := s.Substring("col", 1, 5)
	if got != "substr(col,1,5)" {
		t.Errorf("Substring() = %q, want 'substr(col,1,5)'", got)
	}
}

func TestSQLite_Length(t *testing.T) {
	s := &SQLite{}
	got := s.Length("col")
	if got != "length(col)" {
		t.Errorf("Length() = %q, want 'length(col)'", got)
	}
}

func TestSQLite_ASCII(t *testing.T) {
	s := &SQLite{}
	got := s.ASCII("col")
	if got != "unicode(col)" {
		t.Errorf("ASCII() = %q, want 'unicode(col)'", got)
	}
}

func TestSQLite_Char(t *testing.T) {
	s := &SQLite{}
	got := s.Char(65)
	if got != "char(65)" {
		t.Errorf("Char() = %q, want 'char(65)'", got)
	}
}

func TestSQLite_CommentSequence(t *testing.T) {
	s := &SQLite{}
	if s.CommentSequence() != "-- " {
		t.Errorf("CommentSequence() = %q, want '-- '", s.CommentSequence())
	}
}

func TestSQLite_QuoteString(t *testing.T) {
	s := &SQLite{}
	got := s.QuoteString("O'Brien")
	want := "'O''Brien'"
	if got != want {
		t.Errorf("QuoteString() = %q, want %q", got, want)
	}
}

func TestSQLite_IfThenElse(t *testing.T) {
	s := &SQLite{}
	got := s.IfThenElse("1=1", "'a'", "'b'")
	want := "CASE WHEN 1=1 THEN 'a' ELSE 'b' END"
	if got != want {
		t.Errorf("IfThenElse() = %q, want %q", got, want)
	}
}

func TestSQLite_VersionQuery(t *testing.T) {
	s := &SQLite{}
	if s.VersionQuery() == "" {
		t.Error("VersionQuery() returned empty string")
	}
}

func TestSQLite_ErrorPayloads(t *testing.T) {
	s := &SQLite{}
	payloads := s.ErrorPayloads()
	if len(payloads) == 0 {
		t.Fatal("ErrorPayloads() returned empty slice")
	}
	for _, p := range payloads {
		if p.DBMS != "SQLite" {
			t.Errorf("payload DBMS = %q, want 'SQLite'", p.DBMS)
		}
		if !strings.Contains(p.Template, "{{.Query}}") {
			t.Errorf("payload template missing {{.Query}}: %q", p.Template)
		}
	}
}

func TestSQLite_Capabilities(t *testing.T) {
	s := &SQLite{}
	caps := s.Capabilities()
	if caps.StackedQueries {
		t.Error("StackedQueries should be false")
	}
	if !caps.UnionBased {
		t.Error("UnionBased should be true")
	}
	if !caps.LimitOffset {
		t.Error("LimitOffset should be true (SQLite supports LIMIT/OFFSET)")
	}
	if caps.ErrorBased {
		t.Error("ErrorBased should be false (SQLite error messages are not informative)")
	}
}

func TestSQLite_DumpQuery(t *testing.T) {
	s := &SQLite{}
	got := s.DumpQuery("", "users", []string{"id", "name"}, 0, 10)
	if !strings.Contains(got, "LIMIT 10") {
		t.Errorf("DumpQuery missing LIMIT: %q", got)
	}
	if !strings.Contains(got, "OFFSET 0") {
		t.Errorf("DumpQuery missing OFFSET: %q", got)
	}
}

func TestRegistry_SQLite(t *testing.T) {
	for _, variant := range []string{"SQLite", "sqlite", "sqlite3"} {
		d := Registry(variant)
		if d == nil {
			t.Errorf("Registry(%q) returned nil", variant)
			continue
		}
		if d.Name() != "SQLite" {
			t.Errorf("Registry(%q).Name() = %q, want 'SQLite'", variant, d.Name())
		}
	}
}
