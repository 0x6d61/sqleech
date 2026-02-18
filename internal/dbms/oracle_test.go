package dbms

import (
	"strings"
	"testing"
)

func TestOracle_Name(t *testing.T) {
	o := &Oracle{}
	if o.Name() != "Oracle" {
		t.Errorf("Name() = %q, want 'Oracle'", o.Name())
	}
}

func TestOracle_Concatenate(t *testing.T) {
	o := &Oracle{}
	got := o.Concatenate("a", "b", "c")
	if got != "a||b||c" {
		t.Errorf("Concatenate() = %q, want 'a||b||c'", got)
	}
}

func TestOracle_Substring(t *testing.T) {
	o := &Oracle{}
	got := o.Substring("col", 1, 5)
	if got != "SUBSTR(col,1,5)" {
		t.Errorf("Substring() = %q, want 'SUBSTR(col,1,5)'", got)
	}
}

func TestOracle_Length(t *testing.T) {
	o := &Oracle{}
	got := o.Length("col")
	if got != "LENGTH(col)" {
		t.Errorf("Length() = %q, want 'LENGTH(col)'", got)
	}
}

func TestOracle_ASCII(t *testing.T) {
	o := &Oracle{}
	got := o.ASCII("col")
	if got != "ASCII(col)" {
		t.Errorf("ASCII() = %q, want 'ASCII(col)'", got)
	}
}

func TestOracle_Char(t *testing.T) {
	o := &Oracle{}
	got := o.Char(65)
	if got != "CHR(65)" {
		t.Errorf("Char() = %q, want 'CHR(65)'", got)
	}
}

func TestOracle_CommentSequence(t *testing.T) {
	o := &Oracle{}
	if o.CommentSequence() != "-- " {
		t.Errorf("CommentSequence() = %q, want '-- '", o.CommentSequence())
	}
}

func TestOracle_QuoteString(t *testing.T) {
	o := &Oracle{}
	got := o.QuoteString("O'Brien")
	want := "'O''Brien'"
	if got != want {
		t.Errorf("QuoteString() = %q, want %q", got, want)
	}
}

func TestOracle_IfThenElse(t *testing.T) {
	o := &Oracle{}
	got := o.IfThenElse("1=1", "'a'", "'b'")
	want := "CASE WHEN 1=1 THEN 'a' ELSE 'b' END"
	if got != want {
		t.Errorf("IfThenElse() = %q, want %q", got, want)
	}
}

func TestOracle_ErrorPayloads(t *testing.T) {
	o := &Oracle{}
	payloads := o.ErrorPayloads()
	if len(payloads) == 0 {
		t.Fatal("ErrorPayloads() returned empty slice")
	}
	for _, p := range payloads {
		if p.DBMS != "Oracle" {
			t.Errorf("payload DBMS = %q, want 'Oracle'", p.DBMS)
		}
		if !strings.Contains(p.Template, "{{.Query}}") {
			t.Errorf("payload template missing {{.Query}}: %q", p.Template)
		}
	}
}

func TestOracle_Capabilities(t *testing.T) {
	o := &Oracle{}
	caps := o.Capabilities()
	if caps.StackedQueries {
		t.Error("StackedQueries should be false (Oracle does not support semicolon stacking)")
	}
	if !caps.UnionBased {
		t.Error("UnionBased should be true")
	}
	if caps.LimitOffset {
		t.Error("LimitOffset should be false (Oracle uses ROWNUM)")
	}
}

func TestRegistry_Oracle(t *testing.T) {
	for _, variant := range []string{"Oracle", "oracle"} {
		d := Registry(variant)
		if d == nil {
			t.Errorf("Registry(%q) returned nil", variant)
			continue
		}
		if d.Name() != "Oracle" {
			t.Errorf("Registry(%q).Name() = %q, want 'Oracle'", variant, d.Name())
		}
	}
}
