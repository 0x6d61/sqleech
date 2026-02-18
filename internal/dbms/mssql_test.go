package dbms

import (
	"strings"
	"testing"
)

func TestMSSQL_Name(t *testing.T) {
	m := &MSSQL{}
	if m.Name() != "MSSQL" {
		t.Errorf("Name() = %q, want 'MSSQL'", m.Name())
	}
}

func TestMSSQL_Concatenate(t *testing.T) {
	m := &MSSQL{}
	got := m.Concatenate("a", "b", "c")
	if got != "a+b+c" {
		t.Errorf("Concatenate() = %q, want 'a+b+c'", got)
	}
}

func TestMSSQL_Substring(t *testing.T) {
	m := &MSSQL{}
	got := m.Substring("col", 1, 5)
	if got != "SUBSTRING(col,1,5)" {
		t.Errorf("Substring() = %q", got)
	}
}

func TestMSSQL_Length(t *testing.T) {
	m := &MSSQL{}
	got := m.Length("col")
	if got != "LEN(col)" {
		t.Errorf("Length() = %q, want 'LEN(col)'", got)
	}
}

func TestMSSQL_ASCII(t *testing.T) {
	m := &MSSQL{}
	got := m.ASCII("col")
	if got != "ASCII(col)" {
		t.Errorf("ASCII() = %q", got)
	}
}

func TestMSSQL_Char(t *testing.T) {
	m := &MSSQL{}
	got := m.Char(65)
	if got != "CHAR(65)" {
		t.Errorf("Char() = %q", got)
	}
}

func TestMSSQL_VersionQuery(t *testing.T) {
	m := &MSSQL{}
	if m.VersionQuery() != "@@version" {
		t.Errorf("VersionQuery() = %q", m.VersionQuery())
	}
}

func TestMSSQL_SleepFunction(t *testing.T) {
	m := &MSSQL{}
	cases := []struct {
		seconds int
		want    string
	}{
		{5, "WAITFOR DELAY '0:00:05'"},
		{10, "WAITFOR DELAY '0:00:10'"},
		{60, "WAITFOR DELAY '0:01:00'"},
		{3661, "WAITFOR DELAY '1:01:01'"},
	}
	for _, c := range cases {
		got := m.SleepFunction(c.seconds)
		if got != c.want {
			t.Errorf("SleepFunction(%d) = %q, want %q", c.seconds, got, c.want)
		}
	}
}

func TestMSSQL_IfThenElse(t *testing.T) {
	m := &MSSQL{}
	got := m.IfThenElse("1=1", "'a'", "'b'")
	want := "CASE WHEN 1=1 THEN 'a' ELSE 'b' END"
	if got != want {
		t.Errorf("IfThenElse() = %q, want %q", got, want)
	}
}

func TestMSSQL_CommentSequence(t *testing.T) {
	m := &MSSQL{}
	if m.CommentSequence() != "-- " {
		t.Errorf("CommentSequence() = %q", m.CommentSequence())
	}
}

func TestMSSQL_ErrorPayloads(t *testing.T) {
	m := &MSSQL{}
	payloads := m.ErrorPayloads()
	if len(payloads) == 0 {
		t.Fatal("ErrorPayloads() returned empty slice")
	}
	for _, p := range payloads {
		if p.DBMS != "MSSQL" {
			t.Errorf("payload DBMS = %q, want 'MSSQL'", p.DBMS)
		}
		if !strings.Contains(p.Template, "{{.Query}}") {
			t.Errorf("payload template missing {{.Query}}: %q", p.Template)
		}
		// Verify CONVERT or CAST is used
		upper := strings.ToUpper(p.Template)
		if !strings.Contains(upper, "CONVERT") && !strings.Contains(upper, "CAST") {
			t.Errorf("expected CONVERT or CAST in template, got: %q", p.Template)
		}
	}
}

func TestMSSQL_Capabilities(t *testing.T) {
	m := &MSSQL{}
	caps := m.Capabilities()
	if !caps.StackedQueries {
		t.Error("StackedQueries should be true")
	}
	if !caps.ErrorBased {
		t.Error("ErrorBased should be true")
	}
	if !caps.UnionBased {
		t.Error("UnionBased should be true")
	}
	if caps.LimitOffset {
		t.Error("LimitOffset should be false (MSSQL uses TOP/ROW_NUMBER)")
	}
}

func TestMSSQL_QuoteString(t *testing.T) {
	m := &MSSQL{}
	got := m.QuoteString("O'Brien")
	want := "'O''Brien'"
	if got != want {
		t.Errorf("QuoteString() = %q, want %q", got, want)
	}
}

func TestRegistry_MSSQL(t *testing.T) {
	variants := []string{"MSSQL", "mssql", "sqlserver", "MSSQLServer"}
	for _, v := range variants {
		d := Registry(v)
		if d == nil {
			t.Errorf("Registry(%q) returned nil", v)
			continue
		}
		if d.Name() != "MSSQL" {
			t.Errorf("Registry(%q).Name() = %q, want 'MSSQL'", v, d.Name())
		}
	}
}
