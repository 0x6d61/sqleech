package dbms

import (
	"strings"
	"testing"
)

func newPostgreSQL() *PostgreSQL {
	return &PostgreSQL{}
}

func TestPostgreSQLName(t *testing.T) {
	p := newPostgreSQL()
	if p.Name() != "PostgreSQL" {
		t.Errorf("expected \"PostgreSQL\", got %q", p.Name())
	}
}

// --- String operations ---

func TestPostgreSQLConcatenate(t *testing.T) {
	p := newPostgreSQL()
	tests := []struct {
		parts    []string
		expected string
	}{
		{[]string{"'a'", "'b'"}, "'a'||'b'"},
		{[]string{"'a'", "'b'", "'c'"}, "'a'||'b'||'c'"},
		{[]string{"'x'"}, "'x'"},
	}
	for _, tt := range tests {
		got := p.Concatenate(tt.parts...)
		if got != tt.expected {
			t.Errorf("Concatenate(%v) = %q, want %q", tt.parts, got, tt.expected)
		}
	}
}

func TestPostgreSQLSubstring(t *testing.T) {
	p := newPostgreSQL()
	got := p.Substring("version()", 1, 10)
	expected := "SUBSTRING(version() FROM 1 FOR 10)"
	if got != expected {
		t.Errorf("Substring = %q, want %q", got, expected)
	}
}

func TestPostgreSQLLength(t *testing.T) {
	p := newPostgreSQL()
	got := p.Length("version()")
	expected := "LENGTH(version())"
	if got != expected {
		t.Errorf("Length = %q, want %q", got, expected)
	}
}

func TestPostgreSQLASCII(t *testing.T) {
	p := newPostgreSQL()
	got := p.ASCII("'A'")
	expected := "ASCII('A')"
	if got != expected {
		t.Errorf("ASCII = %q, want %q", got, expected)
	}
}

func TestPostgreSQLChar(t *testing.T) {
	p := newPostgreSQL()
	got := p.Char(65)
	expected := "CHR(65)"
	if got != expected {
		t.Errorf("Char = %q, want %q", got, expected)
	}
}

// --- Version and identity ---

func TestPostgreSQLVersionQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.VersionQuery()
	if got != "version()" {
		t.Errorf("VersionQuery = %q, want \"version()\"", got)
	}
}

func TestPostgreSQLCurrentUserQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.CurrentUserQuery()
	if got != "CURRENT_USER" {
		t.Errorf("CurrentUserQuery = %q, want \"CURRENT_USER\"", got)
	}
}

func TestPostgreSQLCurrentDBQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.CurrentDBQuery()
	if got != "CURRENT_DATABASE()" {
		t.Errorf("CurrentDBQuery = %q, want \"CURRENT_DATABASE()\"", got)
	}
}

func TestPostgreSQLHostnameQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.HostnameQuery()
	if got != "inet_server_addr()" {
		t.Errorf("HostnameQuery = %q, want \"inet_server_addr()\"", got)
	}
}

// --- Enumeration queries ---

func TestPostgreSQLListDatabasesQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.ListDatabasesQuery()
	if !strings.Contains(got, "pg_database") {
		t.Errorf("ListDatabasesQuery should reference pg_database, got %q", got)
	}
	if !strings.Contains(got, "datname") {
		t.Errorf("ListDatabasesQuery should SELECT datname, got %q", got)
	}
}

func TestPostgreSQLListTablesQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.ListTablesQuery("testdb")
	if !strings.Contains(got, "information_schema.tables") {
		t.Errorf("ListTablesQuery should reference information_schema.tables, got %q", got)
	}
	if !strings.Contains(got, "table_name") {
		t.Errorf("ListTablesQuery should SELECT table_name, got %q", got)
	}
	if !strings.Contains(got, "'public'") {
		t.Errorf("ListTablesQuery should filter by schema 'public', got %q", got)
	}
	if !strings.Contains(got, "'testdb'") {
		t.Errorf("ListTablesQuery should filter by catalog 'testdb', got %q", got)
	}
}

func TestPostgreSQLListColumnsQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.ListColumnsQuery("testdb", "users")
	if !strings.Contains(got, "information_schema.columns") {
		t.Errorf("ListColumnsQuery should reference information_schema.columns, got %q", got)
	}
	if !strings.Contains(got, "column_name") {
		t.Errorf("ListColumnsQuery should SELECT column_name, got %q", got)
	}
	if !strings.Contains(got, "'testdb'") {
		t.Errorf("ListColumnsQuery should filter by catalog 'testdb', got %q", got)
	}
	if !strings.Contains(got, "'users'") {
		t.Errorf("ListColumnsQuery should filter by table 'users', got %q", got)
	}
}

func TestPostgreSQLCountRowsQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.CountRowsQuery("testdb", "users")
	if !strings.Contains(got, "COUNT(*)") {
		t.Errorf("CountRowsQuery should contain COUNT(*), got %q", got)
	}
	if !strings.Contains(got, "users") {
		t.Errorf("CountRowsQuery should reference table users, got %q", got)
	}
}

func TestPostgreSQLDumpQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.DumpQuery("testdb", "users", []string{"id", "name", "email"}, 10, 5)
	if !strings.Contains(got, "id,name,email") {
		t.Errorf("DumpQuery should contain column list, got %q", got)
	}
	if !strings.Contains(got, "users") {
		t.Errorf("DumpQuery should reference table users, got %q", got)
	}
	if !strings.Contains(got, "LIMIT 5") {
		t.Errorf("DumpQuery should contain LIMIT 5, got %q", got)
	}
	if !strings.Contains(got, "OFFSET 10") {
		t.Errorf("DumpQuery should contain OFFSET 10, got %q", got)
	}
}

// --- Error-based payloads ---

func TestPostgreSQLErrorPayloads(t *testing.T) {
	p := newPostgreSQL()
	payloads := p.ErrorPayloads()
	if len(payloads) == 0 {
		t.Fatal("ErrorPayloads should return at least one payload")
	}
	for _, pl := range payloads {
		if !strings.Contains(pl.Template, "{{.Query}}") {
			t.Errorf("payload %q template should contain {{.Query}}, got %q", pl.Name, pl.Template)
		}
		if pl.Name == "" {
			t.Error("payload Name should not be empty")
		}
		if pl.DBMS != "PostgreSQL" {
			t.Errorf("payload DBMS should be \"PostgreSQL\", got %q", pl.DBMS)
		}
	}
	// Verify CAST payload exists
	found := false
	for _, pl := range payloads {
		if pl.Name == "cast" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ErrorPayloads should include cast payload")
	}
}

// --- Time-based ---

func TestPostgreSQLSleepFunction(t *testing.T) {
	p := newPostgreSQL()
	got := p.SleepFunction(5)
	expected := "pg_sleep(5)"
	if got != expected {
		t.Errorf("SleepFunction(5) = %q, want %q", got, expected)
	}
}

func TestPostgreSQLHeavyQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.HeavyQuery()
	if !strings.Contains(got, "generate_series") {
		t.Errorf("HeavyQuery should contain generate_series, got %q", got)
	}
}

// --- Boolean constructs ---

func TestPostgreSQLIfThenElse(t *testing.T) {
	p := newPostgreSQL()
	got := p.IfThenElse("1=1", "'true'", "'false'")
	expected := "CASE WHEN 1=1 THEN 'true' ELSE 'false' END"
	if got != expected {
		t.Errorf("IfThenElse = %q, want %q", got, expected)
	}
}

// --- Quoting and comments ---

func TestPostgreSQLQuoteString(t *testing.T) {
	p := newPostgreSQL()
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "'hello'"},
		{"it's", "'it''s'"},
		{"a'b'c", "'a''b''c'"},
		{"", "''"},
		{"no quotes", "'no quotes'"},
	}
	for _, tt := range tests {
		got := p.QuoteString(tt.input)
		if got != tt.expected {
			t.Errorf("QuoteString(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestPostgreSQLCommentSequence(t *testing.T) {
	p := newPostgreSQL()
	got := p.CommentSequence()
	if got != "-- " {
		t.Errorf("CommentSequence = %q, want \"-- \"", got)
	}
}

func TestPostgreSQLInlineComment(t *testing.T) {
	p := newPostgreSQL()
	got := p.InlineComment()
	if got != "/**/" {
		t.Errorf("InlineComment = %q, want \"/**/\"", got)
	}
}

// --- File operations ---

func TestPostgreSQLFileReadQuery(t *testing.T) {
	p := newPostgreSQL()
	got := p.FileReadQuery("/etc/passwd")
	if !strings.Contains(got, "pg_read_file") {
		t.Errorf("FileReadQuery should use pg_read_file, got %q", got)
	}
	if !strings.Contains(got, "/etc/passwd") {
		t.Errorf("FileReadQuery should contain the path, got %q", got)
	}
}

// --- Capabilities ---

func TestPostgreSQLCapabilities(t *testing.T) {
	p := newPostgreSQL()
	caps := p.Capabilities()

	if !caps.StackedQueries {
		t.Error("PostgreSQL should support StackedQueries")
	}
	if !caps.ErrorBased {
		t.Error("PostgreSQL should support ErrorBased")
	}
	if !caps.UnionBased {
		t.Error("PostgreSQL should support UnionBased")
	}
	if !caps.FileRead {
		t.Error("PostgreSQL should support FileRead")
	}
	if !caps.FileWrite {
		t.Error("PostgreSQL should support FileWrite")
	}
	if caps.OSCommand {
		t.Error("PostgreSQL should NOT support OSCommand")
	}
	if caps.OutOfBand {
		t.Error("PostgreSQL should NOT support OutOfBand")
	}
	if !caps.Subqueries {
		t.Error("PostgreSQL should support Subqueries")
	}
	if !caps.CaseWhen {
		t.Error("PostgreSQL should support CaseWhen")
	}
	if !caps.LimitOffset {
		t.Error("PostgreSQL should support LimitOffset")
	}
}
