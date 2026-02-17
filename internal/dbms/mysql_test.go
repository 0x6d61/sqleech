package dbms

import (
	"strings"
	"testing"
)

func newMySQL() *MySQL {
	return &MySQL{}
}

func TestMySQLName(t *testing.T) {
	m := newMySQL()
	if m.Name() != "MySQL" {
		t.Errorf("expected \"MySQL\", got %q", m.Name())
	}
}

// --- String operations ---

func TestMySQLConcatenate(t *testing.T) {
	m := newMySQL()
	tests := []struct {
		parts    []string
		expected string
	}{
		{[]string{"'a'", "'b'"}, "CONCAT('a','b')"},
		{[]string{"'a'", "'b'", "'c'"}, "CONCAT('a','b','c')"},
		{[]string{"'x'"}, "CONCAT('x')"},
	}
	for _, tt := range tests {
		got := m.Concatenate(tt.parts...)
		if got != tt.expected {
			t.Errorf("Concatenate(%v) = %q, want %q", tt.parts, got, tt.expected)
		}
	}
}

func TestMySQLSubstring(t *testing.T) {
	m := newMySQL()
	got := m.Substring("@@version", 1, 10)
	expected := "SUBSTRING(@@version,1,10)"
	if got != expected {
		t.Errorf("Substring = %q, want %q", got, expected)
	}
}

func TestMySQLLength(t *testing.T) {
	m := newMySQL()
	got := m.Length("@@version")
	expected := "LENGTH(@@version)"
	if got != expected {
		t.Errorf("Length = %q, want %q", got, expected)
	}
}

func TestMySQLASCII(t *testing.T) {
	m := newMySQL()
	got := m.ASCII("'A'")
	expected := "ASCII('A')"
	if got != expected {
		t.Errorf("ASCII = %q, want %q", got, expected)
	}
}

func TestMySQLChar(t *testing.T) {
	m := newMySQL()
	got := m.Char(65)
	expected := "CHAR(65)"
	if got != expected {
		t.Errorf("Char = %q, want %q", got, expected)
	}
}

// --- Version and identity ---

func TestMySQLVersionQuery(t *testing.T) {
	m := newMySQL()
	got := m.VersionQuery()
	if got != "@@version" {
		t.Errorf("VersionQuery = %q, want \"@@version\"", got)
	}
}

func TestMySQLCurrentUserQuery(t *testing.T) {
	m := newMySQL()
	got := m.CurrentUserQuery()
	if got != "CURRENT_USER()" {
		t.Errorf("CurrentUserQuery = %q, want \"CURRENT_USER()\"", got)
	}
}

func TestMySQLCurrentDBQuery(t *testing.T) {
	m := newMySQL()
	got := m.CurrentDBQuery()
	if got != "DATABASE()" {
		t.Errorf("CurrentDBQuery = %q, want \"DATABASE()\"", got)
	}
}

func TestMySQLHostnameQuery(t *testing.T) {
	m := newMySQL()
	got := m.HostnameQuery()
	if got != "@@hostname" {
		t.Errorf("HostnameQuery = %q, want \"@@hostname\"", got)
	}
}

// --- Enumeration queries ---

func TestMySQLListDatabasesQuery(t *testing.T) {
	m := newMySQL()
	got := m.ListDatabasesQuery()
	if !strings.Contains(got, "information_schema.schemata") {
		t.Errorf("ListDatabasesQuery should reference information_schema.schemata, got %q", got)
	}
	if !strings.Contains(got, "schema_name") {
		t.Errorf("ListDatabasesQuery should SELECT schema_name, got %q", got)
	}
}

func TestMySQLListTablesQuery(t *testing.T) {
	m := newMySQL()
	got := m.ListTablesQuery("testdb")
	if !strings.Contains(got, "information_schema.tables") {
		t.Errorf("ListTablesQuery should reference information_schema.tables, got %q", got)
	}
	if !strings.Contains(got, "table_name") {
		t.Errorf("ListTablesQuery should SELECT table_name, got %q", got)
	}
	if !strings.Contains(got, "'testdb'") {
		t.Errorf("ListTablesQuery should filter by database 'testdb', got %q", got)
	}
}

func TestMySQLListColumnsQuery(t *testing.T) {
	m := newMySQL()
	got := m.ListColumnsQuery("testdb", "users")
	if !strings.Contains(got, "information_schema.columns") {
		t.Errorf("ListColumnsQuery should reference information_schema.columns, got %q", got)
	}
	if !strings.Contains(got, "column_name") {
		t.Errorf("ListColumnsQuery should SELECT column_name, got %q", got)
	}
	if !strings.Contains(got, "'testdb'") {
		t.Errorf("ListColumnsQuery should filter by database 'testdb', got %q", got)
	}
	if !strings.Contains(got, "'users'") {
		t.Errorf("ListColumnsQuery should filter by table 'users', got %q", got)
	}
}

func TestMySQLCountRowsQuery(t *testing.T) {
	m := newMySQL()
	got := m.CountRowsQuery("testdb", "users")
	if !strings.Contains(got, "COUNT(*)") {
		t.Errorf("CountRowsQuery should contain COUNT(*), got %q", got)
	}
	if !strings.Contains(got, "testdb.users") {
		t.Errorf("CountRowsQuery should reference testdb.users, got %q", got)
	}
}

func TestMySQLDumpQuery(t *testing.T) {
	m := newMySQL()
	got := m.DumpQuery("testdb", "users", []string{"id", "name", "email"}, 10, 5)
	if !strings.Contains(got, "id,name,email") {
		t.Errorf("DumpQuery should contain column list, got %q", got)
	}
	if !strings.Contains(got, "testdb.users") {
		t.Errorf("DumpQuery should reference testdb.users, got %q", got)
	}
	if !strings.Contains(got, "LIMIT 5") {
		t.Errorf("DumpQuery should contain LIMIT 5, got %q", got)
	}
	if !strings.Contains(got, "OFFSET 10") {
		t.Errorf("DumpQuery should contain OFFSET 10, got %q", got)
	}
}

// --- Error-based payloads ---

func TestMySQLErrorPayloads(t *testing.T) {
	m := newMySQL()
	payloads := m.ErrorPayloads()
	if len(payloads) == 0 {
		t.Fatal("ErrorPayloads should return at least one payload")
	}
	for _, p := range payloads {
		if !strings.Contains(p.Template, "{{.Query}}") {
			t.Errorf("payload %q template should contain {{.Query}}, got %q", p.Name, p.Template)
		}
		if p.Name == "" {
			t.Error("payload Name should not be empty")
		}
		if p.DBMS != "MySQL" {
			t.Errorf("payload DBMS should be \"MySQL\", got %q", p.DBMS)
		}
	}
	// Verify specific payloads exist
	names := make(map[string]bool)
	for _, p := range payloads {
		names[p.Name] = true
	}
	if !names["extractvalue"] {
		t.Error("ErrorPayloads should include extractvalue payload")
	}
	if !names["updatexml"] {
		t.Error("ErrorPayloads should include updatexml payload")
	}
}

// --- Time-based ---

func TestMySQLSleepFunction(t *testing.T) {
	m := newMySQL()
	got := m.SleepFunction(5)
	expected := "SLEEP(5)"
	if got != expected {
		t.Errorf("SleepFunction(5) = %q, want %q", got, expected)
	}
}

func TestMySQLHeavyQuery(t *testing.T) {
	m := newMySQL()
	got := m.HeavyQuery()
	if !strings.Contains(got, "BENCHMARK") {
		t.Errorf("HeavyQuery should contain BENCHMARK, got %q", got)
	}
}

// --- Boolean constructs ---

func TestMySQLIfThenElse(t *testing.T) {
	m := newMySQL()
	got := m.IfThenElse("1=1", "'true'", "'false'")
	expected := "IF(1=1,'true','false')"
	if got != expected {
		t.Errorf("IfThenElse = %q, want %q", got, expected)
	}
}

// --- Quoting and comments ---

func TestMySQLQuoteString(t *testing.T) {
	m := newMySQL()
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
		got := m.QuoteString(tt.input)
		if got != tt.expected {
			t.Errorf("QuoteString(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMySQLCommentSequence(t *testing.T) {
	m := newMySQL()
	got := m.CommentSequence()
	if got != "-- " {
		t.Errorf("CommentSequence = %q, want \"-- \"", got)
	}
}

func TestMySQLInlineComment(t *testing.T) {
	m := newMySQL()
	got := m.InlineComment()
	if got != "/**/" {
		t.Errorf("InlineComment = %q, want \"/**/\"", got)
	}
}

// --- File operations ---

func TestMySQLFileReadQuery(t *testing.T) {
	m := newMySQL()
	got := m.FileReadQuery("/etc/passwd")
	if !strings.Contains(got, "LOAD_FILE") {
		t.Errorf("FileReadQuery should use LOAD_FILE, got %q", got)
	}
	if !strings.Contains(got, "/etc/passwd") {
		t.Errorf("FileReadQuery should contain the path, got %q", got)
	}
}

// --- Capabilities ---

func TestMySQLCapabilities(t *testing.T) {
	m := newMySQL()
	caps := m.Capabilities()

	if !caps.StackedQueries {
		t.Error("MySQL should support StackedQueries")
	}
	if !caps.ErrorBased {
		t.Error("MySQL should support ErrorBased")
	}
	if !caps.UnionBased {
		t.Error("MySQL should support UnionBased")
	}
	if !caps.FileRead {
		t.Error("MySQL should support FileRead")
	}
	if !caps.FileWrite {
		t.Error("MySQL should support FileWrite")
	}
	if caps.OSCommand {
		t.Error("MySQL should NOT support OSCommand")
	}
	if caps.OutOfBand {
		t.Error("MySQL should NOT support OutOfBand")
	}
	if !caps.Subqueries {
		t.Error("MySQL should support Subqueries")
	}
	if !caps.CaseWhen {
		t.Error("MySQL should support CaseWhen")
	}
	if !caps.LimitOffset {
		t.Error("MySQL should support LimitOffset")
	}
}
