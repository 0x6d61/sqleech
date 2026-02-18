// Package dbms provides DBMS-specific SQL syntax and query knowledge base.
package dbms

// DBMS provides database-specific SQL syntax and capabilities.
type DBMS interface {
	Name() string

	// String operations
	Concatenate(parts ...string) string
	Substring(expr string, start, length int) string
	Length(expr string) string
	ASCII(expr string) string
	Char(code int) string

	// Version and identity
	VersionQuery() string
	CurrentUserQuery() string
	CurrentDBQuery() string
	HostnameQuery() string

	// Enumeration queries
	ListDatabasesQuery() string
	ListTablesQuery(database string) string
	ListColumnsQuery(database, table string) string
	CountRowsQuery(database, table string) string
	DumpQuery(database, table string, columns []string, offset, limit int) string

	// Error-based payloads
	ErrorPayloads() []PayloadTemplate

	// Time-based
	SleepFunction(seconds int) string
	HeavyQuery() string

	// Boolean constructs
	IfThenElse(condition, trueExpr, falseExpr string) string

	// Quoting and comments
	QuoteString(s string) string
	CommentSequence() string
	InlineComment() string

	// File operations
	FileReadQuery(path string) string

	// Capabilities
	Capabilities() Capabilities
}

// Capabilities describes what a DBMS supports.
type Capabilities struct {
	StackedQueries bool
	ErrorBased     bool
	UnionBased     bool
	FileRead       bool
	FileWrite      bool
	OSCommand      bool
	OutOfBand      bool
	Subqueries     bool
	CaseWhen       bool
	LimitOffset    bool
}

// PayloadTemplate is a parameterized error-based payload.
type PayloadTemplate struct {
	Name     string
	Template string // Use {{.Query}} as placeholder for the expression to extract
	Columns  int
	DBMS     string
}

// Registry returns a DBMS implementation by name.
// It accepts common name variants (e.g. "MySQL", "mysql", "PostgreSQL", "postgres").
// Returns nil if the name is not recognized.
func Registry(name string) DBMS {
	switch name {
	case "MySQL", "mysql":
		return &MySQL{}
	case "PostgreSQL", "postgres", "postgresql":
		return &PostgreSQL{}
	case "MSSQL", "mssql", "sqlserver", "MSSQLServer":
		return &MSSQL{}
	default:
		return nil
	}
}
