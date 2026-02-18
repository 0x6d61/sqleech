package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using SQLite via modernc.org/sqlite (pure Go).
type SQLiteStore struct {
	db *sql.DB
}

// Compile-time check that SQLiteStore implements Store.
var _ Store = (*SQLiteStore)(nil)

// NewSQLiteStore creates a new SQLite-backed store.
// dbPath is the path to the SQLite database file; use ":memory:" for testing.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("session: open database: %w", err)
	}

	// Verify the connection works.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("session: ping database: %w", err)
	}

	// Create the sessions table if it does not exist.
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS sessions (
			id          TEXT PRIMARY KEY,
			target_url  TEXT NOT NULL,
			state_json  TEXT NOT NULL,
			progress    REAL DEFAULT 0,
			dbms        TEXT DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("session: create table: %w", err)
	}

	// Create an index on target_url for fast lookups.
	createIndexSQL := `
		CREATE INDEX IF NOT EXISTS idx_sessions_target_url ON sessions(target_url);
	`
	if _, err := db.Exec(createIndexSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("session: create index: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// Save persists a ScanState to the database.
// If the state's ID is empty, a new UUID is generated and assigned.
func (s *SQLiteStore) Save(ctx context.Context, state *ScanState) error {
	if state.ID == "" {
		state.ID = uuid.New().String()
	}

	now := time.Now().UTC()
	state.UpdatedAt = now
	if state.CreatedAt.IsZero() {
		state.CreatedAt = now
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("session: marshal state: %w", err)
	}

	query := `
		INSERT INTO sessions (id, target_url, state_json, progress, dbms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			target_url = excluded.target_url,
			state_json = excluded.state_json,
			progress   = excluded.progress,
			dbms       = excluded.dbms,
			updated_at = excluded.updated_at
	`
	_, err = s.db.ExecContext(ctx, query,
		state.ID,
		state.TargetURL,
		string(stateJSON),
		state.Progress,
		state.DBMS,
		state.CreatedAt.Format(time.RFC3339),
		state.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("session: save state: %w", err)
	}

	return nil
}

// Load retrieves the most recently updated ScanState for the given target URL.
// Returns (nil, nil) if no session is found.
func (s *SQLiteStore) Load(ctx context.Context, targetURL string) (*ScanState, error) {
	query := `
		SELECT state_json FROM sessions
		WHERE target_url = ?
		ORDER BY updated_at DESC
		LIMIT 1
	`
	return s.loadOne(ctx, query, targetURL)
}

// LoadByID retrieves a ScanState by its unique ID.
// Returns (nil, nil) if no session is found.
func (s *SQLiteStore) LoadByID(ctx context.Context, id string) (*ScanState, error) {
	query := `SELECT state_json FROM sessions WHERE id = ?`
	return s.loadOne(ctx, query, id)
}

// loadOne executes a query that returns a single state_json column and
// deserializes it into a ScanState.
func (s *SQLiteStore) loadOne(ctx context.Context, query string, args ...interface{}) (*ScanState, error) {
	row := s.db.QueryRowContext(ctx, query, args...)

	var stateJSON string
	if err := row.Scan(&stateJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("session: scan row: %w", err)
	}

	var state ScanState
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		return nil, fmt.Errorf("session: unmarshal state: %w", err)
	}

	return &state, nil
}

// List returns a lightweight summary of all stored sessions.
func (s *SQLiteStore) List(ctx context.Context) ([]*ScanSummary, error) {
	query := `SELECT id, target_url, progress, dbms, updated_at FROM sessions ORDER BY updated_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("session: list sessions: %w", err)
	}
	defer rows.Close()

	var summaries []*ScanSummary
	for rows.Next() {
		var (
			summary   ScanSummary
			updatedAt string
		)
		if err := rows.Scan(&summary.ID, &summary.TargetURL, &summary.Progress, &summary.DBMS, &updatedAt); err != nil {
			return nil, fmt.Errorf("session: scan summary row: %w", err)
		}
		t, err := time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			// Fall back to SQLite default format if RFC3339 fails.
			t, err = time.Parse("2006-01-02 15:04:05", updatedAt)
			if err != nil {
				return nil, fmt.Errorf("session: parse updated_at %q: %w", updatedAt, err)
			}
		}
		summary.UpdatedAt = t
		summaries = append(summaries, &summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session: iterate rows: %w", err)
	}

	return summaries, nil
}

// Delete removes a session by its ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM sessions WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("session: delete session: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Cleanup removes sessions whose updated_at is older than maxAge from now.
// It returns the number of deleted sessions.
func (s *SQLiteStore) Cleanup(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)

	query := `DELETE FROM sessions WHERE updated_at < ?`
	result, err := s.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("session: cleanup sessions: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: rows affected: %w", err)
	}

	return deleted, nil
}
