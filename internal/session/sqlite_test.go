package session

import (
	"context"
	"testing"
	"time"
)

func TestNewSQLiteStore(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore(:memory:) returned error: %v", err)
	}
	defer store.Close()

	if store == nil {
		t.Fatal("NewSQLiteStore(:memory:) returned nil store")
	}
	if store.db == nil {
		t.Fatal("NewSQLiteStore(:memory:) db field is nil")
	}
}

func TestSQLiteStore_SaveAndLoad(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	state := &ScanState{
		ID:        "test-id-1",
		TargetURL: "http://example.com/login",
		Target: map[string]interface{}{
			"url":    "http://example.com/login",
			"method": "POST",
		},
		Vulnerabilities: []interface{}{
			map[string]interface{}{
				"parameter": "username",
				"technique": "boolean-based blind",
			},
		},
		DBMS:        "MySQL",
		DBMSVersion: "8.0",
		Config: map[string]interface{}{
			"level": float64(1),
			"risk":  float64(1),
		},
		Progress: 0.75,
	}

	// Save
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	// Load by target URL
	loaded, err := store.Load(ctx, "http://example.com/login")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil state")
	}

	// Verify fields
	if loaded.ID != "test-id-1" {
		t.Errorf("ID = %q, want %q", loaded.ID, "test-id-1")
	}
	if loaded.TargetURL != "http://example.com/login" {
		t.Errorf("TargetURL = %q, want %q", loaded.TargetURL, "http://example.com/login")
	}
	if loaded.DBMS != "MySQL" {
		t.Errorf("DBMS = %q, want %q", loaded.DBMS, "MySQL")
	}
	if loaded.DBMSVersion != "8.0" {
		t.Errorf("DBMSVersion = %q, want %q", loaded.DBMSVersion, "8.0")
	}
	if loaded.Progress != 0.75 {
		t.Errorf("Progress = %f, want %f", loaded.Progress, 0.75)
	}

	// Verify Target was deserialized
	if loaded.Target == nil {
		t.Fatal("Target is nil after Load")
	}
	targetMap, ok := loaded.Target.(map[string]interface{})
	if !ok {
		t.Fatalf("Target is not map[string]interface{}, got %T", loaded.Target)
	}
	if targetMap["url"] != "http://example.com/login" {
		t.Errorf("Target[url] = %v, want %v", targetMap["url"], "http://example.com/login")
	}

	// Verify Vulnerabilities
	if len(loaded.Vulnerabilities) != 1 {
		t.Fatalf("Vulnerabilities length = %d, want 1", len(loaded.Vulnerabilities))
	}

	// Verify Config
	if loaded.Config == nil {
		t.Fatal("Config is nil after Load")
	}
	if loaded.Config["level"] != float64(1) {
		t.Errorf("Config[level] = %v, want %v", loaded.Config["level"], float64(1))
	}

	// Verify timestamps are set
	if loaded.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if loaded.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

func TestSQLiteStore_SaveAndLoadByID(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	state := &ScanState{
		ID:        "unique-id-abc",
		TargetURL: "http://example.com/api",
		DBMS:      "PostgreSQL",
		Progress:  0.5,
	}

	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := store.LoadByID(ctx, "unique-id-abc")
	if err != nil {
		t.Fatalf("LoadByID returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadByID returned nil state")
	}
	if loaded.ID != "unique-id-abc" {
		t.Errorf("ID = %q, want %q", loaded.ID, "unique-id-abc")
	}
	if loaded.TargetURL != "http://example.com/api" {
		t.Errorf("TargetURL = %q, want %q", loaded.TargetURL, "http://example.com/api")
	}
	if loaded.DBMS != "PostgreSQL" {
		t.Errorf("DBMS = %q, want %q", loaded.DBMS, "PostgreSQL")
	}
}

func TestSQLiteStore_List(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	states := []*ScanState{
		{ID: "id-1", TargetURL: "http://example.com/a", DBMS: "MySQL", Progress: 0.1},
		{ID: "id-2", TargetURL: "http://example.com/b", DBMS: "PostgreSQL", Progress: 0.5},
		{ID: "id-3", TargetURL: "http://example.com/c", DBMS: "SQLite", Progress: 1.0},
	}
	for _, s := range states {
		if err := store.Save(ctx, s); err != nil {
			t.Fatalf("Save returned error: %v", err)
		}
	}

	summaries, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(summaries) != 3 {
		t.Fatalf("List returned %d summaries, want 3", len(summaries))
	}

	// Check that summaries contain expected data (order may vary)
	found := make(map[string]bool)
	for _, s := range summaries {
		found[s.ID] = true
		if s.UpdatedAt.IsZero() {
			t.Errorf("Summary %s has zero UpdatedAt", s.ID)
		}
	}
	for _, id := range []string{"id-1", "id-2", "id-3"} {
		if !found[id] {
			t.Errorf("List missing session with ID %q", id)
		}
	}
}

func TestSQLiteStore_Delete(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	state := &ScanState{
		ID:        "delete-me",
		TargetURL: "http://example.com/delete",
		Progress:  0.3,
	}
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	// Verify it exists
	loaded, err := store.LoadByID(ctx, "delete-me")
	if err != nil {
		t.Fatalf("LoadByID returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadByID returned nil before delete")
	}

	// Delete
	if err := store.Delete(ctx, "delete-me"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	// Verify it's gone
	loaded, err = store.LoadByID(ctx, "delete-me")
	if err != nil {
		t.Fatalf("LoadByID returned error after delete: %v", err)
	}
	if loaded != nil {
		t.Error("LoadByID returned non-nil after delete")
	}
}

func TestSQLiteStore_SaveUpdate(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Save initial state
	state := &ScanState{
		ID:        "update-id",
		TargetURL: "http://example.com/update",
		DBMS:      "MySQL",
		Progress:  0.25,
	}
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("first Save returned error: %v", err)
	}

	// Update with same ID
	state.DBMS = "PostgreSQL"
	state.Progress = 0.80
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("second Save returned error: %v", err)
	}

	// Load and verify update
	loaded, err := store.LoadByID(ctx, "update-id")
	if err != nil {
		t.Fatalf("LoadByID returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadByID returned nil")
	}
	if loaded.DBMS != "PostgreSQL" {
		t.Errorf("DBMS = %q, want %q", loaded.DBMS, "PostgreSQL")
	}
	if loaded.Progress != 0.80 {
		t.Errorf("Progress = %f, want %f", loaded.Progress, 0.80)
	}

	// Verify only one entry exists (not two)
	summaries, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(summaries) != 1 {
		t.Errorf("List returned %d summaries after update, want 1", len(summaries))
	}
}

func TestSQLiteStore_LoadNotFound(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Load by URL - not found
	loaded, err := store.Load(ctx, "http://nonexistent.com")
	if err != nil {
		t.Fatalf("Load returned error for non-existent: %v", err)
	}
	if loaded != nil {
		t.Error("Load returned non-nil for non-existent URL")
	}

	// LoadByID - not found
	loaded, err = store.LoadByID(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("LoadByID returned error for non-existent: %v", err)
	}
	if loaded != nil {
		t.Error("LoadByID returned non-nil for non-existent ID")
	}
}

func TestSQLiteStore_Close(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestSQLiteStore_Cleanup(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Save an "old" session
	oldState := &ScanState{
		ID:        "old-session",
		TargetURL: "http://example.com/old",
		Progress:  1.0,
	}
	if err := store.Save(ctx, oldState); err != nil {
		t.Fatalf("Save old session: %v", err)
	}

	// Manually backdate the old session's updated_at to 48 hours ago
	_, err = store.db.ExecContext(ctx,
		"UPDATE sessions SET updated_at = ? WHERE id = ?",
		time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339),
		"old-session",
	)
	if err != nil {
		t.Fatalf("backdate session: %v", err)
	}

	// Save a "new" session
	newState := &ScanState{
		ID:        "new-session",
		TargetURL: "http://example.com/new",
		Progress:  0.5,
	}
	if err := store.Save(ctx, newState); err != nil {
		t.Fatalf("Save new session: %v", err)
	}

	// Cleanup sessions older than 24 hours
	deleted, err := store.Cleanup(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if deleted != 1 {
		t.Errorf("Cleanup deleted %d sessions, want 1", deleted)
	}

	// Old session should be gone
	loaded, err := store.LoadByID(ctx, "old-session")
	if err != nil {
		t.Fatalf("LoadByID old-session error: %v", err)
	}
	if loaded != nil {
		t.Error("old session still exists after cleanup")
	}

	// New session should still be there
	loaded, err = store.LoadByID(ctx, "new-session")
	if err != nil {
		t.Fatalf("LoadByID new-session error: %v", err)
	}
	if loaded == nil {
		t.Error("new session was removed by cleanup")
	}
}

func TestSQLiteStore_EmptyID(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	state := &ScanState{
		ID:        "", // Empty ID should be auto-generated
		TargetURL: "http://example.com/auto-id",
		Progress:  0.1,
	}

	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	// The state's ID should now be populated
	if state.ID == "" {
		t.Fatal("Save did not populate empty ID")
	}

	// Should be a valid UUID (36 chars with hyphens)
	if len(state.ID) != 36 {
		t.Errorf("generated ID length = %d, want 36 (UUID format)", len(state.ID))
	}

	// Should be loadable by the generated ID
	loaded, err := store.LoadByID(ctx, state.ID)
	if err != nil {
		t.Fatalf("LoadByID returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadByID returned nil for auto-generated ID")
	}
	if loaded.TargetURL != "http://example.com/auto-id" {
		t.Errorf("TargetURL = %q, want %q", loaded.TargetURL, "http://example.com/auto-id")
	}
}
