// Package session provides persistence for scan state, allowing scans to be
// saved, resumed, and reviewed.
package session

import (
	"context"
	"time"
)

// ScanState captures everything needed to resume a scan.
type ScanState struct {
	ID              string                 `json:"id"`
	TargetURL       string                 `json:"target_url"`
	Target          interface{}            `json:"target"`          // Serialized ScanTarget
	Vulnerabilities []interface{}          `json:"vulnerabilities"` // Serialized Vulnerabilities
	DBMS            string                 `json:"dbms"`
	DBMSVersion     string                 `json:"dbms_version"`
	Config          map[string]interface{} `json:"config"`
	Progress        float64                `json:"progress"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// ScanSummary is a lightweight session overview.
type ScanSummary struct {
	ID        string    `json:"id"`
	TargetURL string    `json:"target_url"`
	Progress  float64   `json:"progress"`
	DBMS      string    `json:"dbms"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store persists and retrieves scan state.
type Store interface {
	Save(ctx context.Context, state *ScanState) error
	Load(ctx context.Context, targetURL string) (*ScanState, error)
	LoadByID(ctx context.Context, id string) (*ScanState, error)
	List(ctx context.Context) ([]*ScanSummary, error)
	Delete(ctx context.Context, id string) error
	Close() error
}
