// Package report provides formatters for scan result output.
package report

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/0x6d61/sqleech/internal/engine"
)

// Reporter generates output in a specific format.
type Reporter interface {
	// Format returns the format name (e.g., "text", "json").
	Format() string

	// Generate writes the formatted scan result to w.
	Generate(ctx context.Context, result *engine.ScanResult, w io.Writer) error
}

// New creates a reporter by format name ("text" or "json").
// The format name is case-insensitive.
func New(format string) (Reporter, error) {
	switch strings.ToLower(format) {
	case "text":
		return &TextReporter{}, nil
	case "json":
		return &JSONReporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported report format: %q", format)
	}
}
