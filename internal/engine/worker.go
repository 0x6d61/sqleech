package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/0x6d61/sqleech/internal/transport"
)

// job represents a single detection task for one parameter + technique pair.
type job struct {
	parameter Parameter
	technique Technique
	baseline  *transport.Response
	dbms      string
}

// workerPool manages concurrent technique execution across multiple workers.
type workerPool struct {
	workers int
	jobs    chan job
	results chan Vulnerability
	wg      sync.WaitGroup
}

// newWorkerPool creates a pool with the given number of workers.
// The jobs channel is buffered at workers*2 to allow some pipelining.
func newWorkerPool(workers int) *workerPool {
	if workers <= 0 {
		workers = 1
	}
	return &workerPool{
		workers: workers,
		jobs:    make(chan job, workers*2),
		results: make(chan Vulnerability, workers*2),
	}
}

// start launches all worker goroutines. Each worker reads jobs from the
// jobs channel, executes the technique's Detect method, and sends any
// resulting Vulnerability to the results channel.
func (p *workerPool) start(ctx context.Context, client transport.Client, target *ScanTarget) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, client, target)
	}
}

// worker is the main loop for a single worker goroutine.
func (p *workerPool) worker(ctx context.Context, client transport.Client, target *ScanTarget) {
	defer p.wg.Done()

	for j := range p.jobs {
		// Recover from panics so one bad job does not crash the pool.
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("worker recovered from panic",
						"technique", j.technique.Name(),
						"parameter", j.parameter.Name,
						"panic", fmt.Sprintf("%v", r),
					)
				}
			}()

			// Check for context cancellation before running detection.
			if ctx.Err() != nil {
				return
			}

			req := &TechniqueRequest{
				Target:    target,
				Parameter: &j.parameter,
				Baseline:  j.baseline,
				DBMS:      j.dbms,
				Client:    client,
			}

			result, err := j.technique.Detect(ctx, req)
			if err != nil {
				slog.Debug("technique detection error",
					"technique", j.technique.Name(),
					"parameter", j.parameter.Name,
					"error", err,
				)
				return
			}

			vuln := Vulnerability{
				Parameter:  j.parameter,
				Technique:  j.technique.Name(),
				DBMS:       j.dbms,
				Injectable: result.Injectable,
				Confidence: result.Confidence,
				Evidence:   result.Evidence,
				Payload:    result.Payload,
			}

			if result.Injectable {
				vuln.Severity = classifySeverity(j.technique.Name(), result.Confidence)
			}

			p.results <- vuln
		}()
	}
}

// submit adds a job to the queue. It blocks if the jobs channel is full.
func (p *workerPool) submit(j job) {
	p.jobs <- j
}

// close signals that no more jobs will be submitted, then waits for all
// workers to finish and closes the results channel.
func (p *workerPool) close() {
	close(p.jobs)
	p.wg.Wait()
	close(p.results)
}

// classifySeverity assigns a severity level based on technique and confidence.
func classifySeverity(techniqueName string, confidence float64) Severity {
	switch {
	case confidence >= 0.9:
		return SeverityCritical
	case confidence >= 0.7:
		return SeverityHigh
	case confidence >= 0.5:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
