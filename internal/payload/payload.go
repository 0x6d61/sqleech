// Package payload provides SQL injection payload construction with
// context-aware boundary detection and encoding utilities.
package payload

// Payload represents a complete injection payload.
type Payload struct {
	Prefix    string // Boundary prefix to close original query context (e.g., "'" or ")")
	Core      string // The actual injection logic (e.g., "AND 1=1")
	Suffix    string // Boundary suffix (e.g., "-- -" or "#")
	Encoded   string // Final form after encoding
	Technique string // Which technique generated this (e.g., "error-based")
	DBMS      string // Target DBMS (e.g., "MySQL")
}

// String returns the full payload string (Prefix + Core + Suffix).
func (p *Payload) String() string {
	return p.Prefix + p.Core + p.Suffix
}

// Builder constructs payloads with context-aware boundaries.
type Builder struct {
	prefix    string
	core      string
	suffix    string
	technique string
	dbms      string
	encoders  []Encoder
}

// NewBuilder creates a new payload builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// WithPrefix sets the injection prefix.
func (b *Builder) WithPrefix(prefix string) *Builder {
	b.prefix = prefix
	return b
}

// WithCore sets the core payload expression.
func (b *Builder) WithCore(core string) *Builder {
	b.core = core
	return b
}

// WithSuffix sets the injection suffix.
func (b *Builder) WithSuffix(suffix string) *Builder {
	b.suffix = suffix
	return b
}

// WithTechnique sets the technique name.
func (b *Builder) WithTechnique(technique string) *Builder {
	b.technique = technique
	return b
}

// WithDBMS sets the target DBMS.
func (b *Builder) WithDBMS(dbms string) *Builder {
	b.dbms = dbms
	return b
}

// WithEncoder adds an encoder to the chain.
func (b *Builder) WithEncoder(enc Encoder) *Builder {
	b.encoders = append(b.encoders, enc)
	return b
}

// Build produces the final Payload.
func (b *Builder) Build() *Payload {
	p := &Payload{
		Prefix:    b.prefix,
		Core:      b.core,
		Suffix:    b.suffix,
		Technique: b.technique,
		DBMS:      b.dbms,
	}

	raw := p.String()

	if len(b.encoders) > 0 {
		encoded := raw
		for _, enc := range b.encoders {
			encoded = enc.Encode(encoded)
		}
		p.Encoded = encoded
	} else {
		p.Encoded = raw
	}

	return p
}
