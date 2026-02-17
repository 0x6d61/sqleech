# sqleech

Next-generation SQL injection testing tool written in Go.

> **WARNING**: This tool is intended for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## Features

- **High Performance**: Concurrent scanning with goroutine-based worker pool (10-100x faster than traditional tools)
- **Zero Dependencies**: Single binary deployment — no runtime required
- **Multiple Techniques**: Error-based, Boolean-blind, Time-blind, UNION-based, Stacked queries
- **DBMS Support**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- **Smart Detection**: Statistical response analysis with adaptive thresholds
- **WAF Bypass**: Built-in tamper system with 20+ evasion modules
- **Modern Targets**: GraphQL, JSON body, REST API parameter injection
- **CI/CD Ready**: JSON and SARIF output for DevSecOps integration
- **Session Resume**: Save and resume interrupted scans
- **Library Mode**: Use as a Go library in your own tools

## Installation

```bash
go install github.com/0x6d61/sqleech/cmd/sqleech@latest
```

## Quick Start

```bash
# Basic scan
sqleech scan -u "http://target.com/page?id=1"

# POST request scan
sqleech scan -u "http://target.com/login" -d "user=admin&pass=test" --method POST

# With proxy and specific techniques
sqleech scan -u "http://target.com/page?id=1" --proxy http://127.0.0.1:8080 --technique B,E

# JSON output
sqleech scan -u "http://target.com/page?id=1" -f json -o result.json
```

## Build

```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
make all      # Format, vet, lint, test, build
```

## License

MIT License - see [LICENSE](LICENSE) for details.
