# SecureAPI Analyzer - REST API Security Testing Tool

An automated security testing tool for REST APIs, focused on authentication, authorization, and OWASP Top 10 vulnerabilities. Built for penetration testers and security engineers who need fast, repeatable API security assessments.

## Features

- **Authentication Bypass Detection** - Tests for missing auth, empty tokens, malformed JWTs, algorithm confusion (alg:none), and expired token acceptance
- **Broken Access Control** - Horizontal/vertical privilege escalation, IDOR, HTTP method tampering, parameter pollution
- **Rate Limiting Analysis** - Brute force detection, API rate limit verification, account lockout testing
- **Input Validation** - SQL injection, XSS, command injection, NoSQL injection payloads
- **OpenAPI/Swagger Integration** - Automatically discovers endpoints from API specifications
- **Multiple Report Formats** - JSON, HTML, and Markdown reports with CVSS scoring
- **OWASP Top 10 Mapping** - Every finding mapped to the corresponding OWASP category with remediation guidance

## Architecture

```
secure-api-analyzer/
├── cli.py                  # Click-based CLI entry point
├── src/
│   ├── analyzer.py         # Core orchestration engine
│   ├── config.py           # YAML configuration loader
│   ├── reporter.py         # Report generation (JSON/HTML/MD)
│   ├── utils.py            # JWT utilities, HTTP helpers
│   └── tests/
│       ├── auth_bypass.py      # Authentication bypass tests
│       ├── broken_access.py    # Authorization & IDOR tests
│       ├── rate_limiting.py    # Rate limit & brute force tests
│       └── input_validation.py # Injection & validation tests
├── tests/                  # Unit tests (pytest)
├── configs/
│   ├── default.yaml        # Default test configuration
│   └── owasp_payloads.yaml # Curated attack payloads
├── templates/
│   └── report.html         # Jinja2 HTML report template
└── requirements.txt
```

## Setup

```bash
# Clone the repository
git clone https://github.com/jalal-essmail/secure-api-analyzer.git
cd secure-api-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic scan against a target API

```bash
python cli.py analyze --target https://api.example.com --config configs/default.yaml
```

### Scan with authentication token

```bash
python cli.py analyze \
    --target https://api.example.com \
    --token "eyJhbGciOiJIUzI1NiIs..." \
    --config configs/default.yaml \
    --verbose
```

### Scan using an OpenAPI specification

```bash
python cli.py analyze \
    --target https://api.example.com \
    --spec openapi.json \
    --config configs/default.yaml
```

### Generate a report from saved results

```bash
python cli.py report \
    --input results/scan_2026-04-20.json \
    --format html \
    --output report.html
```

### Run specific test suites only

```bash
python cli.py analyze \
    --target https://api.example.com \
    --suite auth_bypass \
    --suite broken_access \
    --verbose
```

## Example Output

```
$ python cli.py analyze --target https://api.example.com --verbose

 SecureAPI Analyzer v1.0.0
 Target: https://api.example.com
 Suites: auth_bypass, broken_access, rate_limiting, input_validation

[AUTH_BYPASS] Testing endpoint: POST /api/v1/login
  [CRITICAL] Missing auth header accepted - returned 200 instead of 401
  [HIGH]     Algorithm none attack: token accepted without signature
  [MEDIUM]   Expired token (exp: 2024-01-01) still accepted

[BROKEN_ACCESS] Testing endpoint: GET /api/v1/users/{id}/profile
  [HIGH] Horizontal privilege escalation: user_123 can access user_456 data
  [HIGH] Method tampering: DELETE allowed without admin role

[RATE_LIMITING] Testing endpoint: POST /api/v1/login
  [MEDIUM] No rate limit detected after 100 requests in 5 seconds

[INPUT_VALIDATION] Testing endpoint: GET /api/v1/search
  [HIGH] SQL injection: payload "' OR 1=1--" returned 200 with data leak

 Scan Complete
 Findings: 4 Critical, 8 High, 3 Medium, 1 Low
 Report saved to: results/scan_2026-04-23_143022.json
```

## OWASP Top 10 API Security (2023) Mapping

| OWASP Category | Test Suite | Tests Implemented |
|---|---|---|
| API1:2023 - Broken Object Level Authorization | `broken_access` | IDOR, horizontal privilege escalation |
| API2:2023 - Broken Authentication | `auth_bypass` | Missing auth, JWT attacks, expired tokens |
| API3:2023 - Broken Object Property Level Authorization | `broken_access` | Mass assignment, property-level access |
| API4:2023 - Unrestricted Resource Consumption | `rate_limiting` | Rate limits, brute force, resource exhaustion |
| API5:2023 - Broken Function Level Authorization | `broken_access` | Vertical escalation, method tampering |
| API6:2023 - Unrestricted Access to Sensitive Business Flows | `rate_limiting` | Account lockout, flow abuse |
| API7:2023 - Server Side Request Forgery | `input_validation` | SSRF payloads in parameters |
| API8:2023 - Security Misconfiguration | `auth_bypass` | CORS, headers, verbose errors |
| API9:2023 - Improper Inventory Management | `analyzer` | Endpoint discovery from specs |
| API10:2023 - Unsafe Consumption of APIs | `input_validation` | Injection in API responses |

## Configuration

Edit `configs/default.yaml` to customize:

```yaml
scan:
  timeout: 30
  max_concurrent: 10
  follow_redirects: false

suites:
  auth_bypass:
    enabled: true
    jwt_algorithms: ["none", "HS256", "RS256"]
  broken_access:
    enabled: true
    test_users:
      - role: user
        token: "Bearer ..."
      - role: admin
        token: "Bearer ..."
```

## Running Tests

```bash
pytest tests/ -v
```

## Disclaimer

This tool is intended for authorized security testing only. Always obtain written permission before testing any API you do not own. Unauthorized testing may violate laws and terms of service.

## License

MIT License - see [LICENSE](LICENSE)

## Author

**J. Essmail** - Security Engineering Student
