# HeaderAnalyzer - HTTP Security Headers Analyzer

Analyzes HTTP response headers for security misconfigurations. Checks for missing security headers, insecure configurations, and provides remediation recommendations.

## Features

- Security header presence checking
- Missing header detection with severity ratings
- CSP (Content Security Policy) analysis
- HSTS configuration validation
- Cookie security flag analysis
- CORS misconfiguration detection
- Server information leakage detection
- JSON/HTML report generation
- Bulk URL analysis

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/headers-analyzer.git
cd headers-analyzer
pip3 install -r requirements.txt
chmod +x headeranalyzer.py
```

## Usage

### Analyze Single URL
```bash
python3 headeranalyzer.py analyze https://example.com
```

### Analyze with Verbose Output
```bash
python3 headeranalyzer.py analyze https://example.com --verbose
```

### Bulk Analysis
```bash
python3 headeranalyzer.py analyze -f urls.txt
```

### Generate Report
```bash
python3 headeranalyzer.py analyze https://example.com --report json --output report.json
python3 headeranalyzer.py analyze https://example.com --report html --output report.html
```

### Check Specific Headers
```bash
python3 headeranalyzer.py analyze https://example.com --check hsts,csp,xframe
```

### Cookie Analysis
```bash
python3 headeranalyzer.py cookies https://example.com
```

### CORS Check
```bash
python3 headeranalyzer.py cors https://example.com --origin https://evil.com
```

## Security Headers Checked

| Header | Severity | Description |
|--------|----------|-------------|
| Strict-Transport-Security | HIGH | HSTS enforcement |
| Content-Security-Policy | HIGH | XSS/injection protection |
| X-Frame-Options | MEDIUM | Clickjacking protection |
| X-Content-Type-Options | MEDIUM | MIME sniffing prevention |
| X-XSS-Protection | LOW | Legacy XSS filter |
| Referrer-Policy | MEDIUM | Referrer leakage control |
| Permissions-Policy | MEDIUM | Feature access control |
| Cross-Origin-Opener-Policy | MEDIUM | Cross-origin isolation |
| Cross-Origin-Resource-Policy | MEDIUM | Resource sharing control |
| Cache-Control | LOW | Sensitive data caching |

## Legal Disclaimer

Only analyze headers on websites you own or have authorization to test.

## License

MIT License
