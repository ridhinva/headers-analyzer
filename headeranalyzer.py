#!/usr/bin/env python3
"""
HeaderAnalyzer - HTTP Security Headers Analyzer
For authorized security testing only.
"""

import argparse
import sys
import json
import csv
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections via HSTS",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "check": "hsts",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Prevents XSS and injection attacks",
        "recommendation": "Add a strict CSP policy appropriate for your application",
        "check": "csp",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing needed)",
        "check": "xframe",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME type sniffing",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "check": "xcontenttype",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated but still useful for older browsers)",
        "recommendation": "Add: X-XSS-Protection: 0 (prefer CSP over this header)",
        "check": "xxss",
    },
    "Referrer-Policy": {
        "severity": "MEDIUM",
        "description": Controls referrer information leakage",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "check": "referrer",
    },
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "description": "Controls browser feature access (camera, mic, geolocation, etc.)",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "check": "permissions",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "MEDIUM",
        "description": "Controls cross-origin window interactions",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
        "check": "coop",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "MEDIUM",
        "description": "Controls cross-origin resource loading",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
        "check": "corp",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "LOW",
        "description": "Controls cross-origin embedding",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
        "check": "coep",
    },
}

HEADERS_TO_REMOVE = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish",
]


class HeaderAnalyzer:
    def __init__(self, url, timeout=10):
        self.url = self._normalize_url(url)
        self.timeout = timeout
        self.headers = {}
        self.findings = []
        self.score = 100

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def fetch_headers(self):
        """Fetch HTTP headers from target URL."""
        try:
            resp = requests.get(self.url, timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": "HeaderAnalyzer/1.0 (Security Audit)"})
            self.headers = dict(resp.headers)
            self.status_code = resp.status_code
            self.final_url = resp.url
            return True
        except requests.exceptions.SSLError:
            try:
                resp = requests.get(self.url.replace('https://', 'http://'), timeout=self.timeout,
                                    allow_redirects=True, verify=False)
                self.headers = dict(resp.headers)
                self.status_code = resp.status_code
                self.final_url = resp.url
                self.findings.append({
                    "severity": "HIGH",
                    "issue": "SSL/TLS Error - site may not support HTTPS properly",
                    "detail": str(resp),
                })
                return True
            except Exception as e:
                self.findings.append({"severity": "CRITICAL", "issue": f"Connection failed: {e}"})
                return False
        except Exception as e:
            self.findings.append({"severity": "CRITICAL", "issue": f"Connection failed: {e}"})
            return False

    def check_security_headers(self, checks=None):
        """Check for security headers."""
        for header, info in SECURITY_HEADERS.items():
            if checks and info["check"] not in checks:
                continue

            if header.lower() in {k.lower(): k for k in self.headers}:
                value = next(v for k, v in self.headers.items() if k.lower() == header.lower())
                self._analyze_header_value(header, value, info)
            else:
                severity = info["severity"]
                self.score -= {"HIGH": 15, "MEDIUM": 8, "LOW": 4}.get(severity, 0)
                self.findings.append({
                    "severity": severity,
                    "issue": f"Missing header: {header}",
                    "description": info["description"],
                    "recommendation": info["recommendation"],
                })

    def _analyze_header_value(self, header, value, info):
        """Analyze specific header values for misconfigurations."""
        value_lower = value.lower()

        if header == "Strict-Transport-Security":
            if "max-age=0" in value_lower:
                self.score -= 15
                self.findings.append({
                    "severity": "HIGH",
                    "issue": "HSTS max-age is 0 (disabled)",
                    "value": value,
                    "recommendation": "Set max-age to at least 31536000 (1 year)",
                })
            elif "max-age" in value_lower:
                import re
                match = re.search(r'max-age=(\d+)', value_lower)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:
                        self.score -= 5
                        self.findings.append({
                            "severity": "MEDIUM",
                            "issue": f"HSTS max-age too short ({max_age}s < 31536000s)",
                            "value": value,
                        })
            if "includesubdomains" not in value_lower:
                self.score -= 3
                self.findings.append({
                    "severity": "LOW",
                    "issue": "HSTS missing includeSubDomains directive",
                    "value": value,
                })

        elif header == "X-Frame-Options":
            if value_lower not in ("deny", "sameorigin"):
                self.score -= 5
                self.findings.append({
                    "severity": "MEDIUM",
                    "issue": f"X-Frame-Options has non-standard value: {value}",
                    "recommendation": "Use DENY or SAMEORIGIN",
                })

        elif header == "Content-Security-Policy":
            if "unsafe-inline" in value_lower:
                self.score -= 10
                self.findings.append({
                    "severity": "HIGH",
                    "issue": "CSP allows unsafe-inline (weakens XSS protection)",
                    "value": value[:100],
                })
            if "unsafe-eval" in value_lower:
                self.score -= 10
                self.findings.append({
                    "severity": "HIGH",
                    "issue": "CSP allows unsafe-eval (weakens injection protection)",
                    "value": value[:100],
                })
            if "*" in value and "default-src" in value_lower:
                self.score -= 8
                self.findings.append({
                    "severity": "MEDIUM",
                    "issue": "CSP default-src uses wildcard (*)",
                    "value": value[:100],
                })

    def check_information_leakage(self):
        """Check for server information leakage."""
        for header in HEADERS_TO_REMOVE:
            if header.lower() in {k.lower(): k for k in self.headers}:
                value = next(v for k, v in self.headers.items() if k.lower() == header.lower())
                self.score -= 3
                self.findings.append({
                    "severity": "LOW",
                    "issue": f"Information leakage: {header} header present",
                    "value": value,
                    "recommendation": f"Remove the {header} header from responses",
                })

    def check_cookies(self):
        """Check cookie security flags."""
        cookies = []
        for key, value in self.headers.items():
            if key.lower() == "set-cookie":
                cookies.append(value)

        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()
            issues = []

            if "secure" not in cookie_lower:
                issues.append("Missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute")

            if issues:
                self.score -= 3
                self.findings.append({
                    "severity": "MEDIUM",
                    "issue": f"Cookie '{cookie_name}' security issues",
                    "detail": "; ".join(issues),
                })

        return cookies

    def check_cors(self, test_origin=None):
        """Check CORS configuration."""
        if not test_origin:
            test_origin = "https://evil.com"

        try:
            resp = requests.get(self.url, timeout=self.timeout,
                                headers={"Origin": test_origin,
                                         "User-Agent": "HeaderAnalyzer/1.0"})
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self.score -= 15
                self.findings.append({
                    "severity": "HIGH",
                    "issue": "CORS allows all origins (*)",
                    "value": acao,
                    "recommendation": "Restrict CORS to specific trusted origins",
                })
            elif acao == test_origin:
                self.score -= 10
                self.findings.append({
                    "severity": "HIGH",
                    "issue": f"CORS reflects arbitrary origin: {test_origin}",
                    "value": acao,
                    "recommendation": "Do not reflect Origin header in CORS response",
                })
        except:
            pass

    def analyze(self, checks=None, check_cors=False, cors_origin=None):
        """Run full analysis."""
        if not self.fetch_headers():
            return

        self.check_security_headers(checks)
        self.check_information_leakage()
        self.check_cookies()
        if check_cors:
            self.check_cors(cors_origin)

        self.score = max(0, min(100, self.score))

    def print_results(self, verbose=False):
        """Print analysis results."""
        print(f"\n  {Fore.WHITE}URL:{Style.RESET_ALL} {self.url}")
        if hasattr(self, 'final_url') and self.final_url != self.url:
            print(f"  {Fore.WHITE}Final URL:{Style.RESET_ALL} {self.final_url}")
        if hasattr(self, 'status_code'):
            print(f"  {Fore.WHITE}Status:{Style.RESET_ALL} {self.status_code}")

        # Score
        if self.score >= 80:
            score_color = Fore.GREEN
            rating = "Good"
        elif self.score >= 60:
            score_color = Fore.YELLOW
            rating = "Fair"
        elif self.score >= 40:
            score_color = Fore.RED
            rating = "Poor"
        else:
            score_color = Fore.RED
            rating = "Critical"

        print(f"\n  {Fore.WHITE}Security Score:{Style.RESET_ALL} {score_color}{self.score}/100 ({rating}){Style.RESET_ALL}")

        # Findings
        if self.findings:
            high = [f for f in self.findings if f["severity"] == "HIGH"]
            medium = [f for f in self.findings if f["severity"] == "MEDIUM"]
            low = [f for f in self.findings if f["severity"] == "LOW"]
            crit = [f for f in self.findings if f["severity"] == "CRITICAL"]

            print(f"\n  {Fore.RED}Critical: {len(crit)}{Style.RESET_ALL} | "
                  f"{Fore.RED}High: {len(high)}{Style.RESET_ALL} | "
                  f"{Fore.YELLOW}Medium: {len(medium)}{Style.RESET_ALL} | "
                  f"{Fore.CYAN}Low: {len(low)}{Style.RESET_ALL}")

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                items = [f for f in self.findings if f["severity"] == severity]
                if items:
                    color = {"CRITICAL": Fore.RED, "HIGH": Fore.RED,
                             "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN}[severity]
                    for f in items:
                        print(f"\n  {color}[{severity}]{Style.RESET_ALL} {f['issue']}")
                        if verbose:
                            if "value" in f:
                                print(f"    Value: {f['value']}")
                            if "detail" in f:
                                print(f"    Detail: {f['detail']}")
                            if "recommendation" in f:
                                print(f"    Fix: {Fore.GREEN}{f['recommendation']}{Style.RESET_ALL}")
        else:
            print(f"\n  {Fore.GREEN}[+] No security issues found!{Style.RESET_ALL}")

        # Present headers
        if verbose and self.headers:
            print(f"\n  {Fore.WHITE}Response Headers:{Style.RESET_ALL}")
            for key, value in self.headers.items():
                print(f"    {key}: {value[:100]}")

    def export_json(self, filename):
        report = {
            "tool": "HeaderAnalyzer",
            "version": VERSION,
            "url": self.url,
            "scan_time": datetime.now().isoformat(),
            "score": self.score,
            "headers": self.headers,
            "findings": self.findings,
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")

    def export_html(self, filename):
        severity_colors = {"CRITICAL": "#ff0000", "HIGH": "#ff4444", "MEDIUM": "#ffaa00", "LOW": "#00aaff"}
        findings_html = ""
        for f in self.findings:
            color = severity_colors.get(f["severity"], "#ffffff")
            findings_html += f'<tr><td style="color:{color}">{f["severity"]}</td><td>{f["issue"]}</td>'
            findings_html += f'<td>{f.get("recommendation", "N/A")}</td></tr>\n'

        html = f"""<!DOCTYPE html>
<html><head><title>HeaderAnalyzer Report - {self.url}</title>
<style>
body {{ font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
h1 {{ color: #00ffff; }} .score {{ font-size: 24px; font-weight: bold; }}
.good {{ color: #00ff00; }} .fair {{ color: #ffaa00; }} .poor {{ color: #ff4444; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
th {{ background: #333; color: #00ffff; }}
</style></head><body>
<h1>HeaderAnalyzer Security Report</h1>
<p>Target: {self.url}</p>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p class="score">Score: {self.score}/100</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Issue</th><th>Recommendation</th></tr>
{findings_html}</table>
</body></html>"""
        with open(filename, 'w') as f:
            f.write(html)
        print(f"\n{Fore.GREEN}[+] HTML report saved to {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="HeaderAnalyzer - HTTP Security Headers Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze https://example.com
  %(prog)s analyze https://example.com --verbose
  %(prog)s analyze -f urls.txt --report json --output report.json
  %(prog)s cookies https://example.com
  %(prog)s cors https://example.com --origin https://evil.com
        """
    )

    sub = parser.add_subparsers(dest="command")

    # analyze
    a = sub.add_parser("analyze", help="Analyze security headers")
    a.add_argument("url", nargs="?", help="Target URL")
    a.add_argument("-f", "--file", help="File with URLs")
    a.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    a.add_argument("--check", help="Specific checks (comma-separated: hsts,csp,xframe,...)")
    a.add_argument("--cors", action="store_true", help="Include CORS check")
    a.add_argument("--report", choices=["json", "html"], help="Report format")
    a.add_argument("--output", help="Output filename")

    # cookies
    c = sub.add_parser("cookies", help="Analyze cookie security")
    c.add_argument("url", help="Target URL")

    # cors
    co = sub.add_parser("cors", help="Check CORS configuration")
    co.add_argument("url", help="Target URL")
    co.add_argument("--origin", default="https://evil.com", help="Test origin")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║  HeaderAnalyzer v{VERSION}          ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    urls = []
    if hasattr(args, 'url') and args.url:
        urls = [args.url]
    elif hasattr(args, 'file') and args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print(f"{Fore.RED}[!] No URL provided{Style.RESET_ALL}")
        sys.exit(1)

    checks = args.check.split(",") if hasattr(args, 'check') and args.check else None

    for url in urls:
        analyzer = HeaderAnalyzer(url)

        if args.command == "analyze":
            analyzer.analyze(checks=checks, check_cors=getattr(args, 'cors', False))
            analyzer.print_results(verbose=getattr(args, 'verbose', False))

            if hasattr(args, 'report') and args.report:
                if args.report == "json":
                    analyzer.export_json(args.output or "header_report.json")
                elif args.report == "html":
                    analyzer.export_html(args.output or "header_report.html")

        elif args.command == "cookies":
            if analyzer.fetch_headers():
                cookies = analyzer.check_cookies()
                analyzer.print_results(verbose=True)

        elif args.command == "cors":
            analyzer.analyze(check_cors=True, cors_origin=args.origin)
            analyzer.print_results(verbose=True)


if __name__ == "__main__":
    main()
