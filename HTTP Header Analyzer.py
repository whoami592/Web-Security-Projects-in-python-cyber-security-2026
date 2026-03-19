#!/usr/bin/env python3
"""
HTTP Header Analyzer
Author: Mr. Sabaz Ali Khan (re-created / modernized style 2025–2026)
Purpose: Analyze security-relevant HTTP response headers
"""

import argparse
import sys
import urllib.parse
from typing import Dict, Optional

import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable only the InsecureRequestWarning (we know what we're doing)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class HttpHeaderAnalyzer:
    def __init__(self, url: str, timeout: float = 12.0, verify_ssl: bool = False):
        self.url = url.strip()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 HeaderAnalyzer/2025 (compatible; SecurityResearch)"
        })

    def fetch_headers(self) -> Optional[Dict[str, str]]:
        try:
            # We do HEAD first → faster and usually enough for headers
            resp = self.session.head(
                self.url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )

            # Some servers respond better to GET
            if resp.status_code >= 400:
                resp = self.session.get(
                    self.url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )

            if resp.status_code >= 400:
                print(f"✗ Status {resp.status_code} – cannot reliably read headers")
                return None

            return dict(resp.headers)

        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e.__class__.__name__}")
            if "SSL" in str(e):
                print("  → Try again with --no-ssl-verify")
            return None

    @staticmethod
    def evaluate_security_headers(headers: Dict[str, str]) -> list:
        findings = []

        h = {k.lower(): v for k, v in headers.items()}  # case-insensitive

        # ┌─────────────────────────────┐
        # │       MUST HAVE headers     │
        # └─────────────────────────────┘

        # 1. Strict-Transport-Security
        if "strict-transport-security" not in h:
            findings.append(("✗ MISSING", "Strict-Transport-Security", "Site is missing HSTS"))
        else:
            val = h["strict-transport-security"].lower()
            if "max-age=0" in val or "max-age=31536000" not in val:
                findings.append(("⚠ WEAK", "HSTS", "max-age too short or disabled"))
            if "includesubdomains" not in val:
                findings.append(("ℹ INFO", "HSTS", "missing includeSubDomains (recommended)"))
            if "preload" not in val:
                findings.append(("ℹ INFO", "HSTS", "missing preload (optional but good)"))

        # 2. X-Content-Type-Options
        if "x-content-type-options" not in h or "nosniff" not in h["x-content-type-options"].lower():
            findings.append(("✗ MISSING/WEAK", "X-Content-Type-Options", "Should be: nosniff"))

        # 3. X-Frame-Options
        if "x-frame-options" not in h:
            findings.append(("✗ MISSING", "X-Frame-Options", "Clickjacking protection missing"))
        elif "deny" not in h["x-frame-options"].lower() and "sameorigin" not in h["x-frame-options"].lower():
            findings.append(("⚠ WEAK", "X-Frame-Options", "Value should be DENY or SAMEORIGIN"))

        # 4. Content-Security-Policy
        if "content-security-policy" not in h:
            findings.append(("✗ MISSING", "Content-Security-Policy", "Strong CSP is highly recommended"))
        else:
            csp = h["content-security-policy"].lower()
            if "default-src 'none'" in csp or "default-src 'self'" in csp:
                findings.append(("✓ GOOD", "CSP", "restrictive default-src found"))
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                findings.append(("⚠ DANGEROUS", "CSP", "Contains unsafe-inline or unsafe-eval"))

        # 5. Referrer-Policy
        if "referrer-policy" not in h:
            findings.append(("⚠ MISSING", "Referrer-Policy", "Recommended: strict-origin-when-cross-origin or same-origin"))
        else:
            rp = h["referrer-policy"].lower()
            if "no-referrer" in rp or "strict-origin" in rp or "same-origin" in rp:
                findings.append(("✓ GOOD", "Referrer-Policy", rp))
            elif "unsafe-url" in rp:
                findings.append(("✗ BAD", "Referrer-Policy", "unsafe-url leaks full referrer"))

        # 6. Permissions-Policy (formerly Feature-Policy)
        if "permissions-policy" not in h and "feature-policy" not in h:
            findings.append(("ℹ INFO", "Permissions-Policy", "Consider adding to restrict dangerous features"))
        elif "geolocation=()" in h.get("permissions-policy", "") or "camera=()" in h.get("permissions-policy", ""):
            findings.append(("✓ GOOD", "Permissions-Policy", "Dangerous features disabled"))

        # 7. Cross-Origin policies (modern)
        for header in ["cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy"]:
            if header not in h:
                findings.append(("ℹ INFO", header.title(), "Consider setting (COOP/COEP/COEP) for better isolation"))

        return findings

    def print_report(self, headers: Dict[str, str]):
        print(f"\n{'═' * 70}")
        print(f"  HTTP Header Analysis Report")
        print(f"  Target : {self.url}")
        print(f"  Status : {headers.get('Status', '—')}")
        print(f"{'═' * 70}\n")

        # All headers (sorted)
        print("→ Received Headers:")
        for k, v in sorted(headers.items()):
            if k.lower() == "set-cookie":
                print(f"  {k: <28} : {v[:80]}{'...' if len(v)>80 else ''}")
            else:
                print(f"  {k: <28} : {v}")

        print("\n→ Security Findings:")
        findings = self.evaluate_security_headers(headers)

        if not findings:
            print("  ✓ All important security headers look good!")
        else:
            for level, header, msg in sorted(findings, key=lambda x: ("A" if "✗" in x[0] else "B" if "⚠" in x[0] else "C")):
                print(f"  {level}  {header: <24} → {msg}")

        print()


def main():
    parser = argparse.ArgumentParser(description="HTTP Security Header Analyzer by Mr. Sabaz Ali Khan style")
    parser.add_argument("url", help="Target URL (http:// or https://)")
    parser.add_argument("--timeout", type=float, default=12.0, help="Request timeout")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--get", action="store_true", help="Use GET instead of HEAD")

    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    analyzer = HttpHeaderAnalyzer(
        url=args.url,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify
    )

    headers = analyzer.fetch_headers()
    if not headers:
        sys.exit(1)

    analyzer.print_report(headers)


if __name__ == "__main__":
    main()
