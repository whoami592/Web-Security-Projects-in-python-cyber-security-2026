#!/usr/bin/env python3
"""
Cookie Security Analyzer
========================

A powerful CLI tool to analyze HTTP cookies for security vulnerabilities
and best practices (Secure, HttpOnly, SameSite, Domain scope, expiration, etc.).

🔒 Checks for:
- Missing Secure flag (MITM risk)
- Missing HttpOnly flag (XSS risk)
- Weak SameSite (CSRF risk)
- Overly broad Domain/Path
- Sensitive cookie names without strong protection
- Expiration & Max-Age issues

Coded by: Mr. Sabaz Ali Khan
Cyber Security Expert | Ethical Hacker | Penetration Tester
GitHub: whoami592

Disclaimer:
This tool is for educational and ethical pentesting purposes only.
Mr. Sabaz Ali Khan and the author are not responsible for any misuse.

Usage:
    python cookie_security_analyzer.py "session=abc123; Secure; HttpOnly; SameSite=Strict"
    python cookie_security_analyzer.py -f cookies.txt          # one Set-Cookie per line
"""

import argparse
import sys
from http.cookies import SimpleCookie
from datetime import datetime
import re

# ANSI colors for beautiful output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def print_banner():
    print(f"""{Colors.BOLD}{Colors.BLUE}
╔════════════════════════════════════════════════════════════╗
║           COOKIE SECURITY ANALYZER v1.0                    ║
║           Coded by Mr. Sabaz Ali Khan                      ║
║     Ethical Hacker | Penetration Tester | Pakistan         ║
╚════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

class CookieSecurityAnalyzer:
    SENSITIVE_NAMES = [
        "session", "sess", "auth", "token", "jwt", "sid", "csrf", "api_key",
        "user", "login", "admin", "id_token", "refresh"
    ]

    def __init__(self):
        self.results = []

    def parse_cookie(self, cookie_str: str):
        """Parse a single Set-Cookie string"""
        # Remove "Set-Cookie:" prefix if present
        cookie_str = re.sub(r"^Set-Cookie:\s*", "", cookie_str.strip(), flags=re.IGNORECASE)

        cookie = SimpleCookie()
        cookie.load(cookie_str)

        for morsel in cookie.values():
            name = morsel.key
            value = morsel.value
            attrs = {
                "secure": bool(morsel.get("secure")),
                "httponly": bool(morsel.get("httponly")),
                "samesite": morsel.get("samesite", "").lower() if morsel.get("samesite") else None,
                "domain": morsel.get("domain"),
                "path": morsel.get("path") or "/",
                "expires": morsel.get("expires"),
                "max_age": morsel.get("max-age"),
            }
            self.analyze(name, value, attrs)

    def analyze(self, name: str, value: str, attrs: dict):
        """Perform security analysis and scoring"""
        issues = []
        score = 100
        recommendations = []

        # === CRITICAL FLAGS ===
        if not attrs["secure"]:
            issues.append("❌ Missing Secure flag → Cookie can be sent over HTTP (MITM)")
            score -= 25
            recommendations.append("Add 'Secure' flag")

        if not attrs["httponly"]:
            issues.append("❌ Missing HttpOnly flag → Vulnerable to XSS attacks")
            score -= 25
            recommendations.append("Add 'HttpOnly' flag")

        # SameSite
        if not attrs["samesite"]:
            issues.append("❌ Missing SameSite → High CSRF risk")
            score -= 25
            recommendations.append("Set SameSite=Strict or Lax")
        elif attrs["samesite"] == "none":
            if not attrs["secure"]:
                issues.append("⚠️  SameSite=None without Secure flag → Invalid & insecure")
                score -= 15
            else:
                issues.append("⚠️  SameSite=None → Only use when absolutely necessary")
                score -= 5
            recommendations.append("Prefer SameSite=Strict for sensitive cookies")
        elif attrs["samesite"] not in ["strict", "lax"]:
            issues.append(f"⚠️  Weak SameSite={attrs['samesite']} → CSRF risk")
            score -= 15

        # Domain & Path scope
        if attrs["domain"] and (attrs["domain"].startswith(".") or len(attrs["domain"].split(".")) > 2):
            issues.append(f"⚠️  Broad domain '{attrs['domain']}' → Subdomain cookie leakage risk")
            score -= 10
            recommendations.append("Use exact domain (no leading dot)")

        if attrs["path"] != "/" and attrs["path"] != "":
            issues.append(f"ℹ️  Custom path '{attrs['path']}' → Slightly better scope")
        else:
            issues.append("⚠️  Path=/ → Cookie sent to all paths on site")

        # Expiration
        has_expiry = bool(attrs["expires"] or attrs["max_age"])
        if not has_expiry:
            if any(s in name.lower() for s in self.SENSITIVE_NAMES):
                issues.append("⚠️  Sensitive cookie with no expiration → Persistent session risk")
                score -= 10
                recommendations.append("Add Expires or Max-Age")
        else:
            issues.append("✅ Has expiration (good)")

        # Sensitive name detection
        is_sensitive = any(s in name.lower() for s in self.SENSITIVE_NAMES)
        if is_sensitive and (score < 80):
            issues.append(f"🔥 Sensitive name '{name}' + weak protection = HIGH RISK")
            score -= 10

        # Final score clamp
        score = max(0, min(100, score))

        # Color coding
        if score >= 85:
            color = Colors.GREEN
            rating = "EXCELLENT"
        elif score >= 65:
            color = Colors.YELLOW
            rating = "MEDIUM"
        else:
            color = Colors.RED
            rating = "CRITICAL"

        self.results.append({
            "name": name,
            "value_preview": value[:30] + "..." if len(value) > 30 else value,
            "score": score,
            "rating": rating,
            "color": color,
            "issues": issues,
            "recommendations": recommendations,
            "attrs": attrs
        })

    def print_report(self):
        """Beautiful terminal report"""
        print_banner()

        if not self.results:
            print(f"{Colors.RED}No cookies provided!{Colors.RESET}")
            return

        total_score = sum(r["score"] for r in self.results) / len(self.results)
        print(f"{Colors.BOLD}Overall Security Score: {Colors.GREEN if total_score >= 80 else Colors.RED}{total_score:.1f}/100{Colors.RESET}\n")

        for result in self.results:
            print(f"{result['color']}{Colors.BOLD}🍪 Cookie: {result['name']}{Colors.RESET}")
            print(f"   Score     : {result['color']}{result['score']}/100 ({result['rating']}){Colors.RESET}")
            print(f"   Value     : {result['value_preview']}")
            print(f"   Secure    : {'✅' if result['attrs']['secure'] else '❌'}")
            print(f"   HttpOnly  : {'✅' if result['attrs']['httponly'] else '❌'}")
            print(f"   SameSite  : {result['attrs']['samesite'] or 'None'}")

            if result["issues"]:
                print(f"   {Colors.YELLOW}Issues:{Colors.RESET}")
                for issue in result["issues"]:
                    print(f"      {issue}")

            if result["recommendations"]:
                print(f"   {Colors.BLUE}Recommendations:{Colors.RESET}")
                for rec in result["recommendations"]:
                    print(f"      → {rec}")

            print("-" * 70)

        print(f"\n{Colors.BOLD}{Colors.BLUE}Tool Coded by Mr. Sabaz Ali Khan{Colors.RESET}")
        print(f"{Colors.YELLOW}Use responsibly - Ethical Hacking Only!{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(description="Cookie Security Analyzer by Mr. Sabaz Ali Khan")
    parser.add_argument("cookies", nargs="*", help="One or more Set-Cookie strings")
    parser.add_argument("-f", "--file", help="Read cookies from a text file (one per line)")
    args = parser.parse_args()

    analyzer = CookieSecurityAnalyzer()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        analyzer.parse_cookie(line)
        except FileNotFoundError:
            print(f"{Colors.RED}File not found: {args.file}{Colors.RESET}")
            sys.exit(1)
    elif args.cookies:
        for cookie_str in args.cookies:
            analyzer.parse_cookie(cookie_str)
    else:
        # Interactive mode if nothing provided
        print(f"{Colors.YELLOW}Enter Set-Cookie strings (one per line). Type 'done' when finished:{Colors.RESET}")
        while True:
            line = input("> ").strip()
            if line.lower() == "done":
                break
            if line:
                analyzer.parse_cookie(line)

    analyzer.print_report()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Analysis stopped by user. Stay safe!{Colors.RESET}")