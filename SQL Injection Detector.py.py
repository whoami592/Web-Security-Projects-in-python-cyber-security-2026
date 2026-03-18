#!/usr/bin/env python3
# =====================================================
# SQL INJECTION DETECTOR
# =====================================================
# Coded by: Mr. Sabaz Ali Khan
# GitHub: whoami592
# Role: Certified Ethical Hacker & Cyber Security Expert
# Language: Python 3
# Purpose: Real-time detection of SQL Injection payloads
#           in user inputs, URLs, forms, or logs.
# =====================================================
# WARNING:
# This is a heuristic detector (regex + payload matching).
# It is NOT 100% accurate. Always use prepared statements
# (parameterized queries) in your real applications.
# This tool is for educational & defensive purposes only.
# =====================================================

import re
import sys
from urllib.parse import urlparse, parse_qs

# ==================== PAYLOAD DATABASE ====================
# Common SQLi patterns (case-insensitive)
SQLI_PATTERNS = [
    # Classic tautologies
    r"(\bor\b|\band\b)\s*(\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*')",
    r"1\s*=\s*1",
    r"'.*?'\s*=\s*'.*?'",
    
    # Statement terminators & comments
    r"(;|--|/\*|\*/|@@|char\()",
    
    # Dangerous keywords
    r"\b(select|union|insert|update|delete|drop|exec|declare|cast|convert|xp_|sp_|information_schema)\b",
    
    # Time-based / Blind
    r"(sleep|benchmark|waitfor\s+delay|pg_sleep)",
    
    # Error-based
    r"(extractvalue|updatexml|dbms_xmlgen|name_const)",
    
    # Hex / Unicode evasion
    r"0x[0-9a-f]+",
    r"\\x[0-9a-f]{2}",
    
    # Out-of-band
    r"(load_file|into outfile|into dumpfile)",
    
    # Common bypass attempts
    r"admin'--",
    r"or '1'='1",
    r"or 1=1--",
    r"'; drop table",
    r"1' or '1'='1",
]

# ==================== DETECTION FUNCTION ====================
def detect_sql_injection(text: str) -> tuple:
    """
    Returns (is_injected: bool, message: str, matched_pattern: str)
    """
    if not text or len(text.strip()) == 0:
        return False, "Empty input", None

    text_lower = text.lower()

    for pattern in SQLI_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            return True, f"🚨 SQL INJECTION DETECTED!", match.group(0)

    # Extra URL parameter check
    try:
        parsed = urlparse(text)
        if parsed.query:
            params = parse_qs(parsed.query)
            for values in params.values():
                for val in values:
                    if any(re.search(p, val.lower()) for p in SQLI_PATTERNS):
                        return True, "🚨 SQL INJECTION DETECTED in URL parameters!", val
    except:
        pass

    return False, "✅ Input appears SAFE", None


# ==================== CLI INTERFACE ====================
def main():
    print("=" * 60)
    print("🔒 SQL INJECTION DETECTOR - by Mr. Sabaz Ali Khan")
    print("🔥 Ethical Hacking Tool | Version 1.0")
    print("=" * 60)
    print("Usage:")
    print("   1. Run without args → Interactive mode")
    print("   2. python detector.py \"your input here\"")
    print("   3. Pipe input: echo \"payload\" | python detector.py")
    print("=" * 60)

    # Command line argument mode
    if len(sys.argv) > 1:
        input_text = " ".join(sys.argv[1:])
        is_injected, msg, pattern = detect_sql_injection(input_text)
        print(f"\n📥 Input: {input_text}")
        print(f"📊 Result: {msg}")
        if is_injected and pattern:
            print(f"🔍 Matched: {pattern}")
        return

    # Interactive mode
    print("\nEnter strings to scan (type 'exit' or 'quit' to stop):\n")
    
    while True:
        try:
            user_input = input("🔍 Enter input > ").strip()
            
            if user_input.lower() in ["exit", "quit", "q"]:
                print("\n👋 Detector stopped by Mr. Sabaz Ali Khan. Stay secure!")
                break
                
            if not user_input:
                continue

            is_injected, msg, pattern = detect_sql_injection(user_input)
            
            print(f"📊 Result: {msg}")
            if is_injected and pattern:
                print(f"🔍 Matched Pattern: {pattern}")
            print("-" * 50)

        except KeyboardInterrupt:
            print("\n\n⛔ Stopped by user. Stay safe!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    main()