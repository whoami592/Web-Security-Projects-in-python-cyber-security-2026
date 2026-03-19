import requests
import argparse
import time
import threading
from queue import Queue
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colors for output
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

banner = f"""
{GREEN}============================================================
      Web Directory Finder  -  by inspired MR Sabaz Ali Khan 
============================================================{RESET}
"""

def get_status_color(status):
    if 200 <= status < 300:
        return GREEN
    elif 300 <= status < 400:
        return YELLOW
    else:
        return RED

def check_directory(base_url, word, queue, verbose=False, timeout=7, allow_redirects=False):
    url = urljoin(base_url, word.strip())
    
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DirectoryFinder/1.0"}
        )
        
        status = r.status_code
        length = len(r.content)
        
        color = get_status_color(status)
        
        line = f"[{color}{status}{RESET}] {length:>7}B → {url}"
        
        if status in [200, 301, 302, 403]:
            print(line)
            if verbose and status != 404:
                print(f"   └─ {r.headers.get('Server', 'Unknown server')}")
        elif verbose:
            print(f"[ ] {status} → {url}")
            
        queue.task_done()
        
    except (requests.RequestException, KeyboardInterrupt):
        queue.task_done()


def main():
    print(banner)
    
    parser = argparse.ArgumentParser(description="Fast Web Directory Finder (brute force)")
    parser.add_argument("url", help="Target URL (with http/https) e.g. https://example.com/")
    parser.add_argument("-w", "--wordlist", default="common.txt",
                        help="Path to wordlist file (one entry per line)")
    parser.add_argument("-t", "--threads", type=int, default=25,
                        help="Number of concurrent threads (default: 25)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all requests (including 404)")
    parser.add_argument("--timeout", type=int, default=7,
                        help="Request timeout in seconds (default: 7)")
    parser.add_argument("--no-redirect", action="store_true",
                        help="Do not follow redirects")
    
    args = parser.parse_args()
    
    base_url = args.url.rstrip("/") + "/"
    print(f"{BLUE}[*] Target : {base_url}{RESET}")
    print(f"{BLUE}[*] Wordlist: {args.wordlist}{RESET}")
    print(f"{BLUE}[*] Threads : {args.threads}{RESET}")
    print(f"{BLUE}[*] Timeout : {args.timeout}s{RESET}\n")
    
    try:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{RED}[-] Wordlist not found: {args.wordlist}{RESET}")
        return
    
    print(f"{GREEN}[+] Loaded {len(words)} words from wordlist{RESET}\n")
    
    queue = Queue()
    for word in words:
        queue.put(word)
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        while not queue.empty():
            word = queue.get()
            future = executor.submit(
                check_directory,
                base_url,
                word,
                queue,
                args.verbose,
                args.timeout,
                not args.no_redirect
            )
            futures.append(future)
        
        # Wait for all tasks to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                pass  # silent error handling
    
    elapsed = time.time() - start_time
    print(f"\n{YELLOW}[*] Finished in {elapsed:.2f} seconds{RESET}")
    print(f"{GREEN}[*] Happy hunting! Stay ethical.{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Stopped by user. Bye!{RESET}")
