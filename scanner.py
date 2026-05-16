import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Service / Risk Database
# ---------------------------------------------------------------------------

SERVICE_DB = {
    20:    {"name": "FTP-Data",    "risk": "high",     "desc": "FTP data transfer — cleartext"},
    21:    {"name": "FTP",         "risk": "high",     "desc": "File Transfer Protocol — credentials sent in cleartext"},
    22:    {"name": "SSH",         "risk": "medium",   "desc": "Secure Shell — brute-force target if exposed"},
    23:    {"name": "Telnet",      "risk": "critical", "desc": "Unencrypted remote access — never expose to internet"},
    25:    {"name": "SMTP",        "risk": "medium",   "desc": "Email transfer — open relay risk"},
    53:    {"name": "DNS",         "risk": "low",      "desc": "Domain Name System — zone transfer / amplification risk"},
    67:    {"name": "DHCP",        "risk": "medium",   "desc": "DHCP server — rogue DHCP attacks possible"},
    69:    {"name": "TFTP",        "risk": "high",     "desc": "Trivial FTP — no authentication"},
    80:    {"name": "HTTP",        "risk": "low",      "desc": "Web server — unencrypted traffic"},
    88:    {"name": "Kerberos",    "risk": "medium",   "desc": "Kerberos authentication — Kerberoasting target"},
    110:   {"name": "POP3",        "risk": "medium",   "desc": "Email retrieval — cleartext credentials"},
    111:   {"name": "RPC",         "risk": "high",     "desc": "Remote Procedure Call — multiple CVEs"},
    119:   {"name": "NNTP",        "risk": "low",      "desc": "News transfer protocol"},
    135:   {"name": "MSRPC",       "risk": "high",     "desc": "MS Remote Procedure Call — MS08-067 target"},
    137:   {"name": "NetBIOS-NS",  "risk": "high",     "desc": "NetBIOS name service — LLMNR/NBT-NS poisoning"},
    138:   {"name": "NetBIOS-DGM", "risk": "high",     "desc": "NetBIOS datagram service"},
    139:   {"name": "NetBIOS-SSN", "risk": "high",     "desc": "NetBIOS session — Windows file sharing"},
    143:   {"name": "IMAP",        "risk": "medium",   "desc": "Email access — cleartext credentials"},
    161:   {"name": "SNMP",        "risk": "high",     "desc": "Network management — default community strings"},
    389:   {"name": "LDAP",        "risk": "medium",   "desc": "Directory service — anonymous bind risk"},
    443:   {"name": "HTTPS",       "risk": "info",     "desc": "Secure web server — check TLS config"},
    445:   {"name": "SMB",         "risk": "critical", "desc": "Windows file sharing — EternalBlue / WannaCry vector"},
    465:   {"name": "SMTPS",       "risk": "low",      "desc": "Secure SMTP"},
    500:   {"name": "IKE/IPsec",   "risk": "medium",   "desc": "VPN — aggressive mode info leak"},
    514:   {"name": "Syslog",      "risk": "medium",   "desc": "System logging — cleartext, spoofable"},
    587:   {"name": "SMTP-Sub",    "risk": "low",      "desc": "Mail submission (STARTTLS)"},
    631:   {"name": "CUPS/IPP",    "risk": "medium",   "desc": "Print service — PrintNightmare CVEs"},
    636:   {"name": "LDAPS",       "risk": "low",      "desc": "Secure LDAP"},
    873:   {"name": "rsync",       "risk": "high",     "desc": "File sync — often misconfigured, no auth"},
    993:   {"name": "IMAPS",       "risk": "low",      "desc": "Secure IMAP"},
    995:   {"name": "POP3S",       "risk": "low",      "desc": "Secure POP3"},
    1080:  {"name": "SOCKS",       "risk": "high",     "desc": "SOCKS proxy — may be open proxy"},
    1194:  {"name": "OpenVPN",     "risk": "low",      "desc": "OpenVPN tunnel"},
    1433:  {"name": "MSSQL",       "risk": "high",     "desc": "Microsoft SQL Server — brute-force target"},
    1434:  {"name": "MSSQL-UDP",   "risk": "high",     "desc": "MS SQL Server Browser"},
    1521:  {"name": "Oracle DB",   "risk": "high",     "desc": "Oracle Database — brute-force target"},
    1723:  {"name": "PPTP",        "risk": "high",     "desc": "VPN — weak MS-CHAPv2 encryption"},
    2049:  {"name": "NFS",         "risk": "high",     "desc": "Network File System — often misconfigured"},
    2181:  {"name": "ZooKeeper",   "risk": "critical", "desc": "ZooKeeper — no auth by default"},
    2375:  {"name": "Docker",      "risk": "critical", "desc": "Docker API (unencrypted) — full host takeover"},
    2376:  {"name": "Docker TLS",  "risk": "high",     "desc": "Docker API (TLS) — verify auth"},
    3000:  {"name": "Dev Server",  "risk": "medium",   "desc": "Common dev server port (Node/Rails/Grafana)"},
    3306:  {"name": "MySQL",       "risk": "high",     "desc": "MySQL database — should not be internet-facing"},
    3389:  {"name": "RDP",         "risk": "critical", "desc": "Remote Desktop — BlueKeep/DejaBlue target, brute-forced heavily"},
    4444:  {"name": "Backdoor",    "risk": "critical", "desc": "Metasploit / common backdoor default port"},
    4848:  {"name": "GlassFish",   "risk": "high",     "desc": "Java application server admin"},
    5000:  {"name": "Dev/UPnP",    "risk": "medium",   "desc": "Common dev port or UPnP"},
    5432:  {"name": "PostgreSQL",  "risk": "high",     "desc": "PostgreSQL — should not be internet-facing"},
    5601:  {"name": "Kibana",      "risk": "high",     "desc": "Kibana dashboard — often no auth"},
    5900:  {"name": "VNC",         "risk": "critical", "desc": "Virtual Network Computing — weak auth, brute-forced"},
    5985:  {"name": "WinRM-HTTP",  "risk": "high",     "desc": "Windows Remote Management over HTTP"},
    5986:  {"name": "WinRM-HTTPS", "risk": "medium",   "desc": "Windows Remote Management over HTTPS"},
    6379:  {"name": "Redis",       "risk": "critical", "desc": "Redis — no auth by default, RCE possible"},
    6443:  {"name": "K8s API",     "risk": "high",     "desc": "Kubernetes API server"},
    7001:  {"name": "WebLogic",    "risk": "critical", "desc": "WebLogic Server — multiple critical CVEs"},
    8080:  {"name": "HTTP-Alt",    "risk": "low",      "desc": "Alternative HTTP / proxy server"},
    8443:  {"name": "HTTPS-Alt",   "risk": "low",      "desc": "Alternative HTTPS"},
    8888:  {"name": "Jupyter",     "risk": "critical", "desc": "Jupyter Notebook — no auth by default, RCE"},
    9000:  {"name": "Dev/PHP-FPM", "risk": "high",     "desc": "Dev server or PHP-FPM — direct access = RCE"},
    9200:  {"name": "Elasticsearch","risk":"critical", "desc": "Elasticsearch — no auth by default, data exposure"},
    9300:  {"name": "ES-Cluster",  "risk": "high",     "desc": "Elasticsearch cluster communication"},
    10250: {"name": "Kubelet",     "risk": "critical", "desc": "Kubernetes Kubelet API — code execution possible"},
    27017: {"name": "MongoDB",     "risk": "critical", "desc": "MongoDB — no auth by default, full data exposure"},
    27018: {"name": "MongoDB-Shard","risk":"high",     "desc": "MongoDB shard server"},
    50000: {"name": "SAP/Hadoop",  "risk": "high",     "desc": "SAP dispatcher or Hadoop services"},
}

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# Port Presets
# ---------------------------------------------------------------------------

PRESETS = {
    "common": sorted([
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    ]),
    "web": sorted([
        80, 443, 8080, 8443, 3000, 4000, 5000, 7000, 7001, 8000,
        8008, 8081, 8088, 8888, 9000, 9001, 9090, 9200, 9300,
    ]),
    "top100": sorted([
        1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88,
        106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389,
        427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554,
        587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
        1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
        2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
        5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
        6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
        8443, 8888, 9100, 9200, 9999, 10000, 27017,
    ]),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MAX_PORTS   = 500
MAX_WORKERS = 200


def parse_ports(spec: str) -> list[int]:
    """Parse specs like '22,80,443', '1-1024', '22,80,1000-2000'."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo.strip()), int(hi.strip()) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)[:MAX_PORTS]


def _scan_port(host: str, port: int, timeout: float) -> dict:
    status = "closed"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                status = "open"
    except socket.timeout:
        status = "filtered"
    except OSError:
        status = "closed"

    info = SERVICE_DB.get(port, {"name": "Unknown", "risk": "info", "desc": "Unregistered / unknown service"})
    return {
        "port":     port,
        "proto":    "tcp",
        "status":   status,
        "service":  info["name"],
        "risk":     info["risk"] if status == "open" else "none",
        "desc":     info["desc"],
    }


# ---------------------------------------------------------------------------
# Main Scan
# ---------------------------------------------------------------------------

def scan_host(host: str, ports: list[int], timeout: float = 0.5) -> dict:
    # Resolve host
    try:
        ip = socket.gethostbyname(host.strip())
    except socket.gaierror as e:
        return {"error": f"Cannot resolve '{host}': {e}"}

    start = time.perf_counter()

    results = []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports))) as ex:
        futures = {ex.submit(_scan_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            results.append(fut.result())

    elapsed = round(time.perf_counter() - start, 2)
    results.sort(key=lambda r: r["port"])

    open_ports    = [r for r in results if r["status"] == "open"]
    filtered_ports = [r for r in results if r["status"] == "filtered"]

    # Highest risk among open ports
    top_risk = "none"
    for r in open_ports:
        if RISK_ORDER.get(r["risk"], -1) > RISK_ORDER.get(top_risk, -1):
            top_risk = r["risk"]

    return {
        "host":           host,
        "ip":             ip,
        "ports_scanned":  len(ports),
        "open_count":     len(open_ports),
        "filtered_count": len(filtered_ports),
        "closed_count":   len(ports) - len(open_ports) - len(filtered_ports),
        "elapsed":        elapsed,
        "top_risk":       top_risk,
        "results":        results,
    }
