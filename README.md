# 📡 NetScan — Network Port Scanner

A cybersecurity-focused web application that performs fast, multi-threaded TCP port scanning with service identification, risk assessment, and a clean threat-intelligence dashboard UI. Built with **Python** and **Flask**.

---

> ⚠️ **Ethical Use Disclaimer**: Only scan hosts and networks that you own or have **explicit written authorization** to test. Unauthorized port scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), or equivalent legislation in your jurisdiction. The author assumes no liability for misuse of this tool.

---

## Features

- **Multi-threaded TCP Scanning** — Uses `ThreadPoolExecutor` with up to 200 concurrent workers for fast scans
- **Service Identification** — Recognizes 60+ well-known services by port number (SSH, RDP, MySQL, Redis, Docker API, Kubernetes, etc.)
- **Risk Assessment** — Assigns a risk level to every open port: `Info` / `Low` / `Medium` / `High` / `Critical`
- **Port Presets**:
  - **Common** (22 high-value ports) — database, remote access, web
  - **Web** (19 ports) — all common HTTP/S and API ports
  - **Top 100** (97 ports) — most commonly scanned ports
  - **Custom** — any combination of ports or ranges (e.g. `22,80,443`, `1-1024`, `22,3000-3010`)
- **3 Port States** — `Open`, `Filtered` (timeout/firewall), `Closed`
- **Summary Dashboard** — host, resolved IP, scan count, open/filtered counts, duration, top risk level
- **Filter View** — toggle between All / Open only / Filtered only
- **Scan History** — last 10 scans stored in localStorage
- **Legal Consent Gate** — scan button locked until user acknowledges authorization
- **Configurable Timeout** — 0.2s to 3.0s per port

---

## Project Structure

```
port-scanner/
├── app.py              # Flask web server & /scan endpoint
├── scanner.py          # Multi-threaded port scanning engine
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── templates/
│   └── index.html      # Web interface
└── static/
    ├── style.css       # Dark neon terminal theme
    └── script.js       # Frontend logic & history
```

---

## How It Works

### TCP Connect Scan

For each port, a TCP connection attempt is made using `socket.connect_ex()`:

| Result                   | Status     | Meaning |
|--------------------------|------------|---------|
| Returns `0`              | **Open**   | Connection succeeded — service is listening |
| Returns non-zero         | **Closed** | Connection actively refused |
| `socket.timeout` raised  | **Filtered** | No response — likely blocked by firewall |

### Risk Levels

| Level    | Color  | Examples |
|----------|--------|---------|
| Info     | Blue   | HTTPS (443), LDAPS |
| Low      | Green  | HTTP (80), DNS (53) |
| Medium   | Amber  | SSH (22), SMTP (25) |
| High     | Orange | FTP (21), MySQL (3306), RDP (3389), SMB (445) |
| Critical | Red    | Telnet (23), VNC (5900), Redis (6379), Docker (2375), MongoDB (27017) |

### Threading

```python
with ThreadPoolExecutor(max_workers=200) as executor:
    futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
    for future in as_completed(futures):
        results.append(future.result())
```

All ports are scanned concurrently, limited by `max_workers`. A 100-port scan completes in approximately the timeout duration (not 100×timeout).

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- pip

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/netscan.git
cd netscan
```

**2. Create a virtual environment (recommended)**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the application**
```bash
python app.py
```

**5. Open your browser**
```
http://localhost:5002
```

---

## API Reference

### `POST /scan`

Runs a port scan and returns full results.

**Request:**
```json
{
  "host": "192.168.1.1",
  "preset": "common",
  "custom_ports": "",
  "timeout": 0.5
}
```

**Response:**
```json
{
  "host": "192.168.1.1",
  "ip": "192.168.1.1",
  "ports_scanned": 22,
  "open_count": 3,
  "filtered_count": 1,
  "closed_count": 18,
  "elapsed": 0.62,
  "top_risk": "high",
  "results": [
    {
      "port": 22,
      "proto": "tcp",
      "status": "open",
      "service": "SSH",
      "risk": "medium",
      "desc": "Secure Shell — brute-force target if exposed"
    },
    ...
  ]
}
```

### Custom Port Formats

| Input             | Ports scanned |
|-------------------|---------------|
| `22`              | 22 |
| `22,80,443`       | 22, 80, 443 |
| `1-1024`          | 1 through 1024 (max 500) |
| `22,80,1000-2000` | 22, 80, 1000–2000 |

---

## Safe Test Targets

You can test against these **publicly authorized** targets:

| Target | Notes |
|--------|-------|
| `127.0.0.1` | Your own machine |
| `scanme.nmap.org` | Nmap's official scan test host |
| Your own VM / home router | Only if you own/administer it |

---

## Technologies Used

| Layer    | Technology                   |
|----------|------------------------------|
| Backend  | Python 3, Flask              |
| Scanner  | `socket`, `concurrent.futures` (stdlib) |
| Frontend | HTML5, CSS3, JavaScript (ES6+) |
| Storage  | Browser `localStorage`       |
| Fonts    | Inter, JetBrains Mono        |

---

## Security Notes

- This tool performs **TCP connect scans only** — no SYN/stealth scanning
- All scanning happens server-side — the Flask server makes the connections
- Max 500 ports per scan to prevent abuse
- Timeout is configurable (0.2s – 3.0s) to balance speed vs accuracy
- No scan results are stored server-side

---

## License

MIT License — free to use, modify, and distribute for authorized security testing and educational purposes.
