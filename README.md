# SafeProbe — Internet Reachability Auditor

**SafeProbe** is a network inspection tool designed to audit restricted or censored segments of the Internet in different countries. The system evaluates censorship effectiveness, identifies technical barriers, and detects vulnerabilities in blocking mechanisms.

The tool generates a profile of host and protocol availability, including DNS, TCP, TLS, HTTP/2, and HTTP/3 behavior.

> ⚠ Android mode is under development. Currently, fully functional versions are available for **Windows** and **Linux**.

---

## Architecture

SafeProbe consists of two main components:

| Component | Purpose |
|-----------|---------|
| `probe_core.py` | High-performance asynchronous network audit core |
| UI Layer (Kivy/KivyMD/Windows shell) | Interface and session management |

**Core Type:** Asynchronous multi-protocol network scanner with active censorship measurement features.

---

## SafeProbe Core Logic

### What is measured

For each domain, SafeProbe performs:

| Test | Checks |
|------|--------|
| DNS local | Local resolution (A/AAAA/CNAME) |
| DNS over HTTPS (Google, Cloudflare) | IP divergence comparison |
| SVCB/HTTPS records | Advertised protocols (including HTTP/3) |
| TCP Connectivity | Port 80/443 reachability |
| TLS Handshake | SNI, no-SNI, ALPN (h2/http1.1) |
| HTTP/2 / HTTP/1.1 | GET/HEAD HTTPS access |
| HTTP over 80 | Fallback verification |
| HTTP/3 (curl) | QUIC blocking detection |
| GeoTagging | ASN and country of IP addresses (MaxMind) |

SafeProbe produces:

- Transport availability flags  
- Divergence diagnostics  
- Server-side fingerprinting  
- Blocking mode assessment  

---

## API (`probe_core.py`)

### Main integration function:

```python
async def probe_one(
    host: str,
    auditor: Auditor,
    custom_nameservers: Optional[List[str]] = None,
    retries: int = 1
) -> ProbeResult
````

**Inputs:**

* `host` — domain name
* `auditor` — log handler
* `custom_nameservers` — DNS servers for local resolution
* `retries` — HTTP request attempts

**Returns:**

```python
@dataclass
class ProbeResult:
    host: str
    url: str
    ips_local: List[str]
    ips_doh_google: List[str]
    ips_doh_cf: List[str]
    dns_ok: bool
    dns_divergence: bool
    tcp443_ok: bool
    tls_sni_ok: bool
    http_ok: bool
    h3_ok: Optional[bool]
    best_transport: Optional[str]
    geo_local: List[Dict[str, Optional[str]]]
    diag: str
    capabilities: List[str]
```

### Supporting API functions:

| Function             | Purpose                                |
| -------------------- | -------------------------------------- |
| `dns_lookup`         | DNS resolution via selected resolver   |
| `doh_json`           | DNS over HTTPS using Google/Cloudflare |
| `tcp_connect`        | TCP port reachability                  |
| `tls_handshake`      | SNI / ALPN testing                     |
| `http_probe_smart`   | Multi-step HTTP verification           |
| `http3_head`         | HTTP/3 check via curl                  |
| `build_capabilities` | Post-processing of results             |

---

## Installation & Run

### Windows

```bash
git clone https://github.com/elmWilh/safenetprobe.git
cd SafeProbe
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Console-only core run:

```bash
python probe_core.py example.com
```

### API Example

```python
import asyncio
from probe_core import Auditor, probe_one

async def run():
    auditor = Auditor(path="audit.log")
    result = await probe_one("wikipedia.org", auditor)
    print(result)

asyncio.run(run())
```

---

## Output Formats

| Format | Use                      |
| ------ | ------------------------ |
| JSON   | Programmatic integration |
| CSV    | Analytics and summaries  |
| UI-log | Live session monitoring  |

Files are generated automatically during scanning.

---

## Safety & Legal Notice

This tool is intended for **research, analytical, and academic purposes**. The operator assumes full responsibility for use on live networks.

---

## Roadmap

| Feature                       | Status            |
| ----------------------------- | ----------------- |
| Android Mode                  | 🚧 In development |
| Auto-report visualization     | Planned           |
| OONI-compatible report export | Planned           |


