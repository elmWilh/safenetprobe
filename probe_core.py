#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, socket, ssl, time, json, csv, shutil, subprocess, shlex, sys, os, random
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple
import httpx
import dns.resolver
from datetime import datetime, timezone
from collections import deque

try:
    import maxminddb  # type: ignore
    HAS_MAXMIND = True
except Exception:
    HAS_MAXMIND = False

try:
    from fastapi import FastAPI, BackgroundTasks
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    HAS_FASTAPI = True
except Exception:
    HAS_FASTAPI = False

CONCURRENCY = 8
TCP_TIMEOUT = 2.5
TLS_TIMEOUT = 3.0
HTTP_TIMEOUT = 5.0
TOTAL_TIMEOUT = 20.0
SAFE_MIN_DELAY = 0.12
SAFE_MAX_DELAY = 0.35
USER_AGENT = "availability-monitor/1.3 (+python httpx; purpose=reachability)"
FALLBACK_PATHS = ["/robots.txt", "/favicon.ico", "/"]
SAFE_USE_CF_TRACE = False
GOOGLE_DNS_JSON = "https://dns.google/resolve?name={host}&type=A"
CLOUDFLARE_DNS_JSON = "https://cloudflare-dns.com/dns-query?name={host}&type=A"

_UI_LOGS = deque(maxlen=2000)
_PROGRESS = {"total": 0, "done": 0, "last_host": None, "started_at": None, "ended_at": None}

def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _ui_log(message: str):
    _UI_LOGS.append({"ts": _ts(), "msg": message})

def _progress_reset(total: int):
    _PROGRESS["total"] = int(total)
    _PROGRESS["done"] = 0
    _PROGRESS["last_host"] = None
    _PROGRESS["started_at"] = _ts()
    _PROGRESS["ended_at"] = None
    _ui_log(f"scan_start total={total}")

def _progress_tick(host: str):
    _PROGRESS["done"] = int(_PROGRESS.get("done", 0)) + 1
    _PROGRESS["last_host"] = host
    _ui_log(f"scanned {host} [{_PROGRESS['done']}/{_PROGRESS['total']}]")

def _progress_finish():
    _PROGRESS["ended_at"] = _ts()
    _ui_log("scan_finish")

@dataclass
class ProbeResult:
    host: str
    url: str
    ips_local: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    ips_doh_google: List[str] = field(default_factory=list)
    ips_doh_cf: List[str] = field(default_factory=list)
    dns_ok: bool = False
    dns_divergence: bool = False
    dns_divergence_kind: Optional[str] = None
    tcp443_ok: bool = False
    tcp443_ms: Optional[float] = None
    tcp80_ok: bool = False
    tcp80_ms: Optional[float] = None
    tls_sni_ok: bool = False
    tls_sni_version: Optional[str] = None
    alpn_sni: Optional[str] = None
    tls_nosni_ok: bool = False
    tls_nosni_version: Optional[str] = None
    http_mode: Optional[str] = None
    http_ok: bool = False
    http_status: Optional[int] = None
    http_ms: Optional[float] = None
    server: Optional[str] = None
    cf_ray: Optional[str] = None
    cf_cache_status: Optional[str] = None
    via: Optional[str] = None
    alt_svc: Optional[str] = None
    alt_svc_h3_advertised: bool = False
    svc_dns: List[str] = field(default_factory=list)
    h3_ok: Optional[bool] = None
    h3_advertised_but_blocked: Optional[bool] = None
    best_transport: Optional[str] = None
    diag: str = ""
    capabilities: List[str] = field(default_factory=list)
    http_err: Optional[str] = None
    geo_local: List[Dict[str, Optional[str]]] = field(default_factory=list)

def now_ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0

def has_curl() -> bool:
    return shutil.which("curl") is not None

def jitter_delay():
    return random.uniform(SAFE_MIN_DELAY, SAFE_MAX_DELAY)

def parse_alt_svc(alt: Optional[str]) -> Dict[str, bool]:
    if not alt: return {"h3": False}
    a = alt.lower()
    return {"h3": ("h3=" in a or "h3-29=" in a or "quic=" in a)}

class Auditor:
    def __init__(self, path: Optional[str]):
        self.path = path
        if path: open(path, "a", encoding="utf-8").close()
    def log(self, message: str):
        ts = _ts()
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(f"{ts} {message}\n")
        _ui_log(message)

class GeoAnnotator:
    def __init__(self, asn_path="GeoLite2-ASN.mmdb", country_path="GeoLite2-Country.mmdb"):
        self.asn = None; self.country = None
        if HAS_MAXMIND:
            try:
                if os.path.exists(asn_path): self.asn = maxminddb.open_database(asn_path)  # type: ignore
            except Exception: self.asn = None
            try:
                if os.path.exists(country_path): self.country = maxminddb.open_database(country_path)  # type: ignore
            except Exception: self.country = None
    def annotate_ip(self, ip: str) -> Dict[str, Optional[str]]:
        info = {"asn": None, "org": None, "country": None}
        try:
            if self.asn:
                d = self.asn.get(ip) or {}
                info["asn"] = str(d.get("autonomous_system_number")) if d.get("autonomous_system_number") else None
                info["org"] = d.get("autonomous_system_organization")
        except Exception: pass
        try:
            if self.country:
                d = self.country.get(ip) or {}
                info["country"] = (d.get("country") or {}).get("iso_code")
        except Exception: pass
        return info

def build_resolver(custom_nameservers: Optional[List[str]]) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(); r.lifetime = 2.0
    if custom_nameservers: r.nameservers = custom_nameservers
    return r

def dns_lookup(host: str, auditor: Auditor, resolver: dns.resolver.Resolver) -> Tuple[List[str], List[str]]:
    auditor.log(f"DNS local A/AAAA/CNAME {host}")
    ips, cname = [], []
    try:
        for rr in resolver.resolve(host, "A"): ips.append(rr.address)
    except Exception: pass
    try:
        for rr in resolver.resolve(host, "AAAA"): ips.append(rr.address)
    except Exception: pass
    try:
        for rr in resolver.resolve(host, "CNAME"): cname.append(str(rr.target).rstrip("."))
    except Exception: pass
    return ips, cname

def dns_svcb_https(host: str, auditor: Auditor, resolver: dns.resolver.Resolver) -> List[str]:
    auditor.log(f"DNS HTTPS/SVCB {host}")
    out = []
    for rrtype in ("HTTPS", "SVCB"):
        try:
            rrset = resolver.resolve(host, rrtype)
            for rr in rrset: out.append(f"{rrtype} {str(rr)}")
        except Exception: pass
    return out

async def doh_json(host: str, auditor: Auditor) -> Tuple[List[str], List[str]]:
    headers = {"User-Agent": USER_AGENT}
    ips_g, ips_cf = [], []
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=headers) as c:
        auditor.log(f"DoH Google JSON {host}")
        try:
            rg = await c.get(GOOGLE_DNS_JSON.format(host=host))
            if rg.status_code == 200:
                j = rg.json()
                ips_g = [a.get("data") for a in j.get("Answer", []) if a.get("type") == 1 and a.get("data")]
        except Exception: pass
        await asyncio.sleep(jitter_delay())
        auditor.log(f"DoH Cloudflare JSON {host}")
        try:
            rc = await c.get(CLOUDFLARE_DNS_JSON.format(host=host), headers={"accept": "application/dns-json"})
            if rc.status_code == 200:
                j = rc.json()
                ips_cf = [a.get("data") for a in j.get("Answer", []) if a.get("type") == 1 and a.get("data")]
        except Exception: pass
    return ips_g, ips_cf

async def tcp_connect(host: str, port: int, timeout: float, auditor: Auditor) -> Tuple[bool, Optional[float]]:
    await asyncio.sleep(jitter_delay()); auditor.log(f"TCP connect {host}:{port}")
    t0 = time.perf_counter()
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return True, now_ms(t0)
    except Exception:
        return False, None

async def tls_handshake(host_or_ip: str, sni: Optional[str], port: int, timeout: float, auditor: Auditor) -> Tuple[bool, Optional[str], Optional[str]]:
    await asyncio.sleep(jitter_delay()); auditor.log(f"TLS handshake {'SNI='+sni if sni else 'noSNI'} to {host_or_ip}:{port}")
    ctx = ssl.create_default_context()
    try: ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError: pass
    try:
        conn = asyncio.open_connection(host_or_ip, port, ssl=ctx, server_hostname=sni)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        tls_obj: ssl.SSLObject = writer.get_extra_info("ssl_object")
        version = tls_obj.version() if tls_obj else None
        alpn = tls_obj.selected_alpn_protocol() if tls_obj else None
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return True, version, alpn
    except Exception:
        return False, None, None

async def http_try(url: str, http2: bool, method: str, timeout: float, auditor: Auditor, headers=None, verify=True):
    await asyncio.sleep(jitter_delay()); auditor.log(f"HTTP {method} {url} http2={http2}")
    t0 = time.perf_counter(); headers = {"User-Agent": USER_AGENT, **(headers or {})}
    try:
        async with httpx.AsyncClient(http2=http2, timeout=timeout, headers=headers, follow_redirects=True, verify=verify) as c:
            r = await c.request(method, url)
            ms = now_ms(t0); h = {k.lower(): v for k, v in r.headers.items()}
            return True, r.status_code, ms, h, None
    except Exception as e:
        return False, None, None, {}, type(e).__name__

async def http_probe_smart(host: str, auditor: Auditor, retries: int = 1) -> Tuple[str, bool, Optional[int], Optional[float], Dict[str, str], Optional[str]]:
    base_https = f"https://{host}"; base_http = f"http://{host}"
    sequence = []
    for p in FALLBACK_PATHS: sequence.append(("H2_GET",  base_https + p, True,  "GET"))
    for p in FALLBACK_PATHS: sequence.append(("H2_HEAD", base_https + p, True,  "HEAD"))
    for p in FALLBACK_PATHS: sequence.append(("H11_GET", base_https + p, False, "GET"))
    for p in FALLBACK_PATHS: sequence.append(("H11_HEAD", base_https + p, False, "HEAD"))
    for p in FALLBACK_PATHS: sequence.append(("H11_P80_GET", base_http + p, False, "GET"))
    last = ("NONE", False, None, None, {}, "NO_RESPONSE")
    for mode, url, http2, method in sequence:
        for _ in range(max(1, retries)):
            ok, code, ms, hdrs, err = await http_try(url, http2=http2, method=method, timeout=HTTP_TIMEOUT, auditor=auditor)
            if ok or code: return (mode, ok, code, ms, hdrs, err)
            await asyncio.sleep(jitter_delay())
        last = (mode, False, None, None, {}, "NO_RESPONSE")
    return last

async def http3_head(url: str, auditor: Auditor) -> Optional[bool]:
    await asyncio.sleep(jitter_delay())
    if not has_curl(): return None
    cmd = f"curl --http3 -I --max-time 5 -s {shlex.quote(url)}"
    auditor.log(f"H3 curl-head {url}")
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode == 0 and stdout: return True
        return False
    except Exception:
        return False

def build_capabilities(res: ProbeResult) -> List[str]:
    caps = []
    if res.dns_ok: caps.append("DNS_local_OK")
    if res.ips_doh_google: caps.append("DoH_Google_OK")
    if res.ips_doh_cf: caps.append("DoH_Cloudflare_OK")
    if res.dns_divergence: caps.append("DNS_DIVERGENCE")
    if res.tcp443_ok: caps.append("TCP_443_OK")
    if res.tcp80_ok: caps.append("TCP_80_OK")
    if res.tls_sni_ok: caps.append(f"TLS_SNI_{res.tls_sni_version or 'OK'}")
    if res.tls_nosni_ok: caps.append("TLS_noSNI_OK")
    if res.http_mode in ("H2_GET", "H2_HEAD") and res.http_ok: caps.append("HTTP2_OK")
    if res.http_mode in ("H11_GET", "H11_HEAD") and res.http_ok: caps.append("HTTP11_OK")
    if res.http_mode == "H11_P80_GET" and res.http_ok: caps.append("HTTP_80_OK")
    if res.h3_ok: caps.append("HTTP3_OK")
    if res.alt_svc: caps.append("AltSvc_advertised")
    if res.svc_dns: caps.append("SVCB_HTTPS_DNS")
    if (res.server and "cloudflare" in (res.server or "").lower()) or res.cf_ray: caps.append("Behind_Cloudflare")
    if res.h3_advertised_but_blocked: caps.append("H3_ADVERTISED_BUT_BLOCKED")
    return caps

def decide_best_transport(res: ProbeResult) -> Optional[str]:
    if res.http_ok:
        if res.http_mode in ("H2_GET", "H2_HEAD"): return "HTTPS_H2"
        if res.http_mode in ("H11_GET", "H11_HEAD"): return "HTTPS_H11"
        if res.http_mode == "H11_P80_GET": return "HTTP_80"
    return None

def diagnose(res: ProbeResult) -> str:
    if not res.dns_ok and not (res.ips_doh_google or res.ips_doh_cf): return "DNS_FAIL_all"
    if res.dns_ok and (res.ips_doh_google or res.ips_doh_cf):
        if res.dns_divergence: return "DNS_DIVERGENCE_" + (res.dns_divergence_kind or "unknown")
    if not res.tcp443_ok and not res.tcp80_ok: return "TCP_BLOCK_80_443"
    if not res.tcp443_ok and res.tcp80_ok: return "TCP443_BLOCK_ONLY"
    if not res.tls_sni_ok:
        if res.tcp443_ok:
            if res.tls_nosni_ok: return "SNI_BLOCK"
            return "TLS_FAIL"
    if not res.http_ok and res.http_status is None:
        if res.http_mode in ("H2_GET", "H2_HEAD"): return "H2_TIMEOUT_OR_DROP"
        if res.http_mode in ("H11_GET", "H11_HEAD", "H11_P80_GET"): return "HTTP_TIMEOUT"
        return "HTTP_TIMEOUT"
    if res.http_status in (403, 451): return f"HTTP_BLOCK_{res.http_status}"
    if res.http_status in (429, 503): return f"HTTP_THROTTLE_{res.http_status}"
    if res.h3_ok is False and res.http_ok: return "OK_NO_H3"
    if res.h3_ok: return "OK_H3"
    if (res.server and "cloudflare" in (res.server or "").lower()) or res.cf_ray: return "OK_CLOUDFLARE"
    if res.http_ok and 200 <= (res.http_status or 0) < 400: return "OK"
    return f"HTTP_ANOMALY:{res.http_mode or '-'}:{res.http_err or res.http_status}"

async def probe_host(host: str, auditor: Auditor, resolver: dns.resolver.Resolver, geo: GeoAnnotator) -> ProbeResult:
    url = f"https://{host}/"
    res = ProbeResult(host=host, url=url)
    try:
        res.ips_local, res.cname = dns_lookup(host, auditor, resolver); res.dns_ok = bool(res.ips_local or res.cname)
    except Exception: pass
    res.geo_local = [geo.annotate_ip(ip) for ip in res.ips_local]
    try: res.svc_dns = dns_svcb_https(host, auditor, resolver)
    except Exception: pass
    try:
        ips_g, ips_cf = await doh_json(host, auditor)
        res.ips_doh_google, res.ips_doh_cf = ips_g, ips_cf
        set_local, set_doh = set(res.ips_local), set(ips_g + ips_cf)
        if set_local and set_doh and set_local != set_doh: res.dns_divergence = True
        if res.dns_divergence:
            def orgs(ips):
                s = set()
                for ip in ips:
                    org = (geo.annotate_ip(ip).get("org") or "").lower()
                    if org: s.add(org)
                return s
            o_local = orgs(res.ips_local); o_doh = orgs(res.ips_doh_google + res.ips_doh_cf)
            res.dns_divergence_kind = "benign" if (o_local and o_doh and (o_local & o_doh)) else "suspicious"
    except Exception: pass
    res.tcp443_ok, res.tcp443_ms = await tcp_connect(host, 443, TCP_TIMEOUT, auditor)
    res.tcp80_ok,  res.tcp80_ms  = await tcp_connect(host, 80,  TCP_TIMEOUT, auditor)
    if res.tcp443_ok:
        s_ok, s_ver, s_alpn = await tls_handshake(host, sni=host, port=443, timeout=TLS_TIMEOUT, auditor=auditor)
        res.tls_sni_ok, res.tls_sni_version, res.alpn_sni = s_ok, s_ver, s_alpn
        target_ip = res.ips_local[0] if res.ips_local else host
        n_ok, n_ver, _ = await tls_handshake(target_ip, sni=None, port=443, timeout=TLS_TIMEOUT, auditor=auditor)
        res.tls_nosni_ok, res.tls_nosni_version = n_ok, n_ver
    if res.tls_sni_ok or res.tcp80_ok:
        mode, ok, code, ms, hdrs, err = await http_probe_smart(host, auditor, retries=2)
        res.http_mode, res.http_ok, res.http_status, res.http_ms, res.http_err = mode, ok, code, (round(ms, 2) if ms else None), err
        if hdrs:
            res.server = hdrs.get("server"); res.cf_ray = hdrs.get("cf-ray")
            res.cf_cache_status = hdrs.get("cf-cache-status"); res.via = hdrs.get("via")
            res.alt_svc = hdrs.get("alt-svc"); res.alt_svc_h3_advertised = parse_alt_svc(res.alt_svc)["h3"]
    try: res.h3_ok = await http3_head(url, auditor)
    except Exception: res.h3_ok = None
    if res.alt_svc_h3_advertised and (res.h3_ok is False): res.h3_advertised_but_blocked = True
    res.best_transport = decide_best_transport(res)
    res.capabilities = build_capabilities(res)
    res.diag = diagnose(res)
    return res

async def run_all(hosts: List[str], auditor: Auditor, resolver: dns.resolver.Resolver, geo: GeoAnnotator) -> List[ProbeResult]:
    _progress_reset(len(hosts))
    sem = asyncio.Semaphore(CONCURRENCY)
    async def wrapped(h):
        async with sem:
            try:
                r = await asyncio.wait_for(probe_host(h, auditor, resolver, geo), timeout=TOTAL_TIMEOUT)
            except asyncio.TimeoutError:
                auditor.log(f"TOTAL_TIMEOUT {h}")
                r = ProbeResult(host=h, url=f"https://{h}/", diag="TOTAL_TIMEOUT")
            finally:
                _progress_tick(h)
                print(f"[{_PROGRESS['done']}/{_PROGRESS['total']}] {h}", file=sys.stderr, flush=True)
            return r
    tasks = [wrapped(h) for h in hosts]
    results: List[ProbeResult] = []
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    results.sort(key=lambda r: r.host)
    _progress_finish()
    return results

def summarize_transport(rows: List[ProbeResult]) -> Dict[str, Dict[str, int]]:
    summary = {
        "DNS_local_OK": 0, "DNS_DIVERGENCE": 0, "DNS_DIV_BENIGN": 0, "DNS_DIV_SUSPICIOUS": 0,
        "DoH_Google_OK": 0, "DoH_Cloudflare_OK": 0,
        "TCP_443_OK": 0, "TCP_80_OK": 0,
        "TLS_SNI": 0, "TLS_noSNI": 0,
        "HTTP2_OK": 0, "HTTP11_OK": 0, "HTTP_80_OK": 0,
        "HTTP3_OK": 0, "AltSvc": 0, "SVCB": 0,
        "Behind_CF": 0, "H3_ADVERTISED_BUT_BLOCKED": 0
    }
    n = len(rows)
    for r in rows:
        if r.dns_ok: summary["DNS_local_OK"] += 1
        if r.dns_divergence: summary["DNS_DIVERGENCE"] += 1
        if r.dns_divergence_kind == "benign": summary["DNS_DIV_BENIGN"] += 1
        if r.dns_divergence_kind == "suspicious": summary["DNS_DIV_SUSPICIOUS"] += 1
        if r.ips_doh_google: summary["DoH_Google_OK"] += 1
        if r.ips_doh_cf: summary["DoH_Cloudflare_OK"] += 1
        if r.tcp443_ok: summary["TCP_443_OK"] += 1
        if r.tcp80_ok: summary["TCP_80_OK"] += 1
        if r.tls_sni_ok: summary["TLS_SNI"] += 1
        if r.tls_nosni_ok: summary["TLS_noSNI"] += 1
        if "HTTP2_OK" in r.capabilities: summary["HTTP2_OK"] += 1
        if "HTTP11_OK" in r.capabilities: summary["HTTP11_OK"] += 1
        if "HTTP_80_OK" in r.capabilities: summary["HTTP_80_OK"] += 1
        if r.h3_ok: summary["HTTP3_OK"] += 1
        if r.alt_svc: summary["AltSvc"] += 1
        if r.svc_dns: summary["SVCB"] += 1
        if "Behind_Cloudflare" in r.capabilities: summary["Behind_CF"] += 1
        if r.h3_advertised_but_blocked: summary["H3_ADVERTISED_BUT_BLOCKED"] += 1
    return {"total_hosts": n, "counts": summary}

def recommendations(summary: Dict[str, Dict[str, int]]) -> List[str]:
    n = summary["total_hosts"]
    c = summary["counts"]
    recs = []
    if c["DNS_DIVERGENCE"] > 0:
        if c["DNS_DIV_SUSPICIOUS"] > 0:
            recs.append("Есть подозрительные DNS-расхождения (иные ASN/владельцы) — вероятно, вмешательство. Сопоставляйте IP с владельцами/ASN.")
        else:
            recs.append("Фиксируются расхождения локального DNS и DoH, но у тех же владельцев (CDN/Anycast) — похоже на нормальную вариацию.")
    if c["DoH_Google_OK"] > 0 or c["DoH_Cloudflare_OK"] > 0:
        recs.append("По крайней мере один публичный DoH-резолвер достижим по HTTPS — резолв через HTTPS в этой сети возможен.")
    if c["TCP_443_OK"] < n and c["TCP_80_OK"] > 0:
        recs.append("Часть хостов недоступна по 443, но 80 жив — HTTPS может блокироваться выборочно.")
    if c["TCP_443_OK"] == n:
        recs.append("HTTPS:443 в целом доступен.")
    if c["TLS_SNI"] < n and c["TLS_noSNI"] > 0:
        recs.append("Замечены признаки SNI-чувствительной фильтрации (без SNI иногда проходит, с SNI — нет).")
    if c["HTTP2_OK"] < c["HTTP11_OK"]:
        recs.append("HTTP/2 местами нестабилен, HTTP/1.1 надёжнее — мониторинг и клиенты стоит ориентировать на 1.1.")
    if c["HTTP3_OK"] == 0:
        recs.append("HTTP/3/UDP:443 не просматривается или в целом заблокирован.")
    if c["H3_ADVERTISED_BUT_BLOCKED"] > 0:
        recs.append("Многие хосты рекламируют H3 (Alt-Svc), но он не проходит — вероятно, UDP/443 фильтруется.")
    if c["Behind_CF"] > 0:
        recs.append("Часть сервисов за CDN (например, Cloudflare) — возможны челленджи/ограничения уровня L7; при мониторинге ожидать 429/503.")
    if not recs:
        recs.append("Сеть выглядит однородно: явных признаков выборочной фильтрации не выявлено.")
    return recs

def summarize_by_country(rows: List[ProbeResult]) -> Dict[str, Dict[str, int]]:
    agg = {"RU": {"hosts":0,"http_ok":0,"h3_ok":0}, "NON_RU": {"hosts":0,"http_ok":0,"h3_ok":0}}
    for r in rows:
        cc = (r.geo_local[0].get("country") if r.geo_local else None) or "??"
        bucket = "RU" if cc == "RU" else "NON_RU"
        agg[bucket]["hosts"] += 1
        if r.http_ok: agg[bucket]["http_ok"] += 1
        if r.h3_ok: agg[bucket]["h3_ok"] += 1
    return agg

def summarize_by_org(rows: List[ProbeResult]) -> Dict[str, Dict[str, int]]:
    from collections import defaultdict
    orgs = defaultdict(lambda: {"hosts":0,"http_ok":0,"h3_ok":0})
    for r in rows:
        org = (r.geo_local[0].get("org") if r.geo_local else None) or "UNKNOWN"
        orgs[org]["hosts"] += 1
        if r.http_ok: orgs[org]["http_ok"] += 1
        if r.h3_ok: orgs[org]["h3_ok"] += 1
    return dict(sorted(orgs.items(), key=lambda kv: kv[1]["hosts"], reverse=True)[:20])

def policy_fingerprint(summary_counts: Dict[str, Dict[str, int]], by_country: Dict[str, Dict[str, int]]) -> List[str]:
    notes = []
    if summary_counts["counts"]["HTTP3_OK"] == 0: notes.append("UDP/443 (HTTP/3) не проходит.")
    if summary_counts["counts"]["HTTP2_OK"] < summary_counts["counts"]["HTTP11_OK"]: notes.append("HTTP/2 деградирует, HTTP/1.1 стабильнее.")
    ru = by_country.get("RU", {"hosts":0,"http_ok":0}); non = by_country.get("NON_RU", {"hosts":0,"http_ok":0})
    if ru["hosts"] and non["hosts"]:
        ru_rate = ru["http_ok"] / max(1, ru["hosts"]); non_rate = non["http_ok"] / max(1, non["hosts"])
        if ru_rate - non_rate >= 0.4: notes.append("Возможен вайтлист по стране/ASN: RU-домены заметно доступнее.")
    return notes

def save_json(path: str, rows: List[ProbeResult], extra: dict):
    data = {"generated_at_utc": _ts(), "summary": extra, "results": [asdict(r) for r in rows]}
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)

def save_csv(path: str, rows: List[ProbeResult]):
    if not rows: return
    fields = list(asdict(rows[0]).keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow(asdict(r))

def append_csv(path: str, rows: List[ProbeResult]):
    ts = _ts()
    fields = ["timestamp","host","diag","http_status","http_mode","alpn_sni","tls_sni_version","h3_ok","best_transport"]
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if write_header: w.writeheader()
        for r in rows:
            w.writerow({"timestamp": ts, "host": r.host, "diag": r.diag, "http_status": r.http_status,
                        "http_mode": r.http_mode, "alpn_sni": r.alpn_sni, "tls_sni_version": r.tls_sni_version,
                        "h3_ok": r.h3_ok, "best_transport": r.best_transport})

def save_prometheus_textfile(path: str, rows: List[ProbeResult], summary: dict):
    lines = []; ts = int(time.time())
    def m(name, labels, value):
        lab = ",".join([f'{k}="{v}"' for k,v in labels.items()]); lines.append(f'{name}{{{lab}}} {value}')
    for r in rows:
        base = {"host": r.host}
        m("probe_dns_ok", base, 1 if r.dns_ok else 0)
        m("probe_tcp_443_ok", base, 1 if r.tcp443_ok else 0)
        m("probe_tls_sni_ok", base, 1 if r.tls_sni_ok else 0)
        m("probe_http_ok", base, 1 if r.http_ok else 0)
        m("probe_http_status", base, r.http_status or 0)
        m("probe_h3_ok", base, 1 if r.h3_ok else 0 if r.h3_ok is False else -1)
    lines.append(f"# TIMESTAMP {ts}")
    with open(path, "w", encoding="utf-8") as f: f.write("\n".join(lines) + "\n")

HTML_HEAD = """<!doctype html><html lang="ru"><meta charset="utf-8"><title>Network Availability Report</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0b0d12;color:#e6e9ef;margin:24px}
 table{border-collapse:collapse;width:100%} th,td{border:1px solid #2a2f3a;padding:8px;font-size:14px}
 th{background:#111826;position:sticky;top:0} .ok{background:#15361e} .warn{background:#3a2f15}
 .err{background:#3a1b1b} .muted{color:#9aa2ad} .chip{display:inline-block;padding:2px 6px;border-radius:10px;background:#1b2130;margin:2px}
 .section{margin:18px 0} code{background:#111826;padding:2px 6px;border-radius:6px}
</style><h1>Network Availability Report</h1>"""

def save_html(path: str, rows: List[ProbeResult], summary: dict, notes: List[str]):
    ts = _ts()
    parts = [HTML_HEAD, f'<p class="muted">Generated at {ts}</p>']
    parts.append('<div class="section"><h2>Summary</h2><pre>')
    parts.append(json.dumps(summary, ensure_ascii=False, indent=2))
    parts.append('</pre></div>')
    parts.append('<div class="section"><h2>Observer notes</h2><ol>')
    for n in notes: parts.append(f"<li>{n}</li>")
    parts.append("</ol></div>")
    parts.append('<div class="section"><h2>Matrix</h2><table>')
    parts.append("<tr><th>Host</th><th>DNS</th><th>DoH</th><th>TCP</th><th>TLS</th><th>HTTP</th><th>H3</th><th>Diag</th><th>Best</th><th>Caps</th></tr>")
    for r in rows:
        dns_cls = "ok" if r.dns_ok else "err"; doh_ok = ("ok" if (r.ips_doh_google or r.ips_doh_cf) else "err")
        tcp_cls = "ok" if (r.tcp443_ok or r.tcp80_ok) else "err"; tls_cls = "ok" if r.tls_sni_ok else "err"
        http_cls = "ok" if r.http_ok else "err"; h3_cls = ("ok" if r.h3_ok else "err" if r.h3_ok==False else "")
        parts.append("<tr>")
        parts.append(f"<td><b>{r.host}</b><div class='muted'>{', '.join(r.ips_local) or '-'}</div></td>")
        parts.append(f"<td class='{dns_cls}'>local={'ok' if r.dns_ok else 'fail'}<br>div={r.dns_divergence_kind or ('no' if not r.dns_divergence else 'yes')}</td>")
        parts.append(f"<td class='{doh_ok}'>g={len(r.ips_doh_google)}, cf={len(r.ips_doh_cf)}</td>")
        parts.append(f"<td class='{tcp_cls}'>443={'ok' if r.tcp443_ok else 'fail'} ({r.tcp443_ms or '-'} ms)<br>80={'ok' if r.tcp80_ok else 'fail'} ({r.tcp80_ms or '-'} ms)</td>")
        parts.append(f"<td class='{tls_cls}'>SNI={'ok' if r.tls_sni_ok else 'fail'} {r.tls_sni_version or ''} / ALPN={r.alpn_sni or '-'}<br>noSNI={'ok' if r.tls_nosni_ok else 'fail'}</td>")
        parts.append(f"<td class='{http_cls}'>mode={r.http_mode or '-'} status={r.http_status or '-'} ({r.http_ms or '-'} ms)<br>Alt-Svc={'yes' if r.alt_svc else 'no'}; h3_adv={'yes' if r.alt_svc_h3_advertised else 'no'}</td>")
        parts.append(f"<td class='{h3_cls}'>{r.h3_ok}</td>")
        parts.append(f"<td>{r.diag}</td>")
        parts.append(f"<td><code>{r.best_transport or '-'}</code>{' <span class=chip>H3 adv but blocked</span>' if r.h3_advertised_but_blocked else ''}</td>")
        parts.append("<td>")
        for c in r.capabilities: parts.append(f"<span class='chip'>{c}</span>")
        parts.append("</td></tr>")
    parts.append("</table></div></html>")
    with open(path, "w", encoding="utf-8") as f: f.write("".join(parts))

def api_probe(hosts: List[str], dns_servers: Optional[List[str]] = None, asn_db: str = "GeoLite2-ASN.mmdb",
              country_db: str = "GeoLite2-Country.mmdb", audit_path: Optional[str] = None) -> Dict:
    resolver = build_resolver(dns_servers)
    auditor = Auditor(audit_path)
    geo = GeoAnnotator(asn_db, country_db)
    rows = asyncio.run(run_all(hosts, auditor, resolver, geo))
    summary = summarize_transport(rows)
    by_country = summarize_by_country(rows)
    by_org = summarize_by_org(rows)
    fingerprint = policy_fingerprint(summary, by_country)
    return {
        "generated_at_utc": _ts(),
        "summary": summary,
        "by_country": by_country,
        "by_org": by_org,
        "policy_fingerprint": fingerprint,
        "progress": dict(_PROGRESS),
        "logs": list(_UI_LOGS),
        "results": [asdict(r) for r in rows],
    }

def build_app() -> Optional[FastAPI]:
    if not HAS_FASTAPI: return None
    app = FastAPI(title="safe_net_probe API", version="1.1")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

    @app.get("/health")
    async def health():
        return {"ok": True, "ts": _ts()}

    @app.get("/progress")
    async def progress():
        return dict(_PROGRESS)

    @app.get("/logs")
    async def logs(limit: int = 200):
        if limit <= 0: limit = 1
        return list(_UI_LOGS)[-min(limit, len(_UI_LOGS)):]  # noqa

    @app.post("/probe")
    async def probe(payload: Dict):
        hosts = payload.get("hosts") or []
        if not isinstance(hosts, list) or not hosts: return {"error": "hosts required"}
        dns_list = payload.get("dns")
        if isinstance(dns_list, str): dns_list = [x.strip() for x in dns_list.split(",") if x.strip()]
        asn_db = payload.get("asn_db") or "GeoLite2-ASN.mmdb"
        country_db = payload.get("country_db") or "GeoLite2-Country.mmdb"
        audit = payload.get("audit")
        return api_probe(hosts, dns_list, asn_db, country_db, audit)

    return app

def main():
    import argparse
    p = argparse.ArgumentParser(description="Safe availability scanner: DNS/DoH/TCP/TLS(SNI)/HTTP2/1.1/H3/Alt-Svc/SVCB (+Geo/ASN, HTML, Prom, API)")
    p.add_argument("hosts", nargs="*", help="Хосты (example.com)")
    p.add_argument("-f", "--file", help="Файл со списком хостов")
    p.add_argument("--json", help="JSON отчёт")
    p.add_argument("--csv", help="CSV (перезапись)")
    p.add_argument("--append-csv", help="Тренды CSV (append)")
    p.add_argument("--html", help="HTML отчёт")
    p.add_argument("--prom-file", help="Prometheus textfile")
    p.add_argument("--audit", help="audit-лог")
    p.add_argument("--dns", help="Кастомные резолверы: 1.1.1.1,8.8.8.8")
    p.add_argument("--asn-db", default="GeoLite2-ASN.mmdb", help="GeoLite2-ASN.mmdb")
    p.add_argument("--country-db", default="GeoLite2-Country.mmdb", help="GeoLite2-Country.mmdb")
    p.add_argument("--serve", action="store_true", help="Запустить API (FastAPI)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()

    if args.serve:
        if not HAS_FASTAPI:
            print("FastAPI/uvicorn не установлены: pip install fastapi uvicorn", file=sys.stderr); sys.exit(2)
        app = build_app(); uvicorn.run(app, host=args.host, port=args.port); return

    hosts: List[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"): hosts.append(s)
    for h in args.hosts:
        s = h.strip()
        if s: hosts.append(s)
    hosts = sorted(set(hosts))
    if not hosts:
        print("Укажите хосты: safe_net_probe.py example.com cloudflare.com  или  -f hosts.txt", file=sys.stderr)
        sys.exit(2)

    dns_list = None
    if args.dns: dns_list = [ip.strip() for ip in args.dns.split(",") if ip.strip()]
    resolver = build_resolver(dns_list)
    auditor = Auditor(args.audit)
    geo = GeoAnnotator(args.asn_db, args.country_db)
    out = asyncio.run(run_all(hosts, auditor, resolver, geo))

    print(f"{'HOST':30} {'DIAG':24} {'http':6} {'mode':12} {'alpn':6} {'tls':8} {'h3':4}  BEST        CAPS")
    for r in out:
        print(f"{r.host:30} {r.diag:24} {str(r.http_status or '-'):6} {str(r.http_mode or '-'):12} {str(r.alpn_sni or '-'):6} {str(r.tls_sni_version or '-'):8} {str(r.h3_ok):4}  {(r.best_transport or '-'):10} {','.join(r.capabilities)}")

    summ = summarize_transport(out)
    recs = recommendations(summ)
    by_cty = summarize_by_country(out)
    by_org = summarize_by_org(out)
    finger = policy_fingerprint(summ, by_cty)

    print("\n=== SUMMARY ==="); print(json.dumps(summ, ensure_ascii=False, indent=2))
    print("\n=== COUNTRY SUMMARY (RU vs non-RU) ==="); print(json.dumps(by_cty, ensure_ascii=False, indent=2))
    print("\n=== TOP ORGS (ASN owners) ==="); print(json.dumps(by_org, ensure_ascii=False, indent=2))
    print("\n=== POLICY FINGERPRINT ===")
    for i, line in enumerate(finger, 1): print(f"{i}. {line}")
    print("\n=== OBSERVER NOTES ===")
    for i, r in enumerate(recs, 1): print(f"{i}. {r}")

    extra = {"transport_summary": summ, "observer_notes": recs, "by_country": by_cty, "by_org": by_org, "policy_fingerprint": finger, "progress": dict(_PROGRESS)}
    if args.json: save_json(args.json, out, extra); print(f"\nJSON → {args.json}")
    if args.csv: save_csv(args.csv, out); print(f"CSV  → {args.csv}")
    if args.append_csv: append_csv(args.append_csv, out); print(f"Trend CSV → {args.append_csv}")
    if args.prom_file: save_prometheus_textfile(args.prom_file, out, summ); print(f"Prom textfile → {args.prom_file}")
    if args.html: save_html(args.html, out, summ, recs); print(f"HTML → {args.html}")

if __name__ == "__main__":
    main()
