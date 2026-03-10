"""
Domain OSINT — asyncwhois (реальний WHOIS) + безкоштовні джерела.
"""
import asyncio, re
import config
from http_client import session as _new

try:
    import asyncwhois
    _AW = True
except ImportError:
    _AW = False


async def scan(domain: str) -> list:
    async with _new() as s:
        results = await asyncio.gather(
            _whois(domain),
            _dns(s, domain),
            _crtsh(s, domain),
            _subdomains(s, domain),
            _headers(s, domain),
            _urlscan(s, domain),
            _wayback(s, domain),
            _robots(s, domain),
            _rapid_domain(s, domain),
            return_exceptions=False,
        )
    return [r for r in results if r]


async def _whois(domain):
    """asyncwhois — справжній WHOIS через протокол (без API)."""
    if not _AW:
        return {"src": "WHOIS", "error": "asyncwhois not installed"}
    try:
        res = await asyncwhois.aio_whois_domain(domain)
        q   = res.query_output or ""
        p   = res.parser_output or {}
        return {
            "src":         "WHOIS",
            "raw":         q[:2500],
            "registrar":   p.get("registrar", ""),
            "created":     str(p.get("created", ""))[:19],
            "expires":     str(p.get("expires", ""))[:19],
            "updated":     str(p.get("updated", ""))[:19],
            "status":      p.get("status", []),
            "nameservers": p.get("name_servers", []),
        }
    except Exception as e:
        return {"src": "WHOIS", "error": str(e)[:80]}


async def _dns(s, domain):
    records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        try:
            r = await s.get(f"https://dns.google/resolve?name={domain}&type={rtype}")
            if r.status == 200:
                d   = await r.json()
                ans = [a.get("data", "") for a in d.get("Answer", [])]
                if ans:
                    records[rtype] = ans
        except Exception:
            pass
    return {"src": "DNS", "records": records} if records else None


async def _crtsh(s, domain):
    r = await s.get(
        f"https://crt.sh/?q=%.{domain}&output=json",
        timeout=25,
    )
    if r.status != 200:
        return None
    data = await r.json()
    subs, issuers = set(), set()
    for c in data[:500]:
        for n in c.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.")
            if domain in n:
                subs.add(n)
        m = re.search(r"CN=([^,]+)", c.get("issuer_name", ""))
        if m:
            issuers.add(m.group(1))
    return {
        "src":        "crt.sh",
        "cert_count": len(data),
        "subdomains": sorted(subs)[:60],
        "issuers":    list(issuers)[:5],
    }


async def _subdomains(s, domain):
    r = await s.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if r.status != 200:
        return None
    txt = await r.text()
    if "error" in txt.lower() or "API count" in txt:
        return {"src": "Subdomains", "rate_limited": True}
    lines = [l.split(",") for l in txt.strip().split("\n") if "," in l]
    return {
        "src":   "Subdomains",
        "hosts": [{"host": l[0], "ip": l[1]} for l in lines[:50]],
    }


async def _headers(s, domain):
    r = await s.get(f"https://{domain}", headers=config.HEADERS)
    if r.status == 0:
        return None
    txt = await r.text()
    # Парсимо заголовки з curl_cffi відповіді — беремо з тексту
    interesting = ["Server", "X-Powered-By", "X-Generator", "CF-Ray",
                   "X-CDN", "Via", "X-Frame-Options", "X-WP-Version",
                   "Strict-Transport-Security", "X-AspNet-Version"]
    hdrs = {}
    for k in interesting:
        m = re.search(rf'{k}:\s*([^\r\n]+)', txt, re.IGNORECASE)
        if m:
            hdrs[k] = m.group(1).strip()[:80]
    return {
        "src":     "HTTP Headers",
        "status":  r.status,
        "url":     f"https://{domain}",
        "headers": hdrs,
    }


async def _urlscan(s, domain):
    r = await s.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5")
    if r.status != 200:
        return None
    d     = await r.json()
    scans = [{"ip":      x.get("page", {}).get("ip", ""),
              "country": x.get("page", {}).get("country", ""),
              "server":  x.get("page", {}).get("server", "")}
             for x in d.get("results", [])]
    return {"src": "URLScan.io", "total": d.get("total", 0), "scans": scans}


async def _wayback(s, domain):
    r = await s.get(f"https://archive.org/wayback/available?url={domain}")
    if r.status != 200:
        return None
    d    = await r.json()
    snap = d.get("archived_snapshots", {}).get("closest", {})
    if not snap:
        return None
    ts = snap.get("timestamp", "")
    return {
        "src":       "Wayback Machine",
        "available": snap.get("available"),
        "url":       snap.get("url", ""),
        "date":      f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts,
    }


async def _robots(s, domain):
    found = {}
    for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt",
                 ".well-known/assetlinks.json", "humans.txt", "crossdomain.xml"):
        r = await s.get(f"https://{domain}/{path}")
        if r.status == 200:
            found[path] = (await r.text())[:400]
    return {"src": "Robots/Files", "files": found} if found else None


async def _rapid_domain(s, domain):
    """RapidAPI — WHOIS XML (якщо є ключ)."""
    if not config.RAPID_KEY:
        return None
    r = await s.get(
        "https://whoisapi-whois-v2.p.rapidapi.com/whoisserver/WhoisService",
        params={"apiKey": config.RAPID_KEY, "domainName": domain, "outputFormat": "JSON"},
        headers={
            "X-RapidAPI-Key":  config.RAPID_KEY,
            "X-RapidAPI-Host": "whoisapi-whois-v2.p.rapidapi.com",
        },
    )
    if r.status != 200:
        return None
    d  = (await r.json()).get("WhoisRecord", {})
    ri = d.get("registrarInfo", {})
    return {
        "src":       "RapidAPI WHOIS",
        "registrar": ri.get("name", ""),
        "created":   d.get("registryData", {}).get("createdDateNormalized", ""),
        "expires":   d.get("registryData", {}).get("expiresDateNormalized", ""),
        "contact":   d.get("contactEmail", ""),
}
  
