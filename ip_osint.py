"""
IP OSINT — тільки безкоштовні джерела + RapidAPI (якщо є ключ).
"""
import asyncio
import config
from http_client import session as _new


async def scan(ip: str) -> list:
    async with _new() as s:
        results = await asyncio.gather(
            _ipinfo(s, ip),
            _ip_api(s, ip),
            _bgpview(s, ip),
            _otx(s, ip),
            _greynoise(s, ip),
            _abuseipdb_free(s, ip),
            _rdns(s, ip),
            _rapid_ip(s, ip),
            _ipqualityscore(s, ip),
            return_exceptions=False,
        )
    return [r for r in results if r]


async def _ipinfo(s, ip):
    r = await s.get(f"https://ipinfo.io/{ip}/json")
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":      "ipinfo.io",
        "ip":       d.get("ip"),
        "hostname": d.get("hostname"),
        "city":     d.get("city"),
        "region":   d.get("region"),
        "country":  d.get("country"),
        "loc":      d.get("loc"),
        "org":      d.get("org"),
        "timezone": d.get("timezone"),
        "bogon":    d.get("bogon", False),
    }


async def _ip_api(s, ip):
    fields = ("status,country,countryCode,regionName,city,zip,"
              "lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    r = await s.get(f"http://ip-api.com/json/{ip}?fields={fields}")
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":     "ip-api.com",
        "country": d.get("country"),
        "cc":      d.get("countryCode"),
        "region":  d.get("regionName"),
        "city":    d.get("city"),
        "isp":     d.get("isp"),
        "org":     d.get("org"),
        "asn":     d.get("as"),
        "asname":  d.get("asname"),
        "rdns":    d.get("reverse"),
        "proxy":   d.get("proxy", False),
        "hosting": d.get("hosting", False),
        "mobile":  d.get("mobile", False),
    }


async def _bgpview(s, ip):
    r = await s.get(f"https://api.bgpview.io/ip/{ip}")
    if r.status != 200:
        return None
    d    = (await r.json()).get("data", {})
    asns = []
    for px in d.get("prefixes", [])[:3]:
        for a in px.get("asns", []):
            asns.append({
                "asn":     a.get("asn"),
                "name":    a.get("name"),
                "country": a.get("country_code"),
                "desc":    a.get("description", "")[:60],
            })
    rir = d.get("rir_allocation", {})
    return {
        "src":    "BGPView.io",
        "ptr":    d.get("ptr_record", ""),
        "asns":   asns,
        "rir":    rir.get("rir_name", ""),
        "prefix": rir.get("prefix", ""),
    }


async def _otx(s, ip):
    r = await s.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    )
    if r.status != 200:
        return None
    d      = await r.json()
    pulses = d.get("pulse_info", {}).get("pulses", [])
    return {
        "src":         "AlienVault OTX",
        "pulse_count": d.get("pulse_info", {}).get("count", 0),
        "reputation":  d.get("reputation", 0),
        "country":     d.get("country_name", ""),
        "asn":         d.get("asn", ""),
        "tags":        [p.get("name") for p in pulses[:5]],
    }


async def _greynoise(s, ip):
    r = await s.get(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": "community", **config.HEADERS},
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":            "GreyNoise",
        "noise":          d.get("noise", False),
        "riot":           d.get("riot", False),
        "classification": d.get("classification", ""),
        "name":           d.get("name", ""),
    }


async def _abuseipdb_free(s, ip):
    """AbuseIPDB — базова перевірка без ключа (обмежена)."""
    r = await s.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": "free", "Accept": "application/json"},
    )
    if r.status != 200:
        return None
    d = (await r.json()).get("data", {})
    return {
        "src":     "AbuseIPDB",
        "score":   d.get("abuseConfidenceScore", 0),
        "reports": d.get("totalReports", 0),
        "country": d.get("countryCode", ""),
        "isp":     d.get("isp", ""),
        "is_tor":  d.get("isTor", False),
    }


async def _rdns(s, ip):
    r = await s.get(f"https://api.hackertarget.com/reversedns/?q={ip}")
    if r.status != 200:
        return None
    return {"src": "Reverse DNS", "data": (await r.text()).strip()}


async def _rapid_ip(s, ip):
    """RapidAPI — IP Reputation (якщо є ключ)."""
    if not config.RAPID_KEY:
        return None
    r = await s.get(
        "https://ip-reputation-geoip-fraud-score.p.rapidapi.com/",
        params={"ip": ip},
        headers={
            "X-RapidAPI-Key":  config.RAPID_KEY,
            "X-RapidAPI-Host": "ip-reputation-geoip-fraud-score.p.rapidapi.com",
        },
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":         "RapidAPI IP Reputation",
        "fraud_score": d.get("fraud_score", 0),
        "vpn":         d.get("vpn", False),
        "tor":         d.get("tor", False),
        "bot":         d.get("bot_status", False),
        "country":     d.get("country_code", ""),
        "isp":         d.get("ISP", ""),
    }


async def _ipqualityscore(s, ip):
    """IPQualityScore — безкоштовний публічний ендпоінт."""
    r = await s.get(
        f"https://ipqualityscore.com/api/json/ip/free/{ip}",
        headers={"User-Agent": config.UA},
    )
    if r.status != 200:
        return None
    d = await r.json()
    if d.get("success") is False:
        return None
    return {
        "src":         "IPQualityScore",
        "fraud_score": d.get("fraud_score", 0),
        "vpn":         d.get("vpn", False),
        "tor":         d.get("tor", False),
        "proxy":       d.get("proxy", False),
        "bot":         d.get("bot_status", False),
        "country":     d.get("country_code", ""),
        "city":        d.get("city", ""),
        "isp":         d.get("ISP", ""),
  }
  
