"""
Email OSINT — повністю безкоштовно (без HIBP/Hunter ключів).
RapidAPI використовується для розширених перевірок якщо є ключ.
"""
import asyncio, hashlib, re
import config
from http_client import session as _new


async def scan(email: str) -> list:
    async with _new() as s:
        results = await asyncio.gather(
            _emailrep(s, email),
            _gravatar(s, email),
            _breach_dir(s, email),
            _dns_mx(s, email),
            _disposable(s, email),
            _tw_holehe(s, email),
            _gh_holehe(s, email),
            _rapid_email(s, email),
            return_exceptions=False,
        )
    return [r for r in results if r]


async def _emailrep(s, email):
    r = await s.get(
        f"https://emailrep.io/{email}",
        headers={"User-Agent": "osint-bot"},
    )
    if r.status != 200:
        return None
    d  = await r.json()
    dt = d.get("details", {})
    return {
        "src":        "EmailRep.io",
        "reputation": d.get("reputation"),
        "suspicious": d.get("suspicious", False),
        "references": d.get("references", 0),
        "breached":   dt.get("data_breach", False),
        "leaked":     dt.get("credentials_leaked", False),
        "disposable": dt.get("disposable", False),
        "spam":       dt.get("spam", False),
        "free":       dt.get("free_provider", False),
        "profiles":   dt.get("profiles", []),
        "first_seen": dt.get("first_seen", ""),
    }


async def _gravatar(s, email):
    h  = hashlib.md5(email.strip().lower().encode()).hexdigest()
    r  = await s.get(f"https://www.gravatar.com/{h}.json")
    if r.status != 200:
        return {"src": "Gravatar", "found": False}
    d  = (await r.json()).get("entry", [{}])[0]
    return {
        "src":      "Gravatar",
        "found":    True,
        "name":     d.get("displayName", ""),
        "url":      d.get("profileUrl", ""),
        "avatar":   f"https://www.gravatar.com/avatar/{h}?s=200",
        "accounts": [a.get("shortname") for a in d.get("accounts", [])],
        "bio":      d.get("aboutMe", "")[:120],
        "location": d.get("currentLocation", ""),
    }


async def _breach_dir(s, email):
    r = await s.get(
        "https://breachdirectory.org/api",
        params={"func": "auto", "term": email},
        headers={"User-Agent": "Mozilla/5.0",
                 "Referer":    "https://breachdirectory.org/"},
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":   "BreachDirectory",
        "found": d.get("found", False),
        "count": d.get("result", {}).get("count", 0) if d.get("found") else 0,
    }


async def _dns_mx(s, email):
    domain = email.split("@")[-1]
    r = await s.get(f"https://dns.google/resolve?name={domain}&type=MX")
    if r.status != 200:
        return None
    d    = await r.json()
    recs = [a.get("data", "") for a in d.get("Answer", [])]
    return {
        "src":    "DNS/MX",
        "domain": domain,
        "has_mx": bool(recs),
        "records": recs[:4],
    }


async def _disposable(s, email):
    """Перевірка через безкоштовний API disposable-email-domains."""
    domain = email.split("@")[-1]
    r = await s.get(
        f"https://open.kickbox.com/v1/disposable/{domain}",
        headers={"User-Agent": "osint-bot"},
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":        "Kickbox Disposable",
        "disposable": d.get("disposable", False),
        "domain":     domain,
    }


async def _tw_holehe(s, email):
    r = await s.get(
        "https://api.twitter.com/i/users/email_available.json",
        params={"email": email},
        headers={"User-Agent": config.UA},
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {"src": "Twitter (holehe)", "registered": not d.get("valid", True)}


async def _gh_holehe(s, email):
    r = await s.post(
        "https://github.com/password_reset",
        data={"email": email},
        headers={"User-Agent": config.UA,
                 "Referer":    "https://github.com/password_reset"},
    )
    txt = await r.text()
    return {"src": "GitHub (holehe)", "registered": "we found" in txt.lower()}


async def _rapid_email(s, email):
    """RapidAPI — Email Reputation (якщо є ключ)."""
    if not config.RAPID_KEY:
        return None
    r = await s.get(
        "https://email-reputation.p.rapidapi.com/",
        params={"email": email},
        headers={
            "X-RapidAPI-Key":  config.RAPID_KEY,
            "X-RapidAPI-Host": "email-reputation.p.rapidapi.com",
        },
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":        "RapidAPI Email",
        "valid":      d.get("valid"),
        "disposable": d.get("disposable"),
        "risky":      d.get("risky"),
        "score":      d.get("score"),
        "reason":     d.get("reason", ""),
  }
  
