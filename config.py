import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ── Обов'язково ────────────────────────────────────────
BOT_TOKEN    = os.getenv("BOT_TOKEN", "")

# ── RapidAPI (один ключ — багато сервісів) ─────────────
# https://rapidapi.com — безкоштовна реєстрація
# Дає доступ до: truecaller, phoneapi, whois, email-checker і ін.
RAPID_KEY    = os.getenv("RAPID_API_KEY", "")

# ── HTTP ───────────────────────────────────────────────
TIMEOUT      = 14
TASKS        = 60          # паралельних запитів у scanner
UA           = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
HEADERS      = {
    "User-Agent":      UA,
    "Accept-Language": "en-US,en;q=0.5",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT":             "1",
}
PROXY        = os.getenv("PROXY_URL") or None


def key_status() -> str:
    return (
        f"  {'✅' if BOT_TOKEN  else '❌'} BOT_TOKEN\n"
        f"  {'✅' if RAPID_KEY  else '⬜'} RAPID_API_KEY"
    )
  
