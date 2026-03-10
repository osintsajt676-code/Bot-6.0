"""
Google Dork генератор для OSINT.
Формує готові dork-запити для пошуку інформації про ціль.
Відкриває пошуковик через посилання — без API, повністю безкоштовно.
"""
from urllib.parse import quote_plus

# ── Базові дорки ────────────────────────────────────────────────────

def _q(query: str) -> str:
    """URL для Google пошуку."""
    return f"https://www.google.com/search?q={quote_plus(query)}"

def _bing(query: str) -> str:
    return f"https://www.bing.com/search?q={quote_plus(query)}"

def _ddg(query: str) -> str:
    return f"https://duckduckgo.com/?q={quote_plus(query)}"

def _yandex(query: str) -> str:
    return f"https://yandex.com/search/?text={quote_plus(query)}"

def _gh(query: str) -> str:
    return f"https://github.com/search?q={quote_plus(query)}&type=code"

def _pt(query: str) -> str:
    return f"https://pastebin.com/search?q={quote_plus(query)}"


# ══════════════════════════════════════════════════════════════════════
#  USERNAME DORKS
# ══════════════════════════════════════════════════════════════════════
def username_dorks(username: str) -> list:
    return [
        # Прямий пошук
        {"label": "Google — всі згадки",      "url": _q(f'"{username}"')},
        {"label": "Bing — всі згадки",         "url": _bing(f'"{username}"')},
        {"label": "DuckDuckGo",                "url": _ddg(f'"{username}"')},
        {"label": "Яндекс",                    "url": _yandex(f'"{username}"')},

        # Соцмережі
        {"label": "Twitter/X профіль",         "url": _q(f'site:x.com OR site:twitter.com "{username}"')},
        {"label": "Instagram профіль",         "url": _q(f'site:instagram.com "{username}"')},
        {"label": "TikTok профіль",            "url": _q(f'site:tiktok.com "@{username}"')},
        {"label": "Reddit профіль",            "url": _q(f'site:reddit.com/user "{username}"')},
        {"label": "LinkedIn профіль",          "url": _q(f'site:linkedin.com/in "{username}"')},
        {"label": "VK профіль",                "url": _q(f'site:vk.com "{username}"')},
        {"label": "Facebook профіль",          "url": _q(f'site:facebook.com "{username}"')},
        {"label": "YouTube канал",             "url": _q(f'site:youtube.com "@{username}"')},
        {"label": "Twitch канал",              "url": _q(f'site:twitch.tv "{username}"')},
        {"label": "GitHub профіль",            "url": _q(f'site:github.com "{username}"')},
        {"label": "GitHub код",                "url": _gh(username)},
        {"label": "Medium профіль",            "url": _q(f'site:medium.com "@{username}"')},
        {"label": "Telegram",                  "url": _q(f'site:t.me "{username}"')},

        # Витоки / паролі
        {"label": "Pastebin витоки",           "url": _pt(username)},
        {"label": "Pastebin Google",           "url": _q(f'site:pastebin.com "{username}"')},
        {"label": "Ghostbin/Hastebin",         "url": _q(f'site:hastebin.com OR site:ghostbin.co "{username}"')},
        {"label": "Пошта + пароль (dork)",     "url": _q(f'"{username}" password OR passwd OR pwd filetype:txt OR filetype:csv')},
        {"label": "Email витоки",              "url": _q(f'"{username}" email leak OR breach OR dump')},

        # Форуми / архіви
        {"label": "Веб-архів",                 "url": f"https://web.archive.org/web/*/{quote_plus(username)}"},
        {"label": "Google cache",              "url": _q(f'cache:"{username}"')},
        {"label": "Форуми/дошки",             "url": _q(f'inurl:"{username}" forum OR board OR community')},

        # Зображення
        {"label": "Google Зображення",        "url": f"https://www.google.com/search?tbm=isch&q={quote_plus(username)}"},
    ]


# ══════════════════════════════════════════════════════════════════════
#  EMAIL DORKS
# ══════════════════════════════════════════════════════════════════════
def email_dorks(email: str) -> list:
    user, domain = (email.split("@") + [""])[:2]
    return [
        {"label": "Google — email",             "url": _q(f'"{email}"')},
        {"label": "Bing — email",               "url": _bing(f'"{email}"')},
        {"label": "GitHub код",                 "url": _gh(email)},
        {"label": "Pastebin",                   "url": _pt(email)},
        {"label": "LinkedIn + email",           "url": _q(f'site:linkedin.com "{email}"')},
        {"label": "Документи з email",          "url": _q(f'"{email}" filetype:pdf OR filetype:doc OR filetype:xls')},
        {"label": "Email + пароль",             "url": _q(f'"{email}" password OR passwd')},
        {"label": "Email в JSON/XML",           "url": _q(f'"{email}" filetype:json OR filetype:xml')},
        {"label": "Email в SQL дампах",         "url": _q(f'"{email}" filetype:sql')},
        {"label": "Профілі за username",        "url": _q(f'"{user}" profile OR account')},
        {"label": "Домен компанії",             "url": _q(f'site:{domain} "{user}"') if domain else ""},
        {"label": "Веб-архів",                  "url": f"https://web.archive.org/web/*/{quote_plus(email)}"},
    ]


# ══════════════════════════════════════════════════════════════════════
#  DOMAIN DORKS
# ══════════════════════════════════════════════════════════════════════
def domain_dorks(domain: str) -> list:
    return [
        # Розвідка
        {"label": "Всі сторінки сайту",        "url": _q(f'site:{domain}')},
        {"label": "Субдомени",                  "url": _q(f'site:*.{domain}')},
        {"label": "Login / Admin панелі",       "url": _q(f'site:{domain} inurl:login OR inurl:admin OR inurl:panel OR inurl:dashboard')},
        {"label": "Файли конфігурації",         "url": _q(f'site:{domain} ext:env OR ext:cfg OR ext:conf OR ext:ini OR ext:yaml')},
        {"label": "Бекапи та дампи",            "url": _q(f'site:{domain} ext:bak OR ext:backup OR ext:sql OR ext:dump')},
        {"label": "Відкриті директорії",        "url": _q(f'site:{domain} intitle:"index of"')},
        {"label": "PHP info / помилки",        "url": _q(f'site:{domain} inurl:phpinfo OR "PHP Warning" OR "Fatal error"')},
        {"label": "Robots.txt",                 "url": f"https://{domain}/robots.txt"},
        {"label": "Sitemap.xml",                "url": f"https://{domain}/sitemap.xml"},
        {"label": ".git відкритий",             "url": _q(f'site:{domain} inurl:.git')},
        {"label": "API ключі в коді",           "url": _q(f'site:{domain} "api_key" OR "api-key" OR "apikey"')},
        {"label": "Паролі в коді",              "url": _q(f'site:{domain} "password" OR "passwd" filetype:txt OR filetype:log')},

        # Технічна розвідка
        {"label": "SSL/crt.sh",                "url": f"https://crt.sh/?q=%.{domain}"},
        {"label": "Shodan",                    "url": f"https://www.shodan.io/search?query={quote_plus(f'hostname:{domain}')}"},
        {"label": "URLScan.io",                "url": f"https://urlscan.io/search/#domain:{domain}"},
        {"label": "Wayback Machine",           "url": f"https://web.archive.org/web/*/{domain}/*"},
        {"label": "VirusTotal домен",          "url": f"https://www.virustotal.com/gui/domain/{domain}"},
        {"label": "DNSDumpster",               "url": f"https://dnsdumpster.com/"},
        {"label": "SecurityTrails",            "url": f"https://securitytrails.com/domain/{domain}/dns"},
        {"label": "Censys",                    "url": f"https://search.censys.io/search?resource=hosts&q={quote_plus(domain)}"},

        # GitHub витоки
        {"label": "GitHub — домен в коді",    "url": _gh(domain)},
        {"label": "Pastebin — домен",         "url": _pt(domain)},
        {"label": "Emails на домені",          "url": _q(f'"@{domain}" email')},
    ]


# ══════════════════════════════════════════════════════════════════════
#  IP DORKS
# ══════════════════════════════════════════════════════════════════════
def ip_dorks(ip: str) -> list:
    return [
        {"label": "Google — IP",               "url": _q(f'"{ip}"')},
        {"label": "Shodan",                    "url": f"https://www.shodan.io/host/{ip}"},
        {"label": "Censys",                    "url": f"https://search.censys.io/hosts/{ip}"},
        {"label": "VirusTotal IP",             "url": f"https://www.virustotal.com/gui/ip-address/{ip}"},
        {"label": "AbuseIPDB",                 "url": f"https://www.abuseipdb.com/check/{ip}"},
        {"label": "GreyNoise",                 "url": f"https://viz.greynoise.io/ip/{ip}"},
        {"label": "Threat Intel",              "url": f"https://otx.alienvault.com/indicator/ip/{ip}"},
        {"label": "BGPView",                   "url": f"https://bgpview.io/ip/{ip}"},
        {"label": "IPVoid",                    "url": f"https://www.ipvoid.com/ip-blacklist-check/?ip={ip}"},
        {"label": "MXToolbox",                 "url": f"https://mxtoolbox.com/blacklists.aspx?domain={ip}"},
        {"label": "Fofa",                      "url": f"https://en.fofa.info/result?qbase64={quote_plus(f'ip=\"{ip}\"')}"},
        {"label": "ZoomEye",                   "url": f"https://www.zoomeye.org/searchResult?q={quote_plus(f'ip:{ip}')}"},
    ]


# ══════════════════════════════════════════════════════════════════════
#  PHONE DORKS
# ══════════════════════════════════════════════════════════════════════
def phone_dorks(phone: str) -> list:
    clean    = phone.replace("+", "").replace(" ", "").replace("-", "")
    variants = list({phone, f"+{clean}", clean,
                     f"{clean[:3]} {clean[3:6]} {clean[6:]}"})
    results  = []
    for v in variants[:3]:
        results += [
            {"label": f'Google "{v}"',         "url": _q(f'"{v}"')},
            {"label": f'Bing "{v}"',            "url": _bing(f'"{v}"')},
        ]
    results += [
        {"label": "Truecaller",                "url": f"https://www.truecaller.com/search/ua/{clean}"},
        {"label": "GetContact web",            "url": f"https://getcontact.com/en/phone/{clean}"},
        {"label": "NumLookup",                 "url": f"https://www.numlookup.com/?q={clean}"},
        {"label": "WhoCalledMe",               "url": f"https://who-called.co.uk/number/{clean}"},
        {"label": "Sync.me",                   "url": f"https://sync.me/search/?number={clean}"},
        {"label": "Pastebin",                  "url": _pt(phone)},
    ]
    return results


# ══════════════════════════════════════════════════════════════════════
#  Форматування
# ══════════════════════════════════════════════════════════════════════
def fmt_dorks(title: str, dorks: list, max_show: int = 20) -> str:
    lines = [f"🔍 *Google Dorks — {title}*", ""]
    for d in dorks[:max_show]:
        if not d.get("url"):
            continue
        lines.append(f"• [{d['label']}]({d['url']})")
    return "\n".join(lines)
    
