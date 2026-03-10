from typing import List, Dict


def split(text: str, n: int = 4000) -> List[str]:
    parts = []
    while text:
        chunk = text[:n]
        nl = chunk.rfind("\n")
        if nl > n // 2:
            chunk = chunk[:nl]
        parts.append(chunk.strip())
        text = text[len(chunk):]
    return [p for p in parts if p]


# ── NICK ──────────────────────────────────────────────
def nick(username: str, found: List[Dict], total: int) -> str:
    lines = [
        "🕵 *OSINT — Username*",
        f"🎯 `{username}` | Сайтів: {total} | ✅ {len(found)}",
        "",
    ]
    if not found:
        lines.append("❌ Акаунти не знайдені.")
    else:
        lines.append("*Знайдені акаунти:*")
        for f in found:
            lines.append(f"• [{f['name']}]({f['url']})")
    return "\n".join(lines)


# ── EMAIL ─────────────────────────────────────────────
def email(addr: str, results: List[Dict]) -> str:
    lines = ["🕵 *OSINT — Email*", f"📧 `{addr}`", ""]
    for r in results:
        if not r:
            continue
        src = r.get("src", "")
        if r.get("error"):
            continue

        if src == "EmailRep.io":
            susp = "⚠️ ПІДОЗРІЛИЙ" if r.get("suspicious") else "✅ Норм"
            lines += ["", f"📋 *EmailRep.io* — {susp}",
                      f"  Репутація: `{r.get('reputation')}` | Посилань: {r.get('references', 0)}"]
            if r.get("breached"):   lines.append("  🔴 Витік даних: ТАК")
            if r.get("leaked"):     lines.append("  🔴 Паролі витекли: ТАК")
            if r.get("disposable"): lines.append("  ⚠️ Одноразова адреса")
            if r.get("spam"):       lines.append("  ⚠️ Скарги на спам")
            if r.get("profiles"):   lines.append(f"  🌐 Профілі: {', '.join(r['profiles'][:6])}")
            if r.get("first_seen"): lines.append(f"  📅 Перший раз: {r['first_seen']}")

        elif src == "Gravatar":
            if r.get("found"):
                n = r.get("name") or "профіль"
                lines += ["", f"🟢 *Gravatar*: [{n}]({r.get('url', '')})"]
                if r.get("location"): lines.append(f"  📍 {r['location']}")
                if r.get("accounts"): lines.append(f"  🌐 {', '.join(a for a in r['accounts'] if a)}")
                if r.get("bio"):      lines.append(f"  Bio: {r['bio']}")
                lines.append(f"  🖼 {r.get('avatar', '')}")
            else:
                lines.append("⚪ *Gravatar*: не знайдено")

        elif src == "BreachDirectory":
            if r.get("found"):
                lines.append(f"🔴 *BreachDirectory*: {r.get('count', '?')} записів")
            else:
                lines.append("🟢 *BreachDirectory*: чисто")

        elif src == "DNS/MX":
            lines.append(f"🌐 *DNS/MX*: {'✅' if r.get('has_mx') else '❌'} | {r.get('domain', '')}")

        elif src == "Kickbox Disposable":
            if r.get("disposable"):
                lines.append(f"⚠️ *Одноразовий домен*: {r.get('domain', '')}")

        elif "holehe" in src.lower():
            reg = r.get("registered")
            if reg is True:
                lines.append(f"🔴 *{src}*: ЗАРЕЄСТРОВАНИЙ")
            elif reg is False:
                lines.append(f"🟢 *{src}*: не знайдено")

        elif src == "RapidAPI Email":
            lines += ["", f"📊 *RapidAPI Email*: score={r.get('score')} risky={r.get('risky')}"]
            if r.get("disposable"): lines.append("  ⚠️ Одноразовий")
            if r.get("reason"):     lines.append(f"  Причина: {r['reason']}")

    return "\n".join(lines)


# ── DOMAIN ────────────────────────────────────────────
def domain(dom: str, results: List[Dict]) -> str:
    lines = ["🕵 *OSINT — Domain*", f"🌐 `{dom}`", ""]
    for r in results:
        if not r:
            continue
        src = r.get("src", "")
        if r.get("error"):
            lines.append(f"⚠️ *{src}*: {r['error'][:60]}")
            continue
        if r.get("rate_limited"):
            lines.append(f"⏳ *{src}*: rate limit")
            continue

        if src == "WHOIS":
            lines += ["", "📋 *WHOIS:*"]
            if r.get("registrar"):   lines.append(f"  Registrar: {r['registrar']}")
            if r.get("created"):     lines.append(f"  Created:   {r['created']}")
            if r.get("expires"):     lines.append(f"  Expires:   {r['expires']}")
            ns = r.get("nameservers", [])
            if ns:                   lines.append(f"  NS: {', '.join(str(n) for n in ns[:3])}")
            st = r.get("status", [])
            if st:                   lines.append(f"  Status: {', '.join(st[:2]) if isinstance(st, list) else st}")

        elif src == "DNS":
            lines += ["", "🔢 *DNS:*"]
            for t, vals in r.get("records", {}).items():
                for v in vals[:2]:
                    lines.append(f"  {t}: {v[:80]}")

        elif src == "crt.sh":
            subs = r.get("subdomains", [])
            lines += ["", f"📜 *crt.sh*: {r.get('cert_count', 0)} сертифікатів | {len(subs)} субдоменів"]
            if r.get("issuers"): lines.append(f"  CA: {', '.join(r['issuers'][:3])}")
            for sub in subs[:20]: lines.append(f"  • {sub}")

        elif src == "Subdomains":
            hosts = r.get("hosts", [])
            lines += ["", f"🔎 *Субдомени*: {len(hosts)}"]
            for h in hosts[:20]: lines.append(f"  • {h['host']} → {h['ip']}")

        elif src == "HTTP Headers":
            lines += ["", f"🌍 *HTTP*: {r.get('status', '')} | {r.get('url', '')}"]
            for k, v in r.get("headers", {}).items():
                lines.append(f"  {k}: {v[:70]}")

        elif src == "URLScan.io":
            lines += ["", f"🔍 *URLScan.io*: {r.get('total', 0)} скань"]
            for sc in r.get("scans", [])[:3]:
                lines.append(f"  IP: {sc.get('ip')} | {sc.get('country')} | {sc.get('server', '')}")

        elif src == "Wayback Machine":
            if r.get("available"):
                lines += ["", f"📦 *Wayback Machine*: знімок {r.get('date', '')}"]
                lines.append(f"  {r.get('url', '')[:100]}")

        elif src == "Robots/Files":
            for fname in r.get("files", {}):
                lines.append(f"📄 /{fname} — знайдено")

        elif src == "RapidAPI WHOIS":
            lines += ["", "📋 *RapidAPI WHOIS:*"]
            if r.get("registrar"): lines.append(f"  Registrar: {r['registrar']}")
            if r.get("created"):   lines.append(f"  Created: {r['created']}")
            if r.get("expires"):   lines.append(f"  Expires: {r['expires']}")
            if r.get("contact"):   lines.append(f"  Contact: {r['contact']}")

    return "\n".join(lines)


# ── IP ────────────────────────────────────────────────
def ip(addr: str, results: List[Dict]) -> str:
    lines = ["🕵 *OSINT — IP*", f"🖥 `{addr}`", ""]
    for r in results:
        if not r:
            continue
        src = r.get("src", "")

        if src == "ipinfo.io":
            lines += ["", "📍 *ipinfo.io:*"]
            lines.append(f"  🌍 {r.get('city', '')}, {r.get('region', '')}, {r.get('country', '')}")
            lines.append(f"  🏢 {r.get('org', '')}")
            lines.append(f"  🖥 {r.get('hostname', '')} | TZ: {r.get('timezone', '')}")
            if r.get("bogon"): lines.append("  ⚠️ Bogon IP")

        elif src == "ip-api.com":
            p = "🔴 PROXY/VPN" if r.get("proxy")   else "✅ Чистий"
            h = " ☁️ Хостинг"  if r.get("hosting") else ""
            m = " 📱 Mobile"   if r.get("mobile")   else ""
            lines += ["", f"🗺 *ip-api.com*: {p}{h}{m}"]
            lines.append(f"  ISP: {r.get('isp', '')} | {r.get('city', '')}, {r.get('country', '')} [{r.get('cc', '')}]")
            lines.append(f"  ASN: {r.get('asn', '')} | rDNS: {r.get('rdns', '')}")

        elif src == "BGPView.io":
            lines += ["", f"🔗 *BGPView*: PTR={r.get('ptr', '') or '—'} | RIR={r.get('rir', '')}"]
            for a in r.get("asns", [])[:3]:
                lines.append(f"  AS{a.get('asn')} {a.get('name', '')} [{a.get('country', '')}]")

        elif src == "AlienVault OTX":
            p    = r.get("pulse_count", 0)
            flag = "🔴" if p > 0 else "🟢"
            lines += ["", f"{flag} *AlienVault OTX*: {p} загроз"]
            if r.get("tags"): lines.append(f"  Теги: {', '.join(t for t in r['tags'] if t)[:80]}")

        elif src == "AbuseIPDB":
            sc   = r.get("score", 0)
            flag = "🔴" if sc > 50 else ("⚠️" if sc > 10 else "🟢")
            lines += ["", f"{flag} *AbuseIPDB*: {sc}/100 | Скарг: {r.get('reports', 0)}"]
            lines.append(f"  ISP: {r.get('isp', '')} | {r.get('country', '')} {'🔴 TOR' if r.get('is_tor') else ''}")

        elif src == "GreyNoise":
            cl   = r.get("classification", "")
            flag = "🔴" if (r.get("noise") and cl == "malicious") else ("⚠️" if r.get("noise") else "🟢")
            lines += ["", f"{flag} *GreyNoise*: {cl or 'unknown'} | {r.get('name', '')}"]

        elif src == "IPQualityScore":
            sc   = r.get("fraud_score", 0)
            flag = "🔴" if sc > 75 else ("⚠️" if sc > 40 else "🟢")
            lines += ["", f"{flag} *IPQualityScore*: fraud={sc}"]
            flags = []
            if r.get("vpn"):   flags.append("VPN")
            if r.get("tor"):   flags.append("TOR")
            if r.get("proxy"): flags.append("Proxy")
            if r.get("bot"):   flags.append("Bot")
            if flags:          lines.append(f"  🏴 {', '.join(flags)}")
            lines.append(f"  {r.get('city', '')} | {r.get('isp', '')}")

        elif src == "RapidAPI IP Reputation":
            lines += ["", f"📊 *RapidAPI IP*: fraud={r.get('fraud_score', 0)}"]
            flags = [k for k in ("vpn", "tor", "bot") if r.get(k)]
            if flags: lines.append(f"  🏴 {', '.join(flags)}")

        elif src == "Reverse DNS":
            lines += ["", f"🔄 *Reverse DNS*: {r.get('data', '')}"]

    return "\n".join(lines)


# ── SOCIAL ────────────────────────────────────────────
def social(username: str, results: List[Dict]) -> str:
    found     = [r for r in results if r.get("found") is True]
    not_found = [r for r in results if r.get("found") is False]
    lines = [
        "🕵 *OSINT — Social*",
        f"🎯 `{username}` | ✅ {len(found)} | ❌ {len(not_found)}",
        "",
    ]
    for r in found:
        p   = r.get("platform", "")
        url = r.get("url", "")
        lines.append(f"🟢 *{p}*: {url}")
        if p == "GitHub":
            if r.get("name"):     lines.append(f"  👤 {r['name']}")
            if r.get("bio"):      lines.append(f"  Bio: {r['bio'][:80]}")
            if r.get("location"): lines.append(f"  📍 {r['location']}")
            if r.get("email"):    lines.append(f"  📧 {r['email']}")
            if r.get("company"):  lines.append(f"  🏢 {r['company']}")
            if r.get("blog"):     lines.append(f"  🔗 {r['blog']}")
            lines.append(f"  Repos: {r.get('repos', 0)} | Followers: {r.get('followers', 0)}")
            if r.get("twitter"):  lines.append(f"  🐦 @{r['twitter']}")
            if r.get("created"):  lines.append(f"  📅 {r['created']}")
            for repo in r.get("top_repos", [])[:3]:
                lines.append(f"  ⭐{repo.get('stars', 0)} [{repo['name']}]({repo.get('url', '')}) {repo.get('lang', '') or ''}")
        elif p == "GitLab":
            if r.get("name"):     lines.append(f"  👤 {r['name']}")
            if r.get("bio"):      lines.append(f"  Bio: {r['bio'][:80]}")
            if r.get("location"): lines.append(f"  📍 {r['location']}")
        elif p == "Reddit":
            lines.append(f"  Karma: {r.get('post_karma', 0)}+{r.get('comment_karma', 0)}={r.get('total_karma', 0)}")
            if r.get("is_mod"): lines.append("  🛡 Mod")
            if r.get("gold"):   lines.append("  ⭐ Gold")
        elif p == "Telegram":
            if r.get("name"):        lines.append(f"  📛 {r['name']}")
            if r.get("subscribers"): lines.append(f"  👥 {r['subscribers']}")
            if r.get("description"): lines.append(f"  📝 {r['description'][:80]}")
        elif p == "Mastodon":
            if r.get("name"):      lines.append(f"  👤 {r['name']} @ {r.get('instance', '')}")
            lines.append(f"  Followers: {r.get('followers', 0)} | Posts: {r.get('posts', 0)}")
        elif p == "Steam":
            if r.get("name"):  lines.append(f"  👤 {r['name']}")
            if r.get("level"): lines.append(f"  🎮 Level: {r['level']}")
        elif p == "YouTube":
            if r.get("name"):        lines.append(f"  👤 {r['name']}")
            if r.get("subscribers"): lines.append(f"  👥 {r['subscribers']}")
        elif p in ("Twitter/X", "TikTok", "Instagram"):
            if r.get("bio"): lines.append(f"  Bio: {r.get('bio', '')[:80]}")
        elif p == "VK":
            if r.get("name"): lines.append(f"  👤 {r['name']}")
            if r.get("desc"): lines.append(f"  📝 {r['desc'][:60]}")
        lines.append("")
    if not_found:
        lines.append(f"*Не знайдено:* {', '.join(r.get('platform', '') for r in not_found)}")
    return "\n".join(lines)


# ── PHONE ─────────────────────────────────────────────
def phone(number: str, results: List[Dict]) -> str:
    lines = ["🕵 *OSINT — Phone*", f"📱 `{number}`", ""]
    for r in results:
        if not r:
            continue
        src = r.get("src", "")
        if r.get("no_lib"): lines.append(f"📦 *{src}*: бібліотека не встановлена"); continue
        if r.get("error"):  continue

        if src == "phonenumbers (Google)":
            valid = r.get("valid")
            lines += ["", f"{'✅' if valid else '❌'} *phonenumbers (Google):*"]
            lines.append(f"  Формат: {r.get('international', '')}")
            lines.append(f"  Тип: {r.get('number_type', '')}")
            if r.get("country"):   lines.append(f"  🌍 {r['country']}")
            if r.get("carrier"):   lines.append(f"  📡 {r['carrier']}")
            if r.get("timezones"): lines.append(f"  🕐 {', '.join(r['timezones'][:2])}")

        elif src in ("NumVerify (free)", "RapidAPI Phone"):
            lines += ["", f"📞 *{src}:*"]
            if r.get("country"):   lines.append(f"  🌍 {r['country']}")
            if r.get("location"):  lines.append(f"  📍 {r['location']}")
            if r.get("carrier"):   lines.append(f"  📡 {r['carrier']}")
            if r.get("line_type"): lines.append(f"  Тип: {r['line_type']}")

        elif src == "Truecaller (RapidAPI)":
            if r.get("name"):
                lines += ["", f"👤 *Truecaller*: `{r['name']}`"]
                if r.get("carrier"): lines.append(f"  📡 {r['carrier']}")
                if r.get("country"): lines.append(f"  🌍 {r['country']}")

        elif src == "Telegram (Fragment)":
            free = r.get("phone_free")
            lines += ["", f"✈️ *Telegram*: {'🟢 Вільний (не зареєстр.)' if free else '🔴 Зайнятий (зареєстр.)'}"]
            if r.get("price_ton"): lines.append(f"  💎 {r['price_ton']} TON")
            lines.append(f"  🔗 {r.get('url', '')}")

        elif src == "WhatsApp":
            lines += ["", f"💬 *WhatsApp*: {r.get('url', '')}"]
            lines.append(f"  ℹ️ {r.get('note', '')}")

        elif src == "Viber":
            lines += ["", f"📲 *Viber*: {r.get('url', '')}"]

        elif src == "Prefix DB":
            lines.append(f"📡 *Оператор (prefix)*: {r.get('carrier_guess', '')} {r.get('prefix', '')}")

        elif src == "Country Prefix":
            lines.append(f"🌍 *Країна (prefix)*: {r.get('country', '')}")

    return "\n".join(lines)
                     
