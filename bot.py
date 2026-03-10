"""
OSINT Telegram Bot v5.0
─────────────────────────────────────────────────────
Рушій:    curl_cffi (обхід TLS/Cloudflare) + aiohttp
Ключі:    тільки BOT_TOKEN + RAPID_API_KEY (опц.)
Нові:     /dorks — Google Dork генератор
          /status — перевірка ключів та бібліотек
"""
import subprocess, sys

_PKGS = [
    "aiogram==3.13.1", "aiohttp==3.10.10", "python-dotenv==1.0.1",
    "curl_cffi==0.7.3", "phonenumbers==8.13.39", "asyncwhois==1.4.1",
]
for _p in _PKGS:
    _mod = _p.split("==")[0].replace("-", "_").replace(".", "_")
    try:
        __import__(_mod)
    except ImportError:
        print(f"[BOOT] {_p}...", flush=True)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", _p])

import asyncio, logging, re
from pathlib import Path
from aiogram import Bot, Dispatcher, Router
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.fsm.storage.memory import MemoryStorage

import config, scanner, dorks
import email_osint, domain_osint, ip_osint, social_osint, phone_osint
import fmt

Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/bot.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)
router = Router()


async def _send(msg: Message, text: str):
    for chunk in fmt.split(text):
        try:
            await msg.answer(chunk, parse_mode="Markdown",
                             disable_web_page_preview=True)
        except Exception:
            await msg.answer(chunk, disable_web_page_preview=True)


# ══════════════════════════════════════════════════════
#  /start
# ══════════════════════════════════════════════════════
@router.message(Command("start"))
async def cmd_start(msg: Message):
    await msg.answer(
        "🕵 *OSINT Bot v5.0*\n\n"
        "`/nick johndoe` — 2000+ сайтів\n"
        "`/email u@mail.com` — розвідка пошти\n"
        "`/domain example.com` — розвідка домену\n"
        "`/ip 8.8.8.8` — геолокація + загрози\n"
        "`/social johndoe` — всі соцмережі\n"
        "`/phone +380...` — пошук за номером\n"
        "`/dorks <мета>` — Google Dork генератор\n"
        "`/status` — стан ключів та бібліотек\n"
        "`/help` — детальна довідка",
        parse_mode="Markdown",
    )


# ══════════════════════════════════════════════════════
#  /help
# ══════════════════════════════════════════════════════
@router.message(Command("help"))
async def cmd_help(msg: Message):
    await msg.answer(
        "🕵 *OSINT Bot v5.0 — Довідка*\n\n"
        "*Команди:*\n"
        "`/nick johndoe` — пошук нікнейму по 2000+ сайтах\n"
        "  ↳ WMN + Sherlock + 500 вбудованих\n"
        "  ↳ curl_cffi обходить Cloudflare\n\n"
        "`/email user@gmail.com`\n"
        "  ↳ EmailRep, Gravatar, BreachDirectory\n"
        "  ↳ Twitter/GitHub holehe, DNS/MX\n"
        "  ↳ Kickbox disposable check\n"
        "  ↳ RapidAPI Email (з ключем)\n\n"
        "`/domain example.com`\n"
        "  ↳ asyncwhois WHOIS (реальний протокол)\n"
        "  ↳ DNS усі типи, crt.sh, субдомени\n"
        "  ↳ URLScan, Wayback, Robots/Headers\n"
        "  ↳ RapidAPI WHOIS (з ключем)\n\n"
        "`/ip 8.8.8.8`\n"
        "  ↳ ipinfo, ip-api, BGPView, OTX\n"
        "  ↳ GreyNoise, AbuseIPDB, IPQualityScore\n"
        "  ↳ RapidAPI IP Reputation (з ключем)\n\n"
        "`/social johndoe`\n"
        "  ↳ GitHub API, GitLab API, Reddit API\n"
        "  ↳ Twitter, Instagram, TikTok, Telegram\n"
        "  ↳ VK, Steam, YouTube, Twitch, Mastodon\n\n"
        "`/phone +380XXXXXXXXX`\n"
        "  ↳ Google phonenumbers (бібліотека)\n"
        "  ↳ Telegram Fragment, WhatsApp, Viber\n"
        "  ↳ RapidAPI Truecaller (ім'я, з ключем)\n\n"
        "`/dorks example.com` або `johndoe` або `8.8.8.8`\n"
        "  ↳ Готові Google Dork запити\n"
        "  ↳ Пошук витоків, субдоменів, файлів\n"
        "  ↳ Bing, DDG, Yandex, GitHub, Pastebin\n\n"
        "*Ключі (Railway → Variables):*\n"
        "`BOT_TOKEN` — обов'язково\n"
        "`RAPID_API_KEY` — один ключ дає:\n"
        "  • Truecaller (ім'я за номером)\n"
        "  • Email Reputation\n"
        "  • IP Fraud Score\n"
        "  • WHOIS XML\n"
        "  Реєстрація: rapidapi.com (безкоштовно)",
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )


# ══════════════════════════════════════════════════════
#  /status
# ══════════════════════════════════════════════════════
@router.message(Command("status"))
async def cmd_status(msg: Message):
    libs = {}
    for lib in ("curl_cffi", "phonenumbers", "asyncwhois", "aiohttp", "aiogram"):
        try:
            __import__(lib)
            libs[lib] = "✅"
        except ImportError:
            libs[lib] = "❌"

    lib_lines = "\n".join(f"  {v} {k}" for k, v in libs.items())
    await msg.answer(
        "⚙️ *OSINT Bot v5.0 — Статус*\n\n"
        "*Бібліотеки:*\n"
        f"{lib_lines}\n\n"
        "*API Ключі:*\n"
        f"{config.key_status()}\n\n"
        "💡 *Без RAPID_API_KEY* — всі функції працюють,\n"
        "але Truecaller / Email Reputation / IP Fraud Score недоступні.\n\n"
        "🚀 Зареєструйся на rapidapi.com → отримай ключ → додай у Railway Variables",
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )


# ══════════════════════════════════════════════════════
#  /nick
# ══════════════════════════════════════════════════════
@router.message(Command("nick"))
async def cmd_nick(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ `/nick <username>`", parse_mode="Markdown")
        return
    username = parts[1].strip().lower()
    if not re.match(r'^[a-z0-9._\-]{2,50}$', username):
        await msg.answer("❌ Username: 2–50 символів (a-z 0-9 . _ -)")
        return

    pm = await msg.answer(
        f"🔍 Сканую `{username}`...\n⏳ Завантажую базу...",
        parse_mode="Markdown",
    )
    total_ref = [0]

    async def progress(checked, total, n_found):
        total_ref[0] = total
        pct = int(checked / total * 100) if total else 0
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        try:
            await pm.edit_text(
                f"🔍 `{username}`\n[{bar}] {pct}%\n"
                f"{checked}/{total} | ✅ {n_found}",
                parse_mode="Markdown",
            )
        except Exception:
            pass

    found = await scanner.scan(username, progress)
    text  = fmt.nick(username, found, total_ref[0])
    try:
        await pm.edit_text(text, parse_mode="Markdown",
                           disable_web_page_preview=True)
    except Exception:
        pass
    for chunk in fmt.split(text)[1:]:
        await msg.answer(chunk, parse_mode="Markdown",
                         disable_web_page_preview=True)


# ══════════════════════════════════════════════════════
#  /email
# ══════════════════════════════════════════════════════
@router.message(Command("email"))
async def cmd_email(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', parts[1].strip()):
        await msg.answer("❌ `/email user@example.com`", parse_mode="Markdown")
        return
    addr = parts[1].strip().lower()
    pm   = await msg.answer(f"🔍 Email: `{addr}`...", parse_mode="Markdown")
    res  = await email_osint.scan(addr)
    text = fmt.email(addr, res)
    try:
        await pm.edit_text(text, parse_mode="Markdown",
                           disable_web_page_preview=True)
    except Exception:
        pass
    for chunk in fmt.split(text)[1:]:
        await _send(msg, chunk)


# ══════════════════════════════════════════════════════
#  /domain
# ══════════════════════════════════════════════════════
@router.message(Command("domain"))
async def cmd_domain(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ `/domain example.com`", parse_mode="Markdown")
        return
    dom = parts[1].strip().lower()
    dom = dom.replace("https://", "").replace("http://", "").split("/")[0]
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$', dom):
        await msg.answer("❌ Невірний домен.")
        return
    pm   = await msg.answer(f"🔍 Domain: `{dom}`...", parse_mode="Markdown")
    res  = await domain_osint.scan(dom)
    text = fmt.domain(dom, res)
    try:
        await pm.edit_text(text, parse_mode="Markdown",
                           disable_web_page_preview=True)
    except Exception:
        pass
    for chunk in fmt.split(text)[1:]:
        await _send(msg, chunk)


# ══════════════════════════════════════════════════════
#  /ip
# ══════════════════════════════════════════════════════
@router.message(Command("ip"))
async def cmd_ip(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parts[1].strip()):
        await msg.answer("❌ `/ip 8.8.8.8`", parse_mode="Markdown")
        return
    addr = parts[1].strip()
    if any(addr.startswith(p) for p in
           ("192.168.", "10.", "127.", "172.16.", "172.17.", "169.254.")):
        await msg.answer("⚠️ Приватний IP — публічних даних немає.")
        return
    pm   = await msg.answer(f"🔍 IP: `{addr}`...", parse_mode="Markdown")
    res  = await ip_osint.scan(addr)
    text = fmt.ip(addr, res)
    try:
        await pm.edit_text(text, parse_mode="Markdown",
                           disable_web_page_preview=True)
    except Exception:
        pass
    for chunk in fmt.split(text)[1:]:
        await _send(msg, chunk)


# ══════════════════════════════════════════════════════
#  /social
# ══════════════════════════════════════════════════════
@router.message(Command("social"))
async def cmd_social(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not 2 <= len(parts[1].strip()) <= 50:
        await msg.answer("❌ `/social <username>`", parse_mode="Markdown")
        return
    username = parts[1].strip()
    pm = await msg.answer(
        f"🔍 Social: `{username}`...\n"
        "GitHub · GitLab · Reddit · Twitter · Instagram\n"
        "TikTok · Telegram · VK · Steam · YouTube · Twitch · Mastodon",
        parse_mode="Markdown",
    )
    res  = await social_osint.scan(username)
    text = fmt.social(username, res)
    try:
        await pm.edit_text(text, parse_mode="Markdown",
                           disable_web_page_preview=True)
    except Exception:
        pass
    for chunk in fmt.split(text)[1:]:
        await _send(msg, chunk)


# ══════════════════════════════════════════════════════
#  /phone
# ══════════════════════════════════════════════════════
@router.message(Command("phone"))
async def cmd_phone(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not re.match(r'^\+?[\d\s\-\(\)]{7,16}$', parts[1].strip()):
        await msg.answer(
            "❌ `/phone +380XXXXXXXXX`\n"
            "Формат: з кодом країни (+380, +7, +1...)",
            parse_mode="Markdown",
        )
        return
    p = parts[1].strip()
    if not p.startswith("+"):
        p = "+" + p
    pm   = await msg.answer(f"🔍 Phone: `{p}`...", parse_mode="Markdown")
    res  = await phone_osint.scan(p)
    text = fmt.phone(p, res)
    try:
        await pm.edit_text(text, parse_mode="Markdown",
                           disable_web_page_preview=True)
    except Exception:
        pass
    for chunk in fmt.split(text)[1:]:
        await _send(msg, chunk)


# ══════════════════════════════════════════════════════
#  /dorks — Google Dork генератор
# ══════════════════════════════════════════════════════
@router.message(Command("dorks"))
async def cmd_dorks(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer(
            "❌ Використання:\n"
            "`/dorks johndoe` — дорки для нікнейму\n"
            "`/dorks user@mail.com` — дорки для email\n"
            "`/dorks example.com` — дорки для домену\n"
            "`/dorks 8.8.8.8` — дорки для IP\n"
            "`/dorks +380...` — дорки для телефону",
            parse_mode="Markdown",
        )
        return

    target = parts[1].strip()

    # Визначаємо тип цілі
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        d_list = dorks.ip_dorks(target)
        title  = f"IP: {target}"

    elif re.match(r'^\+?[\d\s\-]{7,16}$', target) and target[0] in ("+", "7", "1", "3", "9"):
        d_list = dorks.phone_dorks(target)
        title  = f"Phone: {target}"

    elif re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        d_list = dorks.email_dorks(target)
        title  = f"Email: {target}"

    elif re.match(r'^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$', target.lower()):
        d_list = dorks.domain_dorks(target.lower())
        title  = f"Domain: {target}"

    else:
        d_list = dorks.username_dorks(target)
        title  = f"Username: {target}"

    text = dorks.fmt_dorks(title, d_list, max_show=25)
    await _send(msg, text)


# ══════════════════════════════════════════════════════
#  Запуск
# ══════════════════════════════════════════════════════
async def main():
    if not config.BOT_TOKEN:
        log.error("❌ BOT_TOKEN не заданий! Railway → Settings → Variables")
        sys.exit(1)

    try:
        from curl_cffi.requests import AsyncSession
        log.info("✅ curl_cffi активна — обхід TLS fingerprint")
    except ImportError:
        log.warning("⚠️  curl_cffi недоступна — fallback aiohttp")

    bot = Bot(token=config.BOT_TOKEN)
    dp  = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    log.info("🤖 OSINT Bot v5.0 запущено!")
    await dp.start_polling(bot, skip_updates=True)


if __name__ == "__main__":
    asyncio.run(main())

