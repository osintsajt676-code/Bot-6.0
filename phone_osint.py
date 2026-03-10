"""
Phone OSINT — Google phonenumbers + Fragment + RapidAPI Truecaller.
"""
import asyncio, re
import config
from http_client import session as _new

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as tz_lib
    _PN = True
except ImportError:
    _PN = False


async def scan(phone: str) -> list:
    clean = re.sub(r"[^\d+]", "", phone)
    async with _new() as s:
        results = await asyncio.gather(
            _pn_lib(clean),
            _fragment(s, clean),
            _rapid_phone(s, clean),
            _rapid_truecaller(s, clean),
            _numverify_free(s, clean),
            _whatsapp(clean),
            _viber(clean),
            _carrier_prefix(clean),
            return_exceptions=False,
        )
    return [r for r in results if r]


async def _pn_lib(phone: str):
    if not _PN:
        return {"src": "phonenumbers", "no_lib": True}
    try:
        p = phonenumbers.parse(phone, None)
        return {
            "src":           "phonenumbers (Google)",
            "valid":         phonenumbers.is_valid_number(p),
            "possible":      phonenumbers.is_possible_number(p),
            "country_code":  p.country_code,
            "national":      phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL),
            "international": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "e164":          phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
            "country":       geocoder.description_for_number(p, "ru"),
            "carrier":       carrier.name_for_number(p, "ru"),
            "timezones":     list(tz_lib.time_zones_for_number(p)),
            "number_type":   str(phonenumbers.number_type(p)).split(".")[-1],
        }
    except Exception as e:
        return {"src": "phonenumbers (Google)", "error": str(e)}


async def _fragment(s, phone: str):
    clean = phone.lstrip("+")
    r = await s.get(f"https://fragment.com/number/{clean}")
    if r.status != 200:
        return None
    txt  = await r.text()
    free = "available" in txt.lower() and "unavailable" not in txt.lower()
    price = re.search(r"TON\s*([\d.]+)", txt)
    return {
        "src":        "Telegram (Fragment)",
        "phone_free": free,
        "price_ton":  price.group(1) if price else "",
        "url":        f"https://fragment.com/number/{clean}",
        "note":       "Вільний = НЕ зареєстрований" if free else "Зайнятий = зареєстрований в Telegram",
    }


async def _rapid_phone(s, phone: str):
    """RapidAPI — Phone Validation."""
    if not config.RAPID_KEY:
        return None
    r = await s.get(
        "https://phone-number-validator-and-lookup.p.rapidapi.com/lookup",
        params={"phone": phone},
        headers={
            "X-RapidAPI-Key":  config.RAPID_KEY,
            "X-RapidAPI-Host": "phone-number-validator-and-lookup.p.rapidapi.com",
        },
    )
    if r.status != 200:
        return None
    d = await r.json()
    return {
        "src":       "RapidAPI Phone",
        "valid":     d.get("valid"),
        "country":   d.get("country"),
        "location":  d.get("location"),
        "carrier":   d.get("carrier"),
        "line_type": d.get("line_type"),
    }


async def _rapid_truecaller(s, phone: str):
    """RapidAPI — Truecaller (ім'я власника)."""
    if not config.RAPID_KEY:
        return None
    r = await s.get(
        "https://truecaller4.p.rapidapi.com/api/v1/getDetails",
        params={"phone": phone, "countryCode": "UA"},
        headers={
            "X-RapidAPI-Key":  config.RAPID_KEY,
            "X-RapidAPI-Host": "truecaller4.p.rapidapi.com",
        },
    )
    if r.status != 200:
        return None
    d = await r.json()
    if not d.get("data"):
        return None
    p = d["data"].get("phones", [{}])[0] if d["data"].get("phones") else {}
    return {
        "src":     "Truecaller (RapidAPI)",
        "name":    d["data"].get("name", ""),
        "carrier": p.get("carrier", ""),
        "country": p.get("countryCode", ""),
    }


async def _numverify_free(s, phone: str):
    """NumVerify безкоштовний ліміт (100/міс)."""
    clean = phone.lstrip("+")
    r = await s.get(
        f"https://api.apilayer.com/number_verification/validate?number={clean}",
        headers={"apikey": "free"},
    )
    if r.status != 200:
        return None
    d = await r.json()
    if not d.get("valid"):
        return None
    return {
        "src":          "NumVerify (free)",
        "valid":        d.get("valid"),
        "country":      d.get("country_name"),
        "location":     d.get("location"),
        "carrier":      d.get("carrier"),
        "line_type":    d.get("line_type"),
        "national":     d.get("national_format"),
    }


async def _whatsapp(phone: str):
    clean = re.sub(r"[^\d]", "", phone)
    return {
        "src":  "WhatsApp",
        "url":  f"https://wa.me/{clean}",
        "note": "Відкрий посилання — якщо чат відкрився, номер зареєстрований",
    }


async def _viber(phone: str):
    return {
        "src":  "Viber",
        "url":  f"viber://contact?number={phone}",
        "note": "Відкрий на телефоні — якщо чат відкрився, номер зареєстрований",
    }


async def _carrier_prefix(phone: str) -> dict:
    clean = re.sub(r"[^\d]", "", phone)

    _UA = {
        "38050": "Vodafone UA", "38095": "Vodafone UA", "38099": "Vodafone UA",
        "38063": "Kyivstar",    "38067": "Kyivstar",    "38068": "Kyivstar",
        "38066": "Kyivstar",    "38096": "Kyivstar",    "38097": "Kyivstar",
        "38098": "Kyivstar",    "38073": "lifecell",    "38093": "lifecell",
        "38091": "lifecell",    "38089": "Vodafone UA", "38094": "Intertelecom",
        "38092": "PEOPLEnet",   "38088": "Kyivstar",
    }
    _RU = {
        "7916": "MTS",  "7915": "MTS",  "7926": "MTS",  "7910": "MTS",
        "7920": "MTS",  "7925": "MTS",  "7929": "MTS",  "7900": "Beeline",
        "7903": "Beeline", "7905": "Beeline", "7906": "Beeline", "7909": "Beeline",
        "7912": "Megafon", "7918": "Megafon", "7919": "Megafon", "7921": "Megafon",
        "7961": "Tele2", "7962": "Tele2", "7963": "Tele2", "7964": "Tele2",
    }

    for prefix, op in {**_UA, **_RU}.items():
        if clean.startswith(prefix):
            return {"src": "Prefix DB", "carrier_guess": op, "prefix": f"+{prefix[:2]} ({prefix[2:]})"}

    _COUNTRIES = {
        "380": "Україна",         "375": "Білорусь",        "7":   "Росія/Казахстан",
        "1":   "США/Канада",      "44":  "Великобританія",  "49":  "Німеччина",
        "33":  "Франція",         "86":  "Китай",            "81":  "Японія",
        "82":  "Південна Корея",  "91":  "Індія",            "55":  "Бразилія",
        "48":  "Польща",          "90":  "Туреччина",        "966": "Саудівська Аравія",
        "971": "ОАЕ",             "972": "Ізраїль",          "998": "Узбекистан",
        "996": "Киргизстан",      "992": "Таджикистан",      "994": "Азербайджан",
        "995": "Грузія",          "374": "Вірменія",         "373": "Молдова",
    }
    for prefix, country in sorted(_COUNTRIES.items(), key=lambda x: -len(x[0])):
        if clean.startswith(prefix):
            return {"src": "Country Prefix", "country": country, "prefix": f"+{prefix}"}

    return {"src": "Country Prefix", "country": "Невідомо", "prefix": ""}
      
