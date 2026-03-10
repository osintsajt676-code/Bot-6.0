import asyncio, re
import config
from http_client import session as _new


def _og(txt, prop="og:title"):
    m = re.search(rf'<meta property="{prop}" content="([^"]*)"', txt)
    return m.group(1) if m else ""


async def scan(username: str) -> list:
    async with _new() as s:
        results = await asyncio.gather(
            _github(s, username),  _reddit(s, username),
            _twitter(s, username), _instagram(s, username),
            _tiktok(s, username),  _telegram(s, username),
            _steam(s, username),   _vk(s, username),
            _youtube(s, username), _twitch(s, username),
            _gitlab(s, username),  _mastodon(s, username),
            return_exceptions=False,
        )
    return [r for r in results if r]


async def _github(s, username):
    r = await s.get(
        f"https://api.github.com/users/{username}",
        headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "osint-bot"},
    )
    if r.status != 200:
        return {"platform": "GitHub", "found": False}
    d = await r.json()
    repos = []
    r2 = await s.get(
        f"https://api.github.com/users/{username}/repos?per_page=5&sort=updated",
        headers={"User-Agent": "osint-bot"},
    )
    if r2.status == 200:
        for repo in await r2.json():
            repos.append({"name": repo.get("name"), "stars": repo.get("stargazers_count", 0),
                          "lang": repo.get("language"), "url": repo.get("html_url")})
    return {
        "platform": "GitHub",   "found":    True,
        "url":      d.get("html_url"),      "name":      d.get("name", ""),
        "bio":      d.get("bio", ""),       "location":  d.get("location", ""),
        "email":    d.get("email", ""),     "company":   d.get("company", ""),
        "blog":     d.get("blog", ""),      "repos":     d.get("public_repos", 0),
        "gists":    d.get("public_gists", 0), "followers": d.get("followers", 0),
        "twitter":  d.get("twitter_username", ""),
        "created":  (d.get("created_at") or "")[:10],
        "hireable": d.get("hireable", False), "top_repos": repos,
    }


async def _reddit(s, username):
    r = await s.get(
        f"https://www.reddit.com/user/{username}/about.json",
        headers={"User-Agent": "osint-bot/4.0"},
    )
    if r.status != 200:
        return {"platform": "Reddit", "found": False}
    d = (await r.json()).get("data", {})
    return {
        "platform": "Reddit", "found": True,
        "url":      f"https://reddit.com/u/{username}",
        "post_karma": d.get("link_karma", 0),
        "comment_karma": d.get("comment_karma", 0),
        "total_karma": d.get("total_karma", 0),
        "is_mod": d.get("is_mod", False), "gold": d.get("is_gold", False),
    }


async def _twitter(s, username):
    r = await s.get(f"https://x.com/{username}", headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "Twitter/X", "found": False}
    txt = await r.text()
    ok  = "This account doesn't exist" not in txt and "suspended" not in txt
    return {"platform": "Twitter/X", "found": ok,
            "url": f"https://x.com/{username}", "bio": _og(txt, "og:description")}


async def _instagram(s, username):
    r = await s.get(f"https://www.instagram.com/{username}/",
                    headers={**config.HEADERS, "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)"})
    if r.status != 200:
        return {"platform": "Instagram", "found": False}
    txt = await r.text()
    if "Sorry, this page" in txt or "isn't available" in txt:
        return {"platform": "Instagram", "found": False}
    return {"platform": "Instagram", "found": True,
            "url": f"https://www.instagram.com/{username}/",
            "bio": _og(txt, "og:description")}


async def _tiktok(s, username):
    r = await s.get(f"https://www.tiktok.com/@{username}", headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "TikTok", "found": False}
    txt = await r.text()
    return {"platform": "TikTok", "found": "Couldn't find this account" not in txt,
            "url": f"https://www.tiktok.com/@{username}", "title": _og(txt)}


async def _telegram(s, username):
    r = await s.get(f"https://t.me/{username}")
    if r.status != 200:
        return {"platform": "Telegram", "found": False}
    txt   = await r.text()
    found = "tgme_page_title" in txt and "If you have Telegram" not in txt
    name  = re.search(r'<div class="tgme_page_title"><span[^>]*>([^<]+)', txt)
    desc  = re.search(r'<div class="tgme_page_description">([^<]+)', txt)
    subs  = re.search(r'([\d\s,]+)\s*(members|subscribers|followers)', txt)
    return {"platform": "Telegram", "found": found,
            "url": f"https://t.me/{username}",
            "name": name.group(1).strip() if name else "",
            "description": desc.group(1).strip() if desc else "",
            "subscribers": subs.group(0).strip() if subs else ""}


async def _steam(s, username):
    r = await s.get(f"https://steamcommunity.com/id/{username}", headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "Steam", "found": False}
    txt   = await r.text()
    found = "The specified profile could not be found" not in txt
    name  = re.search(r'<span class="actual_persona_name">([^<]+)</span>', txt)
    level = re.search(r'<span class="friendPlayerLevelNum">(\d+)</span>', txt)
    return {"platform": "Steam", "found": found,
            "url": f"https://steamcommunity.com/id/{username}",
            "name": name.group(1) if name else "", "level": level.group(1) if level else ""}


async def _vk(s, username):
    r = await s.get(f"https://vk.com/{username}", headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "VK", "found": False}
    txt   = await r.text()
    found = "404" not in txt and "СТРАНИЦА" not in txt.upper()[:1000]
    return {"platform": "VK", "found": found, "url": f"https://vk.com/{username}",
            "name": _og(txt), "desc": _og(txt, "og:description")}


async def _youtube(s, username):
    r = await s.get(f"https://www.youtube.com/@{username}", headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "YouTube", "found": False}
    txt  = await r.text()
    subs = re.search(r'"subscriberCountText":\{"simpleText":"([^"]+)"', txt)
    return {"platform": "YouTube", "found": True,
            "url": f"https://www.youtube.com/@{username}",
            "name": _og(txt), "subscribers": subs.group(1) if subs else ""}


async def _twitch(s, username):
    r = await s.get(f"https://www.twitch.tv/{username}", headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "Twitch", "found": False}
    txt = await r.text()
    return {"platform": "Twitch", "found": "doesn't exist" not in txt.lower(),
            "url": f"https://www.twitch.tv/{username}", "name": _og(txt)}


async def _gitlab(s, username):
    r = await s.get(f"https://gitlab.com/api/v4/users?username={username}",
                    headers=config.HEADERS)
    if r.status != 200:
        return {"platform": "GitLab", "found": False}
    users = await r.json()
    if not users:
        return {"platform": "GitLab", "found": False}
    u = users[0]
    return {"platform": "GitLab", "found": True,
            "url": u.get("web_url", ""), "name": u.get("name", ""),
            "bio": u.get("bio", ""), "location": u.get("location", ""),
            "created": (u.get("created_at") or "")[:10]}


async def _mastodon(s, username):
    for inst in ("mastodon.social", "mastodon.online", "fosstodon.org",
                 "infosec.exchange", "hachyderm.io"):
        r = await s.get(f"https://{inst}/api/v1/accounts/lookup?acct={username}",
                        headers=config.HEADERS)
        if r.status == 200:
            d = await r.json()
            return {"platform": "Mastodon", "found": True,
                    "url": d.get("url", ""), "instance": inst,
                    "name": d.get("display_name", ""),
                    "bio": re.sub(r"<[^>]+>", "", d.get("note", ""))[:100],
                    "followers": d.get("followers_count", 0),
                    "posts": d.get("statuses_count", 0)}
    return {"platform": "Mastodon", "found": False}
  
