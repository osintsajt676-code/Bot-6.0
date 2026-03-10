"""
Сканер username.  curl_cffi → aiohttp fallback.
Перевірка: HTTP 200 + тіло НЕ містить m_string.
"""
import asyncio, logging
from typing import List, Dict, Optional, Callable
from sites_db import get_sites
import config

log = logging.getLogger(__name__)

try:
    from curl_cffi.requests import AsyncSession as _Curl
    _CURL = True
except ImportError:
    _CURL = False
    import aiohttp


# ── curl_cffi варіант ────────────────────────────────────────────────
async def _chk_curl(sem: asyncio.Semaphore, site: dict, uname: str) -> Optional[Dict]:
    url = site["url"].replace("{}", uname)
    ms  = (site.get("m_string") or "").lower()
    async with sem:
        try:
            async with _Curl(impersonate="chrome120") as s:
                r = await s.get(
                    url, headers=config.HEADERS,
                    proxies={"https": config.PROXY, "http": config.PROXY} if config.PROXY else None,
                    timeout=config.TIMEOUT, allow_redirects=True,
                )
                if r.status_code != 200:
                    return None
                if ms and ms in r.text.lower():
                    return None
                return {"name": site["name"], "url": url}
        except Exception:
            return None


# ── aiohttp варіант ──────────────────────────────────────────────────
async def _chk_aio(sem: asyncio.Semaphore, session, site: dict, uname: str) -> Optional[Dict]:
    url = site["url"].replace("{}", uname)
    ms  = (site.get("m_string") or "").lower()
    async with sem:
        try:
            async with session.get(
                url, headers=config.HEADERS, proxy=config.PROXY,
                allow_redirects=True, ssl=False,
                timeout=aiohttp.ClientTimeout(total=config.TIMEOUT),
            ) as r:
                if r.status != 200:
                    return None
                if ms:
                    body = await r.text(errors="ignore")
                    if ms in body.lower():
                        return None
                return {"name": site["name"], "url": url}
        except Exception:
            return None


# ── Головна функція ──────────────────────────────────────────────────
async def scan(
    username: str,
    on_progress: Optional[Callable] = None,
    batch: int = 80,
) -> List[Dict]:
    sites = await get_sites()
    total = len(sites)
    found: List[Dict] = []
    sem   = asyncio.Semaphore(config.TASKS)

    async def _run_batch(chunk):
        if _CURL:
            tasks = [_chk_curl(sem, s, username) for s in chunk]
        else:
            tasks = [_chk_aio(sem, _session, s, username) for s in chunk]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    if _CURL:
        log.info(f"Scan {username} via curl_cffi — {total} sites")
        for i in range(0, total, batch):
            chunk = sites[i: i + batch]
            found.extend(await _run_batch(chunk))
            if on_progress:
                try:
                    await on_progress(min(i + batch, total), total, len(found))
                except Exception:
                    pass
    else:
        log.info(f"Scan {username} via aiohttp — {total} sites")
        conn = aiohttp.TCPConnector(ssl=False, limit=200, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=conn) as _session:
            for i in range(0, total, batch):
                chunk = sites[i: i + batch]
                tasks = [_chk_aio(sem, _session, s, username) for s in chunk]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                found.extend(r for r in results if isinstance(r, dict))
                if on_progress:
                    try:
                        await on_progress(min(i + batch, total), total, len(found))
                    except Exception:
                        pass

    return found
  
