"""
SmartSession — curl_cffi (обхід TLS/Cloudflare) + aiohttp fallback.
"""
import asyncio, json, logging
import aiohttp
import config

log = logging.getLogger(__name__)

try:
    from curl_cffi.requests import AsyncSession as _CurlSession
    _CURL_OK = True
except ImportError:
    _CURL_OK = False
    log.warning("curl_cffi недоступна — fallback aiohttp")


class Response:
    __slots__ = ("status", "_text", "_raw_json")

    def __init__(self, status: int, text: str):
        self.status    = status
        self._text     = text
        self._raw_json = None

    async def text(self) -> str:
        return self._text

    async def json(self):
        if self._raw_json is None:
            try:
                self._raw_json = json.loads(self._text)
            except Exception:
                self._raw_json = {}
        return self._raw_json


class SmartSession:
    def __init__(self, impersonate: str = "chrome120"):
        self._imp  = impersonate
        self._curl = None
        self._aio  = None

    async def __aenter__(self):
        if _CURL_OK:
            self._curl = _CurlSession(impersonate=self._imp, timeout=config.TIMEOUT)
        else:
            self._aio = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False, limit=200, ttl_dns_cache=300),
                timeout=aiohttp.ClientTimeout(total=config.TIMEOUT),
            )
        return self

    async def __aexit__(self, *_):
        if self._curl:
            try:
                await self._curl.close()
            except Exception:
                pass
        if self._aio:
            try:
                await self._aio.close()
            except Exception:
                pass

    # ── GET ──────────────────────────────────────────────
    async def get(self, url: str, **kw) -> Response:
        headers = kw.pop("headers", config.HEADERS)
        proxy   = kw.pop("proxy",   config.PROXY)
        timeout = kw.pop("timeout", config.TIMEOUT)

        if self._curl:
            try:
                r = await self._curl.get(
                    url, headers=headers,
                    proxies={"https": proxy, "http": proxy} if proxy else None,
                    timeout=timeout, allow_redirects=True, **kw,
                )
                return Response(r.status_code, r.text or "")
            except Exception as e:
                log.debug(f"curl GET {url}: {e}")

        # fallback
        try:
            s = self._aio or aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout))
            async with s.get(url, headers=headers, proxy=proxy,
                             ssl=False, allow_redirects=True, **kw) as r:
                return Response(r.status, await r.text(errors="ignore"))
        except Exception as e:
            log.debug(f"aio GET {url}: {e}")
            return Response(0, "")

    # ── POST ─────────────────────────────────────────────
    async def post(self, url: str, **kw) -> Response:
        headers = kw.pop("headers", config.HEADERS)
        proxy   = kw.pop("proxy",   config.PROXY)
        timeout = kw.pop("timeout", config.TIMEOUT)

        if self._curl:
            try:
                r = await self._curl.post(
                    url, headers=headers,
                    proxies={"https": proxy, "http": proxy} if proxy else None,
                    timeout=timeout, **kw,
                )
                return Response(r.status_code, r.text or "")
            except Exception as e:
                log.debug(f"curl POST {url}: {e}")

        try:
            s = self._aio or aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout))
            async with s.post(url, headers=headers, proxy=proxy,
                              ssl=False, **kw) as r:
                return Response(r.status, await r.text(errors="ignore"))
        except Exception as e:
            log.debug(f"aio POST {url}: {e}")
            return Response(0, "")


def session(impersonate: str = "chrome120") -> SmartSession:
    return SmartSession(impersonate)
  
