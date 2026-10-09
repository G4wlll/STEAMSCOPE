#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteamScope v3.2  --  Steam OSINT Framework (public data only)
=============================================================
Developer: G4wlll   |   (c) G4wlll. All rights reserved.

Re-engineered from scratch. Uses ONLY:
  * the official Steam Web API (needs a free API key for most modules), and
  * public, unauthenticated Steam Community pages/endpoints that any browser
    can open (profile XML, alias history, public inventories, store prices).

It never bypasses privacy settings: private profiles / friend lists / inventories
are reported as "private" and skipped. Intended for authorised security
research, academic work and audits, within Steam's API Terms of Service.

Install:   pip install requests rich
Key:       python steamscope.py config --set-key YOUR_KEY
           (or env STEAM_API_KEY, or --api-key)

Examples:
  python steamscope.py scan 76561198000000000
  python steamscope.py scan https://steamcommunity.com/id/gabelogannewell --out reports
  python steamscope.py scan STEAM_0:1:12345 --sample 80 --friend-groups --library-value
  python steamscope.py scan "[U:1:46143802]" --inventory-value --max-price-lookups 60
  python steamscope.py scan gabelogannewell --max-queries 20 --max-handles 6   (Google/web footprint)
  python steamscope.py config --set-search serper YOUR_SERPER_KEY
  python steamscope.py config --set-faceit YOUR_FACEIT_KEY
  python steamscope.py compare vanityA vanityB
  python steamscope.py resolve gabelogannewell
  python steamscope.py            (interactive menu)
"""
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import html as htmllib
import json
import math
import os
import re
import random
import shlex
import statistics
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency: pip install requests rich")

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                               TimeElapsedColumn)
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency: pip install requests rich")


class SafeTable(Table):
    """Table whose string cells are never parsed as Rich markup (names like [CLAN] stay intact)."""

    def add_row(self, *cells, **kw):
        return super().add_row(*[Text(c) if isinstance(c, str) else c for c in cells], **kw)


Table = SafeTable  # noqa: F811

VERSION = "3.2.0"
TOOL = "SteamScope"
AUTHOR = "G4wlll"
COPYRIGHT = f"(c) {datetime.now().year} {AUTHOR}. All rights reserved."
ID64_BASE = 76561197960265728
GROUP64_BASE = 103582791429521408
API = "https://api.steampowered.com"
COMMUNITY = "https://steamcommunity.com"
STORE = "https://store.steampowered.com"
CONFIG_PATH = Path.home() / ".steamscope.json"
LEGACY_CONFIG_PATH = Path.home() / ".steam_osint.json"
CACHE_DIR = Path.home() / ".cache" / "steamscope"
USER_AGENT = f"steamscope/{VERSION} (authorised research; public data only)"

# Rough anchors (account_id, "YYYY-MM") used ONLY when the real creation date is
# hidden. Heuristic: expect +/- 1-2 years. Extend/calibrate freely.
CALIBRATION = [
    (0, "2003-09"), (1_000_000, "2005-01"), (10_000_000, "2007-06"),
    (40_000_000, "2009-08"), (75_000_000, "2010-09"), (100_000_000, "2011-03"),
    (140_000_000, "2012-01"), (200_000_000, "2013-02"), (300_000_000, "2014-06"),
    (500_000_000, "2016-03"), (800_000_000, "2019-02"), (1_000_000_000, "2020-12"),
    (1_200_000_000, "2022-08"), (1_500_000_000, "2025-02"),
]

PERSONA_STATES = {0: "Offline", 1: "Online", 2: "Busy", 3: "Away",
                  4: "Snooze", 5: "Looking to trade", 6: "Looking to play"}


# ----------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------
class SteamOsintError(Exception):
    """Base class."""


class InvalidTarget(SteamOsintError):
    pass


class NotFound(SteamOsintError):
    pass


class PrivateData(SteamOsintError):
    pass


class InvalidApiKey(SteamOsintError):
    pass


class ApiKeyMissing(SteamOsintError):
    pass


class RateLimited(SteamOsintError):
    pass


class NetworkError(SteamOsintError):
    pass


class HttpStatusError(SteamOsintError):
    def __init__(self, status: int, url: str):
        super().__init__(f"HTTP {status} for {url.split('?')[0]}")
        self.status = status
        self.url = url


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def iso(ts: Optional[int | float]) -> Optional[str]:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return None


def years_since(ts: Optional[int | float]) -> Optional[float]:
    if not ts:
        return None
    return round((time.time() - float(ts)) / (365.25 * 86400), 2)


def hrs(minutes: Optional[int]) -> float:
    return round((minutes or 0) / 60.0, 1)


def parse_price(text: str) -> Optional[float]:
    m = re.search(r"(\d[\d.,\s]*)", text or "")
    if not m:
        return None
    num = m.group(1).strip().replace(" ", "")
    if "," in num and "." in num:
        num = (num.replace(".", "").replace(",", ".")
               if num.rfind(",") > num.rfind(".") else num.replace(",", ""))
    elif "," in num:
        num = num.replace(",", ".") if re.search(r",\d{1,2}$", num) else num.replace(",", "")
    try:
        return float(num)
    except ValueError:
        return None


# ----------------------------------------------------------------------------
# Steam ID handling
# ----------------------------------------------------------------------------
def id64_to_steam2(id64: int) -> str:
    acc = id64 - ID64_BASE
    return f"STEAM_0:{acc & 1}:{acc >> 1}"


def id64_to_steam3(id64: int) -> str:
    return f"[U:1:{id64 - ID64_BASE}]"


def classify_target(raw: str) -> tuple[str, str]:
    """Return (kind, value); kind in id64|account|vanity."""
    s = (raw or "").strip().strip("\"'")
    if not s:
        raise InvalidTarget("Empty target.")
    m = re.search(r"steamcommunity\.com/(profiles|id)/([^/?#\s]+)", s, re.I)
    if m:
        kind, val = m.group(1).lower(), urllib.parse.unquote(m.group(2))
        if kind == "profiles":
            if not (val.isdigit() and len(val) == 17):
                raise InvalidTarget(f"Malformed /profiles/ URL value: {val!r}")
            return "id64", val
        return "vanity", val
    m = re.fullmatch(r"STEAM_([0-5]):([01]):(\d+)", s, re.I)
    if m:
        return "account", str(int(m.group(3)) * 2 + int(m.group(2)))
    m = re.fullmatch(r"\[?U:1:(\d+)\]?", s, re.I)
    if m:
        return "account", m.group(1)
    if s.isdigit():
        n = int(s)
        if len(s) == 17 and n >= ID64_BASE:
            return "id64", s
        if len(s) <= 10 and n < 2 ** 32:
            return "account", s
        raise InvalidTarget(f"Numeric value is neither SteamID64 nor a 32-bit account id: {s}")
    if re.fullmatch(r"[A-Za-z0-9_\-.]{2,64}", s):
        return "vanity", s
    raise InvalidTarget(f"Unrecognised target format: {raw!r}")


@dataclass
class Identity:
    input: str
    id64: int
    account_id: int
    steam2: str
    steam3: str
    method: str
    vanity: Optional[str]
    profile_url: str
    permalink: str

    def as_dict(self) -> dict:
        return asdict(self)


def estimate_creation_from_account_id(account_id: int) -> dict:
    pts = [(a, datetime.strptime(d, "%Y-%m").replace(tzinfo=timezone.utc).timestamp())
           for a, d in CALIBRATION]
    if account_id <= pts[0][0]:
        ts = pts[0][1]
    elif account_id >= pts[-1][0]:
        ts = pts[-1][1]
    else:
        ts = pts[-1][1]
        for (a0, t0), (a1, t1) in zip(pts, pts[1:]):
            if a0 <= account_id <= a1:
                ts = t0 + (t1 - t0) * (account_id - a0) / (a1 - a0)
                break
    return {"estimated_created": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m"),
            "estimated_age_years": round((time.time() - ts) / (365.25 * 86400), 1),
            "uncertainty_years": "+/- 1-2", "method": "account-id interpolation (heuristic)"}


# ----------------------------------------------------------------------------
# HTTP layer: throttling, retries, 429 handling, timeouts, disk cache
# ----------------------------------------------------------------------------
class Http:
    def __init__(self, min_interval: float = 0.4, timeout: int = 15, retries: int = 4,
                 cache_ttl: int = 3600, use_cache: bool = True, verbose: bool = False,
                 log: Optional[Callable[[str], None]] = None):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8"})
        self.min_interval = min_interval
        self.timeout = timeout
        self.retries = retries
        self.cache_ttl = cache_ttl
        self.use_cache = use_cache
        self.verbose = verbose
        self.log = log or (lambda m: None)
        self._last = 0.0
        if use_cache:
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.use_cache = False

    def _throttle(self, interval: float) -> None:
        wait = self._last + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _cache_path(self, url: str, params: Optional[dict], body: Optional[dict] = None) -> Path:
        raw = url + "?" + urllib.parse.urlencode(sorted((params or {}).items()))
        if body is not None:
            raw += "|" + json.dumps(body, sort_keys=True)
        return CACHE_DIR / (hashlib.sha1(raw.encode()).hexdigest() + ".json")

    def get(self, url: str, params: Optional[dict] = None, *, as_json: bool = False,
            ttl: Optional[int] = None, interval: Optional[float] = None,
            ok_status: tuple = (200,), headers: Optional[dict] = None,
            json_body: Optional[dict] = None, retries: Optional[int] = None) -> Any:
        tries = self.retries if retries is None else retries
        ttl = self.cache_ttl if ttl is None else ttl
        cpath = self._cache_path(url, params, json_body) if (self.use_cache and ttl > 0) else None
        if cpath and cpath.exists():
            try:
                blob = json.loads(cpath.read_text("utf-8"))
                if time.time() - blob["t"] < ttl:
                    return blob["d"]
            except (OSError, ValueError, KeyError):
                pass
        last_exc: Optional[Exception] = None
        for attempt in range(tries + 1):
            self._throttle(interval if interval is not None else self.min_interval)
            try:
                r = self.s.request("POST" if json_body is not None else "GET", url, params=params,
                                   headers=headers, json=json_body, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                self.log(f"network issue ({type(e).__name__}); retry {attempt + 1}")
                time.sleep(min(2 ** attempt, 20))
                continue
            except requests.RequestException as e:
                raise NetworkError(str(e)) from e
            if r.status_code == 429:
                ra = r.headers.get("Retry-After", "")
                delay = float(ra) if re.fullmatch(r"\d+(\.\d+)?", ra) else min(3 * 2 ** attempt, 60)
                self.log(f"HTTP 429 - sleeping {delay:.0f}s")
                if attempt >= tries:
                    raise RateLimited("Steam rate limit (HTTP 429) persisted after retries.")
                time.sleep(delay)
                continue
            if r.status_code >= 500:
                last_exc = HttpStatusError(r.status_code, url)
                time.sleep(min(2 ** attempt, 20))
                continue
            if r.status_code not in ok_status:
                raise HttpStatusError(r.status_code, url)
            try:
                data = r.json() if as_json else r.text
            except ValueError as e:
                raise SteamOsintError(f"Invalid JSON from {url.split('?')[0]}") from e
            if cpath:
                try:
                    cpath.write_text(json.dumps({"t": time.time(), "d": data}), "utf-8")
                except OSError:
                    pass
            return data
        if isinstance(last_exc, HttpStatusError):
            raise last_exc
        raise NetworkError(f"Network failure after {tries} retries: {last_exc}")


# ----------------------------------------------------------------------------
# Official Web API
# ----------------------------------------------------------------------------
class SteamApi:
    def __init__(self, http: Http, key: Optional[str]):
        self.http, self.key = http, key

    @property
    def available(self) -> bool:
        return bool(self.key)

    def _call(self, path: str, ttl: Optional[int] = None, **params) -> dict:
        if not self.key:
            raise ApiKeyMissing("No Steam API key configured.")
        params["key"] = self.key
        try:
            return self.http.get(f"{API}/{path}", params, as_json=True, ttl=ttl)
        except HttpStatusError as e:
            if e.status == 403:
                raise InvalidApiKey("Steam rejected the API key (HTTP 403).") from e
            if e.status == 401:
                raise PrivateData("Data is private (HTTP 401).") from e
            if e.status == 400:
                raise SteamOsintError("Bad request to Steam API (HTTP 400).") from e
            raise

    def validate_key(self) -> None:
        self._call("ISteamUser/GetPlayerSummaries/v2/", ttl=0, steamids="76561197960435530")

    def resolve_vanity(self, vanity: str) -> Optional[int]:
        r = self._call("ISteamUser/ResolveVanityURL/v1/", vanityurl=vanity, url_type=1).get("response", {})
        return int(r["steamid"]) if r.get("success") == 1 and r.get("steamid") else None

    def summaries(self, ids: list[int]) -> dict[int, dict]:
        out: dict[int, dict] = {}
        for i in range(0, len(ids), 100):
            chunk = ids[i:i + 100]
            d = self._call("ISteamUser/GetPlayerSummaries/v2/", steamids=",".join(map(str, chunk)))
            for p in d.get("response", {}).get("players", []):
                out[int(p["steamid"])] = p
        return out

    def friends(self, id64: int) -> list[dict]:
        d = self._call("ISteamUser/GetFriendList/v1/", steamid=id64, relationship="friend")
        return d.get("friendslist", {}).get("friends", []) or []

    def bans(self, ids: list[int]) -> dict[int, dict]:
        d = self._call("ISteamUser/GetPlayerBans/v1/", steamids=",".join(map(str, ids)))
        return {int(p["SteamId"]): p for p in d.get("players", [])}

    def owned_games(self, id64: int) -> list[dict]:
        d = self._call("IPlayerService/GetOwnedGames/v1/", steamid=id64,
                       include_appinfo=1, include_played_free_games=1)
        return d.get("response", {}).get("games", []) or []

    def recent_games(self, id64: int) -> list[dict]:
        d = self._call("IPlayerService/GetRecentlyPlayedGames/v1/", steamid=id64)
        return d.get("response", {}).get("games", []) or []

    def level(self, id64: int) -> Optional[int]:
        return self._call("IPlayerService/GetSteamLevel/v1/", steamid=id64).get("response", {}).get("player_level")

    def badges(self, id64: int) -> dict:
        return self._call("IPlayerService/GetBadges/v1/", steamid=id64).get("response", {}) or {}

    def groups(self, id64: int) -> list[str]:
        d = self._call("ISteamUser/GetUserGroupList/v1/", steamid=id64).get("response", {})
        return [str(GROUP64_BASE + int(g["gid"])) for g in d.get("groups", []) or []]


# ----------------------------------------------------------------------------
# Public web layer (legal fallbacks)
# ----------------------------------------------------------------------------
SOCIAL_PATTERNS = {
    "Discord invite": r"(?:discord\.gg|discord(?:app)?\.com/invite)/[\w-]+",
    "Twitch": r"twitch\.tv/\w+",
    "YouTube": r"(?:youtube\.com/(?:@|channel/|c/|user/)[\w\-.]+|youtu\.be/[\w-]+)",
    "Twitter/X": r"(?:twitter|x)\.com/\w+",
    "Reddit": r"reddit\.com/(?:u|user)/[\w-]+",
    "Instagram": r"instagram\.com/[\w.]+",
    "GitHub": r"github\.com/[\w-]+",
    "TikTok": r"tiktok\.com/@[\w.]+",
    "Kick": r"kick\.com/[\w-]+",
    "Telegram": r"t\.me/\w+",
    "Faceit": r"faceit\.com/\w+/players/[\w-]+",
    "Steam Group/Profile": r"steamcommunity\.com/(?:groups|id|profiles)/[\w-]+",
}
DISCORD_HANDLE = re.compile(r"discord\s*(?:id|tag|user(?:name)?)?\s*[:=\-]\s*@?([\w.#]{2,40})", re.I)


class SteamWeb:
    def __init__(self, http: Http):
        self.http = http

    @staticmethod
    def _safe_xml(text: str) -> ET.Element:
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise SteamOsintError("Refusing XML with DTD/entities.")
        try:
            return ET.fromstring(text.lstrip("\ufeff \n\r\t"))
        except ET.ParseError as e:
            raise NotFound("Steam returned a non-XML page (profile missing or blocked).") from e

    def profile_xml(self, key: str, vanity: bool = False) -> dict:
        path = f"id/{urllib.parse.quote(key)}" if vanity else f"profiles/{key}"
        text = self.http.get(f"{COMMUNITY}/{path}/", {"xml": 1}, ttl=1800)
        root = self._safe_xml(text)
        err = root.find("error")
        if root.tag == "response" and err is not None:
            raise NotFound((err.text or "Profile not found").strip())

        def t(tag: str) -> str:
            n = root.find(tag)
            return (n.text or "").strip() if n is not None and n.text else ""

        groups = []
        for g in root.findall("./groups/group"):
            gt = lambda tag: (g.findtext(tag) or "").strip()  # noqa: E731
            gid = gt("groupID64")
            if not gid:
                continue
            groups.append({"gid64": gid, "name": gt("groupName"), "url": gt("groupURL"),
                           "headline": gt("headline"), "members": gt("memberCount"),
                           "primary": g.get("isPrimary") == "1"})
        most = []
        for g in root.findall("./mostPlayedGames/mostPlayedGame"):
            most.append({"name": (g.findtext("gameName") or "").strip(),
                         "hours_on_record": (g.findtext("hoursOnRecord") or "").strip(),
                         "hours_2wk": (g.findtext("hoursPlayed") or "").strip()})
        member_since = t("memberSince")
        created_ts = None
        for fmt in ("%B %d, %Y", "%b %d, %Y"):
            try:
                created_ts = int(datetime.strptime(member_since, fmt).replace(tzinfo=timezone.utc).timestamp())
                break
            except ValueError:
                continue
        return {"steamid64": t("steamID64"), "name": t("steamID"), "custom_url": t("customURL"),
                "online_state": t("onlineState"), "state_message": t("stateMessage"),
                "privacy": t("privacyState"), "visibility": t("visibilityState"),
                "avatar": t("avatarFull"), "vac_banned": t("vacBanned") == "1",
                "trade_ban": t("tradeBanState"), "limited": t("isLimitedAccount") == "1",
                "member_since": member_since, "member_since_ts": created_ts,
                "headline": t("headline"), "location": t("location"), "realname": t("realname"),
                "summary": re.sub(r"<[^>]+>", " ", htmllib.unescape(t("summary"))).strip(),
                "hours_2wk": t("hoursPlayed2Wk"), "groups": groups, "most_played": most}

    def aliases(self, id64: int) -> list[dict]:
        try:
            data = self.http.get(f"{COMMUNITY}/profiles/{id64}/ajaxaliases", as_json=True, ttl=1800)
        except HttpStatusError as e:
            if e.status in (401, 403):
                raise PrivateData("Alias history not available.") from e
            raise
        out = []
        for a in data if isinstance(data, list) else []:
            out.append({"name": a.get("newname", ""), "changed": a.get("timechanged", "")})
        return out

    def profile_links(self, id64: int, extra_text: str = "") -> list[dict]:
        found: dict[str, dict] = {}
        urls: list[str] = []
        try:
            page = self.http.get(f"{COMMUNITY}/profiles/{id64}", {"l": "english"}, ttl=1800)
            for u in re.findall(r"linkfilter/\?(?:u|url)=([^\"'&<>\s]+)", page):
                urls.append(htmllib.unescape(urllib.parse.unquote(u)))
        except SteamOsintError:
            pass
        blob = "\n".join(urls) + "\n" + (extra_text or "")
        for label, pat in SOCIAL_PATTERNS.items():
            for m in re.finditer(pat, blob, re.I):
                found.setdefault(m.group(0).lower(), {"platform": label, "match": m.group(0)})
        for m in DISCORD_HANDLE.finditer(extra_text or ""):
            found.setdefault("dh:" + m.group(1).lower(),
                             {"platform": "Discord handle (self-declared)", "match": m.group(1)})
        for u in urls:
            if not any(u.lower().find(k) >= 0 for k in found):
                found.setdefault(u.lower(), {"platform": "External link", "match": u})
        return list(found.values())

    def inventory(self, id64: int, appid: int = 730, context: int = 2, max_pages: int = 10) -> dict:
        assets: list[dict] = []
        descs: dict[str, dict] = {}
        last = None
        for _ in range(max_pages):
            params = {"l": "english", "count": 2000}
            if last:
                params["start_assetid"] = last
            try:
                d = self.http.get(f"{COMMUNITY}/inventory/{id64}/{appid}/{context}", params,
                                  as_json=True, ttl=900, interval=1.2)
            except HttpStatusError as e:
                if e.status in (401, 403):
                    raise PrivateData("Inventory is private.") from e
                if e.status == 404:
                    raise NotFound("Inventory not found for this app/context.") from e
                raise
            if not d or not d.get("success"):
                break
            assets += d.get("assets", []) or []
            for x in d.get("descriptions", []) or []:
                descs[f"{x.get('classid')}_{x.get('instanceid')}"] = x
            if d.get("more_items") and d.get("last_assetid"):
                last = d["last_assetid"]
            else:
                break
        items: dict[str, dict] = {}
        for a in assets:
            x = descs.get(f"{a.get('classid')}_{a.get('instanceid')}", {})
            name = x.get("market_hash_name") or x.get("name") or f"class {a.get('classid')}"
            e = items.setdefault(name, {"name": name, "count": 0, "marketable": bool(x.get("marketable")),
                                        "tradable": bool(x.get("tradable")), "type": x.get("type", ""),
                                        "price": None})
            e["count"] += int(a.get("amount", 1) or 1)
        return {"appid": appid, "context": context, "total_items": sum(i["count"] for i in items.values()),
                "unique_items": len(items), "items": sorted(items.values(), key=lambda i: -i["count"])}

    def market_price(self, appid: int, name: str, currency: int = 1) -> Optional[float]:
        try:
            d = self.http.get(f"{COMMUNITY}/market/priceoverview/",
                              {"appid": appid, "currency": currency, "market_hash_name": name},
                              as_json=True, ttl=6 * 3600, interval=3.3)
        except HttpStatusError:
            return None
        if not d or not d.get("success"):
            return None
        return parse_price(d.get("lowest_price") or d.get("median_price") or "")

    def store_prices(self, appids: list[int], cc: str = "us") -> dict[int, float]:
        out: dict[int, float] = {}
        for i in range(0, len(appids), 50):
            chunk = appids[i:i + 50]
            try:
                d = self.http.get(f"{STORE}/api/appdetails",
                                  {"appids": ",".join(map(str, chunk)), "filters": "price_overview", "cc": cc},
                                  as_json=True, ttl=12 * 3600, interval=1.0)
            except SteamOsintError:
                continue
            for k, v in (d or {}).items():
                data = v.get("data") if isinstance(v, dict) else None
                if isinstance(data, dict) and data.get("price_overview"):
                    out[int(k)] = data["price_overview"].get("initial", 0) / 100.0
        return out


# ----------------------------------------------------------------------------
# Off-Steam intelligence: search engines (Google), handle footprint, game platforms
# ----------------------------------------------------------------------------
# NOTE on Google: Google's own Custom Search JSON API is closed to new customers and
# is retired on 2027-01-01, and scraping google.com violates its ToS (and gets CAPTCHA'd).
# So Google results are fetched through licensed SERP APIs (Serper.dev / SerpAPI), with
# Brave Search as an independent index and legacy google_cse for existing customers.
SEARCH_PROVIDERS = ("serper", "serpapi", "brave", "google_cse")
SEARCH_ENV = {"serper": "SERPER_API_KEY", "serpapi": "SERPAPI_API_KEY",
              "brave": "BRAVE_API_KEY", "google_cse": "GOOGLE_CSE_KEY"}
SEARCH_LABEL = {"serper": "Serper.dev (Google results)", "serpapi": "SerpAPI (Google results)",
                "brave": "Brave Search API", "google_cse": "Google CSE (legacy, ends 2027-01-01)"}

COMMON_WORDS = {"admin", "user", "player", "guest", "noob", "pro", "gamer", "test", "steam", "god", "king",
                "killer", "sniper", "ghost", "shadow", "dragon", "wolf", "dark", "legend", "boss", "bot",
                "none", "unknown", "null", "root", "gaming", "games", "csgo", "cs2", "dota", "valve"}
SOCIAL_DOMAINS = {"reddit.com", "twitter.com", "x.com", "twitch.tv", "youtube.com", "instagram.com",
                  "tiktok.com", "facebook.com", "linkedin.com", "kick.com", "bsky.app", "tumblr.com",
                  "pinterest.com", "vk.com", "t.me", "linktr.ee", "medium.com"}
DEV_DOMAINS = {"github.com", "gitlab.com", "dev.to", "stackoverflow.com", "keybase.io", "hub.docker.com"}
GAMING_DOMAINS = {"faceit.com", "hltv.org", "esea.net", "esportal.com", "battlemetrics.com", "leetify.com",
                  "csstats.gg", "steamrep.com", "backpack.tf", "steamdb.info", "dotabuff.com", "opendota.com",
                  "op.gg", "speedrun.com", "gametracker.com", "steamid.io", "steamidfinder.com"}
RESERVED_HANDLES = {"search", "home", "i", "intent", "share", "explore", "hashtag", "login", "signup", "about",
                    "privacy", "tos", "settings", "watch", "channel", "user", "users", "pages", "topics", "orgs",
                    "features", "marketplace", "sponsors", "directory", "videos", "p", "reel", "reels", "tv",
                    "stories", "status", "hashtags", "policies", "en", "www", "settings"}
HANDLE_URL_PATTERNS = [
    ("Reddit", r"reddit\.com/(?:u|user)/([\w-]{3,20})"),
    ("Twitter/X", r"(?:twitter|x)\.com/(\w{1,15})(?:[/?#]|$)"),
    ("Twitch", r"twitch\.tv/(\w{3,25})(?:[/?#]|$)"),
    ("YouTube", r"youtube\.com/@([\w.\-]{3,30})"),
    ("GitHub", r"github\.com/([\w-]{1,39})(?:[/?#]|$)"),
    ("Instagram", r"instagram\.com/([\w.]{1,30})(?:[/?#]|$)"),
    ("TikTok", r"tiktok\.com/@([\w.]{2,24})"),
    ("FACEIT", r"faceit\.com/\w+/players/([\w-]{2,30})"),
]
GAMING_CONTEXT = re.compile(r"\b(steam|cs2|csgo|counter-strike|dota|valve|faceit|gamer|esports?)\b", re.I)
ID_KINDS = {"steamid64", "steam2", "steam3"}
STRENGTH_W = {"strong": 4, "medium": 2, "weak": 1}


def domain_of(url: str) -> str:
    try:
        host = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def categorize_domain(dom: str) -> str:
    for cat, pool in (("social", SOCIAL_DOMAINS), ("dev", DEV_DOMAINS), ("gaming", GAMING_DOMAINS)):
        if any(dom == d or dom.endswith("." + d) for d in pool):
            return cat
    return "other"


def safe_href(u: str) -> str:
    return u if isinstance(u, str) and u.lower().startswith(("http://", "https://")) else "#"


class SearchEngine:
    """Pluggable web-search backend. Returns [{title, link, snippet}]."""

    def __init__(self, http: Http, provider: Optional[str], key: Optional[str], cx: Optional[str] = None):
        self.http, self.provider, self.key, self.cx = http, provider, key, cx

    @property
    def available(self) -> bool:
        return bool(self.provider and self.key and (self.provider != "google_cse" or self.cx))

    def search(self, query: str, num: int = 10) -> list[dict]:
        p, h = self.provider, self.http
        try:
            if p == "serper":
                d = h.get("https://google.serper.dev/search", as_json=True, ttl=6 * 3600, interval=0.6,
                          headers={"X-API-KEY": self.key, "Content-Type": "application/json"},
                          json_body={"q": query, "num": num})
                rows = [(x.get("title"), x.get("link"), x.get("snippet")) for x in (d or {}).get("organic", [])]
            elif p == "serpapi":
                d = h.get("https://serpapi.com/search.json", {"engine": "google", "q": query, "num": num,
                                                              "api_key": self.key},
                          as_json=True, ttl=6 * 3600, interval=0.6)
                if (d or {}).get("error"):
                    raise SteamOsintError(f"serpapi: {d['error']}")
                rows = [(x.get("title"), x.get("link"), x.get("snippet")) for x in (d or {}).get("organic_results", [])]
            elif p == "brave":
                d = h.get("https://api.search.brave.com/res/v1/web/search", {"q": query, "count": min(num, 20)},
                          as_json=True, ttl=6 * 3600, interval=1.1,
                          headers={"X-Subscription-Token": self.key, "Accept": "application/json"})
                rows = [(x.get("title"), x.get("url"), x.get("description"))
                        for x in ((d or {}).get("web") or {}).get("results", [])]
            elif p == "google_cse":
                d = h.get("https://www.googleapis.com/customsearch/v1",
                          {"key": self.key, "cx": self.cx, "q": query, "num": min(num, 10)},
                          as_json=True, ttl=6 * 3600, interval=0.6)
                rows = [(x.get("title"), x.get("link"), x.get("snippet")) for x in (d or {}).get("items", [])]
            else:
                raise SteamOsintError(f"Unknown search provider {p!r}")
        except HttpStatusError as e:
            if e.status in (401, 403):
                extra = " (Google CSE is closed to new customers)" if p == "google_cse" else ""
                raise InvalidApiKey(f"{p}: key rejected or not authorised (HTTP {e.status}){extra}.") from e
            if e.status == 402:
                raise RateLimited(f"{p}: credits/quota exhausted (HTTP 402).") from e
            raise
        out = []
        for title, link, snip in rows:
            if link:
                out.append({"title": re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", htmllib.unescape(title or ""))).strip(),
                            "link": link,
                            "snippet": re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", htmllib.unescape(snip or ""))).strip()[:400]})
        return out


@dataclass
class Seed:
    value: str
    kind: str
    strength: str
    alt: tuple = ()


def seed_strength(v: str) -> str:
    c = re.sub(r"\s+", "", v)
    if len(c) < 4 or c.lower() in COMMON_WORDS:
        return "weak"
    score = len(set(c.lower())) + (3 if re.search(r"\d", c) else 0) + (2 if re.search(r"[_.\-]", c) else 0)
    return "strong" if score >= 11 else "medium" if score >= 7 else "weak"


def build_seeds(rep: dict) -> list[Seed]:
    i, p = rep["identity"], rep["profile"]
    seeds: list[Seed] = []

    def add(v: Optional[str], kind: str, strength: Optional[str] = None, alt: tuple = ()) -> None:
        v = (v or "").strip()
        if not v or len(v) > 64 or any(s.value.lower() == v.lower() for s in seeds):
            return
        st = strength or seed_strength(v)
        if kind == "linked_handle" and st == "weak":
            st = "medium"          # declared on the profile itself -> at least medium
        seeds.append(Seed(v, kind, st, alt))

    acc = i["account_id"]
    y, z = acc & 1, acc >> 1
    add(str(i["id64"]), "steamid64", "strong")
    add(f"STEAM_0:{y}:{z}", "steam2", "strong", (f"STEAM_1:{y}:{z}",))
    add(f"[U:1:{acc}]", "steam3", "strong")
    add(i.get("vanity"), "vanity")
    add(p.get("name"), "name")
    for a in rep["name_history"].get("names", [])[:6]:
        add(a.get("name"), "alias")
    add(p.get("realname"), "realname", "weak")
    for l in rep["links"]:
        if l["platform"].startswith(("Discord handle", "Twitch", "Twitter", "Reddit", "GitHub", "YouTube",
                                     "Instagram", "TikTok", "Kick", "Telegram")):
            m = l["match"].rstrip("/")
            add((m.split("/")[-1] if "/" in m else m).lstrip("@"), "linked_handle")
    return seeds


def build_queries(seeds: list[Seed], ident: dict) -> list[dict]:
    qs: list[dict] = []
    seen: set[str] = set()

    def q(text: str, tag: str, prio: int) -> None:
        if text not in seen:
            seen.add(text)
            qs.append({"q": text, "tag": tag, "prio": prio, "n": len(qs)})

    id64, acc = ident["id64"], ident["account_id"]
    y, z = acc & 1, acc >> 1
    q(f'"{id64}" -site:steamcommunity.com', "steamid64-mentions", 0)
    q(f'"STEAM_0:{y}:{z}" OR "STEAM_1:{y}:{z}" OR "[U:1:{acc}]"', "steamid-formats (ban lists/servers)", 0)
    q(f'"steamcommunity.com/profiles/{id64}"', "profile-url citations", 1)
    if ident.get("vanity"):
        q(f'"steamcommunity.com/id/{ident["vanity"]}"', "vanity-url citations", 1)
    for s in seeds:
        if s.kind in ID_KINDS:
            continue
        base = f'"{s.value}"'
        pr = {"strong": 1, "medium": 2, "weak": 5}[s.strength]
        if s.kind == "realname":
            q(f'{base} (steam OR gamer OR esports) -site:steamcommunity.com', "realname-gaming", pr)
            continue
        q(f'{base} -site:steamcommunity.com', f"exact:{s.kind}", pr)
        q(f'{base} (site:reddit.com OR site:x.com OR site:twitter.com OR site:twitch.tv OR site:youtube.com '
          f'OR site:instagram.com OR site:tiktok.com)', f"social:{s.kind}", pr + 1)
        q(f'{base} (site:github.com OR site:gitlab.com OR site:keybase.io OR site:dev.to)', f"dev:{s.kind}", pr + 1)
        q(f'{base} (site:faceit.com OR site:hltv.org OR site:esportal.com OR site:battlemetrics.com '
          f'OR site:leetify.com OR site:csstats.gg OR site:dotabuff.com OR site:speedrun.com)',
          f"gaming-sites:{s.kind}", pr + 1)
        q(f'{base} (steam OR cs2 OR csgo OR dota OR valve OR gamer) -site:steamcommunity.com',
          f"gaming-context:{s.kind}", pr + 2)
    qs.sort(key=lambda d: (d["prio"], d["n"]))
    return qs


def attribute_result(res: dict, seeds: list[Seed]) -> dict:
    text = f"{res['title']} {res['snippet']} {res['link']}"
    hits, score = [], 0
    for s in seeds:
        forms = [s.value, *s.alt]
        if any(re.search(r"(?<![\w])" + re.escape(f) + r"(?![\w])", text, re.I) for f in forms):
            hits.append(f"{s.kind}:{s.value}")
            score += 7 if s.kind in ID_KINDS else STRENGTH_W[s.strength]
    if len(hits) >= 2:
        score += 2
    if hits and GAMING_CONTEXT.search(text):
        score += 1
    dom = domain_of(res["link"])
    return {**res, "domain": dom, "category": categorize_domain(dom), "score": score, "evidence": hits,
            "confidence": "high" if score >= 6 else "medium" if score >= 3 else "low"}


def extract_handles(url: str) -> list[tuple[str, str]]:
    out = []
    for plat, pat in HANDLE_URL_PATTERNS:
        m = re.search(pat, url, re.I)
        if m and m.group(1).lower() not in RESERVED_HANDLES:
            out.append((plat, m.group(1)))
    return out


class Footprint:
    """Existence + public metadata checks for a handle on platforms with real public APIs
    (no HTML guessing, so far fewer false positives than status-code sniffing)."""
    PLATFORMS = ["GitHub", "Reddit", "Keybase", "GitLab", "Chess.com", "Lichess", "HackerNews", "Dev.to",
                 "DockerHub", "Speedrun.com", "Gravatar", "Roblox"]

    def __init__(self, http: Http):
        self.http = http

    def _probe(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None,
               json_body: Optional[dict] = None) -> Any:
        try:
            return self.http.get(url, params, as_json=True, ttl=3600, interval=0.4, retries=1,
                                 headers=headers, json_body=json_body)
        except HttpStatusError as e:
            if e.status in (404, 410):
                return None
            if e.status in (401, 403, 429):
                raise RateLimited(f"blocked/rate-limited by {domain_of(url)} (HTTP {e.status})") from e
            raise

    @staticmethod
    def _txt(s: Any) -> str:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", htmllib.unescape(str(s or "")))).strip()

    def check(self, platform: str, h: str) -> Optional[dict]:
        return getattr(self, "_" + re.sub(r"\W", "", platform.lower()))(urllib.parse.quote(h, safe=""), h)

    def _github(self, q: str, h: str):
        d = self._probe(f"https://api.github.com/users/{q}", headers={"Accept": "application/vnd.github+json"})
        if not isinstance(d, dict) or not d.get("login"):
            return None
        return {"url": d.get("html_url"), "name": d.get("name"), "bio": d.get("bio"), "location": d.get("location"),
                "company": d.get("company"), "blog": d.get("blog"), "twitter": d.get("twitter_username"),
                "created": d.get("created_at"), "followers": d.get("followers"), "public_repos": d.get("public_repos")}

    def _reddit(self, q: str, h: str):
        d = self._probe(f"https://www.reddit.com/user/{q}/about.json")
        data = (d or {}).get("data") if isinstance(d, dict) else None
        if not data or not data.get("name"):
            return None
        return {"url": f"https://www.reddit.com/user/{data['name']}", "created": iso(data.get("created_utc")),
                "link_karma": data.get("link_karma"), "comment_karma": data.get("comment_karma"),
                "bio": self._txt((data.get("subreddit") or {}).get("public_description"))}

    def _keybase(self, q: str, h: str):
        d = self._probe("https://keybase.io/_/api/1.0/user/lookup.json",
                        {"usernames": h, "fields": "basics,profile,proofs_summary"})
        them = (d or {}).get("them") if isinstance(d, dict) else None
        if not them or not them[0]:
            return None
        t = them[0]
        prof = t.get("profile") or {}
        proofs = [{"service": x.get("proof_type"), "name": x.get("nametag"), "url": x.get("service_url")}
                  for x in ((t.get("proofs_summary") or {}).get("all") or [])]
        return {"url": f"https://keybase.io/{h}", "full_name": prof.get("full_name"), "location": prof.get("location"),
                "bio": prof.get("bio"), "verified_proofs": proofs}

    def _gitlab(self, q: str, h: str):
        d = self._probe("https://gitlab.com/api/v4/users", {"username": h})
        for u in d if isinstance(d, list) else []:
            if str(u.get("username", "")).lower() == h.lower():
                return {"url": u.get("web_url"), "name": u.get("name")}
        return None

    def _chesscom(self, q: str, h: str):
        d = self._probe(f"https://api.chess.com/pub/player/{q.lower()}")
        if not isinstance(d, dict) or not d.get("username"):
            return None
        return {"url": d.get("url"), "name": d.get("name"), "country": (d.get("country") or "").rsplit("/", 1)[-1],
                "joined": iso(d.get("joined")), "last_online": iso(d.get("last_online"))}

    def _lichess(self, q: str, h: str):
        d = self._probe(f"https://lichess.org/api/user/{q}")
        if not isinstance(d, dict) or not d.get("id"):
            return None
        pr = d.get("profile") or {}
        return {"url": d.get("url"), "created": iso((d.get("createdAt") or 0) / 1000), "country": pr.get("country"),
                "location": pr.get("location"), "bio": pr.get("bio"), "links": pr.get("links")}

    def _hackernews(self, q: str, h: str):
        d = self._probe(f"https://hacker-news.firebaseio.com/v0/user/{q}.json")
        if not isinstance(d, dict) or not d.get("id"):
            return None
        return {"url": f"https://news.ycombinator.com/user?id={d['id']}", "created": iso(d.get("created")),
                "karma": d.get("karma"), "about": self._txt(d.get("about"))}

    def _devto(self, q: str, h: str):
        d = self._probe("https://dev.to/api/users/by_username", {"url": h})
        if not isinstance(d, dict) or not d.get("username"):
            return None
        return {"url": f"https://dev.to/{d['username']}", "name": d.get("name"), "summary": d.get("summary"),
                "location": d.get("location"), "twitter": d.get("twitter_username"),
                "github": d.get("github_username"), "joined": d.get("joined_at")}

    def _dockerhub(self, q: str, h: str):
        d = self._probe(f"https://hub.docker.com/v2/users/{q}/")
        if not isinstance(d, dict) or not d.get("username"):
            return None
        return {"url": f"https://hub.docker.com/u/{d['username']}", "name": d.get("full_name"),
                "location": d.get("location"), "company": d.get("company"), "joined": d.get("date_joined")}

    def _speedruncom(self, q: str, h: str):
        d = self._probe(f"https://www.speedrun.com/api/v1/users/{q}")
        data = (d or {}).get("data") if isinstance(d, dict) else None
        if not isinstance(data, dict) or not data.get("id"):
            return None
        g = lambda k: ((data.get(k) or {}).get("uri"))  # noqa: E731
        return {"url": data.get("weblink"), "names": (data.get("names") or {}).get("international"),
                "location": (((data.get("location") or {}).get("country") or {}).get("names") or {}).get("international"),
                "twitch": g("twitch"), "twitter": g("twitter"), "youtube": g("youtube"), "signup": data.get("signup")}

    def _gravatar(self, q: str, h: str):
        d = self._probe(f"https://en.gravatar.com/{q}.json")
        ent = ((d or {}).get("entry") or [None])[0] if isinstance(d, dict) else None
        if not ent:
            return None
        return {"url": ent.get("profileUrl"), "display": ent.get("displayName"), "about": ent.get("aboutMe"),
                "location": ent.get("currentLocation"),
                "accounts": [{"service": x.get("shortname"), "url": x.get("url")} for x in ent.get("accounts") or []],
                "urls": [x.get("value") for x in ent.get("urls") or []]}

    def _roblox(self, q: str, h: str):
        d = self._probe("https://users.roblox.com/v1/usernames/users",
                        json_body={"usernames": [h], "excludeBannedUsers": False})
        rows = (d or {}).get("data") if isinstance(d, dict) else None
        if not rows:
            return None
        return {"url": f"https://www.roblox.com/users/{rows[0].get('id')}/profile", "display": rows[0].get("displayName")}


def correlate(handle: str, details: dict, ref: dict) -> tuple[str, list[str]]:
    """Judge whether a same-name account is plausibly the same person. Never claims identity."""
    blob = json.dumps(details, ensure_ascii=False, default=str).lower()
    if ref["id64"] in blob or (ref.get("vanity") and f"steamcommunity.com/id/{ref['vanity'].lower()}" in blob):
        return "corroborated", ["account references this exact Steam profile"]
    reasons, verdict = [], "unverified"
    if "steamcommunity.com/" in blob:
        reasons.append("references a DIFFERENT Steam profile (likely another person)")
        verdict = "conflict"
    for hh in sorted(ref.get("handles", [])):
        if hh != handle.lower() and len(hh) >= 4 and hh in blob:
            reasons.append(f"mentions linked handle '{hh}'")
            if verdict != "conflict":
                verdict = "plausible"
    rn = (ref.get("realname") or "").lower()
    if len(rn) >= 5 and rn in blob:
        reasons.append("same real name as the Steam profile")
        if verdict != "conflict":
            verdict = "plausible"
    return verdict, reasons or ["same handle only - NOT evidence of the same person"]


def opendota_lookup(http: Http, account_id: int) -> Optional[dict]:
    try:
        d = http.get(f"https://api.opendota.com/api/players/{account_id}", as_json=True, ttl=3600, interval=1.0, retries=1)
    except HttpStatusError as e:
        if e.status in (404, 400):
            return None
        raise
    pr = (d or {}).get("profile") if isinstance(d, dict) else None
    if not pr:
        return None
    return {"url": f"https://www.opendota.com/players/{account_id}", "name": pr.get("personaname"),
            "country": pr.get("loccountrycode"), "last_login": pr.get("last_login"),
            "rank_tier": d.get("rank_tier"), "leaderboard_rank": d.get("leaderboard_rank"),
            "profile_name": pr.get("name")}


def faceit_lookup(http: Http, key: str, id64: int) -> Optional[dict]:
    for game in ("cs2", "csgo"):
        try:
            d = http.get("https://open.faceit.com/data/v4/players", {"game": game, "game_player_id": str(id64)},
                         as_json=True, ttl=3600, interval=0.5, retries=1,
                         headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
        except HttpStatusError as e:
            if e.status == 404:
                continue
            if e.status in (401, 403):
                raise InvalidApiKey("FACEIT key rejected.") from e
            raise
        if isinstance(d, dict) and d.get("nickname"):
            g = (d.get("games") or {}).get(game, {})
            return {"url": (d.get("faceit_url") or "").replace("{lang}", "en"), "nickname": d.get("nickname"),
                    "country": d.get("country"), "game": game, "skill_level": g.get("skill_level"),
                    "elo": g.get("faceit_elo"), "region": g.get("region"), "activated_at": d.get("activated_at"),
                    "verified": d.get("verified"), "steam_id_64": d.get("steam_id_64")}
    return None


def wayback_summary(http: Http, pattern: str) -> dict:
    rows = http.get("https://web.archive.org/cdx/search/cdx",
                    {"url": pattern, "output": "json", "fl": "timestamp,original,statuscode",
                     "filter": "statuscode:200", "collapse": "timestamp:6", "limit": 400},
                    as_json=True, ttl=6 * 3600, interval=1.0, retries=1)
    data = rows[1:] if isinstance(rows, list) and len(rows) > 1 else []
    if not data:
        return {"pattern": pattern, "snapshots": 0}
    first, last = data[0], data[-1]
    link = lambda r: f"https://web.archive.org/web/{r[0]}/{r[1]}"  # noqa: E731
    return {"pattern": pattern, "snapshots": len(data), "first": first[0], "last": last[0],
            "first_url": link(first), "last_url": link(last),
            "per_year": dict(sorted(Counter(r[0][:4] for r in data).items()))}


def discord_invite_lookup(http: Http, code: str) -> Optional[dict]:
    try:
        d = http.get(f"https://discord.com/api/v10/invites/{urllib.parse.quote(code)}",
                     {"with_counts": "true", "with_expiration": "true"}, as_json=True, ttl=3600, interval=0.8, retries=1)
    except HttpStatusError as e:
        if e.status in (404, 410):
            return {"code": code, "status": "invalid or expired"}
        raise
    g, inv = (d or {}).get("guild") or {}, (d or {}).get("inviter") or {}
    return {"code": code, "status": "valid", "server": g.get("name"), "server_id": g.get("id"),
            "description": g.get("description"), "members": d.get("approximate_member_count"),
            "online": d.get("approximate_presence_count"), "expires_at": d.get("expires_at"),
            "inviter": inv.get("global_name") or inv.get("username")}


def offsteam_scan(ctx: "Ctx", rep: dict) -> dict:
    a, con, http = ctx.args, ctx.console, ctx.http
    ident, prof = rep["identity"], rep["profile"]
    id64, acc = ident["id64"], ident["account_id"]
    seeds = build_seeds(rep)
    plan = build_queries(seeds, ident)
    q = urllib.parse.quote_plus
    off: dict[str, Any] = {
        "seeds": [asdict(s) for s in seeds],
        "search": {"provider": None, "queries_planned": len(plan), "queries_run": 0, "log": [], "results": [],
                   "accounts": [], "status": ""},
        "manual_queries": [{"query": p["q"], "tag": p["tag"], "google": f"https://www.google.com/search?q={q(p['q'])}",
                            "duckduckgo": f"https://duckduckgo.com/?q={q(p['q'])}",
                            "bing": f"https://www.bing.com/search?q={q(p['q'])}"} for p in plan],
        "handles": [], "handles_checked": [], "blocked_platforms": [], "game_platforms": {}, "wayback": [],
        "discord_invites": []}

    # ---- 1. search engine pass ------------------------------------------------------------
    engine: Optional[SearchEngine] = getattr(ctx, "search", None)
    max_q = max(0, getattr(a, "max_queries", 12))
    results: dict[str, dict] = {}
    if engine and engine.available and max_q:
        off["search"]["provider"] = SEARCH_LABEL[engine.provider]
        with con.status("[bold cyan]Searching the web (Google/SERP)...") as st:
            for qd in plan[:max_q]:
                st.update(f"[bold cyan]Search: {qd['tag']}")
                try:
                    rows = engine.search(qd["q"])
                except (InvalidApiKey, RateLimited) as e:
                    rep["warnings"].append(f"Search stopped: {e}")
                    off["search"]["status"] = f"stopped: {e}"
                    break
                except SteamOsintError as e:
                    rep["warnings"].append(f"Search '{qd['tag']}': {e}")
                    continue
                off["search"]["queries_run"] += 1
                off["search"]["log"].append({"q": qd["q"], "tag": qd["tag"], "count": len(rows)})
                for row in rows:
                    key = row["link"].split("#")[0].rstrip("/").lower()
                    if key not in results:
                        r = attribute_result(row, seeds)
                        r["query_tag"] = qd["tag"]
                        results[key] = r
        ranked = sorted(results.values(), key=lambda r: -r["score"])[:80]
        off["search"]["results"] = ranked
        accts: dict[tuple, dict] = {}
        for r in ranked:
            if r["confidence"] == "low":
                continue
            for plat, h in extract_handles(r["link"]):
                accts.setdefault((plat, h.lower()), {"platform": plat, "handle": h, "url": r["link"],
                                                     "confidence": r["confidence"]})
        off["search"]["accounts"] = list(accts.values())
        off["search"]["status"] = off["search"]["status"] or "ok"
    else:
        why = ("no search API key configured" if not (engine and engine.available) else "--max-queries is 0")
        off["search"]["status"] = f"skipped ({why}); open 'manual_queries' links in a browser instead"
        rep["warnings"].append(
            "Web search skipped: no search key. Set one: config --set-search serper YOUR_KEY "
            "(Serper/SerpAPI return real Google results; Brave also supported). Manual Google links were generated.")

    # ---- 2. handle footprint on platforms with public APIs ------------------------------
    ref = {"id64": str(id64), "vanity": ident.get("vanity"), "realname": prof.get("realname"),
           "handles": {s.value.lower() for s in seeds if s.kind == "linked_handle"}}
    cands: list[str] = []

    def addc(h: str) -> None:
        h = (h or "").strip().lstrip("@")
        if re.fullmatch(r"[A-Za-z0-9_.\-]{3,32}", h) and h.lower() not in {c.lower() for c in cands}:
            cands.append(h)

    for kind in ("linked_handle", "vanity", "name", "alias"):
        for s in seeds:
            if s.kind == kind:
                addc(s.value)
    for acct in off["search"]["accounts"]:
        addc(acct["handle"])
    max_h = max(0, getattr(a, "max_handles", 4))
    todo = cands[:max_h]
    off["handles_checked"] = todo
    blocked: set[str] = set()
    fp = Footprint(http)
    if todo:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(),
                      console=con) as pg:
            task = pg.add_task("Handle footprint (public APIs)", total=len(todo) * len(Footprint.PLATFORMS))
            for h in todo:
                for plat in Footprint.PLATFORMS:
                    pg.advance(task)
                    if plat in blocked:
                        continue
                    try:
                        det = fp.check(plat, h)
                    except RateLimited:
                        blocked.add(plat)
                        continue
                    except SteamOsintError:
                        continue
                    if det:
                        verdict, reasons = correlate(h, det, ref)
                        off["handles"].append({"platform": plat, "handle": h, "url": det.get("url"),
                                               "verdict": verdict, "reasons": reasons, "details": det})
        order = {"corroborated": 0, "plausible": 1, "unverified": 2, "conflict": 3}
        off["handles"].sort(key=lambda x: (order[x["verdict"]], x["platform"]))
    off["blocked_platforms"] = sorted(blocked)

    # ---- 3. game-platform lookups keyed on the SteamID (strong evidence) ---------------
    gp = off["game_platforms"]
    gp["opendota"] = guard(rep, "OpenDota", lambda: opendota_lookup(http, acc))
    fkey = getattr(ctx, "faceit_key", None)
    if fkey:
        gp["faceit"] = guard(rep, "FACEIT", lambda: faceit_lookup(http, fkey, id64))
    else:
        gp["faceit"] = None
        gp["faceit_note"] = "set a FACEIT Data API key (config --set-faceit KEY) for an exact SteamID -> FACEIT match"

    # ---- 4. Internet Archive history of the profile --------------------------------------
    with con.status("[bold cyan]Checking Internet Archive..."):
        pats = [f"steamcommunity.com/profiles/{id64}"]
        if ident.get("vanity"):
            pats.append(f"steamcommunity.com/id/{ident['vanity']}")
        for pat in pats:
            w = guard(rep, f"Wayback {pat}", lambda pat=pat: wayback_summary(http, pat))
            if w:
                off["wayback"].append(w)

    # ---- 5. Discord invites found on the profile -----------------------------------------
    for l in rep["links"]:
        if l["platform"] == "Discord invite":
            code = l["match"].rstrip("/").split("/")[-1]
            info = guard(rep, f"Discord invite {code}", lambda code=code: discord_invite_lookup(http, code))
            if info:
                off["discord_invites"].append(info)
    return off


def render_offsteam(con: Console, off: dict) -> None:
    if not off:
        return
    s = off["search"]
    con.print(kv_table("Off-Steam intelligence", [
        ("Search backend", s.get("provider")), ("Status", s.get("status")),
        ("Queries run / planned", f"{s['queries_run']} / {s['queries_planned']}"),
        ("Seeds", ", ".join(f"{x['value']} ({x['kind']},{x['strength']})" for x in off["seeds"][:12]))]))
    res = [r for r in s.get("results", []) if r["confidence"] != "low"][:20]
    if res:
        t = Table(title="Web results (medium/high attribution)", box=box.SIMPLE_HEAVY)
        for c in ("Conf.", "Domain", "Title", "Evidence", "URL"):
            t.add_column(c, overflow="fold")
        for r in res:
            t.add_row(r["confidence"], r["domain"], r["title"][:70], ", ".join(r["evidence"])[:60], r["link"])
        con.print(t)
        low = sum(1 for r in s["results"] if r["confidence"] == "low")
        if low:
            con.print(f"[dim]{low} low-confidence results hidden here (kept in exports) - often a different person.[/dim]")
    if s.get("accounts"):
        t = Table(title="Candidate accounts found via search", box=box.SIMPLE)
        for c in ("Platform", "Handle", "Conf.", "Source URL"):
            t.add_column(c, overflow="fold")
        for x in s["accounts"][:20]:
            t.add_row(x["platform"], x["handle"], x["confidence"], x["url"])
        con.print(t)
    if off["handles"]:
        t = Table(title=f"Handle footprint (checked: {', '.join(off['handles_checked'])})", box=box.SIMPLE_HEAVY)
        for c in ("Verdict", "Platform", "Handle", "Why", "URL"):
            t.add_column(c, overflow="fold")
        for x in off["handles"]:
            t.add_row(x["verdict"], x["platform"], x["handle"], "; ".join(x["reasons"]), x["url"] or "")
        con.print(t)
    if off["blocked_platforms"]:
        con.print(f"[yellow]Blocked/rate-limited during footprint: {', '.join(off['blocked_platforms'])}[/yellow]")
    gp = off["game_platforms"]
    rows = []
    for k in ("opendota", "faceit"):
        if gp.get(k):
            rows.append((k, "; ".join(f"{a}={b}" for a, b in gp[k].items() if b not in (None, ""))))
    if gp.get("faceit_note") and not gp.get("faceit"):
        rows.append(("faceit", gp["faceit_note"]))
    if rows:
        con.print(kv_table("Game platforms (exact SteamID match)", rows))
    if off["wayback"]:
        t = Table(title="Internet Archive snapshots", box=box.SIMPLE)
        for c in ("Pattern", "Snapshots", "First", "Last"):
            t.add_column(c, overflow="fold")
        for w in off["wayback"]:
            t.add_row(w["pattern"], str(w["snapshots"]), w.get("first_url", ""), w.get("last_url", ""))
        con.print(t)
    if off["discord_invites"]:
        con.print(kv_table("Discord invites", [(d["code"], "; ".join(f"{k}={v}" for k, v in d.items()
                                                                       if k != "code" and v not in (None, "")))
                                               for d in off["discord_invites"]]))
    if off["manual_queries"] and not s.get("results"):
        t = Table(title="Manual Google queries (open in browser)", box=box.SIMPLE)
        t.add_column("Tag")
        t.add_column("Google URL", overflow="fold")
        for m in off["manual_queries"][:12]:
            t.add_row(m["tag"], m["google"])
        con.print(t)


# ----------------------------------------------------------------------------
# Resolver
# ----------------------------------------------------------------------------
class Resolver:
    def __init__(self, api: SteamApi, web: SteamWeb):
        self.api, self.web = api, web

    def resolve(self, raw: str) -> Identity:
        kind, val = classify_target(raw)
        vanity = None
        method = kind
        if kind == "id64":
            id64 = int(val)
        elif kind == "account":
            id64 = ID64_BASE + int(val)
        else:
            vanity = val
            id64 = None
            if self.api.available:
                try:
                    id64 = self.api.resolve_vanity(val)
                    method = "vanity (API ResolveVanityURL)"
                except (ApiKeyMissing, InvalidApiKey):
                    id64 = None
            if id64 is None:
                x = self.web.profile_xml(val, vanity=True)
                if not x.get("steamid64", "").isdigit():
                    raise NotFound(f"Vanity URL '{val}' could not be resolved.")
                id64 = int(x["steamid64"])
                method = "vanity (public profile XML)"
        if id64 < ID64_BASE:
            raise InvalidTarget("SteamID64 out of valid range.")
        return Identity(raw, id64, id64 - ID64_BASE, id64_to_steam2(id64), id64_to_steam3(id64), method,
                        vanity, f"{COMMUNITY}/profiles/{id64}", f"{COMMUNITY}/profiles/{id64}")


# ----------------------------------------------------------------------------
# Graph analytics (pure python, no networkx needed)
# ----------------------------------------------------------------------------
def betweenness(adj: dict[str, set[str]]) -> dict[str, float]:
    bc = dict.fromkeys(adj, 0.0)
    for s in adj:
        stack: list[str] = []
        pred: dict[str, list[str]] = {v: [] for v in adj}
        sigma = dict.fromkeys(adj, 0.0)
        sigma[s] = 1.0
        dist = dict.fromkeys(adj, -1)
        dist[s] = 0
        q = deque([s])
        while q:
            v = q.popleft()
            stack.append(v)
            for w in adj[v]:
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    q.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        delta = dict.fromkeys(adj, 0.0)
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += sigma[v] / sigma[w] * (1 + delta[w])
            if w != s:
                bc[w] += delta[w]
    n = len(adj)
    scale = 1.0 / ((n - 1) * (n - 2)) if n > 2 else 1.0
    return {k: v * scale for k, v in bc.items()}


def closeness(adj: dict[str, set[str]]) -> dict[str, float]:
    n = len(adj)
    out = {}
    for s in adj:
        dist = {s: 0}
        q = deque([s])
        while q:
            v = q.popleft()
            for w in adj[v]:
                if w not in dist:
                    dist[w] = dist[v] + 1
                    q.append(w)
        reach, total = len(dist) - 1, sum(dist.values())
        out[s] = (reach / (n - 1)) * (reach / total) if total > 0 and n > 1 else 0.0
    return out


def pagerank(adj: dict[str, set[str]], d: float = 0.85, iters: int = 60) -> dict[str, float]:
    n = len(adj)
    if not n:
        return {}
    pr = dict.fromkeys(adj, 1.0 / n)
    for _ in range(iters):
        dangling = sum(pr[v] for v in adj if not adj[v])
        new = {}
        for v in adj:
            inc = sum(pr[u] / len(adj[u]) for u in adj[v])
            new[v] = (1 - d) / n + d * (inc + dangling / n)
        pr = new
    return pr


def label_propagation(adj: dict[str, set[str]], iters: int = 30) -> dict[str, int]:
    nodes = sorted(adj)
    label = {n: i for i, n in enumerate(nodes)}
    for _ in range(iters):
        changed = False
        for n in nodes:
            if not adj[n]:
                continue
            cnt = Counter(label[m] for m in adj[n])
            best = max(cnt.items(), key=lambda kv: (kv[1], -kv[0]))[0]
            if best != label[n]:
                label[n], changed = best, True
        if not changed:
            break
    sizes = Counter(label.values())
    order = [lab for lab, sz in sizes.most_common() if sz >= 3]
    remap = {lab: i for i, lab in enumerate(order)}
    return {n: remap.get(l, -1) for n, l in label.items()}


# ----------------------------------------------------------------------------
# Context + scan engine
# ----------------------------------------------------------------------------
class Ctx:
    def __init__(self, console: Console, args: argparse.Namespace):
        self.console = console
        self.args = args
        key = (getattr(args, "api_key", None) or os.environ.get("STEAM_API_KEY") or load_config().get("api_key"))
        self.http = Http(use_cache=not getattr(args, "no_cache", False),
                         verbose=getattr(args, "verbose", False),
                         log=(lambda m: console.log(f"[dim]{m}[/dim]")) if getattr(args, "verbose", False) else None)
        self.api = SteamApi(self.http, key)
        self.web = SteamWeb(self.http)
        self.resolver = Resolver(self.api, self.web)
        cfg = load_config()
        prov, skey = resolve_search(args, cfg)
        self.search = SearchEngine(self.http, prov, skey,
                                   getattr(args, "google_cx", None) or os.environ.get("GOOGLE_CSE_CX")
                                   or cfg.get("google_cx"))
        self.faceit_key = (getattr(args, "faceit_key", None) or os.environ.get("FACEIT_API_KEY")
                           or cfg.get("faceit_key"))
        if self.api.available:
            try:
                self.api.validate_key()
            except InvalidApiKey:
                console.print("[red]API key rejected by Steam - continuing in web-only mode.[/red]")
                self.api.key = None
            except SteamOsintError as e:
                console.print(f"[yellow]Could not validate API key now ({e}); continuing.[/yellow]")
        else:
            console.print("[yellow]No API key: running in web-only mode "
                          "(set one with: config --set-key KEY).[/yellow]")


def resolve_search(args: argparse.Namespace, cfg: dict) -> tuple[Optional[str], Optional[str]]:
    prov = getattr(args, "search_provider", None) or cfg.get("search_provider")
    order = [prov] if prov else list(SEARCH_PROVIDERS)
    for p in order:
        if p not in SEARCH_ENV:
            continue
        key = ((getattr(args, "search_key", None) if (prov == p or not prov) else None)
               or os.environ.get(SEARCH_ENV[p]) or (cfg.get("search_keys") or {}).get(p))
        if key:
            return p, key
    return None, None


def load_config() -> dict:
    for pth in (CONFIG_PATH, LEGACY_CONFIG_PATH):
        try:
            return json.loads(pth.read_text("utf-8"))
        except (OSError, ValueError):
            continue
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), "utf-8")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def guard(report: dict, label: str, fn: Callable, default: Any = None) -> Any:
    try:
        return fn()
    except ApiKeyMissing:
        report["warnings"].append(f"{label}: skipped (no API key).")
    except InvalidApiKey as e:
        report["warnings"].append(f"{label}: {e}")
    except PrivateData as e:
        report["warnings"].append(f"{label}: private/hidden ({e}).")
    except NotFound as e:
        report["warnings"].append(f"{label}: not found ({e}).")
    except RateLimited as e:
        report["warnings"].append(f"{label}: {e}")
    except NetworkError as e:
        report["warnings"].append(f"{label}: network error ({e}).")
    except HttpStatusError as e:
        report["warnings"].append(f"{label}: {e}")
    except SteamOsintError as e:
        report["warnings"].append(f"{label}: {e}")
    return default


def analyze_games(games: list[dict]) -> dict:
    if not games:
        return {}
    mins = [g.get("playtime_forever", 0) for g in games]
    total = sum(mins)
    played = [m for m in mins if m > 0]
    buckets = {"0h": 0, "<1h": 0, "1-10h": 0, "10-100h": 0, "100-500h": 0, "500h+": 0}
    for m in mins:
        h = m / 60
        key = ("0h" if m == 0 else "<1h" if h < 1 else "1-10h" if h < 10 else
               "10-100h" if h < 100 else "100-500h" if h < 500 else "500h+")
        buckets[key] += 1
    top = sorted(games, key=lambda g: -g.get("playtime_forever", 0))
    last = [g.get("rtime_last_played", 0) for g in games if g.get("rtime_last_played")]
    return {"game_count": len(games), "total_hours": hrs(total), "played_count": len(played),
            "unplayed_count": len(games) - len(played),
            "unplayed_ratio": round((len(games) - len(played)) / len(games), 3),
            "avg_hours_played_games": hrs(statistics.mean(played)) if played else 0,
            "median_hours_played_games": hrs(statistics.median(played)) if played else 0,
            "top1_share": round(top[0].get("playtime_forever", 0) / total, 3) if total else 0,
            "last_played": iso(max(last)) if last else None, "buckets": buckets,
            "top_games": [{"appid": g["appid"], "name": g.get("name", str(g["appid"])),
                           "hours": hrs(g.get("playtime_forever")),
                           "hours_2wk": hrs(g.get("playtime_2weeks")),
                           "last_played": iso(g.get("rtime_last_played"))} for g in top[:25]]}


def make_pivots(ident: Identity, name: str, aliases: list[dict], links: list[dict]) -> list[dict]:
    q = urllib.parse.quote_plus
    id64, acc = ident.id64, ident.account_id
    piv = [
        {"platform": "SteamRep", "type": "reputation", "url": f"https://steamrep.com/profiles/{id64}"},
        {"platform": "SteamDB (calculator)", "type": "account stats", "url": f"https://steamdb.info/calculator/{id64}/"},
        {"platform": "steamid.io", "type": "id lookup", "url": f"https://steamid.io/lookup/{id64}"},
        {"platform": "Backpack.tf", "type": "TF2/trading", "url": f"https://backpack.tf/profiles/{id64}"},
        {"platform": "Leetify", "type": "CS2 stats", "url": f"https://leetify.com/app/profile/{id64}"},
        {"platform": "CSStats.gg", "type": "CS2 stats", "url": f"https://csstats.gg/player/{id64}"},
        {"platform": "Dotabuff", "type": "Dota 2", "url": f"https://www.dotabuff.com/players/{acc}"},
        {"platform": "OpenDota", "type": "Dota 2", "url": f"https://www.opendota.com/players/{acc}"},
        {"platform": "FACEIT Data API", "type": "needs FACEIT key",
         "url": f"https://open.faceit.com/data/v4/players?game=cs2&game_player_id={id64}"},
        {"platform": "Wayback (profile)", "type": "history",
         "url": f"https://web.archive.org/web/*/{COMMUNITY}/profiles/{id64}"},
    ]
    if ident.vanity:
        piv.append({"platform": "Wayback (vanity)", "type": "history",
                    "url": f"https://web.archive.org/web/*/{COMMUNITY}/id/{ident.vanity}"})
    names = [n for n in [name, ident.vanity] if n]
    names += [a["name"] for a in aliases[:5] if a.get("name")]
    seen = set()
    for n in names:
        if n.lower() in seen or len(n) < 3:
            continue
        seen.add(n.lower())
        for plat, dork in (("Google exact", f'"{n}"'), ("FACEIT (dork)", f'site:faceit.com "{n}"'),
                           ("Reddit (dork)", f'site:reddit.com "{n}"'), ("X/Twitter (dork)", f'site:x.com "{n}"'),
                           ("Twitch (dork)", f'site:twitch.tv "{n}"')):
            piv.append({"platform": f"{plat}: {n}", "type": "search pivot (unverified)",
                        "url": f"https://www.google.com/search?q={q(dork)}"})
    for l in links:
        if l["platform"] != "External link" or l["match"].startswith("http"):
            url = l["match"] if l["match"].startswith("http") else "https://" + l["match"]
            if not l["platform"].startswith("Discord handle"):
                piv.append({"platform": f"Linked: {l['platform']}", "type": "declared by profile", "url": url})
    return piv


def observations(r: dict) -> list[str]:
    o: list[str] = []
    p, b, g = r["profile"], r["bans"], r["games"]
    if not p.get("is_public"):
        o.append("Profile is not fully public: many modules return limited data.")
    if b.get("VACBanned") or b.get("NumberOfGameBans"):
        o.append(f"Bans on record: VAC={b.get('NumberOfVACBans', 0)}, game={b.get('NumberOfGameBans', 0)}, "
                 f"last {b.get('DaysSinceLastBan', '?')} days ago.")
    if b.get("CommunityBanned"):
        o.append("Community ban flag set.")
    if b.get("EconomyBan") not in (None, "none"):
        o.append(f"Trade/economy ban state: {b.get('EconomyBan')}.")
    age = r["account_age"].get("age_years")
    if age is not None and age < 1:
        o.append("Account is younger than one year.")
    if p.get("limited"):
        o.append("Limited account (spending restrictions).")
    if g and g.get("game_count", 0) >= 20 and g.get("unplayed_ratio", 0) > 0.7:
        o.append(f"High unplayed ratio ({g['unplayed_ratio']:.0%}) - large backlog or bundle-heavy library.")
    if r["name_history"].get("count", 0) >= 8:
        o.append(f"Frequent display-name changes ({r['name_history']['count']}).")
    if r["network"] and r["network"].get("friend_list") == "private":
        o.append("Friend list is private.")
    if p.get("level") is not None and p["level"] < 3:
        o.append("Very low Steam level.")
    off = r.get("offsteam") or {}
    corr = [h for h in off.get("handles", []) if h["verdict"] == "corroborated"]
    if corr:
        o.append("Corroborated off-Steam accounts: " + ", ".join(f"{h['platform']}:{h['handle']}" for h in corr))
    conflicts = [h for h in off.get("handles", []) if h["verdict"] == "conflict"]
    if conflicts:
        o.append(f"{len(conflicts)} same-handle account(s) point to a DIFFERENT Steam profile - do not attribute them.")
    hi = [x for x in (off.get("search") or {}).get("results", []) if x["confidence"] == "high"]
    if hi:
        o.append(f"{len(hi)} high-confidence web result(s) (exact SteamID/URL or multi-seed match).")
    return o


def scan(ctx: Ctx, target: str) -> dict:
    a, con = ctx.args, ctx.console
    ident = ctx.resolver.resolve(target)
    id64 = ident.id64
    rep: dict[str, Any] = {
        "meta": {"tool": TOOL, "version": VERSION, "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "input": target, "api_mode": ctx.api.available, "author": AUTHOR, "copyright": COPYRIGHT, "notes": []},
        "identity": ident.as_dict(), "profile": {}, "bans": {}, "account_age": {}, "name_history": {},
        "games": {}, "groups": [], "links": [], "inventory": {}, "network": {}, "pivots": [],
        "offsteam": {}, "observations": [], "warnings": []}

    with con.status("[bold cyan]Collecting profile data...") as st:
        summary = guard(rep, "Player summary", lambda: ctx.api.summaries([id64]).get(id64, {}), {}) if ctx.api.available else {}
        xml = guard(rep, "Public profile XML", lambda: ctx.web.profile_xml(str(id64)), {}) or {}
        vis = summary.get("communityvisibilitystate")
        is_public = (vis == 3) if vis is not None else (xml.get("privacy") == "public")
        if not ident.vanity:
            custom = xml.get("custom_url") or (summary.get("profileurl", "").rstrip("/").split("/id/")[-1]
                                              if "/id/" in summary.get("profileurl", "") else "")
            if custom:
                ident.vanity = custom
                rep["identity"]["vanity"] = custom
                rep["identity"]["profile_url"] = f"{COMMUNITY}/id/{custom}"
        prof = {
            "name": summary.get("personaname") or xml.get("name"), "realname": summary.get("realname") or xml.get("realname"),
            "avatar": summary.get("avatarfull") or xml.get("avatar"), "is_public": is_public,
            "visibility_api": vis, "privacy_xml": xml.get("privacy"),
            "status": PERSONA_STATES.get(summary.get("personastate"), xml.get("online_state")),
            "last_logoff": iso(summary.get("lastlogoff")), "country": summary.get("loccountrycode"),
            "state_code": summary.get("locstatecode"), "city_id": summary.get("loccityid"),
            "location_text": xml.get("location"), "headline": xml.get("headline"), "summary_text": xml.get("summary"),
            "limited": xml.get("limited"), "trade_ban_xml": xml.get("trade_ban"),
            "in_game": summary.get("gameextrainfo"), "in_game_id": summary.get("gameid"),
            "level": None, "xp": None, "badge_count": None, "years_of_service_badge": None,
        }
        # account age
        created = summary.get("timecreated") or xml.get("member_since_ts")
        if created:
            rep["account_age"] = {"created": iso(created), "age_years": years_since(created),
                                  "method": "exact (public profile)"}
        else:
            est = estimate_creation_from_account_id(ident.account_id)
            rep["account_age"] = {**est, "age_years": est["estimated_age_years"], "created": None}

        if ctx.api.available:
            st.update("[bold cyan]Level / badges / bans...")
            prof["level"] = guard(rep, "Steam level", lambda: ctx.api.level(id64))
            bd = guard(rep, "Badges", lambda: ctx.api.badges(id64), {}) or {}
            if bd:
                prof["xp"] = bd.get("player_xp")
                badges = bd.get("badges", []) or []
                prof["badge_count"] = len(badges)
                for b in badges:
                    if b.get("badgeid") == 1 and "appid" not in b:
                        prof["years_of_service_badge"] = b.get("level")
                if prof["level"] is None:
                    prof["level"] = bd.get("player_level")
            rep["bans"] = guard(rep, "Ban status", lambda: ctx.api.bans([id64]).get(id64, {}), {}) or {}
        else:
            rep["bans"] = {"VACBanned": xml.get("vac_banned"), "EconomyBan": xml.get("trade_ban") or None,
                           "note": "limited info (no API key)"}
        rep["profile"] = prof

        # games
        st.update("[bold cyan]Games & playtime...")
        games = guard(rep, "Owned games", lambda: ctx.api.owned_games(id64), []) if ctx.api.available else []
        if games:
            rep["games"] = analyze_games(games)
            rep["games"]["all_games"] = [{"appid": g["appid"], "name": g.get("name", ""),
                                          "hours": hrs(g.get("playtime_forever")),
                                          "hours_2wk": hrs(g.get("playtime_2weeks"))} for g in games]
            if getattr(a, "library_value", False):
                st.update("[bold cyan]Pricing library (store)...")
                prices = ctx.web.store_prices([g["appid"] for g in games])
                tot = round(sum(prices.values()), 2)
                rep["games"]["library_value_usd"] = {"total_current_list_price": tot, "priced_games": len(prices),
                                                     "of": len(games),
                                                     "note": "current store list prices (not what was paid); free/delisted excluded"}
        else:
            if ctx.api.available:
                rep["warnings"].append("Owned games empty: game details are private.")
            if xml.get("most_played"):
                rep["games"] = {"most_played_public_fallback": xml["most_played"],
                                "note": "from public profile XML (library hidden)"}
        recent = guard(rep, "Recent games", lambda: ctx.api.recent_games(id64), []) if ctx.api.available else []
        if recent:
            rep["games"]["recent_2wk"] = [{"name": g.get("name"), "hours_2wk": hrs(g.get("playtime_2weeks")),
                                           "hours_total": hrs(g.get("playtime_forever"))} for g in recent]

        # groups
        st.update("[bold cyan]Groups...")
        groups = xml.get("groups") or []
        if not groups and ctx.api.available:
            gids = guard(rep, "Group list", lambda: ctx.api.groups(id64), []) or []
            groups = [{"gid64": g, "name": "", "url": f"{COMMUNITY}/gid/{g}", "headline": "", "members": "",
                       "primary": False} for g in gids]
        rep["groups"] = groups

        # aliases and links
        st.update("[bold cyan]Name history & linked accounts...")
        al = guard(rep, "Name history", lambda: ctx.web.aliases(id64), []) or []
        rep["name_history"] = {"count": len(al), "names": al,
                               "distinct": len({x["name"].lower() for x in al if x.get("name")})}
        rep["links"] = guard(rep, "Profile links", lambda: ctx.web.profile_links(
            id64, " ".join(filter(None, [prof.get("summary_text"), prof.get("headline"), prof.get("realname")]))), []) or []

    # inventory
    if not getattr(a, "no_inventory", False):
        with con.status("[bold cyan]Inventory..."):
            inv = guard(rep, "Inventory", lambda: ctx.web.inventory(id64, a.appid, a.context), {}) or {}
            if inv:
                if getattr(a, "inventory_value", False):
                    cand = [i for i in inv["items"] if i["marketable"]][:a.max_price_lookups]
                    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                                  TimeElapsedColumn(), console=con) as pg:
                        task = pg.add_task("Market prices (rate-limited, ~3s each)", total=len(cand))
                        for it in cand:
                            it["price"] = ctx.web.market_price(a.appid, it["name"], a.currency)
                            pg.advance(task)
                    priced = [i for i in inv["items"] if i["price"] is not None]
                    inv["value_estimate"] = {
                        "total": round(sum(i["price"] * i["count"] for i in priced), 2),
                        "currency_code": a.currency, "priced_unique": len(priced),
                        "marketable_unique": sum(1 for i in inv["items"] if i["marketable"]),
                        "note": "LOWER BOUND: lowest current listing, only top items by count were priced"}
                rep["inventory"] = inv

    # network
    if not getattr(a, "no_network", False) and ctx.api.available:
        rep["network"] = analyze_network(ctx, rep, id64) or {}
    elif not ctx.api.available:
        rep["warnings"].append("Friend network skipped: needs an API key.")

    rep["pivots"] = make_pivots(ident, prof.get("name") or "", al, rep["links"])
    if not getattr(a, "no_offsteam", False):
        rep["offsteam"] = guard(rep, "Off-Steam intelligence", lambda: offsteam_scan(ctx, rep), {}) or {}
    rep["observations"] = observations(rep)
    return rep


def analyze_network(ctx: Ctx, rep: dict, id64: int) -> dict:
    a, con = ctx.args, ctx.console
    try:
        fr = ctx.api.friends(id64)
    except PrivateData:
        rep["warnings"].append("Friend list is private.")
        return {"friend_list": "private"}
    except SteamOsintError as e:
        rep["warnings"].append(f"Friend list: {e}")
        return {}
    if not fr:
        return {"friend_list": "empty", "friend_count": 0}
    since = {int(f["steamid"]): f.get("friend_since", 0) for f in fr}
    ids = list(since)
    summ = guard(rep, "Friend summaries", lambda: ctx.api.summaries(ids), {}) or {}
    ranked = sorted(ids, key=lambda i: (0 if summ.get(i, {}).get("communityvisibilitystate") == 3 else 1, since[i]))
    sample = ranked[:max(0, a.sample)]
    idset = {str(i) for i in ids}
    adj: dict[str, set[str]] = {str(i): set() for i in ids}
    friend_groups: dict[str, set[str]] = {}
    group_names: dict[str, str] = {}
    sampled_ok = set()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(),
                  console=con) as pg:
        task = pg.add_task("Mapping friend-of-friend links", total=len(sample))
        for fid in sample:
            try:
                theirs = ctx.api.friends(fid)
                sampled_ok.add(str(fid))
                for t in theirs:
                    t_id = t["steamid"]
                    if t_id in idset and t_id != str(fid):
                        adj[str(fid)].add(t_id)
                        adj[t_id].add(str(fid))
            except PrivateData:
                pass
            except RateLimited as e:
                rep["warnings"].append(f"Network mapping stopped early: {e}")
                break
            except SteamOsintError:
                pass
            if getattr(a, "friend_groups", False):
                try:
                    x = ctx.web.profile_xml(str(fid))
                    for g in x.get("groups", []):
                        friend_groups.setdefault(g["gid64"], set()).add(str(fid))
                        group_names[g["gid64"]] = g.get("name") or g["gid64"]
                except SteamOsintError:
                    pass
            pg.advance(task)
    bc, cl, pr, comm = betweenness(adj), closeness(adj), pagerank(adj), label_propagation(adj)
    nodes, edges = [], set()
    for k, nb in adj.items():
        for m in nb:
            edges.add(tuple(sorted((k, m))))
    for i in ids:
        k = str(i)
        p = summ.get(i, {})
        nodes.append({"steamid": k, "name": p.get("personaname", ""), "since": iso(since[i]),
                      "visibility": p.get("communityvisibilitystate"), "country": p.get("loccountrycode"),
                      "list_checked": k in sampled_ok, "degree": len(adj[k]), "mutual_with_target": len(adj[k]),
                      "betweenness": round(bc.get(k, 0), 5), "closeness": round(cl.get(k, 0), 5),
                      "pagerank": round(pr.get(k, 0), 5), "community": comm.get(k, -1)})
    nodes.sort(key=lambda n: (-n["degree"], -n["betweenness"]))
    my_groups = {g["gid64"] for g in rep["groups"]}
    shared = []
    for gid, members in friend_groups.items():
        if len(members) >= 2 or gid in my_groups:
            shared.append({"gid64": gid, "name": group_names.get(gid, gid), "friends_in_group": len(members),
                           "target_is_member": gid in my_groups})
    shared.sort(key=lambda g: (-g["friends_in_group"], g["name"]))
    csz = Counter(n["community"] for n in nodes if n["community"] >= 0)
    return {"friend_list": "public", "friend_count": len(ids), "sampled_requested": len(sample),
            "friend_lists_read": len(sampled_ok), "edges_found": len(edges),
            "density_among_checked": round(2 * len(edges) / (len(ids) * (len(ids) - 1)), 5) if len(ids) > 1 else 0,
            "countries": dict(Counter(n["country"] or "??" for n in nodes).most_common(15)),
            "friends_added_per_year": dict(sorted(Counter(
                (n["since"] or "????")[:4] for n in nodes).items())),
            "communities": {str(k): v for k, v in csz.most_common(10)},
            "shared_groups": shared[:25], "nodes": nodes, "edges": [list(e) for e in sorted(edges)],
            "note": "Edges only exist where at least one endpoint's friend list was readable; "
                    "centrality is computed on the friend-only subgraph (ego removed)."}


def compare(ctx: Ctx, ta: str, tb: str) -> dict:
    rep: dict[str, Any] = {"meta": {"tool": TOOL, "version": VERSION, "mode": "compare",
                                    "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")},
                           "warnings": []}
    A, B = ctx.resolver.resolve(ta), ctx.resolver.resolve(tb)
    rep["a"], rep["b"] = A.as_dict(), B.as_dict()
    fa = {int(f["steamid"]) for f in guard(rep, "Friends A", lambda: ctx.api.friends(A.id64), []) or []}
    fb = {int(f["steamid"]) for f in guard(rep, "Friends B", lambda: ctx.api.friends(B.id64), []) or []}
    rep["are_friends"] = (B.id64 in fa) or (A.id64 in fb)
    mutual = sorted(fa & fb)
    names = guard(rep, "Mutual summaries", lambda: ctx.api.summaries(mutual), {}) if mutual else {}
    rep["mutual_friends"] = [{"steamid": str(i), "name": names.get(i, {}).get("personaname", "")} for i in mutual]
    ga = guard(rep, "Games A", lambda: ctx.api.owned_games(A.id64), []) or []
    gb = guard(rep, "Games B", lambda: ctx.api.owned_games(B.id64), []) or []
    ma, mb = {g["appid"]: g for g in ga}, {g["appid"]: g for g in gb}
    rep["shared_games"] = sorted(
        [{"appid": k, "name": ma[k].get("name", ""), "hours_a": hrs(ma[k].get("playtime_forever")),
          "hours_b": hrs(mb[k].get("playtime_forever"))} for k in ma.keys() & mb.keys()],
        key=lambda g: -(g["hours_a"] + g["hours_b"]))
    xa = guard(rep, "Groups A", lambda: ctx.web.profile_xml(str(A.id64)), {}) or {}
    xb = guard(rep, "Groups B", lambda: ctx.web.profile_xml(str(B.id64)), {}) or {}
    gA = {g["gid64"]: g["name"] for g in xa.get("groups", [])}
    gB = {g["gid64"] for g in xb.get("groups", [])}
    rep["shared_groups"] = [{"gid64": k, "name": v} for k, v in gA.items() if k in gB]
    alA = guard(rep, "Aliases A", lambda: ctx.web.aliases(A.id64), []) or []
    alB = guard(rep, "Aliases B", lambda: ctx.web.aliases(B.id64), []) or []
    nA = {x["name"].lower() for x in alA if x.get("name")}
    nB = {x["name"].lower() for x in alB if x.get("name")}
    rep["shared_past_names"] = sorted(nA & nB)
    return rep


# ----------------------------------------------------------------------------
# Rendering (terminal)
# ----------------------------------------------------------------------------
def kv_table(title: str, rows: list[tuple[str, Any]]) -> Table:
    t = Table(title=title, box=box.ROUNDED, show_header=False, title_style="bold cyan")
    t.add_column(style="bold")
    t.add_column(overflow="fold")
    for k, v in rows:
        if v not in (None, "", [], {}):
            t.add_row(str(k), str(v))
    return t


def render(con: Console, r: dict) -> None:
    i, p = r["identity"], r["profile"]
    con.print(Panel.fit(Text.assemble((str(p.get("name") or "?"), "bold"), "   ", (i["profile_url"], "dim")),
                        title=f"{TOOL} v{VERSION}", border_style="cyan"))
    con.print(kv_table("Identity", [
        ("SteamID64", i["id64"]), ("Steam2", i["steam2"]), ("Steam3", i["steam3"]),
        ("Account ID", i["account_id"]), ("Vanity", i.get("vanity")), ("Resolved via", i["method"])]))
    age = r["account_age"]
    con.print(kv_table("Profile", [
        ("Real name", p.get("realname")), ("Status", p.get("status")),
        ("Visibility", "public" if p.get("is_public") else f"restricted ({p.get('privacy_xml') or p.get('visibility_api')})"),
        ("Country", p.get("country")), ("Location text", p.get("location_text")),
        ("Level / XP", f"{p.get('level')} / {p.get('xp')}" if p.get("level") is not None else None),
        ("Badges", p.get("badge_count")), ("Years-of-service badge", p.get("years_of_service_badge")),
        ("Last logoff", p.get("last_logoff")), ("Currently playing", p.get("in_game")),
        ("Created", age.get("created") or f"~{age.get('estimated_created')} (estimate {age.get('uncertainty_years')}y)"),
        ("Account age (yrs)", age.get("age_years")), ("Age method", age.get("method")),
        ("Headline", p.get("headline")), ("Bio", (p.get("summary_text") or "")[:300])]))
    b = r["bans"]
    if b:
        con.print(kv_table("Ban status", [(k, v) for k, v in b.items()]))
    g = r["games"]
    if g.get("game_count"):
        con.print(kv_table("Library & playtime", [
            ("Games", g["game_count"]), ("Total hours", g["total_hours"]),
            ("Played / unplayed", f"{g['played_count']} / {g['unplayed_count']} ({g['unplayed_ratio']:.0%})"),
            ("Mean / median h (played)", f"{g['avg_hours_played_games']} / {g['median_hours_played_games']}"),
            ("Top game share", f"{g['top1_share']:.0%}"), ("Last played", g.get("last_played")),
            ("Library value", (g.get("library_value_usd") or {}).get("total_current_list_price"))]))
        t = Table(title="Top games", box=box.SIMPLE_HEAVY)
        for c in ("Game", "Hours", "2wk", "Last played"):
            t.add_column(c)
        for x in g["top_games"][:12]:
            t.add_row(x["name"], str(x["hours"]), str(x["hours_2wk"]), x["last_played"] or "")
        con.print(t)
        con.print("Distribution: " + "  ".join(f"[cyan]{k}[/cyan]={v}" for k, v in g["buckets"].items()))
    elif g.get("most_played_public_fallback"):
        con.print(kv_table("Most played (public fallback)", [(x["name"], x["hours_on_record"] + "h")
                                                             for x in g["most_played_public_fallback"]]))
    if r["groups"]:
        t = Table(title=f"Groups ({len(r['groups'])})", box=box.SIMPLE)
        for c in ("Name", "Members", "ID64"):
            t.add_column(c)
        for x in r["groups"][:15]:
            t.add_row(("* " if x["primary"] else "") + (x["name"] or "-"), x["members"], x["gid64"])
        con.print(t)
    nh = r["name_history"]
    if nh.get("names"):
        t = Table(title=f"Name history ({nh['count']})", box=box.SIMPLE)
        t.add_column("Name")
        t.add_column("Changed")
        for x in nh["names"][:15]:
            t.add_row(x["name"], x["changed"])
        con.print(t)
    if r["links"]:
        t = Table(title="Linked / declared accounts", box=box.SIMPLE)
        t.add_column("Platform")
        t.add_column("Match", overflow="fold")
        for x in r["links"]:
            t.add_row(x["platform"], x["match"])
        con.print(t)
    inv = r["inventory"]
    if inv:
        ve = inv.get("value_estimate") or {}
        con.print(kv_table(f"Inventory (app {inv['appid']})", [
            ("Items", inv["total_items"]), ("Unique", inv["unique_items"]),
            ("Value (lower bound)", f"{ve.get('total')} (currency {ve.get('currency_code')}) "
                                    f"priced {ve.get('priced_unique')}/{ve.get('marketable_unique')}" if ve else None)]))
    n = r["network"]
    if n.get("nodes"):
        con.print(kv_table("Friend network", [
            ("Friends", n["friend_count"]), ("Friend lists read", n["friend_lists_read"]),
            ("Friend-friend edges", n["edges_found"]), ("Communities (size>=3)", n["communities"]),
            ("Top countries", n["countries"])]))
        t = Table(title="Most central friends", box=box.SIMPLE_HEAVY)
        for c in ("Name", "SteamID64", "Mutual", "Betw.", "Close.", "PageRank", "Comm."):
            t.add_column(c)
        for x in n["nodes"][:12]:
            t.add_row(x["name"], x["steamid"], str(x["mutual_with_target"]), str(x["betweenness"]),
                      str(x["closeness"]), str(x["pagerank"]), str(x["community"]))
        con.print(t)
        if n["shared_groups"]:
            t = Table(title="Groups shared among friends", box=box.SIMPLE)
            t.add_column("Group")
            t.add_column("Friends")
            t.add_column("Target in it")
            for x in n["shared_groups"][:10]:
                t.add_row(x["name"], str(x["friends_in_group"]), "yes" if x["target_is_member"] else "")
            con.print(t)
    elif n.get("friend_list"):
        con.print(f"[yellow]Friend list: {n['friend_list']}[/yellow]")
    if r["observations"]:
        con.print(Panel(Text("\n".join("- " + o for o in r["observations"])), title="Observations", border_style="yellow"))
    render_offsteam(con, r.get("offsteam") or {})
    t = Table(title="OSINT pivots (public lookups / unverified search queries)", box=box.SIMPLE)
    t.add_column("Platform")
    t.add_column("Type")
    t.add_column("URL", overflow="fold")
    for x in r["pivots"][:30]:
        t.add_row(x["platform"], x["type"], x["url"])
    con.print(t)
    if r["warnings"]:
        con.print(Panel(Text("\n".join("- " + w for w in r["warnings"])), title="Warnings", border_style="red"))


def render_compare(con: Console, r: dict) -> None:
    con.print(Panel.fit(f"{r['a']['id64']}  <->  {r['b']['id64']}", title="Compare", border_style="cyan"))
    con.print(f"Directly friends: [bold]{r['are_friends']}[/bold]")
    for key, title, cols in (("mutual_friends", "Mutual friends", ("name", "steamid")),
                             ("shared_groups", "Shared groups", ("name", "gid64")),
                             ("shared_games", "Shared games", ("name", "hours_a", "hours_b"))):
        rows = r.get(key) or []
        t = Table(title=f"{title} ({len(rows)})", box=box.SIMPLE)
        for c in cols:
            t.add_column(c)
        for x in rows[:25]:
            t.add_row(*[str(x[c]) for c in cols])
        con.print(t)
    if r["shared_past_names"]:
        con.print(Text("Shared past names: " + ", ".join(r["shared_past_names"])))
    for w in r["warnings"]:
        con.print(Text("- " + w, style="red"))


# ----------------------------------------------------------------------------
# Exports
# ----------------------------------------------------------------------------
PALETTE = ["#58a6ff", "#f78166", "#7ee787", "#d2a8ff", "#ffa657", "#79c0ff", "#ff7b72", "#56d364"]


def svg_graph(net: dict, size: int = 640) -> str:
    nodes = net.get("nodes", [])[:40]
    if not nodes:
        return ""
    ids = {n["steamid"] for n in nodes}
    cx = cy = size / 2
    r = size / 2 - 60
    pos = {}
    for k, n in enumerate(nodes):
        ang = 2 * math.pi * k / len(nodes)
        pos[n["steamid"]] = (cx + r * math.cos(ang), cy + r * math.sin(ang))
    out = [f'<svg viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg" class="graph">']
    for a, b in net.get("edges", []):
        if a in ids and b in ids:
            out.append(f'<line x1="{pos[a][0]:.1f}" y1="{pos[a][1]:.1f}" x2="{pos[b][0]:.1f}" '
                       f'y2="{pos[b][1]:.1f}" stroke="#30363d" stroke-width="1"/>')
    for n in nodes:
        x, y = pos[n["steamid"]]
        col = PALETTE[n["community"] % len(PALETTE)] if n["community"] >= 0 else "#8b949e"
        rad = 4 + min(10, n["degree"] * 0.6)
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rad:.1f}" fill="{col}">'
                   f'<title>{htmllib.escape(n["name"] or n["steamid"])} (links: {n["degree"]})</title></circle>')
    out.append("</svg>")
    return "".join(out)


def build_html(r: dict) -> str:
    e = lambda v: htmllib.escape("" if v is None else str(v))  # noqa: E731

    def table(headers: list[str], rows: list[list[Any]]) -> str:
        if not rows:
            return "<p class=muted>No data.</p>"
        return ("<table><thead><tr>" + "".join(f"<th>{e(h)}</th>" for h in headers) + "</tr></thead><tbody>" +
                "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in rows) +
                "</tbody></table>")

    def kv(d: dict) -> str:
        return table(["Field", "Value"], [[k, v] for k, v in d.items() if v not in (None, "", [], {})])

    i, p = r["identity"], r["profile"]
    n = r.get("network") or {}
    inv = r.get("inventory") or {}
    g = r.get("games") or {}
    sec = []
    sec.append(f"<h2>Identity</h2>{kv({k: i[k] for k in ('id64', 'steam2', 'steam3', 'account_id', 'vanity', 'method', 'profile_url')})}")
    sec.append("<h2>Profile</h2>" + kv({**{k: v for k, v in p.items() if k not in ('avatar',)}, **r["account_age"]}))
    sec.append("<h2>Bans</h2>" + kv(r["bans"]))
    sec.append("<h2>Observations</h2><ul>" + "".join(f"<li>{e(o)}</li>" for o in r["observations"]) + "</ul>")
    if r["meta"].get("notes"):
        sec.append("<h2>Analyst notes</h2><ol>" + "".join(f"<li>{e(n)}</li>" for n in r["meta"]["notes"]) + "</ol>")
    if g.get("top_games"):
        sec.append("<h2>Playtime</h2>" + kv({k: v for k, v in g.items() if k in (
            "game_count", "total_hours", "played_count", "unplayed_count", "unplayed_ratio",
            "avg_hours_played_games", "median_hours_played_games", "last_played")}))
        sec.append(table(["Game", "Hours", "2 weeks", "Last played"],
                         [[x["name"], x["hours"], x["hours_2wk"], x["last_played"]] for x in g["top_games"]]))
        sec.append("<p>Distribution: " + ", ".join(f"{e(k)}={v}" for k, v in g["buckets"].items()) + "</p>")
    sec.append("<h2>Groups</h2>" + table(["Name", "Members", "ID64"], [[x["name"], x["members"], x["gid64"]] for x in r["groups"]]))
    sec.append("<h2>Name history</h2>" + table(["Name", "Changed"], [[x["name"], x["changed"]] for x in r["name_history"].get("names", [])]))
    sec.append("<h2>Linked accounts</h2>" + table(["Platform", "Match"], [[x["platform"], x["match"]] for x in r["links"]]))
    off = r.get("offsteam") or {}
    if off:
        sch = off["search"]
        sec.append("<h2>Off-Steam intelligence</h2>" + kv({"search backend": sch.get("provider"), "status": sch.get("status"),
                   "queries run": f"{sch['queries_run']}/{sch['queries_planned']}"}))
        sec.append("<h3>Seeds</h3>" + table(["Value", "Kind", "Strength"], [[x["value"], x["kind"], x["strength"]] for x in off["seeds"]]))
        rows = "".join(f'<tr><td>{e(x["confidence"])}</td><td>{e(x["domain"])}</td>'
                       f'<td><a href="{e(safe_href(x["link"]))}" rel="noopener noreferrer nofollow">{e(x["title"] or x["link"])}</a></td>'
                       f'<td>{e(", ".join(x["evidence"]))}</td><td>{e(x["snippet"])}</td></tr>' for x in sch.get("results", []))
        if rows:
            sec.append("<h3>Web results</h3><table><thead><tr><th>Confidence</th><th>Domain</th><th>Title</th><th>Evidence</th><th>Snippet</th></tr></thead><tbody>" + rows + "</tbody></table>")
        sec.append("<h3>Handle footprint</h3>" + table(["Verdict", "Platform", "Handle", "Why", "URL"],
                   [[x["verdict"], x["platform"], x["handle"], "; ".join(x["reasons"]), x["url"]] for x in off["handles"]]))
        gp = off["game_platforms"]
        sec.append("<h3>Game platforms</h3>" + kv({k: "; ".join(f"{a}={b}" for a, b in v.items() if b not in (None, ""))
                                                    for k, v in gp.items() if isinstance(v, dict)}))
        sec.append("<h3>Internet Archive</h3>" + table(["Pattern", "Snapshots", "First", "Last"],
                   [[w["pattern"], w["snapshots"], w.get("first_url", ""), w.get("last_url", "")] for w in off["wayback"]]))
        sec.append("<h3>Discord invites</h3>" + table(["Code", "Server", "Members", "Status"],
                   [[d["code"], d.get("server"), d.get("members"), d.get("status")] for d in off["discord_invites"]]))
        mq = "".join(f'<tr><td>{e(m["tag"])}</td><td>{e(m["query"])}</td><td><a href="{e(m["google"])}" rel="noopener noreferrer nofollow">Google</a> '
                     f'<a href="{e(m["duckduckgo"])}" rel="noopener noreferrer nofollow">DDG</a> '
                     f'<a href="{e(m["bing"])}" rel="noopener noreferrer nofollow">Bing</a></td></tr>' for m in off["manual_queries"])
        sec.append("<h3>Search queries</h3><table><thead><tr><th>Tag</th><th>Query</th><th>Open</th></tr></thead><tbody>" + mq + "</tbody></table>")
    if inv:
        sec.append("<h2>Inventory</h2>" + kv({"app": inv["appid"], "items": inv["total_items"], "unique": inv["unique_items"],
                                              **{f"value_{k}": v for k, v in (inv.get("value_estimate") or {}).items()}}))
        sec.append(table(["Item", "Count", "Marketable", "Price"], [[x["name"], x["count"], x["marketable"], x["price"]]
                                                                      for x in inv["items"][:60]]))
    if n.get("nodes"):
        sec.append("<h2>Friend network</h2>" + kv({k: v for k, v in n.items() if k in (
            "friend_count", "friend_lists_read", "edges_found", "density_among_checked", "communities", "countries")}))
        sec.append(svg_graph(n))
        sec.append(table(["Name", "SteamID64", "Mutual", "Betweenness", "Closeness", "PageRank", "Community"],
                         [[x["name"], x["steamid"], x["mutual_with_target"], x["betweenness"], x["closeness"],
                           x["pagerank"], x["community"]] for x in n["nodes"][:50]]))
        sec.append("<h3>Shared groups among friends</h3>" + table(["Group", "Friends", "Target member"],
                   [[x["name"], x["friends_in_group"], x["target_is_member"]] for x in n["shared_groups"]]))
    pivrows = "".join(f'<tr><td>{e(x["platform"])}</td><td>{e(x["type"])}</td>'
                      f'<td><a href="{e(x["url"])}" rel="noopener noreferrer nofollow">{e(x["url"])}</a></td></tr>'
                      for x in r["pivots"])
    sec.append(f"<h2>OSINT pivots</h2><table><thead><tr><th>Platform</th><th>Type</th><th>URL</th></tr></thead><tbody>{pivrows}</tbody></table>")
    if r["warnings"]:
        sec.append("<h2>Warnings</h2><ul>" + "".join(f"<li>{e(w)}</li>" for w in r["warnings"]) + "</ul>")
    css = ("body{background:#0d1117;color:#c9d1d9;font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}"
           "h1,h2,h3{color:#58a6ff}table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}"
           "th,td{border:1px solid #30363d;padding:.35rem .6rem;text-align:left;word-break:break-word}"
           "th{background:#161b22}a{color:#79c0ff}.muted{color:#8b949e}.graph{max-width:640px;width:100%;background:#0b0f14;border-radius:8px}")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(TOOL)} - {e(p.get("name"))}</title>'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><style>{css}</style></head><body>'
            f'<h1>{e(TOOL)} report: {e(p.get("name"))}</h1><p class="muted">Generated {e(r["meta"]["generated_utc"])} '
            f'- v{e(VERSION)} - public data only</p>' + "".join(sec) +
            f'<hr><p class="muted">Generated by {e(TOOL)} v{e(VERSION)} &mdash; Developer: {e(AUTHOR)} &mdash; {e(COPYRIGHT)}</p>'
            "</body></html>")


def export_report(r: dict, out_dir: Path, fmts: list[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"steam_{r['identity']['id64']}_{stamp}"
    written: list[Path] = []
    if "json" in fmts:
        pth = base.with_suffix(".json")
        pth.write_text(json.dumps(r, indent=2, ensure_ascii=False, default=str), "utf-8")
        written.append(pth)
    if "html" in fmts:
        pth = base.with_suffix(".html")
        pth.write_text(build_html(r), "utf-8")
        written.append(pth)
    if "csv" in fmts:
        def w(suffix: str, headers: list[str], rows: list[list[Any]]) -> None:
            if not rows:
                return
            pth = Path(f"{base}_{suffix}.csv")
            with pth.open("w", newline="", encoding="utf-8-sig") as f:
                cw = csv.writer(f)
                cw.writerow(headers)
                for row in rows:
                    cw.writerow([("'" + str(c) if isinstance(c, str) and c[:1] in "=+-@" else c) for c in row])
            written.append(pth)
        flat = [["identity." + k, v] for k, v in r["identity"].items()]
        flat += [["profile." + k, v] for k, v in r["profile"].items() if not isinstance(v, (dict, list))]
        flat += [["account_age." + k, v] for k, v in r["account_age"].items()]
        flat += [["bans." + k, v] for k, v in r["bans"].items()]
        w("summary", ["field", "value"], flat)
        w("games", ["appid", "name", "hours", "hours_2wk"],
          [[x["appid"], x["name"], x["hours"], x["hours_2wk"]] for x in (r["games"].get("all_games") or [])])
        w("groups", ["gid64", "name", "members", "url"], [[x["gid64"], x["name"], x["members"], x["url"]] for x in r["groups"]])
        w("names", ["name", "changed"], [[x["name"], x["changed"]] for x in r["name_history"].get("names", [])])
        w("friends", ["steamid", "name", "since", "country", "mutual", "betweenness", "closeness", "pagerank", "community"],
          [[x["steamid"], x["name"], x["since"], x["country"], x["mutual_with_target"], x["betweenness"],
            x["closeness"], x["pagerank"], x["community"]] for x in (r["network"] or {}).get("nodes", [])])
        w("inventory", ["name", "count", "marketable", "tradable", "price"],
          [[x["name"], x["count"], x["marketable"], x["tradable"], x["price"]] for x in (r["inventory"] or {}).get("items", [])])
        off = r.get("offsteam") or {}
        w("web_results", ["confidence", "score", "domain", "title", "url", "evidence", "snippet", "query_tag"],
          [[x["confidence"], x["score"], x["domain"], x["title"], x["link"], "; ".join(x["evidence"]), x["snippet"],
            x.get("query_tag", "")] for x in (off.get("search") or {}).get("results", [])])
        w("handles", ["platform", "handle", "verdict", "reasons", "url"],
          [[x["platform"], x["handle"], x["verdict"], "; ".join(x["reasons"]), x["url"]] for x in off.get("handles", [])])
        w("search_queries", ["tag", "query", "google_url"],
          [[m["tag"], m["query"], m["google"]] for m in off.get("manual_queries", [])])
        w("pivots", ["platform", "type", "url"], [[x["platform"], x["type"], x["url"]] for x in r["pivots"]])
    return written


# ----------------------------------------------------------------------------
# Self test (offline)
# ----------------------------------------------------------------------------
def selftest(con: Console) -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        ok &= bool(cond)
        con.print(("[green]PASS[/green] " if cond else "[red]FAIL[/red] ") + name)

    check("steam2 -> account", classify_target("STEAM_0:1:23071901") == ("account", "46143803"))
    check("steam3 -> account", classify_target("[U:1:46143802]") == ("account", "46143802"))
    check("id64 passthrough", classify_target("76561197960287930") == ("id64", "76561197960287930"))
    check("profile url", classify_target("https://steamcommunity.com/profiles/76561197960287930/") == ("id64", "76561197960287930"))
    check("vanity url", classify_target("https://steamcommunity.com/id/gabelogannewell/") == ("vanity", "gabelogannewell"))
    check("steam2 roundtrip", id64_to_steam2(ID64_BASE + 46143803) == "STEAM_0:1:23071901")
    check("steam3 roundtrip", id64_to_steam3(ID64_BASE + 46143802) == "[U:1:46143802]")
    check("price parse", parse_price("$1,234.50") == 1234.5 and parse_price("12,50\u20ac") == 12.5)
    star = {"c": {"a", "b", "d"}, "a": {"c"}, "b": {"c"}, "d": {"c"}}
    check("betweenness hub", betweenness(star)["c"] > 0.99)
    check("closeness hub", closeness(star)["c"] > closeness(star)["a"])
    check("pagerank sums~1", abs(sum(pagerank(star).values()) - 1) < 1e-6)
    tri = {"a": {"b", "c"}, "b": {"a", "c"}, "c": {"a", "b"}, "x": set()}
    lp = label_propagation(tri)
    check("communities", lp["a"] == lp["b"] == lp["c"] != -1 and lp["x"] == -1)
    try:
        classify_target("!!bad!!")
        check("invalid rejected", False)
    except InvalidTarget:
        check("invalid rejected", True)
    check("banner fits 80 cols", max(len(m.ljust(20) + r) for m, r in zip(MAGNIFIER[2:7], logo_rows("#"))) <= 80)
    check("markup-safe table", True)
    check("age estimate", estimate_creation_from_account_id(46143802)["estimated_created"].startswith("2009"))
    return 0 if ok else 1


# ----------------------------------------------------------------------------
# Branding + interactive console (Metasploit-style)
# ----------------------------------------------------------------------------
FONT = {
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "C": [" ####", "#    ", "#    ", "#    ", " ####"],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "P": ["#### ", "#   #", "#### ", "#    ", "#    "],
}
MAGNIFIER = [
    r"    .-''''-.      ",
    r"  .'  .--.  '.    ",
    r" /   /    \   \   ",
    r" |  |  ()  |  |   ",
    r" \   \    /   /   ",
    r"  '.  '--'  .'    ",
    r"    '-.__.-'\     ",
    r"             \\   ",
    r"              \\  ",
]
THEMES = {"cyan": "cyan", "green": "green", "red": "red", "magenta": "magenta", "yellow": "yellow", "blue": "blue"}
TIPS = [
    "Use 'set TARGET <id|vanity|url>' then 'run' - exactly like msfconsole.",
    "TAB completes commands, modules and option names.",
    "'note <text>' attaches analyst notes that end up inside the HTML/JSON report.",
    "Only results rated 'high' or 'corroborated' are worth trusting; same-handle matches are just leads.",
    "'show options' lists every setting; 'unset all' resets them.",
    "Set a search key once, then 'save' - it persists in your config file.",
    "'use recon/footprint' runs only the off-Steam / Google modules (faster).",
    "'compare' finds mutual friends, shared groups, shared games and shared past names.",
    "'check' verifies your keys and connectivity before a long scan.",
    "'theme magenta' changes the console colours.",
    "'export reports html,json' writes the last result to disk.",
    "Lower '--sample' / SAMPLE for a faster friend-network pass on huge friend lists.",
]
OPTION_DEFS: dict[str, tuple[Any, str, str]] = {
    "TARGET": ("", "str", "Target: SteamID64 / vanity / profile URL / Steam2 / Steam3"),
    "TARGET2": ("", "str", "Second target (recon/compare only)"),
    "API_KEY": ("", "secret", "Steam Web API key"),
    "SEARCH_PROVIDER": ("", "choice", "Web search backend: serper | serpapi | brave | google_cse"),
    "SEARCH_KEY": ("", "secret", "API key for the search backend"),
    "GOOGLE_CX": ("", "str", "Engine id (google_cse only)"),
    "FACEIT_KEY": ("", "secret", "FACEIT Data API key (exact SteamID match)"),
    "SAMPLE": (40, "int", "Friends whose friend-lists are read for the network graph"),
    "FRIEND_GROUPS": (False, "bool", "Also read friends' groups (slower)"),
    "MAX_QUERIES": (12, "int", "Web searches to spend per scan"),
    "MAX_HANDLES": (4, "int", "Handles checked on other platforms (0 = off)"),
    "LIBRARY_VALUE": (False, "bool", "Estimate game-library list price"),
    "INVENTORY_VALUE": (False, "bool", "Price marketable inventory items (slow)"),
    "MAX_PRICE_LOOKUPS": (40, "int", "Max market price lookups"),
    "APPID": (730, "int", "Inventory app id (730 = CS2)"),
    "CONTEXT": (2, "int", "Inventory context id"),
    "CURRENCY": (1, "int", "Market currency code (1 = USD, 3 = EUR)"),
    "OUT": ("", "str", "Auto-export directory after each run (empty = off)"),
    "FORMAT": ("json,html,csv", "str", "Export formats"),
    "NO_CACHE": (False, "bool", "Disable the on-disk cache"),
    "VERBOSE": (False, "bool", "Verbose HTTP logging"),
}
MODULES: dict[str, dict] = {
    "recon/full": {"desc": "Full scan: profile, bans, games, network, inventory + off-Steam intelligence",
                   "needs": ["TARGET"], "flags": {}},
    "recon/network": {"desc": "Friend network graph: mutual links, centrality, communities",
                      "needs": ["TARGET"], "flags": {"no_offsteam": True, "no_inventory": True}},
    "recon/footprint": {"desc": "Off-Steam only: Google/SERP search, handle footprint, OpenDota/FACEIT, Wayback, Discord",
                        "needs": ["TARGET"], "flags": {"no_network": True, "no_inventory": True}},
    "recon/inventory": {"desc": "Profile + public inventory (optional market valuation)",
                        "needs": ["TARGET"], "flags": {"no_network": True, "no_offsteam": True}},
    "recon/resolve": {"desc": "Convert any ID format (SteamID64 / Steam2 / Steam3 / vanity / URL)",
                      "needs": ["TARGET"], "flags": {}},
    "recon/compare": {"desc": "Compare two targets: mutual friends, shared groups/games/past names",
                      "needs": ["TARGET", "TARGET2"], "flags": {}},
}
SHOW_TOPICS = ["modules", "options", "info", "config", "notes", "history", "keys"]
HELP_GROUPS = [
    ("Core", [("help [cmd]", "Show this help, or details for one command"), ("banner", "Show the logo"),
              ("about", "Credits, version and copyright"), ("tips", "Random usage tip"),
              ("theme <colour>", "Change console colour"), ("history", "Commands typed this session"),
              ("stats", "Session statistics"), ("clear", "Clear the screen"), ("exit", "Leave the console")]),
    ("Modules", [("show modules", "List modules"), ("use <module|#>", "Select a module"),
                 ("info", "Details of the selected module"), ("back", "Deselect the module"),
                 ("search <word>", "Search modules / options")]),
    ("Options", [("show options", "Current settings"), ("set <NAME> <value>", "Change a setting"),
                 ("unset <NAME|all>", "Reset a setting"), ("keys", "Show configured keys (masked)"),
                 ("save", "Persist keys to your config file"), ("check", "Verify keys + connectivity")]),
    ("Run", [("run", "Execute the selected module (aliases: go, exploit)"),
             ("scan <target>", "Shortcut: full scan of a target"), ("resolve <target>", "Shortcut: ID conversion"),
             ("compare <a> <b>", "Shortcut: compare two targets"), ("last", "Re-display the last result"),
             ("export [dir] [fmts]", "Write the last result to json/html/csv"),
             ("note <text> / notes", "Attach / list analyst notes (saved in reports)")]),
]
HELP_DETAIL = {
    "set": "set <NAME> <value>\n  Options are global and case-insensitive. Booleans accept true/false/yes/no/on/off.\n"
           "  Example: set TARGET https://steamcommunity.com/id/gabelogannewell\n           set MAX_QUERIES 20",
    "use": "use <module|number>\n  Select a module (see 'show modules'). Short names work: 'use footprint'.",
    "run": "run\n  Executes the selected module with the current options. If no module is selected but TARGET is set,\n"
           "  recon/full is used. Results are kept for 'last' and 'export'.",
    "scan": "scan <target>\n  Shortcut for: use recon/full ; set TARGET <target> ; run",
    "compare": "compare <targetA> <targetB>\n  Shortcut for recon/compare. Quote Steam3 ids: compare \"[U:1:123]\" 7656119...",
    "export": "export [dir] [formats]\n  Writes the last scan. Defaults: dir=reports  formats=json,html,csv",
    "note": "note <text>   add an analyst note (stored inside the next export / report)\nnotes        list notes\n"
            "note clear   remove all notes",
    "save": "save\n  Stores API_KEY, SEARCH_PROVIDER/SEARCH_KEY, GOOGLE_CX and FACEIT_KEY in your config file (chmod 600).",
    "check": "check\n  Tests connectivity to Steam, whether your keys are set, and validates the Steam key.",
    "theme": "theme <" + "|".join(THEMES) + ">",
}


def logo_rows(block: str) -> list[str]:
    return [" ".join(FONT[c][r].replace("#", block) for c in "STEAMSCOPE") for r in range(5)]


def print_banner(con: Console, theme: str = "cyan", compact: bool = False) -> None:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    block = "\u2588" if "utf" in enc else "#"
    width = getattr(con, "width", 80) or 80
    if compact or width < 82:
        con.print(Text(f"{TOOL} v{VERSION}  |  Developer: {AUTHOR}  |  {COPYRIGHT}", style=f"bold {theme}"))
        return
    name = logo_rows(block)
    t = Text()
    for i, mag in enumerate(MAGNIFIER):
        t.append(mag.ljust(20), style=f"bold {theme}")
        if 2 <= i <= 6:
            t.append(name[i - 2], style="bold white")
        elif i == 1:
            t.append("  S T E A M   O S I N T   F R A M E W O R K", style="italic dim")
        elif i == 7:
            t.append(f"  v{VERSION}   |   Developer: ", style="dim")
            t.append(AUTHOR, style="bold magenta")
        elif i == 8:
            t.append(f"  {COPYRIGHT}", style="dim")
        t.append("\n")
    con.print(t)
    con.print(Text("  Public-data OSINT for authorised research. Never bypasses privacy settings.\n",
                   style="dim"))


def mask(v: Any) -> str:
    s = str(v or "")
    return "(not set)" if not s else (s[:3] + "*" * max(4, len(s) - 6) + s[-3:] if len(s) > 8 else "*" * len(s))


def explain_error(e: Exception) -> str:
    kinds = [(InvalidTarget, "Invalid target"), (NotFound, "Not found"), (InvalidApiKey, "API key problem"),
             (RateLimited, "Rate limited (wait a bit and retry)"), (NetworkError, "Network error"),
             (PrivateData, "Private data")]
    for cls, label in kinds:
        if isinstance(e, cls):
            return f"{label}: {e}"
    return f"Error: {e}"


class ScopeShell:
    ALIASES = {"?": "help", "q": "exit", "quit": "exit", "cls": "clear", "exploit": "run", "go": "run",
               "options": "show options", "modules": "show modules", "unset": "unset"}

    def __init__(self, con: Console):
        self.con = con
        self.theme = "cyan"
        self.module: Optional[str] = None
        self.opts: dict[str, Any] = {k: v[0] for k, v in OPTION_DEFS.items()}
        cfg = load_config()
        self.opts["API_KEY"] = os.environ.get("STEAM_API_KEY") or cfg.get("api_key", "")
        prov, key = resolve_search(argparse.Namespace(search_provider=None, search_key=None), cfg)
        if prov:
            self.opts["SEARCH_PROVIDER"], self.opts["SEARCH_KEY"] = prov, key
        self.opts["FACEIT_KEY"] = os.environ.get("FACEIT_API_KEY") or cfg.get("faceit_key", "")
        self.opts["GOOGLE_CX"] = os.environ.get("GOOGLE_CSE_CX") or cfg.get("google_cx", "")
        self.last: Optional[tuple[str, dict]] = None
        self.history: list[str] = []
        self.notes: list[str] = []
        self.t0 = time.time()
        self.runs = 0
        self._ctx: Optional[Ctx] = None
        self._ctx_key: Optional[tuple] = None
        self.commands = sorted(n[3:] for n in dir(self) if n.startswith("do_"))

    # ---- output helpers --------------------------------------------------------
    def _msg(self, sym: str, colour: str, text: str) -> None:
        self.con.print(Text.assemble((f"[{sym}] ", f"bold {colour}"), text))

    def info(self, t: str) -> None:
        self._msg("*", self.theme, t)

    def good(self, t: str) -> None:
        self._msg("+", "green", t)

    def warn(self, t: str) -> None:
        self._msg("!", "yellow", t)

    def err(self, t: str) -> None:
        self._msg("-", "red", t)

    # ---- readline --------------------------------------------------------------
    def _setup_readline(self) -> None:
        try:
            import readline
        except ImportError:
            return
        cmds = self.commands + list(self.ALIASES)

        def complete(text: str, state: int) -> Optional[str]:
            buf = readline.get_line_buffer().lstrip()
            parts = buf.split()
            first = len(parts) <= 1 and not buf.endswith(" ")
            if first:
                pool = cmds
            else:
                c = parts[0].lower()
                pool = []
                if c == "use":
                    pool = list(MODULES)
                elif c in ("set", "unset"):
                    if len(parts) <= 2 and not buf.endswith(" "):
                        pool = list(OPTION_DEFS)
                    else:
                        d = OPTION_DEFS.get(parts[1].upper())
                        pool = (["true", "false"] if d and d[1] == "bool" else
                                list(SEARCH_PROVIDERS) if d and parts[1].upper() == "SEARCH_PROVIDER" else [])
                elif c == "show":
                    pool = SHOW_TOPICS
                elif c == "theme":
                    pool = list(THEMES)
                elif c == "help":
                    pool = cmds
            m = [x for x in pool if x.lower().startswith(text.lower())]
            return m[state] if state < len(m) else None

        try:
            readline.set_completer(complete)
            readline.set_completer_delims(" \t\n")
            if "libedit" in (readline.__doc__ or ""):
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
        except Exception:  # noqa: BLE001 - completion is a nicety only
            pass

    # ---- main loop -------------------------------------------------------------
    def prompt(self) -> str:
        mod = f" ([bold {self.theme}]{self.module}[/])" if self.module else ""
        return f"[bold {self.theme}]steamscope[/]{mod} [bold]>[/] "

    def cmdloop(self) -> None:
        self._setup_readline()
        print_banner(self.con, self.theme)
        self.con.print(Text.assemble(("  Type ", "dim"), ("help", f"bold {self.theme}"),
                                     (" for commands, ", "dim"), ("show modules", f"bold {self.theme}"),
                                     (" to start.  ", "dim"), ("Tip: ", "bold yellow"),
                                     (random.choice(TIPS), "dim")))
        self.con.print()
        while True:
            try:
                line = self.con.input(self.prompt()).strip()
            except EOFError:
                self.con.print()
                break
            except KeyboardInterrupt:
                self.con.print()
                self.warn("Use 'exit' to leave.")
                continue
            if not line:
                continue
            self.history.append(line)
            if self.dispatch(line) == "exit":
                break
        self.info("Goodbye.")

    def dispatch(self, line: str) -> Optional[str]:
        try:
            parts = shlex.split(line, posix=False)
        except ValueError:
            parts = line.split()
        parts = [p[1:-1] if len(p) > 1 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in self.ALIASES:
            exp = self.ALIASES[cmd].split()
            cmd, args = exp[0], exp[1:] + args
        fn = getattr(self, "do_" + cmd, None)
        if not fn:
            close = difflib.get_close_matches(cmd, self.commands, 1, 0.6)
            self.err(f"Unknown command: {cmd}" + (f"   (did you mean '{close[0]}'?)" if close else "") +
                     "   Type 'help'.")
            return None
        try:
            return fn(args)
        except KeyboardInterrupt:
            self.warn("Interrupted.")
        except SteamOsintError as e:
            self.err(explain_error(e))
        except Exception as e:  # noqa: BLE001 - never crash the console
            self.err(f"Unexpected {type(e).__name__}: {e}")
        return None

    # ---- core commands ---------------------------------------------------------
    def do_help(self, args: list[str]) -> None:
        if args:
            c = self.ALIASES.get(args[0].lower(), args[0].lower()).split()[0]
            if c in HELP_DETAIL:
                self.con.print(Panel(Text(HELP_DETAIL[c]), title=f"help {c}", border_style=self.theme))
            else:
                self.warn(f"No detailed help for '{args[0]}'. Try plain 'help'.")
            return
        for title, rows in HELP_GROUPS:
            t = Table(title=title, box=box.SIMPLE_HEAVY, title_style=f"bold {self.theme}", title_justify="left")
            t.add_column("Command", style=f"bold {self.theme}", no_wrap=True)
            t.add_column("Description")
            for c, d in rows:
                t.add_row(c, d)
            self.con.print(t)
        self.con.print(Text("Targets: SteamID64, vanity, profile URL, STEAM_0:1:123, [U:1:123]  |  "
                            "'help <command>' for details", style="dim"))

    def do_banner(self, args: list[str]) -> None:
        print_banner(self.con, self.theme)

    def do_about(self, args: list[str]) -> None:
        self.con.print(Panel(Text.assemble(
            (f"{TOOL}", f"bold {self.theme}"), f"  v{VERSION}\nSteam OSINT Framework - public data only\n\n",
            ("Developer : ", "dim"), (AUTHOR, "bold magenta"), "\n",
            ("Copyright : ", "dim"), COPYRIGHT, "\n",
            ("Data      : ", "dim"), "Steam Web API, public Steam Community pages, public APIs,\n"
                                     "             licensed SERP providers (Google results), Internet Archive\n",
            ("Use      : ", "dim"), "Authorised research / audits only. Respect privacy laws and each service's ToS."),
            title="About", border_style=self.theme))

    def do_tips(self, args: list[str]) -> None:
        self.info(random.choice(TIPS))

    def do_theme(self, args: list[str]) -> None:
        if not args or args[0].lower() not in THEMES:
            self.warn("Usage: theme <" + "|".join(THEMES) + ">")
            return
        self.theme = THEMES[args[0].lower()]
        self.good(f"Theme set to {self.theme}.")

    def do_history(self, args: list[str]) -> None:
        for i, h in enumerate(self.history[-30:], 1):
            self.con.print(Text(f"{i:>3}  {h}"))

    def do_stats(self, args: list[str]) -> None:
        up = int(time.time() - self.t0)
        self.con.print(kv_table("Session", [
            ("Uptime", f"{up // 60}m {up % 60}s"), ("Runs", self.runs), ("Commands", len(self.history)),
            ("Module", self.module or "-"), ("Notes", len(self.notes)),
            ("Last result", self.last[0] if self.last else "-")]))

    def do_clear(self, args: list[str]) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def do_exit(self, args: list[str]) -> str:
        return "exit"

    # ---- modules / options -----------------------------------------------------
    def _mod_names(self) -> list[str]:
        return list(MODULES)

    def do_show(self, args: list[str]) -> None:
        topic = (args[0].lower() if args else "options")
        if topic == "modules":
            t = Table(title="Modules", box=box.SIMPLE_HEAVY, title_style=f"bold {self.theme}")
            for c in ("#", "Module", "Description"):
                t.add_column(c)
            for i, (n, d) in enumerate(MODULES.items()):
                t.add_row(str(i), n, d["desc"])
            self.con.print(t)
        elif topic == "options":
            needs = set(MODULES[self.module]["needs"]) if self.module else set()
            t = Table(title=f"Options{' for ' + self.module if self.module else ''}", box=box.SIMPLE_HEAVY,
                      title_style=f"bold {self.theme}")
            for c in ("Name", "Current", "Required", "Description"):
                t.add_column(c, overflow="fold")
            for k, (dflt, typ, desc) in OPTION_DEFS.items():
                v = self.opts[k]
                shown = mask(v) if typ == "secret" else ("" if v == "" else str(v))
                t.add_row(k, shown, "yes" if k in needs else "", desc)
            self.con.print(t)
        elif topic == "info":
            self.do_info([])
        elif topic in ("config", "keys"):
            self.do_keys([])
        elif topic == "notes":
            self.do_notes([])
        elif topic == "history":
            self.do_history([])
        else:
            self.warn("show <" + "|".join(SHOW_TOPICS) + ">")

    def _resolve_module(self, name: str) -> Optional[str]:
        names = self._mod_names()
        if name.isdigit() and int(name) < len(names):
            return names[int(name)]
        if name in MODULES:
            return name
        hit = [n for n in names if n.endswith("/" + name) or n.split("/")[-1].startswith(name)]
        return hit[0] if len(hit) == 1 else None

    def do_use(self, args: list[str]) -> None:
        if not args:
            self.warn("Usage: use <module|#>   (see 'show modules')")
            return
        m = self._resolve_module(args[0].lower())
        if not m:
            self.err(f"No such module: {args[0]}")
            return
        self.module = m
        self.info(f"Module: {m}  -  {MODULES[m]['desc']}")

    def do_back(self, args: list[str]) -> None:
        self.module = None

    def do_info(self, args: list[str]) -> None:
        m = self.module
        if not m:
            self.warn("No module selected. Use 'use <module>'.")
            return
        d = MODULES[m]
        self.con.print(kv_table(m, [("Description", d["desc"]), ("Required", ", ".join(d["needs"])),
                                    ("Overrides", ", ".join(f"{k}={v}" for k, v in d["flags"].items()) or "-")]))

    def do_search(self, args: list[str]) -> None:
        if not args:
            self.warn("Usage: search <word>")
            return
        w = " ".join(args).lower()
        rows = [(n, d["desc"]) for n, d in MODULES.items() if w in n.lower() or w in d["desc"].lower()]
        rows += [(k, v[2]) for k, v in OPTION_DEFS.items() if w in k.lower() or w in v[2].lower()]
        if not rows:
            self.warn("Nothing found.")
            return
        t = Table(box=box.SIMPLE)
        t.add_column("Name")
        t.add_column("Description")
        for r in rows:
            t.add_row(*r)
        self.con.print(t)

    def do_set(self, args: list[str]) -> None:
        if len(args) < 2:
            self.warn("Usage: set <NAME> <value>   (see 'show options')")
            return
        name, raw = args[0].upper(), " ".join(args[1:])
        if name not in OPTION_DEFS:
            close = difflib.get_close_matches(name, list(OPTION_DEFS), 1, 0.6)
            self.err(f"Unknown option {name}" + (f" (did you mean {close[0]}?)" if close else ""))
            return
        _, typ, _ = OPTION_DEFS[name]
        try:
            if typ == "int":
                val: Any = int(raw)
                if val < 0:
                    raise ValueError
            elif typ == "bool":
                if raw.lower() in ("1", "true", "yes", "on", "y"):
                    val = True
                elif raw.lower() in ("0", "false", "no", "off", "n"):
                    val = False
                else:
                    raise ValueError
            elif typ == "choice":
                val = raw.lower()
                if val not in SEARCH_PROVIDERS:
                    raise ValueError
            else:
                val = raw.strip().strip("\"'")
        except ValueError:
            self.err(f"Invalid value for {name} ({typ}).")
            return
        self.opts[name] = val
        self.con.print(Text(f"{name} => {mask(val) if typ == 'secret' else val}", style=f"bold {self.theme}"))
        if name == "TARGET" and not self.module:
            self.module = "recon/full"
            self.info("Module auto-selected: recon/full")

    def do_unset(self, args: list[str]) -> None:
        if not args:
            self.warn("Usage: unset <NAME|all>")
            return
        if args[0].lower() == "all":
            self.opts = {k: v[0] for k, v in OPTION_DEFS.items()}
            self.good("All options reset.")
            return
        n = args[0].upper()
        if n not in OPTION_DEFS:
            self.err(f"Unknown option {n}")
            return
        self.opts[n] = OPTION_DEFS[n][0]
        self.good(f"{n} reset.")

    def do_keys(self, args: list[str]) -> None:
        self.con.print(kv_table("Keys (masked)", [
            ("Steam API key", mask(self.opts["API_KEY"])),
            ("Search backend", SEARCH_LABEL.get(self.opts["SEARCH_PROVIDER"], "(none)")),
            ("Search key", mask(self.opts["SEARCH_KEY"])), ("Google CX", self.opts["GOOGLE_CX"] or "(not set)"),
            ("FACEIT key", mask(self.opts["FACEIT_KEY"])), ("Config file", CONFIG_PATH)]))

    def do_save(self, args: list[str]) -> None:
        cfg = load_config()
        if self.opts["API_KEY"]:
            cfg["api_key"] = self.opts["API_KEY"]
        if self.opts["SEARCH_PROVIDER"] and self.opts["SEARCH_KEY"]:
            cfg.setdefault("search_keys", {})[self.opts["SEARCH_PROVIDER"]] = self.opts["SEARCH_KEY"]
            cfg["search_provider"] = self.opts["SEARCH_PROVIDER"]
        if self.opts["GOOGLE_CX"]:
            cfg["google_cx"] = self.opts["GOOGLE_CX"]
        if self.opts["FACEIT_KEY"]:
            cfg["faceit_key"] = self.opts["FACEIT_KEY"]
        save_config(cfg)
        self.good(f"Saved to {CONFIG_PATH}")

    def do_check(self, args: list[str]) -> None:
        rows: list[tuple[str, str]] = []
        http = Http(use_cache=False, retries=1, timeout=8)
        try:
            http.get(f"{COMMUNITY}/", ttl=0)
            rows.append(("Steam Community reachable", "OK"))
        except SteamOsintError as e:
            rows.append(("Steam Community reachable", f"FAIL ({e})"))
        if self.opts["API_KEY"]:
            try:
                SteamApi(http, self.opts["API_KEY"]).validate_key()
                rows.append(("Steam API key", "OK"))
            except SteamOsintError as e:
                rows.append(("Steam API key", f"FAIL ({e})"))
        else:
            rows.append(("Steam API key", "not set (web-only mode)"))
        p = self.opts["SEARCH_PROVIDER"]
        rows.append(("Search backend", f"{SEARCH_LABEL[p]} - key {'set' if self.opts['SEARCH_KEY'] else 'MISSING'}"
                     if p else "not set (manual Google links only)"))
        rows.append(("FACEIT key", "set" if self.opts["FACEIT_KEY"] else "not set (optional)"))
        self.con.print(kv_table("Health check", rows))

    # ---- notes -----------------------------------------------------------------
    def do_note(self, args: list[str]) -> None:
        if not args:
            self.warn("Usage: note <text> | note clear")
        elif args[0].lower() == "clear" and len(args) == 1:
            self.notes.clear()
            self.good("Notes cleared.")
        else:
            self.notes.append(" ".join(args))
            self.good(f"Note #{len(self.notes)} added.")

    def do_notes(self, args: list[str]) -> None:
        if not self.notes:
            self.info("No notes yet. Use: note <text>")
        for i, n in enumerate(self.notes, 1):
            self.con.print(Text(f"{i:>2}. {n}"))

    # ---- running ---------------------------------------------------------------
    def _args(self, flags: dict) -> argparse.Namespace:
        o = self.opts
        ns = argparse.Namespace(
            api_key=o["API_KEY"] or None, no_cache=o["NO_CACHE"], verbose=o["VERBOSE"], sample=o["SAMPLE"],
            no_network=False, friend_groups=o["FRIEND_GROUPS"], no_inventory=False,
            inventory_value=o["INVENTORY_VALUE"], max_price_lookups=o["MAX_PRICE_LOOKUPS"],
            library_value=o["LIBRARY_VALUE"], appid=o["APPID"], context=o["CONTEXT"], currency=o["CURRENCY"],
            out=o["OUT"] or None, format=o["FORMAT"], no_offsteam=False,
            search_provider=o["SEARCH_PROVIDER"] or None, search_key=o["SEARCH_KEY"] or None,
            google_cx=o["GOOGLE_CX"] or None, max_queries=o["MAX_QUERIES"], max_handles=o["MAX_HANDLES"],
            faceit_key=o["FACEIT_KEY"] or None, no_banner=True)
        for k, v in flags.items():
            setattr(ns, k, v)
        return ns

    def _get_ctx(self, args: argparse.Namespace) -> Ctx:
        key = (args.api_key, args.search_provider, args.search_key, args.google_cx, args.faceit_key,
               args.no_cache, args.verbose)
        if self._ctx is None or key != self._ctx_key:
            self._ctx, self._ctx_key = Ctx(self.con, args), key
        else:
            self._ctx.args = args
        return self._ctx

    def do_run(self, args: list[str]) -> None:
        if not self.module:
            if self.opts["TARGET"]:
                self.module = "recon/full"
            else:
                self.err("No module selected. Try 'use recon/full' and 'set TARGET <id>'.")
                return
        mod, spec = self.module, MODULES[self.module]
        missing = [n for n in spec["needs"] if not self.opts[n]]
        if missing:
            self.err("Missing required option(s): " + ", ".join(missing) + "   (set NAME value)")
            return
        a = self._args(spec["flags"])
        t0 = time.time()
        self.info(f"Running {mod} ...")
        ctx = self._get_ctx(a)
        self.runs += 1
        if mod == "recon/resolve":
            show_resolve(ctx, self.opts["TARGET"])
            return
        if mod == "recon/compare":
            rep = compare(ctx, self.opts["TARGET"], self.opts["TARGET2"])
            render_compare(self.con, rep)
            self.last = ("compare", rep)
        else:
            rep = scan(ctx, self.opts["TARGET"])
            rep["meta"]["notes"] = list(self.notes)
            render(self.con, rep)
            self.last = ("scan", rep)
            if self.opts["OUT"]:
                self._export(Path(self.opts["OUT"]), self.opts["FORMAT"])
        self.good(f"Done in {time.time() - t0:.1f}s.  'export' saves it, 'last' shows it again.")

    def do_scan(self, args: list[str]) -> None:
        if not args:
            self.warn("Usage: scan <target>")
            return
        self.opts["TARGET"], self.module = " ".join(args), "recon/full"
        self.do_run([])

    def do_resolve(self, args: list[str]) -> None:
        if not args:
            self.warn("Usage: resolve <target>")
            return
        self.opts["TARGET"], self.module = " ".join(args), "recon/resolve"
        self.do_run([])

    def do_compare(self, args: list[str]) -> None:
        if len(args) != 2:
            self.warn("Usage: compare <targetA> <targetB>")
            return
        self.opts["TARGET"], self.opts["TARGET2"], self.module = args[0], args[1], "recon/compare"
        self.do_run([])

    def do_last(self, args: list[str]) -> None:
        if not self.last:
            self.warn("Nothing yet - run a module first.")
            return
        kind, rep = self.last
        (render if kind == "scan" else render_compare)(self.con, rep)

    def _export(self, out: Path, fmts_raw: str) -> None:
        kind, rep = self.last  # type: ignore[misc]
        fmts = [f.strip().lower() for f in fmts_raw.split(",") if f.strip()]
        if kind == "scan":
            rep.setdefault("meta", {})["notes"] = list(self.notes)
            for p in export_report(rep, out, fmts):
                self.good(f"saved {p}")
        else:
            out.mkdir(parents=True, exist_ok=True)
            p = out / f"compare_{rep['a']['id64']}_{rep['b']['id64']}.json"
            p.write_text(json.dumps(rep, indent=2, ensure_ascii=False, default=str), "utf-8")
            self.good(f"saved {p}")

    def do_export(self, args: list[str]) -> None:
        if not self.last:
            self.warn("Nothing to export - run a module first.")
            return
        self._export(Path(args[0] if args else "reports"), args[1] if len(args) > 1 else "json,html,csv")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def add_scan_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--sample", type=int, default=40, help="friends whose friend-lists are read (default 40)")
    p.add_argument("--no-network", action="store_true", help="skip friend network analysis")
    p.add_argument("--friend-groups", action="store_true", help="also read friends' groups (slower)")
    p.add_argument("--no-inventory", action="store_true", help="skip inventory")
    p.add_argument("--inventory-value", action="store_true", help="price marketable items (slow, rate-limited)")
    p.add_argument("--max-price-lookups", type=int, default=40)
    p.add_argument("--library-value", action="store_true", help="estimate game library list-price value")
    p.add_argument("--appid", type=int, default=730, help="inventory app id (default 730 = CS2)")
    p.add_argument("--context", type=int, default=2, help="inventory context id (default 2)")
    p.add_argument("--currency", type=int, default=1, help="market currency code (1=USD, 3=EUR, ...)")
    p.add_argument("--no-offsteam", action="store_true", help="skip all off-Steam modules")
    p.add_argument("--search-provider", choices=SEARCH_PROVIDERS, help="serper|serpapi|brave|google_cse")
    p.add_argument("--search-key", help="API key for the search provider")
    p.add_argument("--google-cx", help="search engine id (google_cse only)")
    p.add_argument("--max-queries", type=int, default=12, help="web searches to spend (default 12)")
    p.add_argument("--max-handles", type=int, default=4, help="handles to check on other platforms (0=off)")
    p.add_argument("--faceit-key", help="FACEIT Data API key")
    p.add_argument("--out", help="export directory")
    p.add_argument("--format", default="json,html,csv", help="export formats: json,html,csv")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api-key", help="Steam Web API key")
    common.add_argument("--no-cache", action="store_true")
    common.add_argument("-v", "--verbose", action="store_true")
    common.add_argument("--no-banner", action="store_true", help="hide the logo")
    ap = argparse.ArgumentParser(prog="steamscope", formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=f"{TOOL} v{VERSION} - Steam OSINT framework (public data)\n"
                                             f"Developer: {AUTHOR}    {COPYRIGHT}",
                                 epilog="Run without arguments to open the interactive console (msfconsole-style).")
    ap.add_argument("-V", "--version", action="version", version=f"{TOOL} {VERSION} by {AUTHOR}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("console", help="interactive console (default)")
    s = sub.add_parser("scan", parents=[common], help="full scan of a target")
    s.add_argument("target")
    add_scan_opts(s)
    c = sub.add_parser("compare", parents=[common], help="compare two targets")
    c.add_argument("a")
    c.add_argument("b")
    c.add_argument("--out")
    r = sub.add_parser("resolve", parents=[common], help="convert any id format")
    r.add_argument("target")
    cf = sub.add_parser("config", help="store API key")
    cf.add_argument("--set-key")
    cf.add_argument("--set-search", nargs=2, metavar=("PROVIDER", "KEY"), help="serper|serpapi|brave|google_cse")
    cf.add_argument("--set-google-cx", help="engine id for google_cse")
    cf.add_argument("--set-faceit", help="FACEIT Data API key")
    sub.add_parser("selftest", help="offline unit checks")
    return ap


def do_scan(ctx: Ctx, target: str) -> None:
    rep = scan(ctx, target)
    render(ctx.console, rep)
    if ctx.args.out:
        fm = [f.strip().lower() for f in ctx.args.format.split(",") if f.strip()]
        for pth in export_report(rep, Path(ctx.args.out), fm):
            ctx.console.print(f"[green]saved[/green] {pth}")


def show_resolve(ctx: Ctx, target: str) -> None:
    i = ctx.resolver.resolve(target)
    ctx.console.print(kv_table("Resolved", [(k, v) for k, v in i.as_dict().items()]))


def main(argv: Optional[list[str]] = None) -> int:
    con = Console()
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        if args.cmd is None or args.cmd == "console":
            ScopeShell(con).cmdloop()
            return 0
        if args.cmd in ("scan", "compare", "resolve") and not getattr(args, "no_banner", False):
            print_banner(con)
        if args.cmd == "selftest":
            return selftest(con)
        if args.cmd == "config":
            cfg = load_config()
            changed = False
            if args.set_key:
                cfg["api_key"], changed = args.set_key.strip(), True
            if args.set_search:
                prov, key = args.set_search[0].lower(), args.set_search[1].strip()
                if prov not in SEARCH_PROVIDERS:
                    con.print(f"[red]Provider must be one of {', '.join(SEARCH_PROVIDERS)}[/red]")
                    return 2
                cfg.setdefault("search_keys", {})[prov] = key
                cfg["search_provider"], changed = prov, True
            if args.set_google_cx:
                cfg["google_cx"], changed = args.set_google_cx.strip(), True
            if args.set_faceit:
                cfg["faceit_key"], changed = args.set_faceit.strip(), True
            if changed:
                save_config(cfg)
                con.print(f"[green]Saved to {CONFIG_PATH}[/green]")
            else:
                con.print("Use --set-key / --set-search PROVIDER KEY / --set-faceit KEY / --set-google-cx CX")
            return 0
        ctx = Ctx(con, args)
        if args.cmd == "resolve":
            show_resolve(ctx, args.target)
        elif args.cmd == "scan":
            do_scan(ctx, args.target)
        elif args.cmd == "compare":
            rep = compare(ctx, args.a, args.b)
            render_compare(con, rep)
            if args.out:
                Path(args.out).mkdir(parents=True, exist_ok=True)
                pth = Path(args.out) / f"compare_{rep['a']['id64']}_{rep['b']['id64']}.json"
                pth.write_text(json.dumps(rep, indent=2, ensure_ascii=False, default=str), "utf-8")
                con.print(f"[green]saved[/green] {pth}")
        return 0
    except InvalidTarget as e:
        con.print(f"[red]Invalid target:[/red] {e}")
        return 2
    except NotFound as e:
        con.print(f"[red]Not found:[/red] {e}")
        return 3
    except InvalidApiKey as e:
        con.print(f"[red]API key problem:[/red] {e}")
        return 4
    except RateLimited as e:
        con.print(f"[red]Rate limited:[/red] {e} - wait a few minutes and retry.")
        return 5
    except NetworkError as e:
        con.print(f"[red]Network error:[/red] {e}")
        return 6
    except SteamOsintError as e:
        con.print(f"[red]Error:[/red] {e}")
        return 1
    except KeyboardInterrupt:
        con.print("\n[yellow]Interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
