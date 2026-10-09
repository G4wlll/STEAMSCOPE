# SteamScope

**Steam OSINT framework with a Metasploit-style console**

Public-data reconnaissance for Steam profiles: identity resolution, playtime analytics, friend-network graphs,
and off-Steam footprinting (Google/SERP search, other platforms, game-stat sites, Internet Archive).

`Python 3.10+` · `Single file` · `No telemetry` · `Public data only`

Developer: **G4wlll** · [العربية](README.ar.md)

</div>

---

## Table of contents
1. [What it does](#what-it-does)
2. [Warnings and responsible use](#warnings-and-responsible-use)
3. [Download](#download)
4. [Install](#install)
5. [API keys](#api-keys)
6. [Run it](#run-it)
7. [Console command reference](#console-command-reference)
8. [Options](#options)
9. [Command-line mode](#command-line-mode)
10. [Output and reports](#output-and-reports)
11. [How to read the results](#how-to-read-the-results)
12. [Limitations](#limitations)
13. [Transparency: what the program contacts](#transparency-what-the-program-contacts)
14. [Troubleshooting](#troubleshooting)
15. [License and copyright](#license-and-copyright)

---

## What it does

| Area | Details |
|---|---|
| **ID resolution** | Accepts SteamID64, vanity name, profile URL, Steam2 (`STEAM_0:1:123`) and Steam3 (`[U:1:123]`) and converts between them. |
| **Profile intelligence** | Display name, real name, country, level, badges, bans (VAC / game / community / economy), account age (exact when public, heuristic estimate when hidden). |
| **Games & playtime** | Library size, total hours, played vs. unplayed ratio, mean/median hours, distribution buckets, top games, recent activity, optional library price estimate. |
| **Name history** | Previous display names from Steam's public alias endpoint. |
| **Friend network** | Reads friend lists of a sample of friends, builds the friend-to-friend graph, computes betweenness, closeness, PageRank, detects communities, shared groups, country and "friends added per year" breakdowns. |
| **Inventory** | Public inventory item counts; optional market-price valuation (lower bound). |
| **Off-Steam: web search** | Builds targeted queries (SteamID in all formats, vanity URL citations, names/aliases on social, dev and gaming sites) and runs them through a search API (Google results via Serper or SerpAPI, or Brave). Every result gets an **attribution score** (high / medium / low) with the evidence shown. |
| **Off-Steam: handle footprint** | Checks the same handle on GitHub, Reddit, Keybase, GitLab, Chess.com, Lichess, HackerNews, Dev.to, Docker Hub, Speedrun.com, Gravatar, Roblox using their **public APIs**. Each hit gets a verdict: `corroborated`, `plausible`, `unverified` or `conflict`. |
| **Game platforms** | OpenDota lookup by account id; FACEIT lookup by SteamID64 (needs a free FACEIT key). |
| **History** | Internet Archive snapshot count/first/last for the profile URLs. |
| **Discord invites** | Resolves invite links found on the profile (server name, member count). |
| **Console** | `msfconsole`-style shell: `use`, `set`, `show options`, `run`, tab completion, notes, themes, history. |
| **Export** | JSON, a self-contained HTML report (with network graph), and CSV files. |

---

## Warnings and responsible use

> **Read this before using the tool.**

- **Authorised use only.** Use SteamScope for security research, academic work, journalism, due diligence on your *own* accounts, or audits where you have a legitimate, lawful reason and any required permission.
- **Do not use it to harass, stalk, dox, threaten or defame anyone.** Gathering public information about a private individual can still cause real harm and may be illegal where you live.
- **A matching name is not proof of identity.** Common nicknames are shared by thousands of people. Treat anything below `high` / `corroborated` as a lead to verify, never as a conclusion. Do not publish accusations based on this tool's output.
- **Respect privacy settings.** The tool never bypasses them: private profiles, friend lists and inventories are reported as private and skipped.
- **Respect terms of service and law.** You are responsible for complying with the [Steam Web API Terms](https://steamcommunity.com/dev/apiterms), the terms of every service the tool queries (see the list below), and privacy/data-protection law (for example GDPR) in your country.
- **Reports contain personal data.** Store them securely, share them only with people who need them, and delete them when finished.
- **Never commit secrets.** Your API keys live in `~/.steamscope.json`. The included `.gitignore` excludes reports and config files; keep it.
- **No warranty.** Provided "as is". The author is not liable for misuse or for the accuracy of third-party data.
- **Rate limits.** Steam and other services throttle heavy use. The tool backs off automatically; do not try to circumvent limits.

---

## Download

**Option A - Git**
```bash
git clone https://github.com/YOUR_USERNAME/SteamScope.git
cd SteamScope
```

**Option B - ZIP**
On the repository page click **Code → Download ZIP**, extract it, and open a terminal in the extracted folder.

---

## Install

Requires **Python 3.10+** (3.9 should work) and two packages.

```bash
pip install -r requirements.txt
# or:  pip install requests rich
```

Windows tip: if `python` is not recognised, use `py` instead (`py steamscope.py`). Use **Windows Terminal** for the best rendering of the logo.

Quick self-check (works offline):
```bash
python steamscope.py selftest
```

---

## API keys

All keys are **optional**; the tool degrades gracefully and tells you what was skipped.

| Key | Needed for | Where to get it |
|---|---|---|
| **Steam Web API key** | Friend lists, owned games, bans, level/badges, summaries | <https://steamcommunity.com/dev/apikey> (free; your Steam account must not be limited) |
| **Search API key** | Web search (Google results) | [Serper.dev](https://serper.dev) or [SerpAPI](https://serpapi.com) (Google results), or [Brave Search API](https://brave.com/search/api/) |
| **FACEIT Data API key** | Exact SteamID → FACEIT match | <https://developers.faceit.com> (free) |

> **About Google:** Google's own Custom Search JSON API is closed to new customers and is scheduled to be retired on 2027-01-01, and scraping google.com violates its terms. SteamScope therefore gets Google results through licensed SERP providers. Legacy `google_cse` support exists only for people who already have access. Without any search key the tool still generates ready-made Google / DuckDuckGo / Bing links for manual use.

**Set keys inside the console and save them:**
```
set API_KEY your_steam_key
set SEARCH_PROVIDER serper
set SEARCH_KEY your_serper_key
set FACEIT_KEY your_faceit_key
save
```
Or from the shell:
```bash
python steamscope.py config --set-key YOUR_STEAM_KEY
python steamscope.py config --set-search serper YOUR_SERPER_KEY
python steamscope.py config --set-faceit YOUR_FACEIT_KEY
```
Environment variables also work: `STEAM_API_KEY`, `SERPER_API_KEY`, `SERPAPI_API_KEY`, `BRAVE_API_KEY`, `FACEIT_API_KEY`.

---

## Run it

```bash
python steamscope.py
```
This opens the interactive console:

```
steamscope > check
steamscope > use footprint
steamscope (recon/footprint) > set TARGET gabelogannewell
steamscope (recon/footprint) > run
steamscope (recon/footprint) > export reports
```

**Valid targets**

| Format | Example |
|---|---|
| SteamID64 | `76561198000000000` |
| Profile URL | `https://steamcommunity.com/id/gabelogannewell` |
| Vanity name | `gabelogannewell` |
| Steam2 | `STEAM_0:1:23071901` |
| Steam3 | `"[U:1:46143802]"` (quote it) |

> The *display name* shown on a profile cannot be used as a target - Steam has no search by display name and names are not unique. Use the profile URL / vanity / ID.

---

## Console command reference

Type `help` for the full list, or `help <command>` for details. TAB completes commands, modules and option names.

| Command | Purpose |
|---|---|
| `show modules` / `use <module>` / `back` / `info` | Browse and select modules |
| `show options` / `set NAME value` / `unset NAME\|all` | View and change settings |
| `run` (`go`, `exploit`) | Run the selected module |
| `scan <target>` / `resolve <target>` / `compare <a> <b>` | One-line shortcuts |
| `last` / `export [dir] [formats]` | Re-display / save the last result |
| `note <text>` / `notes` | Add analyst notes (saved inside reports) |
| `check` | Test connectivity and keys |
| `keys` / `save` | Show (masked) / persist keys |
| `theme <colour>` / `banner` / `about` / `tips` / `stats` / `history` / `clear` / `exit` | Utilities |

**Modules**

| Module | What it runs |
|---|---|
| `recon/full` | Everything: profile, bans, games, network, inventory, off-Steam |
| `recon/network` | Friend network graph |
| `recon/footprint` | Off-Steam only (search, handles, OpenDota/FACEIT, Wayback, Discord) |
| `recon/inventory` | Profile + public inventory |
| `recon/resolve` | ID conversion |
| `recon/compare` | Two targets: mutual friends, shared groups/games/past names |

---

## Options

| Option | Default | Description |
|---|---|---|
| `TARGET`, `TARGET2` | - | Target(s); `TARGET2` only for compare |
| `API_KEY` | - | Steam Web API key |
| `SEARCH_PROVIDER`, `SEARCH_KEY`, `GOOGLE_CX` | - | Web-search backend and key |
| `FACEIT_KEY` | - | FACEIT Data API key |
| `SAMPLE` | 40 | Friends whose friend lists are read for the graph |
| `FRIEND_GROUPS` | false | Also read friends' groups (slower) |
| `MAX_QUERIES` | 12 | Web searches per scan (each costs search credit) |
| `MAX_HANDLES` | 4 | Handles checked on other platforms (0 = off) |
| `LIBRARY_VALUE` | false | Estimate library list price |
| `INVENTORY_VALUE`, `MAX_PRICE_LOOKUPS` | false, 40 | Market valuation (slow, rate-limited) |
| `APPID`, `CONTEXT`, `CURRENCY` | 730, 2, 1 | Inventory app / context / market currency |
| `OUT`, `FORMAT` | -, json,html,csv | Auto-export directory and formats |
| `NO_CACHE`, `VERBOSE` | false | Cache and logging |

---

## Command-line mode

```bash
python steamscope.py scan gabelogannewell --out reports
python steamscope.py scan "https://steamcommunity.com/id/gabelogannewell" --max-queries 20 --max-handles 6
python steamscope.py scan 76561198000000000 --friend-groups --library-value --out reports
python steamscope.py compare vanityA vanityB --out reports
python steamscope.py resolve "[U:1:46143802]"
python steamscope.py --help
```
Add `--no-banner` to hide the logo, `--no-offsteam` to skip all off-Steam modules.

---

## Output and reports

With `--out reports` (or `export`) the tool writes:

- `steam_<id>_<time>.json` - full structured data
- `steam_<id>_<time>.html` - self-contained report with network graph and analyst notes
- `..._summary.csv`, `_games.csv`, `_groups.csv`, `_names.csv`, `_friends.csv`, `_inventory.csv`, `_web_results.csv`, `_handles.csv`, `_search_queries.csv`, `_pivots.csv`

CSV cells starting with `= + - @` are neutralised to prevent spreadsheet formula injection.

---

## How to read the results

- **Web results** are scored by evidence. An exact SteamID / Steam2 / Steam3 / profile-URL match is strong; a unique vanity is medium-strong; a short or common name is weak. Two independent matches raise the score. `high` ≥ 6, `medium` ≥ 3, otherwise `low`.
- **Handle footprint verdicts**
  - `corroborated` - the other account's public data references this exact Steam profile.
  - `plausible` - it mentions a linked handle or the same real name.
  - `unverified` - same handle only; **not** evidence of the same person.
  - `conflict` - it references a *different* Steam profile, so it is probably someone else.
- **Account age** is exact when the profile is public; otherwise an interpolation from the account number (±1-2 years, heuristic).
- **Inventory value** is a *lower bound* (only the most numerous marketable items are priced, at the lowest current listing).
- **Library value** uses current store list prices, not what the user paid.

---

## Limitations

- The friend-network graph is built from a **sample** of readable friend lists, so centrality is an approximation.
- Steam and third parties change endpoints without notice; some modules may break and degrade to a warning.
- Search quality depends on your search provider; free tiers are small.
- The program was developed and tested with unit tests and simulated responses; real-world behaviour depends on live services. Please open an issue with the full error text if something fails.

---

## Transparency: what the program contacts

SteamScope is **one readable Python file** (`steamscope.py`) with no obfuscation, no telemetry, no auto-update and no remote code loading. Your keys are sent only to the service they belong to. You are encouraged to verify this yourself:

```bash
# risky calls - the only match should be the 'clear' command
grep -nE "\beval\(|\bexec\(|subprocess|os\.system|base64|pickle|__import__" steamscope.py

# every domain the code can contact
grep -oE "https?://[a-zA-Z0-9._-]+" steamscope.py | sort -u
```

Services used: `api.steampowered.com`, `steamcommunity.com`, `store.steampowered.com`, `web.archive.org`, `discord.com` (public invite API), `api.opendota.com`, `open.faceit.com`, `api.github.com`, `www.reddit.com`, `keybase.io`, `gitlab.com`, `api.chess.com`, `lichess.org`, `hacker-news.firebaseio.com`, `dev.to`, `hub.docker.com`, `www.speedrun.com`, `en.gravatar.com`, `users.roblox.com`, and your chosen search provider (`google.serper.dev`, `serpapi.com`, `api.search.brave.com`). Other URLs in the code are only *links printed for you to open yourself*.

Local files: config at `~/.steamscope.json` (permissions set to owner-only on Unix), cache at `~/.cache/steamscope`. Delete them any time.

---

## Troubleshooting

| Message | Fix |
|---|---|
| `Missing dependency: pip install requests rich` | Run `pip install -r requirements.txt` |
| `API key problem` / HTTP 403 | Wrong key: `set API_KEY ...`, then `check` |
| `Rate limited` / HTTP 429 | Wait a few minutes; lower `SAMPLE`, `MAX_QUERIES`, `MAX_HANDLES` |
| `private/hidden` warnings | The user's privacy settings hide that data - expected |
| `Web search skipped` | No search key set; configure one or use the generated manual links |
| Garbled logo on old Windows `cmd` | Use Windows Terminal |

---

## License and copyright

Copyright (c) 2026 **G4wlll**. Released under the [MIT License](LICENSE): you may use, copy, modify and distribute the software free of charge, provided the copyright notice and licence text are kept. The software is provided "as is", without warranty of any kind.

Steam is a trademark of Valve Corporation. SteamScope is an independent project and is not affiliated with, endorsed by, or sponsored by Valve or any service it queries.

---

<div align="center">

**Verify, don't trust: read the source, run the audit commands above, and use it responsibly.**

Developed by **G4wlll**

</div>
