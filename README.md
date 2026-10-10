# Lazarus — expired-domain supply-chain watch

> Maintainer email domains expire, lapse, and get quietly re-registered by
> strangers. Lazarus finds them before someone else does — and explains the
> risk in plain English.

Built for **MLH Hacktoberfest** at **SRM University AP, India**. Pure Python
stdlib backend, single-page vanilla-JS dashboard, zero external assets.

## The problem

npm and PyPI packages are published by people, and people identify themselves
with email addresses. Those addresses live on domains — small side-project
domains that expire, lapse for a month, and get registered by whoever notices.
Once an attacker controls the domain, they control the password reset flow for
every registry account still using it. This is not hypothetical: the March 2022
**node-ipc incident** saw a hugely-depended-upon package turned into
protestware that wiped files on developer machines. Lazarus treats maintainer
email domains as attack surface: harvest them, check their registration health
via RDAP, score the takeover risk, and have a language model narrate what it
means.

## What it does

1. **Harvest** — pull maintainer emails from the npm search API and the PyPI
   top-packages list, extract unique domains (free-mail providers excluded —
   gmail.com and friends cannot expire).
2. **RDAP** — resolve each domain through the IANA RDAP bootstrap: registered?
   created when? expires when? never raises — network failures become an
   `error` field.
3. **Score** — deterministic, testable rules (unregistered domain, recent
   re-registration inside 180 days, expiry under 90/30 days, dependent count,
   weekly downloads, maintainer dormancy) producing a 0–100 risk score and a
   CRITICAL/HIGH/MEDIUM/LOW severity.
4. **Narrate** — [Gemma](https://ai.google.dev/gemma) writes the plain-English
   verdict, narrative, and recommendation, via the free Gemini API (key),
   a local Ollama `gemma3:4b`, or a deterministic offline template when
   neither is available.

## Architecture

```
browser (static/index.html, vanilla JS + EventSource)
    |
    |  GET /api/run  ── SSE: start -> progress* -> finding* -> done
    |  GET /api/findings, /api/graph, /api/cached, /api/skills
    |  POST /api/narrate
    v
app.py  ── stdlib http.server (ThreadingHTTPServer), no dependencies
    |
    ├── harvester.py   npm search API + PyPI top-packages -> domains
    ├── rdap.py        IANA RDAP bootstrap -> registration/expiry (cached)
    ├── scorer.py      deterministic risk rules -> 0-100 + severity
    ├── graph.py       domain -> maintainer -> package graph
    ├── judge.py       Gemma: Gemini API | Ollama | offline template
    └── skill_loader.py  bundled agent skills (SKILL.md)
```

Every module is pure stdlib, importable standalone, and unit-testable without
network. The module contract lives in `INTERFACES.md`.

## How to run

Requires **Python 3.10+** (project standard: `python` = 3.11, which has the
needed packages; `python3` = 3.13 has zero packages on this machine). No pip
installs. No build step.

```bash
cd lazarus
python app.py
# then open http://localhost:8741
```

The dashboard boots instantly from the seeded run in `data/cached_run.json` —
**no API key and no network required** — and live-streams a fresh scan on load
via SSE. `Run scan` restarts the stream at any time.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `0.0.0.0` | bind address |
| `PORT` | `8741` | bind port |
| `GEMINI_API_KEY` | — | enables live Gemma narration via the free Gemini API |
| `LAZARUS_LIVE` | — | `1` forces the real harvest/RDAP pipeline on `/api/run` |

`GET /api/run?demo=1` replays the seeded run; `?live=1` forces the real
pipeline. Without the harvester/rdap/scorer modules (or when they fail on a
dead venue network), the run falls back to the seeded replay automatically —
the demo never goes dark.

## API

| Route | Method | Returns |
|---|---|---|
| `/` | GET | the dashboard (`static/index.html`) |
| `/api/skills` | GET | bundled fixture skills (name + description) |
| `/api/findings` | GET | last run (in-memory + `data/last_run.json`), else the seeded run |
| `/api/graph` | GET | `build_graph(findings)` — nodes + edges |
| `/api/cached` | GET | the full pre-seeded run — works with no key, no network |
| `/api/narrate` | POST | `{"domain": "..."}` → verdict / narrative / recommendation |
| `/api/run` | GET | SSE scan stream: `start`, `progress*`, `finding*`, `done` |

## Demo data

`data/cached_run.json` is a full pre-seeded scan: 7 realistic findings across
npm and PyPI, including the **atlantis-software.net** case — created
2026-05-07, expires 2027-05-07, hosting the `node-ipc` maintainer email,
scored HIGH (75) for recent re-registration plus a dormant maintainer. Each
finding carries a pre-written narrative so the "Narrate with Gemma" flow
renders instantly even offline.

## Credits & further reading

- **The node-ipc incident (March 2022)** — the maintainer of `node-ipc`
  (alongside `colors.js`) shipped protestware that destroyed files on affected
  machines. The canonical reminder that maintainer identity and domain control
  *are* supply-chain control; the seed case in this project is modelled on it.
- **Backstabber's Knife Collection** — Vu et al., ACSAC 2020
  ([arXiv:2002.01117](https://arxiv.org/abs/2002.01117)) — the academic corpus
  of malicious npm/PyPI packages. The threat-modeling and research framing of
  this project follows the same open, reproducible style used by industry
  security research labs such as NVIDIA's AI Red Team.
- **IANA RDAP bootstrap** — <https://data.iana.org/rdap/dns.json>.
- **Gemma / Gemini** — narration models; Gemini's free tier is reachable from
  India (~64 ms verified), with a local Ollama fallback and an offline
  template beyond that.
- **MLH Hacktoberfest** — hackathon home.

## License

MIT — see [LICENSE](LICENSE).
