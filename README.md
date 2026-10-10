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
every registry account still using it.

This is not hypothetical. In **May 2026** the popular npm package **`node-ipc`**
(424 dependents, ~658k weekly downloads) was compromised exactly this way: a
dormant maintainer's email domain, `atlantis-software.net`, had expired in
**January 2025**, was **re-registered on 2026-05-07** (RDAP-verified), and
seven days later — **2026-05-14** — three trojaned versions (`9.1.6`, `9.2.3`,
`12.0.1`) shipped with a credential stealer. The attacker did not target
node-ipc; they swept npm for accounts with custom-domain emails, found expired
ones, and took whatever was available.

Lazarus treats maintainer email domains as attack surface: harvest them, check
their registration health via RDAP, score the takeover risk, and have a
language model reason over the evidence.

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

Requires **Python 3.10+** (tested on 3.11). No pip installs. No build step.

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
| `HOST` | `127.0.0.1` | bind address (loopback — a security tool should not listen on the venue network) |
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

`data/cached_run.json` is a **seeded** run, not a live scan — it is a replay so
the demo works with no API key and no network. The dashboard shows a visible
**REPLAY** badge whenever it is rendering seeded data, and labels live runs
**LIVE**. The `atlantis-software.net` finding is the real, RDAP-verified case
(created 2026-05-07, expires 2027-05-07, hosting the `node-ipc` maintainer
`atiertant`, scored by the real scorer at the attack date); the other six are
realistic companions so the dashboard has range. Each seeded finding carries a
pre-written narrative so the "Narrate with Gemma" flow renders instantly
offline.

## Credits & further reading

- **The node-ipc compromise (May 2026)** — a dormant maintainer account
  (`atiertant`) was taken over via the expired domain `atlantis-software.net`;
  three malicious versions (`9.1.6`, `9.2.3`, `12.0.1`) were published
  2026-05-14. Registration date RDAP-verified as 2026-05-07. This is the
  incident the seed case is modelled on. (Sources: CSO Online, Snyk,
  StepSecurity, Socket — all May 2026.)
- **Backstabber's Knife Collection** — Ohm, Plate, Sykosch, Meier,
  *DIMVA 2020* ([arXiv:2005.09535](https://arxiv.org/abs/2005.09535)) — the
  academic corpus of malicious npm/PyPI packages that grounds this project's
  threat model in published research.
- **IANA RDAP bootstrap** — <https://data.iana.org/rdap/dns.json>.
- **Gemma / Gemini** — the reasoning/narration model. Narration runs via the
  free Gemini API (Gemma 4), a local Ollama fallback, or a deterministic
  offline template; the model actually used is reported per-run.
- **MLH Hacktoberfest** — hackathon home.

## License

MIT — see [LICENSE](LICENSE).
