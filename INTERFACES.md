# Lazarus — Module Interface Contract
All modules are pure stdlib Python (3.10+; CI uses 3.11).
Every function must be importable standalone and unit-testable without network.

---

## harvester.py

```python
def harvest_npm(max_packages: int = 500) -> list[dict]
# Paginates https://registry.npmjs.org/-/v1/search?text=popularity:1&size=250&from=N
# Each item: {"package": str, "maintainers": [{"name": str, "email": str}],
#             "dependents": int, "downloads_week": int}
# Emails come from the search API (verified present). dependents is a string in the
# API — parse to int. Downloads from api.npmjs.org/downloads/point/last-week/<pkg>
# (bulk-comma endpoint verified: 51 pkgs in one call).

def harvest_pypi(max_packages: int = 200) -> list[dict]
# Seed from https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json
# (301 redirects — use curl -L equivalent, urllib follows by default).
# Per package fetch https://pypi.org/pypi/<pkg>/json, extract free-text
# maintainer_email / author_email strings via regex <email@domain>.
# Each item: {"package": str, "maintainer_emails": [str], "downloads": int|None}

def extract_domains(emails: list[str]) -> list[str]
# Split on @, lowercase, dedupe. Free-mail providers (gmail.com, outlook.com,
# yahoo.com, proton.me, protonmail.com, icloud.com, hotmail.com, live.com,
# gmx.de, mail.ru, qq.com, 163.com, yandex.ru) are EXCLUDED — they can't expire.
```

## rdap.py

```python
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

def resolve_domain(domain: str) -> dict
# IANA bootstrap → pick server for the TLD → GET <server>/domain/<DOMAIN>
# Returns: {"domain": str, "registered": bool, "created": str|None,
#           "expires": str|None, "status": [str], "error": str|None}
# 404 → registered=False. Parse events[] for registration/expiration.
# Never raises — network errors become {"error": ...}.

def resolve_domains(domains: list[str], cache_path: str, concurrency: int = 8) -> list[dict]
# ThreadPoolExecutor, SQLite/JSON cache keyed on domain, never re-fetches.
# Polite: 0.1s stagger, User-Agent "lazarus-research/1.0 (contact: <email>)",
# retry once on 5xx/timeout, then error field.
```

## scorer.py

```python
def score_finding(finding: dict) -> dict
# Input: {"domain": str, "packages": [str], "dependents": int,
#         "downloads_week": int, "rdap": {...}, "maintainers": [str]}
# Output: {"risk": int 0-100, "severity": "CRITICAL|HIGH|MEDIUM|LOW",
#          "signals": [str], "reasoning": [str]}
#
# Scoring rules (deterministic, testable):
#   domain not registered (registered=False, no error)  -> +60  "domain unregistered"
#   created < 180 days ago (re-registered!)             -> +50  "recently re-registered"
#   expires < 90 days                                    -> +35  "expiring soon"
#   expires < 30 days                                    -> +15  (extra)
#   dependents >= 1000                                   -> +20
#   dependents >= 100                                    -> +10
#   downloads_week >= 100000                             -> +10
#   maintainer dormant (no publish 24mo — pass flag in)  -> +15
#   MX present + re-registered                           -> +10  (needs DNS check)
# Cap at 100. severity: >=80 CRITICAL, >=60 HIGH, >=35 MEDIUM, else LOW.

def severity_label(risk: int) -> str
```

## judge.py

```python
class Judge:
    def __init__(self, backend: str = "auto"):  # "auto"|"gemini"|"ollama"|"offline"
        # auto: GEMINI_API_KEY env → gemini; else localhost:11434 → ollama; else offline
    def narrate(self, finding: dict) -> dict
        # Returns {"verdict": str one-line, "narrative": str 2-4 sentences,
        #          "recommendation": str}
        # NEVER raises. Offline mode returns a template-generated narrative
        # built from finding["signals"] — deterministic, still useful.
    def is_live(self) -> bool  # False in offline mode
```

Gemini path: POST https://generativelanguage.googleapis.com/v1beta/models/gemma-4-31b-it:generateContent
  header x-goog-api-key, body {"contents":[{"parts":[{"text": prompt}]}]}
  Model id configurable, default gemma-4-31b-it, fallback gemma-4-26b-a4b-it.
Ollama path: POST http://localhost:11434/api/generate {"model":"gemma3:4b","prompt":...,"stream":false}
Offline: template from signals.

## graph.py

```python
def build_graph(findings: list[dict]) -> dict
# {"nodes": [{"id","type","label","risk"}], "edges": [{"source","target","label"}]}
# types: "domain", "maintainer", "package". domain→maintainer "hosts email",
# maintainer→package "maintains". Node risk propagated from domain score.
```

## skill_loader.py

```python
def load_skill(path: str) -> dict
# Parse SKILL.md YAML frontmatter (no PyYAML — hand-rolled minimal parser,
# or fallback line parser). Validate name rules per the Agent Skill Open Standard.
# Returns {"name","description","license","metadata","allowed_tools","body","scripts":[...]}
# name must match parent directory, lowercase+hyphens, <=64 chars.

def run_script(skill_dir: str, script_name: str, args: list[str]) -> dict
# subprocess.run, cwd=skill_dir/scripts, timeout=30, returns {stdout,stderr,code}
```

## app.py (stdlib http.server)

```python
# GET /                  -> static/index.html
# GET /api/skills        -> bundled fixture skills (name + description)
# GET /api/findings      -> the scan results (from the last run, in-memory + JSON file)
# GET /api/graph         -> build_graph(findings)
# POST /api/narrate      -> body {domain} -> judge.narrate(finding)
# GET /api/run           -> SSE stream of a scan run (progress events + findings)
# GET /api/cached        -> a full pre-seeded run (demo insurance, no API needed)
```

## static/index.html
Vanilla JS + EventSource. Dark, monospace numbers. No external assets.
States: loading (skeletons), live (streaming cards), degraded (banner), no-key (cached).
