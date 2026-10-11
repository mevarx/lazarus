# Status

Branch `hoplite/delphoi-0878d7cd`, 2026-10-11. Nothing here is a claim about a live Gemini call: none was possible (see Unverified).

## Done and tested

| Step | What | Evidence |
|---|---|---|
| 1 | Frontend is `static/` (served by `app.py`). The old `web/` Vite project was built on a third-party dashboard template, was never served, and has been removed. New UI has a rules-vs-Gemma comparison panel: rules score and severity beside Gemma's severity, cited evidence and draft email, an agreement badge, and a provider chip (`Gemma 4` / `Gemma 3` / `Offline template`, model id, fallback chain). The brand is Lazarus only. | `tests/test_static_ui.py` (no inline script, no `innerHTML` with data, no external URLs, no foreign brand strings). Headless-Chrome screenshots (replay, light theme, 390px width, agree/disagree/not-independent/Gemma 3 comparison variants) were taken by the UI work; I personally reviewed the replay dashboard and the disagree variant. Screenshots are not committed. |
| 2 | Default live model is Gemma 4 on the Gemini API (`gemma-4-31b-it`, then `gemma-4-26b-a4b-it`), discovered via `ListModels`; then Ollama (`gemma3:4b`, labelled Gemma 3); then the offline template. 429 and 5xx are retried with backoff and `Retry-After`. Attribution reports the model that actually answered. | `tests/test_judge.py`, `tests/test_compare.py` (mocked transport). |
| 3 | Blast radius counts only CRITICAL and HIGH; the threshold parameter was removed. Null dependents/downloads are reported as unverified, not zero. UI and README state the rule. | `tests/test_blast_radius.py`, including every severity combination and a MEDIUM-never-counted case. |
| 4 | `verify.py` cross-checks every CRITICAL/HIGH finding with DNS NS/SOA/MX (Google DNS-over-HTTPS) and a second RDAP server; flags `needs_manual_check` for RDAP errors, missing bootstrap entries, not-found-but-in-DNS, disagreement, or DNS failure. `data/harvest.json` has confirmed vs uncertain counts and no maintainer data or at-risk names. | `tests/test_verify.py`, `tests/test_harvest_all.py`. Real run: 100 npm packages, 60 domains, 1 CRITICAL / 4 HIGH / 5 MEDIUM / 50 LOW; 4 confirmed, 1 uncertain (missing TLD bootstrap). |
| 5 | Backtest on a labeled set of N=21 (1 positive, 20 negatives, 3 "harder"). Rules HIGH+: precision 1.00, recall 1.00; CRITICAL-only: recall 0.00, precision undefined. node-ipc timeline in `data/backtest/node_ipc_timeline.json` with the March 10 vs May 7 disagreement. | `tests/test_backtest.py`; `python3 tools/backtest.py --offline-only`. |
| 6 | Loopback default, Host-header check, CSP and security headers, 2 MB lockfile cap, input validation, per-client rate limits, scan concurrency cap, RDAP/npm/PyPI rate limiting, caching, timeouts and response-size caps, key scrubbing in logs and errors, `.gitignore` secret rules. | `tests/test_security.py` (includes a git-ignore check, a tracked-secrets scan, and a fake key that must never appear in responses or logs), `tests/test_rdap.py`, `tests/test_harvester.py`. |
| 7 | CLI exit codes 0 / 1 / 2; workflow now propagates exit codes; skills validate; fresh-clone run. | See below. |
| 8-9 | README rewritten, `DEMO.md` and this file added. | Commands in `DEMO.md` were run. |

**Test suite:** 386 tests, all passing (`python3 -m unittest discover -s tests`). The original 256 are still present. Assertions were changed in two places, both because behaviour intentionally changed: the judge's `narrate()` result may now carry extra provenance keys (the check is now "contains the three original keys" instead of "equals them"), and `mask_email` now masks the whole local part.

**Step 7 detail**
- Skills: `agentskills validate skills/domain-expiry-check` and `... skills/domain-triage` both exit 0. The package is `skills-ref` 0.1.1 from PyPI, whose command is `agentskills` (there is no `skills-ref` executable). It was installed in a throwaway venv, not added to the project.
- CLI, measured: no arguments 2; missing file 2; invalid JSON on stdin 2; empty dependency list 0; patched CRITICAL result 1; HIGH-only result 0.
- Fresh clone (`python3 tools/fresh_clone_check.py --branch hoplite/delphoi-0878d7cd`, commit `e4cd1b4`): **24/24 checks passed**: clone, 386 tests, app starts on 127.0.0.1, 18 route checks (every GET and POST route, plus invalid-input and 404 cases), CLI on `examples/package-lock.json` exit 0, CLI missing file exit 2, CLI no args exit 2. Run before the final comment-only `harvester.py` edit.

## Deviations worth knowing

- `PITCH.md` was deleted: it named the maintainer account, had a machine-specific path, a stale "227 tests" claim and an uncited statistic. `DEMO.md` replaces it.
- API responses now replace maintainers with `maintainer-N` placeholders. The replay data was rebuilt from verified sources only (3 rows: node-ipc HIGH, two LOW controls). The earlier seeded companions were fabricated or wrong (live RDAP showed several unregistered or different creation dates) and were removed.
- The offline mode is named `replay` end to end (`demo=1` is still accepted).
- node-ipc is kept as a **scorable** positive for the RDAP-derived signals only. The helper agent had excluded it because the takeover mechanism is reported as a hypothesis; I kept it because the registration event (2026-05-07) predates the 2026-05-13 as-of date, and recorded the caveats. This choice drives the only positive in the backtest.

## Unverified

- **Live Gemini behaviour**: `ListModels` and Gemma 4 generation were never run (no `GEMINI_API_KEY`). Model IDs come from Google's documentation page, and the code marks them `models_verified: false` when `ListModels` fails.
- **Ollama** path never ran (not installed here).
- **Gemma-assisted vs rules-only**: **not measured**. No numbers exist.
- **GitHub Action**: structure and shell logic are tested locally; it has not run on GitHub.
- **March 10** re-registration date (reported by one source; RDAP does not show it). Also unverified: the takeover mechanism, node-ipc dependents and dormancy, and historical downloads/MX for the as-of date.
- **Comparison panel with a real Gemma answer**: screenshots of agree/disagree/Gemma 3 states used canned API fixtures; the real `/api/compare` was only seen returning the offline template.
- "Confirmed" in the harvest means RDAP facts were corroborated, not that the domain is at risk. Whether the flagged domains renew is unknown.

## Needs a human

1. **Repo description**: the GitHub integration returned 403 on edit. Suggested text: *Expired-domain supply-chain watch for npm/PyPI maintainer email domains: RDAP + DNS checks, deterministic risk scoring, and an optional Gemma 4 (Gemini API) second opinion with local Ollama and offline-template fallbacks. Stdlib Python, MIT.* The current description still says narratives are written "with Gemma 4".
2. **Run with a key**: set `GEMINI_API_KEY`, check `/api/status` and `/api/compare`, run `python3 tools/backtest.py --judge gemini`, and update the README numbers.
3. **Disclosure**: the 5 CRITICAL/HIGH harvest findings are in the gitignored `data/harvest.local.json` inside this sandbox only. Re-run `python3 tools/harvest_all.py --npm 100` to regenerate, then decide who contacts them. No outreach was done.
4. **Git history**: the original commits (before `d060c54`) contain a maintainer handle and real maintainer email addresses from the old seed data. Removing them needs a history rewrite and force-push, which I did not do.
5. **Review** the `PITCH.md` removal and the node-ipc scorable decision above; no pull request was opened.
6. Open the dashboard in a real browser once, at desktop and phone width.
