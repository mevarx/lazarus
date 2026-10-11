# Lazarus

Lazarus watches the email domains behind npm and PyPI maintainer accounts. A
maintainer who lets their email domain lapse can lose their registry account to
whoever registers the domain next, because the registry's password-reset email
goes to the new owner. Lazarus finds those domains, checks them against public
registration data, scores the risk with fixed rules, and can ask a Gemma model
for an independent second opinion plus a draft disclosure email.

**Risk flags are heuristics, not proof of compromise.** See [Limitations](#limitations).

- Backend: Python standard library only (`http.server`), no dependencies.
- Frontend: hand-written HTML, CSS and JS in `static/`, no build step, no external assets.
- License: MIT.

## The two node-ipc incidents are different

| | March 2022 | May 2026 |
|---|---|---|
| What happened | The maintainer deliberately published code that harmed machines at Russian and Belarusian IP addresses, as a protest. | Malicious versions were published to `node-ipc` after the maintainer account was reportedly taken over. |
| Expired-domain takeover? | **No.** | **Reported**; the mechanism is described as a hypothesis by the sources we read. |
| Affected versions | 10.1.1 and 10.1.2 (CVE-2022-23812, [OSV](https://osv.dev/vulnerability/CVE-2022-23812)) | 9.1.6, 9.2.3, 12.0.1, published 2026-05-14 (npm registry timestamps) |
| Relevance to Lazarus | None. It is protestware, not a domain takeover. | The case Lazarus is built around. |

For May 2026, what we verified ourselves is in
[`data/backtest/node_ipc_timeline.json`](data/backtest/node_ipc_timeline.json):

- The `.net` registry RDAP record for `atlantis-software.net` shows a registration event at **2026-05-07T11:49:33Z** ([Verisign RDAP](https://rdap.verisign.com/net/v1/domain/atlantis-software.net)).
- The npm registry shows the three malicious versions published on **2026-05-14** ([registry](https://registry.npmjs.org/node-ipc)).
- **Reports disagree on the re-registration date.** A [Depi post](https://www.linkedin.com/posts/depi-security_activity-7460796467608338433-y4wJ) says March 10; RDAP shows May 7. The current RDAP record shows no March 10 event (and cannot show earlier expiry or deletion), so March 10 is **unverified**. See also [StepSecurity](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack).

## How it works

1. **Harvest** maintainer email domains from the npm search API, PyPI metadata, or a lockfile. Free-mail providers are excluded.
2. **RDAP** looks up each domain through the IANA bootstrap (`data.iana.org/rdap/dns.json`). Failures become an `error` field, never an exception.
3. **Score** with fixed rules (`scorer.py`), giving 0-100 and a severity:

   | Signal | Points |
   |---|---|
   | Domain unregistered | +60 |
   | Created < 180 days ago (possible re-registration) | +50 |
   | Expires < 90 days / additionally < 30 days | +35 / +15 |
   | Dependents >= 1000 / >= 100 | +20 / +10 |
   | Weekly downloads >= 100,000 | +10 |
   | Maintainer dormant (no publish in 24 months) | +15 |
   | MX present on a recently re-registered domain | +10 |

   Capped at 100. **CRITICAL >= 80, HIGH >= 60, MEDIUM >= 35, otherwise LOW.**
4. **Verify** (`verify.py`, used by the unattended harvest). Every CRITICAL or HIGH finding is cross-checked with independent DNS NS/SOA/MX lookups (Google DNS-over-HTTPS) and a second RDAP server where one exists. A finding is marked `needs_manual_check` and its `verified_severity` becomes `UNVERIFIED` when RDAP errored, the TLD has no bootstrap entry, RDAP says not-found but DNS shows the domain, the second RDAP disagrees, or DNS cannot corroborate. **"Confirmed" means the RDAP facts were corroborated, not that a takeover is likely.**
5. **Compare** (`compare.py`, `GET /api/compare`). The dashboard shows the rules score next to a Gemma assessment that is given only the raw evidence, never the rules verdict. Agreement is `agree` (same severity), `partial` (one level apart), `disagree` (two or more apart), `not_independent` (the offline template only restates the rules), or `unavailable`.

### Which model answers

`judge.py` tries, in order, and reports what actually answered (`provider.label`, model id, family, and any fallback chain):

1. **Gemma 4 on the Gemini API**, when `GEMINI_API_KEY` is set. Model IDs come from a `ListModels` call; if that call fails, the two IDs documented by Google ([Run Gemma with the Gemini API](https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api)) are used and the result is marked `models_verified: false`. Those IDs are `gemma-4-31b-it` and `gemma-4-26b-a4b-it`. If `ListModels` succeeds but lists no Gemma 4 model, Lazarus does not guess an ID and moves to the next provider.
2. **Local Ollama**, default `gemma3:4b` (override with `OLLAMA_MODEL`). This is **Gemma 3** and is labelled that way everywhere.
3. **Offline template**, a deterministic restatement of the rules. No model runs.

HTTP 429 and 5xx responses are retried with exponential backoff and `Retry-After`; other 4xx errors move straight to the next provider. **The live Gemini path has not been exercised in the development environment (no API key was available), so it is tested with mocks only.**

## LIVE vs REPLAY

| | REPLAY | LIVE |
|---|---|---|
| Data | `data/cached_run.json`, recorded from public sources | Real harvest, RDAP and scoring when you click **Run scan** with *Live scan* selected (`/api/run?live=1`) |
| Network | None | npm / PyPI / RDAP, rate-limited and cached |
| Needs a key | No | No (a Gemma assessment needs a key or Ollama; otherwise the offline template answers) |
| UI label | `REPLAY - recorded data, not a live scan` | `LIVE` |

The dashboard opens on REPLAY data. Note that `/api/run` called with no parameters attempts a live scan; the dashboard always passes `live=1` or `replay=1` explicitly. REPLAY contains three rows (see [Measured results](#measured-results)); nothing in it is re-measured when replayed. `/api/run?replay=1` (or `demo=1`) forces it; a failed live scan falls back to it and says so.

## Run it

Python 3.10+, no installs:

```bash
python3 app.py            # http://127.0.0.1:8741
python3 -m unittest discover -s tests
```

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. The API has no authentication; a non-loopback value prints a warning. |
| `PORT` | `8741` | Bind port |
| `GEMINI_API_KEY` | unset | Enables Gemma 4 on the Gemini API. Never logged, returned, or committed. |
| `OLLAMA_MODEL` | `gemma3:4b` | Local fallback model |
| `LAZARUS_LIVE` | unset | `1` forces `/api/run` to run live even when replay is requested |
| `LAZARUS_MAX_UPLOAD_BYTES` | 2,000,000 | Cap on a pasted lockfile |
| `LAZARUS_MAX_SCAN_DEPS` | 200 | Cap on dependencies per scan |

### API

| Route | Method | Returns |
|---|---|---|
| `/api/status` | GET | mode, provider, limits (no secrets) |
| `/api/findings`, `/api/cached` | GET | findings with stats and blast radius (maintainers are placeholders) |
| `/api/compare?domain=` | GET | rules vs Gemma comparison for one finding |
| `/api/graph`, `/api/skills` | GET | dependency graph, bundled skills |
| `/api/run` | GET (SSE) | scan stream: `start`, `progress*`, `finding*`, `done` |
| `/api/scan-repo` | POST | scan a pasted `package.json` / lockfile |
| `/api/narrate`, `/api/analyze`, `/api/triage` | POST | Gemma narrative / structured analysis / ranking |

Input is validated (hostnames, JSON shape), bodies are size-capped, AI and scan routes are rate-limited per client, and responses carry a strict CSP.

### Blast radius

The blast-radius figures count **only CRITICAL and HIGH domains**; MEDIUM and LOW never contribute. This is enforced in `app.blast_radius` (the threshold is not a parameter) and by tests. Values that could not be verified (for example dependents) are reported as unverified, not as zero.

### CLI and GitHub Action

```bash
python3 lazarus.py check package-lock.json      # or package.json, or "-" for stdin
python3 lazarus.py check package-lock.json --json
```

Exit codes: **0** no CRITICAL finding, **1** at least one CRITICAL, **2** usage or input error. Output never prints maintainer names or email addresses (the domain itself is shown). `.github/workflows/lazarus.yml` runs the tests and the check, fails the job on exit 1 or 2, and has a warn-only input. The workflow has not been run on GitHub from this repository's development environment.

### Skills

`skills/domain-triage` and `skills/domain-expiry-check` follow the Agent Skills format and validate with `agentskills validate` (from the `skills-ref` package).

## Measured results

Everything here is from files in this repository; nothing is estimated. All numbers are point-in-time (2026-10-11).

**Unattended harvest** (`tools/harvest_all.py`, output `data/harvest.json`): the 100 most popular npm search results, **60** maintainer domains found.

| Severity | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| Domains | 1 | 4 | 5 | 50 |

Of the 5 CRITICAL/HIGH domains, **4 were confirmed and 1 needs a manual check** (its TLD has no IANA RDAP bootstrap entry). The committed file withholds domain and package names for these findings; the full record stays in a gitignored local file. All five were flagged because long-registered domains of very popular packages were within roughly 90 days of their listed expiry date, not because of a re-registration. Whether they renew is not known.

**Backtest** (`tools/backtest.py`, output `data/backtest/results.json`): the labeled set has **N = 21** scorable rows: **1 positive** (node-ipc, May 2026) and **20 negatives** (long-registered domains, 3 of them registered in 2022-2024). Three incidents were documented; only one could be reconstructed from verified data, and the others are listed but excluded (`ctx`, because the current RDAP date postdates the 2022 attack; and a 2023 researcher demonstration that names no domain).

| Rules only | Precision | Recall | Confusion matrix |
|---|---|---|---|
| HIGH or above | 1.00 | 1.00 | TP 1, FP 0, FN 0, TN 20 |
| CRITICAL only | undefined (no predictions) | 0.00 | TP 0, FP 0, FN 1, TN 20 |

With one positive, these figures say almost nothing about real-world performance. The node-ipc row scores HIGH (60), not CRITICAL, because its dependents and dormancy are unverified and scored as zero. **Gemma-assisted: not measured.** No `GEMINI_API_KEY` was available, and nothing was simulated.

**Replay data** (`data/cached_run.json`): 3 rows, 1 HIGH (node-ipc) and 2 LOW (stable control domains). There are no CRITICAL or MEDIUM rows because no verified row scores there.

## Limitations

- **Flags are not proof.** An expiring or recently registered domain is a precondition for takeover, not evidence of one. Two-factor authentication and registrar grace periods can prevent a takeover.
- **RDAP gaps.** Some TLDs have no RDAP bootstrap entry, and some registries return errors or not-found for registered domains. The verifier flags these as `needs_manual_check` rather than guessing.
- **Small test sets.** The backtest has one positive. The harvest is the top 100 npm packages, not the ecosystem. Negatives are "not documented as compromised", not "proven safe".
- **Reconstruction.** Backtest RDAP values were fetched in October 2026 and applied to a May 2026 date. This is sound only because the registration event predates that date. Historical downloads, dependents, dormancy and MX records were not available.
- **Gemma 4 live behaviour is unverified** in this repository's environment; see above.
- Only domains that appear in registry metadata are checked. Maintainers with no public email are not covered.

## Responsible disclosure

Lazarus drafts a disclosure email but never sends one; there is no mail-sending code. Do not publish at-risk maintainer names or unredacted addresses. API responses, the CLI, logs, and committed data replace maintainers with placeholders, and the committed harvest omits domain and package names. If you find a genuinely at-risk domain, tell the maintainer and the registry's security contact privately, and give them time to move their account email before any public write-up.

## References

- M. Ohm, H. Plate, A. Sykosch, M. Meier. *Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks.* DIMVA 2020 (17th International Conference, Lisbon, June 24-26, 2020). [arXiv:2005.09535](https://arxiv.org/abs/2005.09535). Verified: arXiv lists these four authors and a 19 May 2020 submission.
- node-ipc 2022 protestware: [OSV / GHSA-97m3-w2cp-4xx6](https://osv.dev/vulnerability/CVE-2022-23812), [Snyk](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/).
- node-ipc 2026: the sources listed in [`data/backtest/node_ipc_timeline.json`](data/backtest/node_ipc_timeline.json).
- [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json), [Gemma on the Gemini API](https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api).

[MIT](LICENSE)
