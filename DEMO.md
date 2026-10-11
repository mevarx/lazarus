# Lazarus demo guide (2 minutes)

Everything below works with no network and no API key. Say plainly which mode you are in; the dashboard shows it.

## Before you start (30 seconds)

```bash
python3 app.py                      # http://127.0.0.1:8741
curl -s localhost:8741/api/status   # mode, provider, limits; no secrets
```

Open `http://127.0.0.1:8741`. The header should read **REPLAY - recorded data, not a live scan**. Optional, only if you have them: `export GEMINI_API_KEY=...` before starting (Gemma 4 on the Gemini API), or a running local Ollama (answers as **Gemma 3**).

Have a second terminal ready for the RDAP check in step 3:

```bash
curl -s https://rdap.verisign.com/net/v1/domain/atlantis-software.net | python3 -m json.tool | grep -A2 '"registration"'
```

## Click-path

| Time | Do | Say |
|---|---|---|
| 0:00 | Point at the header badge and the three KPI cards. | "Lazarus watches the email domains behind npm and PyPI maintainer accounts. If a domain lapses and someone else registers it, they can reset the registry password. This is REPLAY mode: recorded data, not a live scan." |
| 0:20 | Point at **Blast radius**. | "Only CRITICAL and HIGH domains count here; MEDIUM and LOW never do. Where a number could not be verified, it says unverified instead of showing zero." |
| 0:35 | Click `atlantis-software.net` in the table. | "This is the domain tied to the May 2026 node-ipc compromise. The rules engine scores it HIGH, 60: recently re-registered plus high downloads. Dependents and dormancy are unverified, so they count as zero." |
| 0:55 | Run the `curl` from the second terminal. | "That is the registry's own record: registered 2026-05-07 11:49 UTC. Malicious versions were published on 2026-05-14. One report says March 10 for the re-registration; RDAP does not show that, so I treat it as unverified." |
| 1:15 | Scroll to the comparison panel. | "Left: the rules score. Right: a Gemma assessment that only sees raw evidence, not our verdict, plus a drafted disclosure email. The chip says exactly what answered. Offline right now, so it says NOT INDEPENDENT: the template only restates the rules." |
| 1:35 | Point at the provider chip. If a key or Ollama was configured before you started, it names the model that answered. | "With a key this is Gemma 4 via the Gemini API; with Ollama it is labelled Gemma 3. It never claims Gemma 4 unless that model answered." |
| 1:50 | Select **Live scan** and click **Run scan** (only with network). | "LIVE does a real harvest and RDAP lookup. If the network fails it falls back to REPLAY and says so." |
| 2:00 | Stop. | "Flags are heuristics, not proof. The backtest has one positive; I will not claim accuracy from that." |

## If something breaks

| Failure | What to do |
|---|---|
| Network is down | Stay in REPLAY. It makes no network calls. Skip the RDAP curl and read the dates from `data/backtest/node_ipc_timeline.json`. |
| Gemini API returns 429 or 500 | Nothing to do: the judge retries with backoff, then tries the fallback Gemma 4 model, then Ollama, then the offline template. The chip and "fell back from" note show what happened. |
| No key, no Ollama | The offline template answers and the panel says NOT INDEPENDENT. Say so. |
| Server will not start | Check the port (`python3 app.py --port 8080`). Or demo the CLI: `python3 lazarus.py check examples/package-lock.json` (needs network) and `python3 -m unittest discover -s tests` (does not). |
| Page is blank | `curl -s localhost:8741/api/status`. If it answers, hard-refresh. |

## Likely judge questions

**Is the AI doing real work, or is it a wrapper?** The rules engine is deterministic and decides severity. Gemma is given only raw evidence and returns its own severity, cited evidence and a draft email; the panel shows whether they agree. When only the offline template ran, the panel says it is not independent. Whether Gemma-assisted detection beats rules-only is **not measured**: no API key was available for the backtest.

**Is that Gemma 4 or Gemma 3?** Whatever the chip says. Gemini API calls use Gemma 4 IDs (`gemma-4-31b-it`, `gemma-4-26b-a4b-it`); local Ollama defaults to `gemma3:4b`, which is Gemma 3. The live Gemini path has been tested with mocks only; I have not run it against the real API.

**How accurate is it?** On the labeled set (N=21: 1 incident positive, 20 controls) rules at HIGH+ got precision 1.0 and recall 1.0, but with a single positive that is anecdote, not evidence. At CRITICAL-only recall is 0. No false positives among the 20 controls.

**How many real findings did you get?** One harvest of the top 100 npm search results gave 60 domains: 1 CRITICAL, 4 HIGH, 5 MEDIUM, 50 LOW. Of the 5 CRITICAL/HIGH, 4 were corroborated by DNS and a second RDAP server and 1 needs a manual check. They were flagged for approaching expiry on very popular packages, not for a re-registration. I do not know whether they will renew, and I have not named them because the owners have not been told.

**Was node-ipc really an expired-domain takeover?** Reports describe it that way but call the mechanism a hypothesis. Verified by us: RDAP registration 2026-05-07 and npm publish times on 2026-05-14. Reports disagree on March 10 versus May 7; RDAP supports May 7 only. The March 2022 node-ipc incident was deliberate protestware by the maintainer and is unrelated.

**Is that the same as expired-domain tools that already exist?** I did not compare against other tools and will not claim a difference I have not tested.

**Could this leak maintainer emails?** API responses, CLI output, logs and committed data replace maintainers with placeholders. Tests assert this. Domain names of at-risk findings are withheld from the committed harvest.

**Does it send the disclosure email?** No. It drafts one for a human to review.

**What are the limits?** Heuristic flags, RDAP gaps (some TLDs have no bootstrap entry), a tiny labeled set, and historical values that could not be reconstructed. See the README Limitations section.
