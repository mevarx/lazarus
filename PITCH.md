# Lazarus — Demo Day Pitch Script
**Format:** MLH science fair, ~4 min per team per judge, 3 judges, stack-ranked. **Total pitch: 3:30, leaving 30s for questions.**

---

## 0. Before you walk up (30 seconds of setup)

- [ ] Terminal: `cd D:\CODING\lazarus && python app.py --port 8080` — **already running, dashboard open in a browser tab**
- [ ] Second tab: the live RDAP command ready to paste:
  `curl -s "https://rdap.verisign.com/net/v1/domain/ATLANTIS-SOFTWARE.NET"`
- [ ] If you have the key: `export GEMINI_API_KEY=*** done, so the narrative comes from Gemma 4 31B. Without it, local Gemma 3 narrates — the demo works either way, but say which one is live if asked.
- [ ] Phone: this file, in case you freeze.

**The one-sentence answer to "what is this?"** — *"We warn people when a trusted domain gets taken over by a stranger, before the attack happens."*

---

## 1. The hook (0:00–1:00) — problem first, no tech

> "Quick question. Your bank has your phone number. Years later you stop paying the bill, the number gets released, and a stranger buys it. Now the bank's calls go to the stranger — and the bank still trusts that number.
>
> That's what happens to software, with domains instead of phone numbers. A developer's email is `dev@mysite.com`. They forget to renew mysite.com. A hacker buys it, clicks 'forgot password' on their npm account, gets the reset email, and takes over the account — then ships poisoned code to everyone who depends on it.
>
> This isn't hypothetical. In May, a popular package called node-ipc was compromised exactly this way. A dormant maintainer's email domain expired. The attacker re-registered it on **May 7th** — and **seven days later** shipped three versions carrying a credential stealer that exfiltrates through DNS.
>
> Everything you need to know that attack was coming was sitting in a public database the whole time. Nobody was watching."

**Why this hook:** it's the phone-number analogy, not jargon. Judges who don't know what RDAP is will still follow it. The seven-day gap is the fact that makes them lean in.

---

## 2. The demo (1:00–2:30) — show, don't tell

**Step 1 — the headline (15s).**
Point at the dashboard. "This is the attack domain, atlantis-software.net, scored **95 out of 100, critical**. Five signals fired: recently re-registered, dormant maintainer, 424 dependents, 650 thousand weekly downloads, and mail servers live on a freshly registered domain."

**Step 2 — prove it's real public data (20s).**
Run the curl in the second tab. "That's not our database. That's the IANA public registry. Created May 7th 2026. Anyone can pull it. We're just the ones watching."

**Step 3 — the Gemma moment (30s).**
Click **Narrate with Gemma** on the card. As the text streams in:
> "And here's the part that matters — a maintainer can't read a WHOIS record. So Gemma reads the signals and writes the warning a human can act on."

Read the verdict aloud. *"Atlantis-software.net's 'atiertant' maintainer presents a critical risk due to recent re-registration, high download volume and widespread dependency."*

**Step 4 — the graph (20s).**
Show the dependency graph. "This is the blast radius. One domain, one maintainer, and everything downstream that would install the poisoned version."

**Step 5 — the working product (15s).**
"Everything you just saw runs offline, from a seeded run, no API key, no venue WiFi. `python app.py` and it's up. 227 tests pass. The repo's public, MIT licensed."

---

## 3. Why it's different (2:30–3:00) — preempt the attack before it lands

**Say this before they ask it:**

> "You might be thinking — domainhunter exists, NtHiM exists, there's a JFrog tool called npm_domain_check. Fair. Here's the difference. Those check DNS records, or they hunt expired domains for *phishing*. npm_domain_check flags domains that are *already expired* — and by the time a domain is expired, the attacker has usually already got it.
>
> **We watch for the re-registration event itself.** That's the seven-day window where the attacker holds the domain but hasn't struck yet. That's the only moment you can still win. Plus blast radius — who actually depends on this — and the Gemma narrative, so the alert is something a maintainer can read."

---

## 4. Honest limitations (3:00–3:20) — say these first

Judges reward this. Delivering it unprompted reads as confidence, not weakness.

> "Two honest caveats. One: an expired domain isn't automatically hijackable — two-factor auth and registrar redemption periods exist. Published research puts the real hijack rate at well under one percent. We're surfacing the *precondition* for an attack, and we say so on every card. Two: the risk score is a heuristic, not a verdict. It's deterministic and testable — but the number is a triage signal, not proof."

---

## 5. The close (3:20–3:30)

> "Microsoft's own advice for this attack is 'review your stored memory by hand and delete entries you don't recognize.' That's not a defense. We warn people when a trusted name gets taken over by a stranger — before the attack happens. That's Lazarus."

Then stop talking. Let them ask.

---

## Judge-attack drill (memorize these four)

| They ask | You answer |
|---|---|
| *"npm_domain_check already does this."* | "It flags *already-expired* domains. We catch the **re-registration** — the window where the attacker holds it but hasn't published yet. Different signal, different moment." |
| *"You're just reading public RDAP data."* | "True, and that's the point — the data is public, nobody was watching it. The value is the detection logic, the risk model, the blast radius, and the model that writes the warning." |
| *"How many warnings are actually real?"* | "Well under one percent, per published research. We surface the precondition, not a confirmed attack. It says so on every card." |
| *"Is that Gemma 4 or Gemma 3?"* | "The judge is model-agnostic. With an API key it's Gemma 4 31B through the Gemini API; without one it falls back to local Gemma 3 4B. Same architecture, same narrative quality — and it degrades gracefully instead of dying on venue WiFi." |

---

## Track-specific one-liners (if the judge is scoring a specific category)

**DigitalOcean — Best Open-Source AI Project:**
> "Open-weight AI is load-bearing here: strip Gemma out and it's a curl wrapper. The scoring is deterministic; Gemma writes the risk narrative a maintainer can act on. Public repo, MIT license, and the triage policy the judge follows ships as an Agent Skill per the Open Standard."

**Google DeepMind — Best Use of Gemma 4:**
> "It's a focused tool — one job, done with an open-weight model. Gemma takes structured risk signals and turns them into plain-English warnings. Registry lookups are just plumbing; the judgment is the model."

---

## If something breaks on stage

| Failure | Recovery |
|---|---|
| Server won't start | Seeded run is committed as `data/cached_run.json` — narrate the findings straight from the file, walk the graph on paper |
| No API key | Everything works. Say "Gemma 3 locally right now" and move on |
| Venue WiFi dead | Same — the seeded run is fully offline |
| Judge asks you to run it live | `python app.py --port 8080`, then paste a domain into the terminal — real RDAP, real score, real narrative in ~10s |

**The rule:** if the demo dies, the pitch still works. The seven-day timeline is the story; the dashboard is just proof.
