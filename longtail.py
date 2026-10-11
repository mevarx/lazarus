"""longtail.py — scan the LONG TAIL: stale npm packages whose current
maintainers use personal (custom) email domains, where lapsed-domain
supply-chain risk actually lives.

Why this exists: the popularity-ranked top-N scan (harvester.harvest_npm)
structurally cannot surface CRITICAL risk — the top packages are popular
*precisely because* their maintainers keep domains paid-up. Real risk hides in
the long tail: packages untouched for years whose maintainer is on a custom
domain that could quietly lapse.

The npm search API can't deep-page (offset is capped / rate-limited), so this
module works from a curated seed list of historically-abandoned or
incident-adjacent packages, resolves each packument's CURRENT maintainer
emails + last-modified date live, and hands the domains to rdap + scorer.

Pure stdlib. Honest by construction: it reports what the live registry shows
right now; a package npm re-homed to npm@npmjs.com is correctly low-risk.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

USER_AGENT = "lazarus-longtail (+hackathon; contact via repo)"

# Historically-abandoned or incident-adjacent packages. These are the packages
# whose supply-chain story is known; we check their CURRENT maintainer domains
# live rather than trusting history. Not a vulnerability list — a staleness
# probe set.
STALE_SEED = [
    "node-ipc", "event-stream", "getcookies", "coa", "rc", "flatmap-stream",
    "crossenv", "twilio-npm", "eslint-scope", "ua-parser-js", "jquery-backstretch",
    "bootstrap-switch", "is-my-json-valid", "moment-timezone",
    "request", "superagent", "bluebird", "lodash-node", "gulp-util",
]

FREE_MAIL = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com",
    "proton.me", "icloud.com", "live.com", "aol.com", "gmx.com", "mail.com",
    "yandex.com", "zoho.com",
}


def _packument(package: str, timeout: int = 20):
    url = f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='')}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _age_days(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - t).days


def harvest_longtail(packages: list[str] | None = None) -> list[dict]:
    """Resolve current maintainer domains + staleness for the seed packages."""
    names = packages if packages is not None else STALE_SEED
    items: list[dict] = []
    for name in names:
        try:
            doc = _packument(name)
        except Exception:
            continue  # 404 / network — skip, never fabricate
        maintainers = []
        for m in doc.get("maintainers", []) or []:
            email = (m.get("email") or "").strip().lower()
            if "@" in email:
                maintainers.append({"name": m.get("name"), "email": email})
        if not maintainers:
            continue
        modified = (doc.get("time") or {}).get("modified")
        items.append({
            "package": name,
            "maintainers": maintainers,
            "dependents": 0,
            "downloads_week": 0,
            "last_updated": modified,
            "age_days": _age_days(modified),
        })
    return items


def scan_longtail(packages: list[str] | None = None, rdap_mod=None, scorer_mod=None) -> list[dict]:
    """Harvest stale packages, group by custom domain, RDAP-resolve, score.

    Reuses the project's rdap + scorer. Sets last_publish_days and
    maintainer_dormant so the abandonment rules fire. npm-owned domains
    (npmjs.com) are kept but naturally score low.
    """
    if rdap_mod is None:
        import rdap as rdap_mod  # noqa: F811
    if scorer_mod is None:
        import scorer as scorer_mod  # noqa: F811

    items = harvest_longtail(packages)
    by_domain: dict[str, dict] = {}
    for it in items:
        age = it.get("age_days") or 0
        for m in it["maintainers"]:
            dom = m["email"].split("@", 1)[1]
            e = by_domain.setdefault(dom, {
                "domain": dom, "packages": [], "maintainers": set(),
                "dependents": 0, "downloads_week": 0,
                "last_publish_days": age, "last_updated": it["last_updated"],
            })
            e["packages"].append(it["package"])
            e["maintainers"].add(m["email"])
            e["last_publish_days"] = max(e["last_publish_days"], age)

    domains = sorted(by_domain.keys())
    resolved = rdap_mod.resolve_domains(domains, "data/rdap_cache.json")
    rdap_by = {r["domain"]: r for r in resolved}

    findings = []
    for dom in domains:
        e = by_domain[dom]
        custom = [d for d in [dom] if d not in FREE_MAIL]
        f = {
            "domain": dom,
            "ecosystem": "npm",
            "packages": sorted(set(e["packages"])),
            "maintainers": sorted(e["maintainers"]),
            "dependents": e["dependents"],
            "downloads_week": e["downloads_week"],
            "last_publish_days": e["last_publish_days"],
            "maintainer_dormant": e["last_publish_days"] >= 730,
            "free_mail_only": dom in FREE_MAIL,
            "custom_domain": bool(custom),
            "rdap": rdap_by.get(dom),
        }
        f.update(scorer_mod.score_finding(f))
        findings.append(f)
    findings.sort(key=lambda x: -x["risk"])
    return findings


if __name__ == "__main__":
    found = scan_longtail()
    print(f"scored {len(found)} long-tail domains")
    for f in found:
        r = f.get("rdap") or {}
        print(f"  {f['risk']:3d} {f['severity']:8s} {f['domain']:22s} "
              f"age={f['last_publish_days']}d created={str(r.get('created'))[:10]} "
              f"pkgs={f['packages'][:2]}")
    counts = {s: sum(1 for f in found if f["severity"] == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    print("severity counts:", counts)
