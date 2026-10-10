"""Smoke test: score the real atlantis-software.net finding.

Reproduces the node-ipc (May 2026) attack pattern against RDAP data:
  domain:   atlantis-software.net
  created:  2026-05-07  (re-registered 7 days before the attack)
  expires:  2027-05-07
  status:   ['client transfer prohibited']
  attack:   malicious node-ipc versions 9.1.6 / 9.2.3 / 12.0.1 on 2026-05-14

Run:  python smoke.py
"""

from datetime import datetime, timezone

from graph import build_graph
from scorer import score_finding

ATTACK_DATE = datetime(2026, 5, 14, 0, 0, 0, tzinfo=timezone.utc)

FINDING = {
    "domain": "atlantis-software.net",
    "packages": ["node-ipc"],
    "dependents": 50000,
    "downloads_week": 2_000_000,
    "rdap": {
        "domain": "atlantis-software.net",
        "registered": True,
        "created": "2026-05-07",
        "expires": "2027-05-07",
        "status": ["client transfer prohibited"],
        "error": None,
    },
    "maintainers": ["maintainer@atlantis-software.net"],
    "maintainer_dormant": True,
    "mx_present": True,
}


def main() -> None:
    result = score_finding(FINDING, now=ATTACK_DATE)

    print("=" * 70)
    print("LAZARUS SMOKE TEST — real atlantis-software.net finding")
    print("=" * 70)
    print(f"domain:        {FINDING['domain']}")
    print(f"rdap created:  {FINDING['rdap']['created']}")
    print(f"rdap expires:  {FINDING['rdap']['expires']}")
    print(f"rdap status:   {FINDING['rdap']['status']}")
    print(f"evaluated at:  {ATTACK_DATE.isoformat()} (attack publication date)")
    print("-" * 70)
    print(f"risk:          {result['risk']}/100")
    print(f"severity:      {result['severity']}")
    print("-" * 70)
    print("signals:")
    for signal in result["signals"]:
        print(f"  - {signal}")
    print("reasoning:")
    for reason in result["reasoning"]:
        print(f"  - {reason}")
    print("-" * 70)

    graph_result = build_graph([{**FINDING, "risk": result["risk"],
                                 "severity": result["severity"]}])
    print(f"graph nodes:   {len(graph_result['nodes'])}")
    print(f"graph edges:   {len(graph_result['edges'])}")
    for node in graph_result["nodes"]:
        print(f"  [{node['type']:>10}] {node['label']:<40} "
              f"risk={node['risk']}")
    for edge in graph_result["edges"]:
        print(f"  {edge['source']} --{edge['label']}--> {edge['target']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
