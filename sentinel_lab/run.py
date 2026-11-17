import json, os, sys
from . import gen, detect as D, report

def main(out="out"):
    os.makedirs(out, exist_ok=True); p = f"{out}/events.jsonl"; gen.write(p)
    df = D.load(p)
    before = D.evaluate(df, D.detect(df, allowlist={}))
    alerts = D.detect(df); after = D.evaluate(df, alerts)
    json.dump(alerts, open(f"{out}/alerts.json", "w"), indent=2)
    json.dump({"without_allowlist": before, "with_allowlist": after}, open(f"{out}/metrics.json", "w"), indent=2)
    report.render(alerts, before, after, f"{out}/report.html")
    print(f"events={len(df)} alerts={len(alerts)} recall={after['recall']:.2f} precision={after['precision']:.2f} (no allowlist precision={before['precision']:.2f}, FPs={len(before['false_positives'])})")
    for l, v in after["per_scenario"].items(): print(f"  {l:12s} detected={v['detected']} by={v['by']}")
if __name__ == "__main__": main(*sys.argv[1:])
