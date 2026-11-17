import html, json
from .report import CSS
e = html.escape

def render(path="out/real_report.html", data="data"):
    import os
    dev = json.load(open(f"{data}/real_dev.json")); te = json.load(open(f"{data}/real_test.json")); s = te["summary"]
    allr = dev["results"] + te["results"]; det_all = sum(r["detected"] for r in allr)
    bars = "".join(f'<div class="bar"><em>{t}</em><i style="width:{max(3, 100 * v["detected"] / v["n"] * .55)}%;background:var(--{"ok" if v["detected"] == v["n"] else "h"})"></i><b>{v["detected"]}/{v["n"]}</b></div>' for t, v in s["per_technique"].items())
    rows = "".join(f'<tr><td>{e(r["id"])}</td><td>{e(r["title"][:52])}</td><td>{" ".join(r["techs"])}</td><td>{"covered" if r["in_scope"] else "no rule"}</td><td>{"&#10003;" if r["detected"] else "&#10007;"}</td><td><small>{e(" ".join(r["by"]) or "-")}</small></td></tr>' for r in sorted(te["results"], key=lambda r: (r["detected"], r["id"])))
    v2sec = ""
    if os.path.exists(f"{data}/real_v2_test.json"):
        v2 = json.load(open(f"{data}/real_v2_test.json")); s2 = v2["summary"]; a1 = {r["id"]: r for r in te["results"]}
        gained = [r for r in v2["results"] if r["detected"] and not a1[r["id"]]["detected"]]
        b2 = "".join(f'<div class="bar"><em>{t}</em><b>{s["per_technique"][t]["detected"]}/{s["per_technique"][t]["n"]} &rarr; {s2["per_technique"][t]["detected"]}/{s2["per_technique"][t]["n"]}</b></div>' for t in s["per_technique"])
        g = "".join(f'<tr><td>{e(r["id"])}</td><td>{e(r["title"][:50])}</td><td>{" ".join(r["techs"])}</td><td><small>{e(" ".join(r["by"]))}</small></td></tr>' for r in gained)
        v2sec = f'''<div class="grid" style="margin-top:12px"><div class="card"><h2>Run 2 (v2: + PowerShell rules) vs v1, test split</h2><div class="kpis" style="grid-template-columns:1fr 1fr"><div class="card k"><b>{s["recall_overall"]:.0%} &rarr; {s2["recall_overall"]:.0%}</b><span>Recall, all datasets</span></div><div class="card k"><b>{s["mean_offlabel_techniques"]:.2f} &rarr; {s2["mean_offlabel_techniques"]:.2f}</b><span>Off-label techniques / dataset</span></div></div>{b2}<div class="note"><b>Not a clean held-out result:</b> v2 was designed after the v1 test misses were known. Treat the gain as an upper bound; v1 numbers above remain the held-out figures.</div></div><div class="card wrap"><h2>Datasets gained by v2</h2><table><tr><th>Dataset</th><th>Title</th><th>Label</th><th>Rule</th></tr>{g}</table></div></div>'''
    k = lambda v, t: f'<div class="card k"><b>{v}</b><span>{t}</span></div>'
    out = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel Lab - Real-Data Evaluation</title><style>{CSS}</style></head><body>
<h1>Sentinel Lab &middot; Evaluation on real attack telemetry</h1><div class="sub">OTRF Security-Datasets: real attacks (Empire, Covenant, Mimikatz, ...) run in a lab, labelled with ATT&amp;CK techniques by the dataset authors. Rules frozen on the dev split, then run once on the held-out test split.</div>
<div class="kpis">{k(len(allr), "Datasets (28 dev / 69 test)")}{k(f"{s['recall_overall']:.0%}", "Held-out recall, all datasets")}{k(f"{s['recall_in_scope']:.0%}", "Held-out recall, covered techniques")}{k(s["out_of_scope"], "Test datasets with no rule")}{k(f"{det_all}/{len(allr)}", "Detected, all splits")}</div>
<div class="grid"><div class="card"><h2>Held-out recall by technique</h2>{bars}</div><div class="card"><h2>Read this before quoting numbers</h2><div class="note">Labels are dataset-level and author-assigned. Datasets are attack-only lab telemetry, so false-positive rate on benign traffic is <b>not measured</b>; precision is unknown. Off-label alerts per dataset (test): {s['mean_offlabel_techniques']:.2f}, but attack chains legitimately span techniques. Misses are mostly in-memory tooling (no process-creation event) and remote-service techniques.</div></div></div>
<div class="card wrap"><h2>Held-out test datasets (misses first)</h2><table><tr><th>Dataset</th><th>Title</th><th>Label</th><th>Coverage</th><th>Hit</th><th>Rules</th></tr>{rows}</table></div>{v2sec}</body></html>"""
    open(path, "w", encoding="utf-8").write(out)
if __name__ == "__main__": render()
