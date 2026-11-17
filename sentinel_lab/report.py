"""Render a self-contained dark dashboard (no JS, no external assets) from alerts + metrics."""
import html
from collections import Counter

CSS = """:root{--bg:#0b0d1a;--card:#111426;--line:#262b4a;--fg:#e8ebff;--mut:#8a90b8;--c:#ff4d5e;--h:#ff9f43;--m:#f4c542;--l:#5b8cff;--ok:#2ecc8f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif;padding:20px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:16px}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;min-width:0}.k b{display:block;font-size:26px}.k span{color:var(--mut)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;margin-bottom:12px}h2{font-size:13px;color:var(--mut);margin:0 0 10px;text-transform:uppercase;letter-spacing:.05em}
.bar{display:flex;align-items:center;gap:8px;margin:6px 0}.bar i{display:block;height:10px;border-radius:5px}.bar em{font-style:normal;min-width:120px;color:var(--mut)}
table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--mut);font-weight:500}
.wrap{overflow-x:auto}.s{padding:1px 8px;border-radius:10px;font-size:12px;color:#000}.critical{background:var(--c)}.high{background:var(--h)}.medium{background:var(--m)}.low{background:var(--l)}
.note{color:var(--mut);font-size:12px;margin-top:8px}svg{width:100%;height:auto}"""
COL = {"critical": "var(--c)", "high": "var(--h)", "medium": "var(--m)", "low": "var(--l)"}
e = html.escape

def _bars(counter, color=None, total=None):
    mx = max(counter.values(), default=1)
    return "".join(f'<div class="bar"><em>{e(str(k))}</em><i style="width:{max(4, 100 * v / mx * .55)}%;background:{color or COL.get(k, "var(--l)")}"></i><b>{v}</b></div>' for k, v in counter.most_common())

def _trend(alerts):
    hrs = Counter(int(a["ts"][11:13]) for a in alerts); mx = max(hrs.values(), default=1)
    pts = " ".join(f"{10 + h * 12.5:.1f},{90 - 80 * hrs.get(h, 0) / mx:.1f}" for h in range(24))
    return f'<svg viewBox="0 0 310 105"><polyline points="{pts}" fill="none" stroke="var(--c)" stroke-width="2"/><line x1="10" y1="90" x2="300" y2="90" stroke="var(--line)"/><text x="10" y="102" fill="#8a90b8" font-size="8">00:00</text><text x="270" y="102" fill="#8a90b8" font-size="8">23:00</text></svg>'

def render(alerts, before, after, path):
    sev = Counter(a["severity"] for a in alerts); tech = Counter(f'{a["technique"]} {a["technique_name"]}' for a in alerts if a["technique"] != "BEH")
    iocs = {i for a in alerts for v in a["iocs"].values() for i in v}
    rows = "".join(f'<tr><td>{e(a["id"])}</td><td><span class="s {a["severity"]}">{a["severity"]}</span></td><td>{e(a["rule"])}</td><td>{e(a["technique"])}<br><small>{e(a["tactic"])}</small></td><td>{e(a["src_ip"])}</td><td>{e(a["evidence"])}</td><td>{e(a["source"])}</td><td><small>{e(a["mitigation"])}</small></td></tr>' for a in alerts[:40])
    fps = "".join(f'<tr><td>{e(f["rule"])}</td><td>{e(f["src_ip"])}</td><td>{e(f["truth"])}</td></tr>' for f in before["false_positives"]) or '<tr><td colspan=3>none</td></tr>'
    k = lambda v, t: f'<div class="card k"><b>{v}</b><span>{t}</span></div>'
    out = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel Lab - Threat Detection Dashboard</title><style>{CSS}</style></head><body>
<h1>Sentinel Lab &middot; Threat Detection Dashboard</h1><div class="sub">Synthetic benign-lab logs (RFC 5737 IPs, *.example domains). Rules + Isolation Forest, mapped to MITRE ATT&amp;CK.</div>
<div class="kpis">{k(len(alerts), "Alerts")}{k(sev["critical"] + sev["high"], "Critical + High")}{k(len({a["technique"] for a in alerts} - {"BEH"}), "ATT&amp;CK techniques")}{k(len(iocs), "Unique IOCs")}{k(f"{after['recall']:.0%}", "Scenario recall")}{k(f"{after['precision']:.0%}", "Alert precision")}</div>
<div class="grid"><div class="card"><h2>Alerts by severity</h2>{_bars(sev)}</div><div class="card"><h2>Alerts over time (hourly)</h2>{_trend(alerts)}</div><div class="card"><h2>Alerts by ATT&amp;CK technique</h2>{_bars(tech, "var(--l)")}</div></div>
<div class="card wrap"><h2>Alert queue</h2><table><tr><th>ID</th><th>Sev</th><th>Rule</th><th>ATT&amp;CK</th><th>Source</th><th>Evidence</th><th>Origin</th><th>Mitigation</th></tr>{rows}</table></div>
<div class="grid" style="margin-top:12px"><div class="card wrap"><h2>False positives without allowlist ({before['alerts']} alerts, precision {before['precision']:.0%})</h2><table><tr><th>Rule</th><th>Source</th><th>Ground truth</th></tr>{fps}</table>
<div class="note">After allowlisting the approved scanner and backup job: {after['alerts']} alerts, precision {after['precision']:.0%}, {len(after['false_positives'])} remaining false positives.</div></div>
<div class="card"><h2>Detection limits</h2><div class="note">Results come from synthetic data with injected scenarios; recall/precision are entity-level and optimistic. Thresholds were set by the author. Real traffic needs baselining, labelled data and tuning. ATT&amp;CK mappings are analyst heuristics.</div></div></div></body></html>"""
    open(path, "w", encoding="utf-8").write(out)
