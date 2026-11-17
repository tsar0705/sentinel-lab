"""Parse -> normalise -> extract IOCs -> rule detections + Isolation Forest -> ATT&CK-mapped alerts."""
import json, math, re
from collections import Counter
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .gen import BAD_HASH

ATTACK = {  # technique id -> (name, tactic). Mappings are analyst-assigned heuristics, not vendor-verified.
    "T1110": ("Brute Force", "Credential Access"), "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"), "T1568.002": ("Dynamic Resolution: DGA", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"), "T1059.001": ("PowerShell", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"), "BEH": ("Behavioural anomaly (unmapped)", "Triage")}
MITIGATION = {
    "T1110": "Enforce MFA and key-only SSH; rate-limit/lock out; block source at the edge.",
    "T1046": "Restrict exposed services; alert on sweeps; segment networks; allowlist approved scanners.",
    "T1190": "Patch and parametrise queries; deploy WAF rules; validate input; review access logs.",
    "T1568.002": "Sinkhole/block the parent domain; DNS filtering; isolate host and investigate.",
    "T1041": "Egress filtering and volume baselines; DLP; isolate host; review what left.",
    "T1059.001": "Constrained Language Mode and script-block logging; restrict encoded commands.",
    "T1204.002": "Quarantine file; block hash via EDR; reimage host; trace delivery path.",
    "BEH": "Manual triage: review the host's events in that window; tune or suppress if benign."}
ALLOWLIST = {"10.0.0.5": "approved vulnerability scanner", "10.0.0.9": "nightly backup job"}
IOC_HASHES = {BAD_HASH}
SQLI = re.compile(r"(?:'|%27)\s*or\s+1=1|union\s+select|\.\./|<script|;\s*drop\s+table", re.I)
PS_ENC = re.compile(r"powershell.*\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"); HASH_RE = re.compile(r"\b[a-f0-9]{64}\b")
DOM_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:example|com|net|org)\b", re.I)

def normalise(df):
    df = df.copy(); df["ts"] = pd.to_datetime(df["ts"], format="ISO8601")
    for c, d in {"dst_port": 0, "bytes_out": 0, "status": "", "url": "", "domain": "", "cmd": "", "sha256": "", "user": "", "label": "unknown", "dst_ip": ""}.items():
        if c not in df: df[c] = d
        df[c] = df[c].fillna(d)
    df["status"] = df["status"].astype(str)
    return df.sort_values("ts").reset_index(drop=True)

def load(path):
    with open(path) as f: return normalise(pd.DataFrame([json.loads(l) for l in f if l.strip()]))

def entropy(s):
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0

def extract_iocs(text):
    return {"ip": sorted(set(IP_RE.findall(text))), "domain": sorted({d.lower() for d in DOM_RE.findall(text)}), "sha256": sorted(set(HASH_RE.findall(text)))}

def _alert(ts, rule, sev, tech, src, dst, evidence, iocs):
    n, tac = ATTACK[tech]
    return dict(ts=pd.Timestamp(ts).isoformat(), rule=rule, severity=sev, technique=tech, technique_name=n, tactic=tac,
                src_ip=src, dst_ip=dst, evidence=evidence, iocs=iocs, mitigation=MITIGATION[tech], source="rule")

def rule_bruteforce(df):
    f = df[(df.event == "ssh_auth") & (df.status == "failed")]
    for (s, d, _), g in f.groupby(["src_ip", "dst_ip", f.ts.dt.floor("5min")]):
        if len(g) >= 20: yield _alert(g.ts.min(), "R1-ssh-bruteforce", "high", "T1110", s, d, f"{len(g)} failed SSH logins in 5 min", {"ip": [s]})

def rule_portscan(df):
    f = df[df.event == "flow"]
    for (s, d, _), g in f.groupby(["src_ip", "dst_ip", f.ts.dt.floor("1min")]):
        if g.dst_port.nunique() >= 15: yield _alert(g.ts.min(), "R2-port-scan", "medium", "T1046", s, d, f"{g.dst_port.nunique()} distinct ports in 1 min", {"ip": [s]})

def rule_web(df):
    f = df[df.event == "http"]; hit = f[f.url.str.contains(SQLI)]
    for s, g in hit.groupby("src_ip"):
        if len(g) >= 3: yield _alert(g.ts.min(), "R3-web-injection", "high", "T1190", s, g.dst_ip.iloc[0], f"{len(g)} requests with SQLi/traversal/XSS patterns", {"ip": [s]})

def rule_dga(df):
    f = df[df.event == "dns"].copy()
    f["parent"] = f.domain.str.split(".").str[-2:].str.join("."); f["lab"] = f.domain.str.split(".").str[0]; f["ent"] = f.lab.map(entropy)
    for (s, p), g in f.groupby(["src_ip", "parent"]):
        if len(g) >= 10 and g.lab.nunique() >= 10 and g.ent.mean() > 3.0:
            yield _alert(g.ts.min(), "R4-dga-beaconing", "high", "T1568.002", s, g.dst_ip.iloc[0], f"{len(g)} queries to {p}, mean label entropy {g.ent.mean():.2f}", {"ip": [s], "domain": [p]})

def rule_exfil(df):
    f = df[(df.event == "flow") & ~df.dst_ip.str.startswith("10.")]
    for (s, d, _), g in f.groupby(["src_ip", "dst_ip", f.ts.dt.floor("1h")]):
        mb = g.bytes_out.sum() / 1e6
        if mb >= 200: yield _alert(g.ts.min(), "R5-large-egress", "critical", "T1041", s, d, f"{mb:.0f} MB sent to external host in 1 h", {"ip": [s, d]})

def rule_process(df):
    for _, r in df[df.event == "process"].iterrows():
        if PS_ENC.search(r.cmd): yield _alert(r.ts, "R6-encoded-powershell", "high", "T1059.001", r.src_ip, "", "PowerShell with encoded command", {"ip": [r.src_ip], **{k: v for k, v in extract_iocs(r.cmd).items() if v and k != "ip"}})
        if r.sha256 in IOC_HASHES: yield _alert(r.ts, "R7-known-bad-hash", "critical", "T1204.002", r.src_ip, "", f"Process {r.cmd} matches IOC hash", {"ip": [r.src_ip], "sha256": [r.sha256]})

def anomaly_alerts(df, contamination=0.005):
    d = df.assign(w=df.ts.dt.floor("10min"), failed=(df.status == "failed"), port=df.dst_port.where(df.event == "flow"))
    d["ent"] = d.domain.map(lambda x: entropy(x.split(".")[0]) if x else 0.0)
    g = d.groupby(["src_ip", "w"]).agg(n=("event", "size"), failed=("failed", "sum"), ports=("port", "nunique"), dsts=("dst_ip", "nunique"),
                                      mb=("bytes_out", lambda s: s.sum() / 1e6), dns=("event", lambda s: (s == "dns").sum()), ent=("ent", "mean"))
    X = StandardScaler().fit_transform(g.values)
    m = IsolationForest(n_estimators=200, contamination=contamination, random_state=0).fit(X)
    score = -m.decision_function(X)
    for (s, w), flag, sc, row in zip(g.index, m.predict(X) == -1, score, g.itertuples()):
        if flag:
            a = _alert(w, "M1-isolation-forest", "medium", "BEH", s, "", f"anomaly score {sc:.2f}: {row.n} events, {row.failed} failed, {row.ports} ports, {row.mb:.0f} MB", {"ip": [s]})
            a["source"] = "model"; yield a

def detect(df, allowlist=ALLOWLIST):
    raw = []
    for r in (rule_bruteforce, rule_portscan, rule_web, rule_dga, rule_exfil, rule_process): raw += list(r(df))
    rule_ips = {a["src_ip"] for a in raw if a["src_ip"] not in allowlist}
    raw += list(anomaly_alerts(df))
    merged = {}
    for a in raw:
        if a["src_ip"] in allowlist: continue
        k = (a["rule"], a["src_ip"])
        if k in merged: merged[k]["windows"] += 1
        else: merged[k] = {**a, "windows": 1}
    out = []
    for a in merged.values():
        if a["source"] == "model": a["source"] = "model+rules" if a["src_ip"] in rule_ips else "model-only"
        a["id"] = f"A-{len(out) + 1:03d}"; out.append(a)
    return sorted(out, key=lambda a: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}[a["severity"]], a["ts"]))

def evaluate(df, alerts):
    atk = df[~df.label.str.startswith("benign")]
    truth = {l: set(g.src_ip) for l, g in atk.groupby("label")}; bad = set().union(*truth.values())
    per = {l: {"detected": any(a["src_ip"] in ips for a in alerts), "by": sorted({a["rule"] for a in alerts if a["src_ip"] in ips})} for l, ips in truth.items()}
    why = df.groupby("src_ip").label.agg(lambda s: s.value_counts().index[0])
    fp = [{"rule": a["rule"], "src_ip": a["src_ip"], "truth": why.get(a["src_ip"], "?")} for a in alerts if a["src_ip"] not in bad]
    tp = len(alerts) - len(fp)
    return {"recall": sum(v["detected"] for v in per.values()) / len(per), "precision": tp / len(alerts) if alerts else 0.0,
            "alerts": len(alerts), "false_positives": fp, "per_scenario": per}
