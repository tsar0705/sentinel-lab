"""Load OTRF Security-Datasets (real lab telemetry: Sysmon, Security, PowerShell logs) into one normalised DataFrame."""
import json, zipfile
import pandas as pd

COLS = ["host", "ts", "eid", "chan", "image", "cmd", "parent", "parent_cmd", "src_img", "tgt_img", "granted", "tobj", "text", "ps"]

def _row(e):
    ch = (e.get("Channel") or "").lower(); sysmon = "sysmon" in ch
    eid = int(e.get("EventID") or 0)
    return dict(
        host=e.get("Hostname") or e.get("host") or "", ts=e.get("EventTime") or e.get("TimeCreated") or e.get("@timestamp"), eid=eid,
        chan="sysmon" if sysmon else ("security" if ch == "security" else ("powershell" if "powershell" in ch else ch)),
        image=e.get("Image") or e.get("NewProcessName") or "", cmd=e.get("CommandLine") or "",
        parent=e.get("ParentImage") or e.get("ParentProcessName") or "", parent_cmd=e.get("ParentCommandLine") or "",
        src_img=e.get("SourceImage") or "", tgt_img=e.get("TargetImage") or "", granted=(e.get("GrantedAccess") or "").lower(),
        tobj=e.get("TargetObject") or "", text=(e.get("Message") or "")[:1500],
        ps=((e.get("ScriptBlockText") or e.get("Payload") or e.get("Message") or "")[:8000]) if "powershell" in ch else "")

def load_zip(path):
    rows = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if not n.lower().endswith(".json"): continue
            for line in z.open(n):
                try: rows.append(_row(json.loads(line)))
                except Exception: continue
    df = pd.DataFrame(rows, columns=COLS)
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce", format="mixed")
    for c in ("image", "cmd", "parent", "parent_cmd", "src_img", "tgt_img", "tobj", "text", "ps"):
        df[c] = df[c].fillna("").astype(str)
    df["proc"] = ((df.chan == "sysmon") & (df.eid == 1)) | ((df.chan == "security") & (df.eid == 4688))
    return df.sort_values("ts").reset_index(drop=True)
