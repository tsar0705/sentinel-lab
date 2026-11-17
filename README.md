# Sentinel Lab: Detection Engineering on Real Attack Telemetry

A detection-engineering project in two parts:

1. **Real-data evaluation (the headline).** 15 Sigma-style detection rules over Windows telemetry (Sysmon, Security, PowerShell logs), mapped to MITRE ATT&CK and evaluated on **97 real attack datasets** from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets): attacks such as Empire, Covenant, Mimikatz and Rubeus executed in a lab, each labelled with ATT&CK techniques **by the dataset authors, not by me**.
2. **Synthetic network demo.** A small pipeline (generator -> parser -> IOC extraction -> rules + Isolation Forest -> alerts -> dashboard) with injected scenarios and deliberate false positives, used as a fixture and for tuning/allowlisting practice. Its "100% recall" is self-graded and **not** evidence of real-world performance.

## Evaluation protocol (Part 1)
- Datasets are split into **dev (28) / test (69)** by a hash of the dataset ID (`real_eval.split_of`), fixed before any rule was run.
- Rules were written from public detection knowledge (Sigma/ATT&CK data sources), debugged **only on dev**, then **frozen** and run **once** on test. No rule was changed after seeing test results.
- A dataset counts as *detected* if any alert carries one of its labelled techniques (parent-technique level).
- Datasets whose techniques have no rule are reported as **no rule** and counted as misses in the "overall" figure.

## Results

| | Datasets | Detected | Recall |
|---|---|---|---|
| **Held-out test, all datasets** | 69 | 37 | **54%** |
| Held-out test, techniques with a rule | 54 | 37 | **69%** |
| Dev (rules debugged here) | 28 | 20 | 71% |
| All 97 | 97 | 57 | 59% |

Per technique (test): T1218 proxy execution 8/8, T1047 WMI 4/4, T1087 account discovery 2/2, T1562 impair defenses 4/5, T1003 credential dumping 7/12, T1021 remote services 4/9, T1055 injection 2/3, T1059 scripting 2/3, T1053 scheduled tasks 2/3, T1069 group discovery 1/3. Full table: `results/` and `out/real_report.html`.

Dev -> test dropped (80% -> 69% on covered techniques), the expected optimism gap from tuning on dev.

## Why it misses (examples from the test split)
- **In-memory tooling** (Empire/Covenant Mimikatz modules, DCSync, NinjaCopy) often creates no process-creation event, so command-line rules never see it; PowerShell script-block logging and richer Security events would be needed.
- **Remote-service techniques** (T1021: SharpSC, DCOM variants) leave telemetry mostly on the target host's network/service events that these rules do not parse.
- **Label ambiguity:** some datasets carry one technique label although the attack chain spans several, so a correct alert on another technique counts as a miss.
- **15 techniques have no rule at all** (e.g. T1222, T1546, T1548, T1134). They are counted as misses in the overall figure.

## Run 2: PowerShell content rules (separate run, v1 untouched)
v1 only read process-creation and Sysmon/Security events. Many misses were in-memory tooling (Empire/Covenant modules) that leaves its trace in PowerShell logs instead. **v2 = the 15 v1 rules, unchanged, plus 12 rules over PowerShell script-block (4104), module-logging (4103) and pipeline (800) text** (`rules_v2.py`), keyed on public offensive tool/cmdlet names (PowerSploit, PowerView, Empire, Mimikatz modules). `rules.py` and the original test results (`results/real_test.json`) are byte-identical to the v1 run.

| Test split (69 datasets) | v1 | v2 |
|---|---|---|
| Detected, all datasets | 37 (54%) | 45 (65%) |
| Detected, techniques with a rule | 37/54 (69%) | 45/54 (83%) |
| Off-label techniques per dataset | 0.64 | 1.19 |
| Alerts per dataset | 1.32 | 2.23 |

Gains (8 datasets, none lost): credential dumping 7/12 -> 11/12 (DCSync, Mimikatz SAM/backup-keys, NinjaCopy), discovery (Find-LocalAdminAccess, Get-NetSession), remoting (DCOM ShellWindows, PS Remoting). Dev recall was unchanged (80% on covered techniques) because dev had few PowerShell-dependent misses.

**How to read this**
- **v2 is not a clean held-out result.** I wrote it after the v1 test misses were known, so the test split informed what to add. The patterns are generic public names, but treat 83% as an upper bound. A clean estimate needs datasets neither version has seen (e.g. newer OTRF releases or Splunk attack_data).
- **Noise roughly doubled** (more alerts and more off-label techniques). Two noise fixes were made on dev only: dropping bare `invoke-expression` (appears in benign module internals) and `Invoke-CimMethod` (a built-in alias definition). Precision is still unmeasurable here.
- **Keyword rules are evadable** by renaming or obfuscating functions; this is signature detection, not behaviour detection.
- Remaining misses are mostly remote-service techniques (SharpSC, DCOM RegisterXLL), the PowerShell HTTP listener, and ambiguous labels.

## Limitations (read before quoting numbers)
- **Precision / false-positive rate is not measured.** The datasets are attack-only lab captures; there is no labelled benign traffic. Off-label technique alerts per dataset are reported (0.64 on test) but attack chains legitimately span techniques, so this is a noise indicator, not a precision figure.
- Labels are dataset-level, not event-level. Detection means "the rules noticed *something* matching the technique", not that the exact malicious event was pinpointed.
- I saw all dataset titles and technique labels before writing rules, and surveyed event-ID/field names on the first 40 datasets alphabetically (schema only). I did not inspect test-set event contents for rule writing. Dev misses were inspected to fix generic weaknesses (quoted executable paths, Kerberos tool names, services that launch shells).
- Security event 1102 ("log cleared") was excluded from the T1562 rule because the lab operator generates it when resetting logs before each capture; it would otherwise give free credit.
- Small dataset (97), one lab environment (Windows, Sysmon config, Mordor/OTRF tooling). Results will not transfer unchanged to production telemetry.

## Pre-rendered dashboards
`docs/real_evaluation.html` (real-data evaluation, v1 vs v2) and `docs/synthetic_dashboard.html` (synthetic demo): download and open in a browser. Raw numbers are in `results/`.

## Run
```bash
pip install -r requirements.txt
python -m sentinel_lab.fetch_data         # downloads the OTRF zips listed in data/items.json (52 MB, not redistributed)
python -m sentinel_lab.real_eval dev      # then: python -m sentinel_lab.real_eval test   (v1)
python -m sentinel_lab.real_eval test --v2 # v2 run (writes data/real_v2_test.json)
python -m sentinel_lab.real_report        # out/real_report.html
python -m sentinel_lab.run                # synthetic network demo -> out/report.html
python -m pytest -q                       # 15 unit tests (no download needed)
```

## Part 2: synthetic network demo
Synthetic, benign-lab logs only (RFC 5737 documentation IPs, `*.example` domains, a hash of a harmless placeholder). 7 network/host rules (SSH brute force, port scan, web injection, DGA-style beaconing, large egress, encoded PowerShell, IOC hash) plus an Isolation Forest over per-host windows. Without an allowlist it produces 2 deliberate false positives (an approved scanner, a nightly backup); with one, 7/7 injected scenarios and no false positives. Across seeds 1-20 precision is 0.89-1.00, and the Isolation Forest alone catches about 26% of scenarios, so it is a triage supplement, not a detector. Recall here is 100% by construction because I wrote the generator and the thresholds.

## Data credit
Security Datasets by Roberto Rodriguez and Jose Luis Rodriguez (OTRF). Check the repository's licence before redistributing any data; this repo ships only the metadata list (`data/items.json`) and scripts.
