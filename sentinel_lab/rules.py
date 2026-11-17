"""Sigma-style detections over Windows telemetry. Written from public detection knowledge (Sigma/ATT&CK data sources),
NOT fitted to the evaluation datasets: rules were debugged on the 'dev' split only and frozen before the 'test' split was run."""
import re
from .detect import extract_iocs

ATTACK_W = {"T1003": "OS Credential Dumping", "T1218": "System Binary Proxy Execution", "T1047": "Windows Management Instrumentation",
            "T1053": "Scheduled Task/Job", "T1547": "Boot/Logon Autostart Execution", "T1055": "Process Injection", "T1059": "Command and Scripting Interpreter",
            "T1562": "Impair Defenses", "T1069": "Permission Groups Discovery", "T1087": "Account Discovery", "T1049": "System Network Connections Discovery",
            "T1135": "Network Share Discovery", "T1021": "Remote Services"}
TRUSTED_SRC = r"\\(?:msmpeng|csrss|wininit|services|svchost|lsass|werfault|vmtoolsd|mssense|sysmon64?|taskhostw|searchindexer)\.exe$"
ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x1f1fff", "0x1f0fff"}
RULES = []

def rule(rid, tech, sev, title):
    def deco(fn): RULES.append((rid, tech, sev, title, fn)); return fn
    return deco

def cmdhas(df, rx): return df.proc & df.cmd.str.replace('"', "", regex=False).str.contains(rx, case=False, regex=True)
def msg(df, chan, eids, rx): return (df.chan == chan) & df.eid.isin(eids) & df.text.str.contains(rx, case=False, regex=True)

@rule("W01-lsass-access", "T1003", "critical", "Suspicious process access to LSASS")
def _(df): return (df.chan == "sysmon") & (df.eid == 10) & df.tgt_img.str.lower().str.endswith("lsass.exe") & df.granted.isin(ACCESS) & ~df.src_img.str.lower().str.contains(TRUSTED_SRC, regex=True)

@rule("W02-credential-tooling", "T1003", "critical", "Credential-dumping tool or command line")
def _(df): return cmdhas(df, r"comsvcs(?:\.dll)?[, ]+#?(?:24|minidump)|minidump|procdump.*lsass|sekurlsa|lsadump|mimikatz|dumpcreds|logonpasswords|powerdump|reg(?:\.exe)?\s+save\s+hklm\\(?:sam|security|system)|ntdsutil|ac i ntds|esentutl.*/vss|vssadmin.*create\s+shadow|ntds\.dit|get-hash|rubeus|kerberoast|asktgt|asktgs")

@rule("W03-dcsync", "T1003", "critical", "Directory replication request (DCSync)")
def _(df): return msg(df, "security", [4662], r"1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2")

@rule("W04-lolbin-proxy", "T1218", "high", "Signed-binary proxy execution")
def _(df): return cmdhas(df, r"mshta(?:\.exe)?\s.*(?:http|vbscript|javascript|\.hta|about:)|regsvr32.*(?:/i:|scrobj|http)|rundll32.*(?:javascript:|mshtml|runhtmlapplication|advpack)|cmstp.*\s/(?:s|ni|au)\b|installutil|\bhh(?:\.exe)?\s.*\.chm|wuauclt.*updatedeploymentprovider|register-cimprovider|control(?:\.exe)?\s.*\.cpl")

@rule("W05-wmi-exec", "T1047", "high", "WMI used for execution")
def _(df): return (df.proc & df.parent.str.lower().str.endswith("wmiprvse.exe")) | cmdhas(df, r"wmic.*(?:process\s+call\s+create|/node:)|invoke-wmimethod|invoke-cimmethod|win32_process|invoke-wmi") | ((df.chan == "sysmon") & df.eid.isin([19, 20, 21]))

@rule("W06-scheduled-task", "T1053", "medium", "Scheduled task created")
def _(df): return cmdhas(df, r"schtasks(?:\.exe)?\s+.*/create|register-scheduledtask|new-scheduledtask|\bat(?:\.exe)?\s+\d") | msg(df, "security", [4698], r"scheduled task")

@rule("W07-run-key", "T1547", "medium", "Autostart registry key modified")
def _(df): return ((df.chan == "sysmon") & df.eid.isin([12, 13]) & df.tobj.str.contains(r"\\currentversion\\run(?:once)?(?:ex)?\\|\\winlogon\\(?:shell|userinit)", case=False, regex=True)) | cmdhas(df, r"reg(?:\.exe)?\s+add.*\\currentversion\\run")

@rule("W08-injection", "T1055", "high", "Process injection indicators")
def _(df): return ((df.chan == "sysmon") & (df.eid == 8) & ~df.src_img.str.lower().str.contains(TRUSTED_SRC, regex=True)) | cmdhas(df, r"mavinject.*/injectrunning|invoke-dllinjection|invoke-psinject|virtualallocex|writeprocessmemory")

@rule("W09-script-abuse", "T1059", "high", "Suspicious PowerShell / script interpreter use")
def _(df): return cmdhas(df, r"powershell.*(?:\s-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|downloadstring|invoke-expression|\biex\b|-w(?:indowstyle)?\s+hidden)|(?:wscript|cscript).*\.(?:vbs|js|vbe|wsf)|python.*-m\s+http\.server") | msg(df, "powershell", [4103, 4104, 800], r"httplistener|downloadstring|frombase64string|invoke-webrequest")

@rule("W10-impair-defenses", "T1562", "high", "Logging / defences tampered with")
def _(df): return cmdhas(df, r"auditpol.*(?:/set|/clear|/remove)|wevtutil\s+(?:cl|clear-log|sl)|sc(?:\.exe)?\s+(?:config|stop).*(?:eventlog|windefend|mpssvc)|netsh.*(?:advfirewall|firewall).*(?:add|set|off)|set-mppreference.*disable|disableantispyware|disablerealtimemonitoring") | ((df.chan == "sysmon") & df.eid.isin([12, 13]) & df.tobj.str.contains(r"\\services\\eventlog\\|\\control\\minint|processcreationincludecmdline_enabled|\\audit\\", case=False, regex=True)) | ((df.chan == "security") & df.eid.isin([4719]))

@rule("W11-group-discovery", "T1069", "low", "Group discovery")
def _(df): return cmdhas(df, r"net1?(?:\.exe)?\s+(?:localgroup|group)|get-netlocalgroup|get-domaingroup|find-localadminaccess|invoke-userhunter")

@rule("W12-account-discovery", "T1087", "low", "Account discovery")
def _(df): return cmdhas(df, r"net1?(?:\.exe)?\s+(?:user|accounts)|whoami\s+/(?:groups|all|priv)|get-netuser|get-domainuser|dsquery\s+user")

@rule("W13-session-discovery", "T1049", "low", "Network session discovery")
def _(df): return cmdhas(df, r"net1?(?:\.exe)?\s+session|get-netsession|netstat")

@rule("W14-share-discovery", "T1135", "low", "Network share discovery")
def _(df): return cmdhas(df, r"net1?(?:\.exe)?\s+(?:view|share)|get-netshare|get-smbshare")

@rule("W15-remote-service", "T1021", "high", "Remote service execution (PsExec/SMB/WinRM/DCOM)")
def _(df): return cmdhas(df, r"psexe|invoke-psexec|invoke-smbexec|invoke-dcom|enter-pssession|sc(?:\.exe)?\s+\\\\|schtasks.*\s/s\s") | (df.proc & df.parent.str.lower().str.contains(r"wsmprovhost\.exe$", regex=True)) | (df.proc & df.parent.str.lower().str.endswith("mmc.exe") & df.parent_cmd.str.contains("-embedding", case=False)) | msg(df, "security", [5140, 5145], r"share name:\s+\\\\\*\\(?:admin\$|c\$)") | msg(df, "security", [4697, 7045], r"psexesvc|admin\$|(?:service file name|image path):\s+.*(?:%comspec%|cmd(?:\.exe)?\s+/c|powershell)")

COVERED = {r[1] for r in RULES}

def run_rules(df, host_cols=("host",)):
    alerts = []
    for rid, tech, sev, title, fn in RULES:
        m = fn(df)
        if not m.any(): continue
        for h, g in df[m].groupby("host"):
            ev = (g.cmd.where(g.cmd != "", g.tobj.where(g.tobj != "", g.src_img.where(g.src_img != "", g.text.str[:100]))).iloc[0])[:140]
            alerts.append(dict(rule=rid, technique=tech, technique_name=ATTACK_W[tech], severity=sev, title=title, host=h,
                               ts=str(g.ts.min()), hits=int(len(g)), evidence=ev, iocs=extract_iocs(" ".join(g.cmd.head(50)))))
    return alerts
