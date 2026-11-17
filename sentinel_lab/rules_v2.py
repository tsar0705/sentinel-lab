"""v2 = v1 rules (unchanged, imported) + PowerShell content rules over script-block (4104), module-logging (4103) and pipeline (800) text.
Patterns are public offensive-tool/cmdlet names (PowerSploit, PowerView, Empire, Mimikatz modules): keyword-based, so evadable by renaming/obfuscation.
Designed after v1 results were known; evaluated as a separate run, see README."""
from . import rules as v1
from .detect import extract_iocs

RULES_V2 = []
def prule(rid, tech, sev, title, rx):
    RULES_V2.append((rid, tech, sev, title, lambda df, rx=rx: (df.ps != "") & df.ps.str.contains(rx, case=False, regex=True)))

prule("P01-ps-credential-tooling", "T1003", "critical", "Credential-dumping function in PowerShell", r"invoke-mimikatz|dumpcreds|sekurlsa|lsadump|invoke-powerdump|get-lsasecret|invoke-ninjacopy|invoke-kerberoast|get-gpppassword|invoke-credentialinjection|get-vaultcredential|invoke-internalmonologue|copy-vss|\bdcsync\b")
prule("P02-ps-group-discovery", "T1069", "low", "Group discovery cmdlets", r"get-netlocalgroup|get-netgroup|get-domaingroup|get-netgroupmember|find-localadminaccess|invoke-userhunter|invoke-stealthuserhunter|get-adgroupmember|get-localgroup")
prule("P03-ps-account-discovery", "T1087", "low", "Account discovery cmdlets", r"get-netuser|get-domainuser|get-aduser|get-localuser")
prule("P04-ps-session-discovery", "T1049", "low", "Session discovery cmdlets", r"get-netsession|invoke-getsession|get-netloggedon|get-loggedonlocal")
prule("P05-ps-share-discovery", "T1135", "low", "Share discovery cmdlets", r"get-netshare|invoke-sharefinder|find-domainshare|get-smbshare|invoke-filefinder")
prule("P06-ps-injection", "T1055", "high", "Injection primitives in PowerShell", r"invoke-psinject|invoke-dllinjection|invoke-reflectivepeinjection|invoke-shellcode|virtualallocex|writeprocessmemory|createremotethread")
prule("P07-ps-scheduled-task", "T1053", "medium", "Scheduled-task cmdlets", r"register-scheduledtask|new-scheduledtask|schtasks")
prule("P08-ps-wmi", "T1047", "high", "WMI/CIM execution cmdlets", r"invoke-wmimethod|new-ciminstance|set-wmiinstance|win32_process")
prule("P09-ps-script-abuse", "T1059", "high", "Listener / download-cradle / decode patterns", r"httplistener|downloadstring|frombase64string.*(?:\biex\b|invoke-expression)")
prule("P10-ps-remoting", "T1021", "high", "Remoting / remote-exec functions", r"enter-pssession|new-pssession|invoke-psexec|invoke-smbexec|invoke-dcom|invoke-command.*-computername")
prule("P11-ps-run-key", "T1547", "medium", "Run-key persistence via PowerShell", r"(?:set|new)-itemproperty.*\\currentversion\\run")
prule("P12-ps-impair-defenses", "T1562", "high", "Defender/logging tampering via PowerShell", r"set-mppreference.*disable|stop-service.*(?:eventlog|windefend)|wevtutil|auditpol")

ALL = v1.RULES + RULES_V2
COVERED = {r[1] for r in ALL}  # identical to v1 coverage, so dev/test in-scope sets are comparable

def run_rules(df):
    alerts = []
    for rid, tech, sev, title, fn in ALL:
        m = fn(df)
        if not m.any(): continue
        for h, g in df[m].groupby("host"):
            col = g.ps.where(g.ps != "", g.cmd.where(g.cmd != "", g.tobj.where(g.tobj != "", g.src_img.where(g.src_img != "", g.text.str[:100]))))
            alerts.append(dict(rule=rid, technique=tech, technique_name=v1.ATTACK_W[tech], severity=sev, title=title, host=h, ts=str(g.ts.min()),
                               hits=int(len(g)), evidence=col.iloc[0][:140].replace("\n", " "), iocs=extract_iocs(" ".join(g.cmd.head(50)))))
    return alerts
