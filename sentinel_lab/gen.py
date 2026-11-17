"""Synthetic benign-lab log generator.
Only RFC 5737 documentation IPs (203.0.113.0/24, 198.51.100.0/24) and *.example domains are used.
No real malware, no real infrastructure. Ground-truth labels exist only because the data is synthetic."""
import base64, hashlib, json, random
from datetime import datetime, timedelta

T0 = datetime(2026, 11, 1)
SCANNER, BACKUP = "10.0.0.5", "10.0.0.9"          # legitimate but "noisy" hosts (hard negatives)
BAD_HASH = hashlib.sha256(b"lab-fake-sample").hexdigest()
BAD_DOMAIN = "bad-lab.example"

def _ev(t, src, dst, ev, label="benign", **kw):
    return dict(ts=t.isoformat(), src_ip=src, dst_ip=dst, event=ev, label=label, **kw)

def generate(seed=7):
    r = random.Random(seed); out = []
    hosts = [f"10.0.1.{i}" for i in range(10, 40)]
    ext = lambda: f"203.0.113.{r.randint(1, 250)}"
    rt = lambda: T0 + timedelta(hours=r.randint(0, 23), minutes=r.randint(0, 59), seconds=r.randint(0, 59))
    for _ in range(2500):                                   # benign background
        h, t, k = r.choice(hosts), rt(), r.random()
        if k < .30: out.append(_ev(t, h, "10.0.2.10", "http", url=r.choice(["/", "/login", "/api/items", "/static/app.js", "/search?q=report"]), status=str(r.choice([200, 200, 200, 302, 404])), dst_port=443, bytes_out=r.randint(200, 4000)))
        elif k < .55: out.append(_ev(t, h, "10.0.0.53", "dns", domain=r.choice(["intranet.example", "mail.example", "cdn.example", "wiki.example"]), dst_port=53, bytes_out=80))
        elif k < .70: out.append(_ev(t, h, "10.0.1.100", "ssh_auth", user=r.choice(["alice", "bob"]), status=r.choices(["success", "failed"], [9, 1])[0], dst_port=22))
        elif k < .90: out.append(_ev(t, h, ext(), "flow", dst_port=443, bytes_out=r.randint(1_000, 200_000)))
        else: out.append(_ev(t, h, "", "process", cmd=r.choice(["python app.py", "powershell Get-Date", "notepad.exe"]), sha256=hashlib.sha256(str(r.random()).encode()).hexdigest()))
    for k in range(60):                                      # hard negative: approved scanner sweeps ports
        out.append(_ev(T0 + timedelta(hours=2, seconds=k * .5), SCANNER, "10.0.1.20", "flow", "benign_scanner", dst_port=1 + k, bytes_out=60))
    for k in range(3):                                       # hard negative: nightly backup (large upload)
        out.append(_ev(T0 + timedelta(hours=3, minutes=k * 5), BACKUP, "198.51.100.7", "flow", "benign_backup", dst_port=443, bytes_out=100_000_000))
    a = "203.0.113.50"                                       # SSH brute force
    for k in range(80): out.append(_ev(T0 + timedelta(hours=5, seconds=k * 3), a, "10.0.1.100", "ssh_auth", "brute_force", user="root", status="failed", dst_port=22))
    out.append(_ev(T0 + timedelta(hours=5, minutes=4, seconds=50), a, "10.0.1.100", "ssh_auth", "brute_force", user="root", status="success", dst_port=22))
    for k, p in enumerate(r.sample(range(1, 65535), 120)):   # port scan
        out.append(_ev(T0 + timedelta(hours=8, minutes=10, seconds=k * .4), "203.0.113.77", "10.0.1.20", "flow", "port_scan", dst_port=p, bytes_out=60))
    sq = ["/item?id=1' OR 1=1--", "/item?id=1 UNION SELECT user,pass FROM users", "/../../etc/passwd", "/search?q=<script>alert(1)</script>"]
    for k in range(30): out.append(_ev(T0 + timedelta(hours=11, seconds=k * 20), "203.0.113.99", "10.0.2.10", "http", "web_attack", url=r.choice(sq) if k % 5 else "/", status=str(r.choice([200, 404, 500])), dst_port=443, bytes_out=500))
    for k in range(90):                                      # DGA-like beaconing from an infected host
        sub = "".join(r.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
        out.append(_ev(T0 + timedelta(hours=14, minutes=k, seconds=r.randint(0, 5)), "10.0.1.201", "10.0.0.53", "dns", "beacon", domain=f"{sub}.{BAD_DOMAIN}", dst_port=53, bytes_out=90))
    for k in range(4):                                       # data exfiltration
        out.append(_ev(T0 + timedelta(hours=3, minutes=20 + k * 5), "10.0.1.202", "198.51.100.77", "flow", "exfil", dst_port=443, bytes_out=120_000_000))
    enc = base64.b64encode("Write-Output 'lab-test'".encode("utf-16-le")).decode()
    out.append(_ev(T0 + timedelta(hours=16), "10.0.1.203", "", "process", "ps_encoded", cmd=f"powershell.exe -NoP -enc {enc}", sha256=hashlib.sha256(b"ps").hexdigest()))
    out.append(_ev(T0 + timedelta(hours=18), "10.0.1.204", "", "process", "ioc_hash", cmd="invoice.exe", sha256=BAD_HASH))
    return sorted(out, key=lambda e: e["ts"])

def write(path, seed=7):
    with open(path, "w") as f:
        for e in generate(seed): f.write(json.dumps(e) + "\n")
