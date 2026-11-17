"""Download the OTRF Security-Datasets host-telemetry zips listed in data/items.json (not redistributed here; see their licence)."""
import json, os, subprocess
from concurrent.futures import ThreadPoolExecutor

def main(out="data"):
    items = json.load(open(f"{out}/items.json"))
    def dl(it):
        p = f"{out}/{it['id']}.zip"
        if not (os.path.exists(p) and os.path.getsize(p) > 1000):
            subprocess.run(["curl", "-sL", "-m", "120", "-o", p, it["link"]], check=False)
        return os.path.exists(p) and os.path.getsize(p) > 1000
    with ThreadPoolExecutor(4) as ex: ok = list(ex.map(dl, items))
    print(f"{sum(ok)}/{len(items)} datasets available in {out}/")
if __name__ == "__main__": main()
