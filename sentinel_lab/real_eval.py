"""Evaluate the rules on real OTRF Security-Datasets with dataset-level ATT&CK labels (assigned by the dataset authors)."""
import hashlib, json, os, sys
from collections import defaultdict
from . import winlog, rules, rules_v2

DATA = os.environ.get("SL_DATA", "data")

def split_of(dataset_id): return "dev" if int(hashlib.sha1(dataset_id.encode()).hexdigest()[:8], 16) % 3 == 0 else "test"

def evaluate(items, split, rs=rules):
    res = []
    for it in items:
        if split != "all" and split_of(it["id"]) != split: continue
        p = f"{DATA}/{it['id']}.zip"
        if not os.path.exists(p) or os.path.getsize(p) < 1000: continue
        df = winlog.load_zip(p); al = rs.run_rules(df)
        techs = set(it["techs"]); fired = {a["technique"] for a in al}
        res.append(dict(id=it["id"], title=it["title"], techs=sorted(techs), events=len(df), alerts=len(al), fired=sorted(fired),
                        in_scope=bool(techs & rules.COVERED), detected=bool(techs & fired), offlabel=len(fired - techs),
                        by=sorted({a["rule"] for a in al if a["technique"] in techs})))
    return res

def summarise(res):
    ins = [r for r in res if r["in_scope"]]; per = defaultdict(lambda: [0, 0])
    for r in ins:
        for t in set(r["techs"]) & rules.COVERED: per[t][0] += r["detected"]; per[t][1] += 1
    return {"datasets": len(res), "in_scope": len(ins), "out_of_scope": len(res) - len(ins),
            "recall_in_scope": sum(r["detected"] for r in ins) / len(ins) if ins else 0.0,
            "recall_overall": sum(r["detected"] for r in res) / len(res) if res else 0.0,
            "mean_offlabel_techniques": sum(r["offlabel"] for r in res) / len(res) if res else 0.0,
            "per_technique": {t: {"detected": a, "n": n} for t, (a, n) in sorted(per.items())}}

if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "dev"; v2 = "--v2" in sys.argv; rs = rules_v2 if v2 else rules; tag = "v2_" if v2 else ""
    items = json.load(open("data/items.json")); res = evaluate(items, split, rs); s = summarise(res)
    print(f"[{tag}{split}] datasets={s['datasets']} in-scope={s['in_scope']} recall(in-scope)={s['recall_in_scope']:.2f} recall(all)={s['recall_overall']:.2f} off-label techniques/dataset={s['mean_offlabel_techniques']:.2f}")
    for t, v in s["per_technique"].items(): print(f"  {t} {rules.ATTACK_W[t][:34]:34s} {v['detected']}/{v['n']}")
    json.dump({"summary": s, "results": res}, open(f"data/real_{tag}{split}.json", "w"), indent=1)
    if "-v" in sys.argv:
        for r in res:
            if r["in_scope"] and not r["detected"]: print("  MISS", r["id"], r["techs"], r["title"][:50], "| fired:", r["fired"])
