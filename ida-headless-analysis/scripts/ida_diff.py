"""Cross-version function matching using layered semantic fingerprints.

Build an index for each binary with ida_intel.py index/packet, then compare functions by exact
fingerprint first and weighted feature similarity second. Names/types should only be propagated for
high-confidence matches.
"""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path
from difflib import SequenceMatcher
from _common import state_root


def rows(binary):
    db=state_root(binary)/"semantic.sqlite"
    if not db.exists(): raise FileNotFoundError(f"missing semantic index: {db}; run ida_intel.py BIN index")
    con=sqlite3.connect(db); con.row_factory=sqlite3.Row
    try:
        meta={r["key"]:r["value"] for r in con.execute("SELECT key,value FROM metadata")}
    except sqlite3.OperationalError:
        meta={}
    stored_epoch=int(meta.get("analysis_epoch",0)); epoch_file=state_root(binary)/"analysis_epoch.txt"; current_epoch=int(epoch_file.read_text().strip()) if epoch_file.exists() else 0
    if stored_epoch!=current_epoch:
        con.close(); raise RuntimeError(f"stale semantic index for {binary}: stored epoch={stored_epoch} current epoch={current_epoch}; rebuild index")
    out=[dict(x) for x in con.execute("SELECT ea,name,summary,score,fingerprint FROM functions")]; con.close(); return out,meta

def sim(a,b):
    if a.get("fingerprint") and a["fingerprint"]==b.get("fingerprint"): return 1.0
    ns=SequenceMatcher(None,a.get("name",""),b.get("name","")).ratio() if not a.get("name","").startswith("sub_") else 0
    ss=SequenceMatcher(None,a.get("summary","")[:3000],b.get("summary","")[:3000]).ratio()
    return round(.2*ns+.8*ss,4)

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("old_binary"); ap.add_argument("new_binary"); ap.add_argument("--min-confidence",type=float,default=.72); ap.add_argument("--limit",type=int,default=5000); ap.add_argument("--out"); ap.add_argument("--allow-profile-mismatch",action="store_true")
    a=ap.parse_args(); old,old_meta=rows(a.old_binary); new,new_meta=rows(a.new_binary)
    old_profile=old_meta.get("analysis_profile_digest"); new_profile=new_meta.get("analysis_profile_digest")
    if not a.allow_profile_mismatch and (not old_profile or not new_profile or old_profile!=new_profile):
        raise RuntimeError(f"semantic-index analysis profile mismatch or missing: old={old_profile!r} new={new_profile!r}; rebuild both under the same IDA/Hex-Rays profile or pass --allow-profile-mismatch and treat results as degraded")
    exact={x["fingerprint"]:x for x in new if x.get("fingerprint")}; used=set(); matches=[]
    for x in old[:a.limit]:
        y=exact.get(x.get("fingerprint")) if x.get("fingerprint") else None; conf=1.0 if y else 0.0
        if not y:
            best=None; bests=0.0
            # Narrow by rough interest score to avoid an O(n^2) carnival on giant binaries.
            for cand in new:
                if cand["ea"] in used or abs(float(cand.get("score",0))-float(x.get("score",0)))>35: continue
                s=sim(x,cand)
                if s>bests: bests=s; best=cand
            y=best; conf=bests
        if y and conf>=a.min_confidence:
            used.add(y["ea"]); matches.append({"old":{"ea":x["ea"],"name":x["name"]},"new":{"ea":y["ea"],"name":y["name"]},"confidence":conf,"exact_fingerprint":conf==1.0})
    payload={"old":a.old_binary,"new":a.new_binary,"analysis_profiles":{"old":old_profile,"new":new_profile,"matched":old_profile==new_profile and old_profile is not None},"degraded_profile_mismatch":bool(a.allow_profile_mismatch and old_profile!=new_profile),"matches":matches,"unmatched_old":len(old)-len(matches),"unmatched_new":len(new)-len(used)}
    out=Path(a.out) if a.out else state_root(a.new_binary)/"queries"/"version_diff.json"; out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"saved":str(out),"matches":len(matches),"unmatched_old":payload["unmatched_old"],"unmatched_new":payload["unmatched_new"]},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
