"""Report tool effect contracts, prerequisites, and availability for autonomous planning."""
from __future__ import annotations
import argparse, json
from pathlib import Path

ROOT=Path(__file__).resolve().parent

CAPABILITIES={
 "triage":{"script":"ida_query.py","read_only":True,"destructive":False,"idempotent":True,"open_world":True,"requires":["ida","hexrays"]},
 "exact-string":{"script":"ida_query.py","read_only":True,"destructive":False,"idempotent":True,"open_world":False,"requires":["ida"]},
 "ctree":{"script":"ida_ctree.py","read_only":True,"destructive":False,"idempotent":True,"open_world":True,"requires":["ida","hexrays"]},
 "microcode":{"script":"ida_dataflow.py","read_only":True,"destructive":False,"idempotent":True,"open_world":True,"requires":["ida","hexrays"]},
 "taint":{"script":"ida_taint.py","read_only":True,"destructive":False,"idempotent":True,"open_world":True,"requires":["ida","hexrays"]},
 "semantic-index":{"script":"ida_intel.py","read_only":False,"destructive":False,"idempotent":True,"open_world":True,"effects":["writes-project-cache"],"requires":["ida","hexrays"]},
 "evidence":{"script":"ida_evidence.py","read_only":False,"destructive":False,"idempotent":False,"open_world":False,"effects":["writes-evidence-db"],"requires":[]},
 "reference-import":{"script":"ida_reference.py","read_only":False,"destructive":False,"idempotent":True,"open_world":True,"effects":["reads-reference-tree","writes-project-evidence"],"requires":[]},
 "artifact-inspect":{"script":"ida_artifact.py","read_only":False,"destructive":False,"idempotent":True,"open_world":True,"effects":["writes-project-evidence"],"requires":[]},
 "process-capture":{"script":"ida_capture.py","read_only":False,"destructive":False,"idempotent":False,"open_world":True,"effects":["executes-declared-target","may-change-target-state","writes-capture"],"requires":["explicit-scenario"]},
 "apply-findings":{"script":"ida_apply_findings.py","read_only":False,"destructive":False,"idempotent":False,"open_world":False,"effects":["mutates-ida-database"],"requires":["explicit-mode-apply","high-confidence"]},
 "rollback-findings":{"script":"ida_apply_findings.py","read_only":False,"destructive":False,"idempotent":False,"open_world":False,"effects":["mutates-ida-database"],"requires":["rollback-manifest"]},
 "eval":{"script":"ida_eval.py","read_only":True,"destructive":False,"idempotent":False,"open_world":True,"effects":["executes-generated-analysis-code"],"requires":["ida","hexrays"],"remediation":"use canned helpers first; --allow-write is exceptional"},
}


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("name",nargs="?"); a=ap.parse_args()
    rows=[]
    for name,spec in sorted(CAPABILITIES.items()):
        if a.name and a.name!=name: continue
        script=ROOT/spec["script"]; rows.append({"name":name,**spec,"available":script.exists(),"reason":"available" if script.exists() else "script_missing","remediation":spec.get("remediation") if script.exists() else f"restore {script.name}"})
    print(json.dumps(rows[0] if a.name and rows else rows,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
