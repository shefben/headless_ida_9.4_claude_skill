"""Pure-Python conformance checks for evidence/unknown/completion/reconstruction semantics."""
from __future__ import annotations
import json, os, tempfile
from pathlib import Path
from ida_evidence import record_evidence, create_unknown, update_unknown, build_completion_ledger, upsert_obligation


def require(cond,msg):
    if not cond: raise AssertionError(msg)


def main()->int:
    old_root=os.environ.get("IDA_RE_PROJECT_ROOT"); old_id=os.environ.get("IDA_RE_PROJECT_ID")
    old_cwd=Path.cwd()
    with tempfile.TemporaryDirectory(prefix="ida-skill-conformance-") as td:
        root=Path(td); os.chdir(root); os.environ["IDA_RE_PROJECT_ROOT"]=str(root); os.environ["IDA_RE_PROJECT_ID"]="conformance"
        binary=root/"fixture.bin"; binary.write_bytes(b"IDA-SKILL-CONFORMANCE\x00"*32)
        e1=record_evidence(binary,operation="fixture.observe",result={"value":1},parameters={"x":2},confidence="observed",authority="shipped-artifact")
        e2=record_evidence(binary,operation="fixture.observe",result={"value":1},parameters={"x":2},confidence="observed",authority="shipped-artifact")
        require(e1["evidence_id"]==e2["evidence_id"],"evidence identity is not deterministic")
        runtime=record_evidence(binary,operation="fixture.runtime",result={"value":1},parameters={},confidence="observed",authority="controlled-replay",predicate_type="ida.runtime.capture")
        u=create_unknown(binary,{"question":"What is the fixture value?","domain":"conformance","supporting_evidence_ids":[e1["evidence_id"]],"recommended_probes":[{"operation":"fixture.observe","rationale":"direct observation"}]})
        stale=False
        try: update_unknown(binary,u["unknown_id"],99,{"status":"investigating"})
        except RuntimeError: stale=True
        require(stale,"stale unknown revision was accepted")
        u2=update_unknown(binary,u["unknown_id"],1,{"status":"resolved","resolution":{"disposition":"verified","rationale":"fixture evidence","evidence_ids":[e1["evidence_id"]]}})
        require(u2["status"]=="resolved" and u2["revision"]==2,"unknown resolution failed")
        ledger=build_completion_ledger(binary,[{"claim_id":"a","status":"pass","evidence_ids":[e1["evidence_id"]]},{"claim_id":"b","status":"unknown","evidence_ids":[e1["evidence_id"]]}])
        require(ledger["summary"]["complete"] is False,"completion ledger did not fail closed")
        spec={"obligation_id":"fixture.reconstruction","title":"Fixture reconstruction","required":True,"required_case_kinds":["positive"],"requires_parser_type":False,"owner":{"module_path":"fixture.py","symbol":"run","owner_sha256":"0"*64},"original_cases":[{"kind":"positive","evidence_id":e1["evidence_id"]}],"reconstruction_cases":[{"kind":"positive","evidence_id":e1["evidence_id"]}],"residual_unknown_ids":[u["unknown_id"]],"required_verifier_authority":"controlled-replay","verifier":{"status":"pass","authority":"controlled-replay","evidence_id":runtime["evidence_id"]}}
        ready=upsert_obligation(binary,spec); require(ready["status"]=="ready","reconstruction obligation should close after verified unknown resolution")
        print(json.dumps({"status":"PASS","evidence_id":e1["evidence_id"],"unknown_id":u["unknown_id"],"ledger_id":ledger["ledger_id"],"obligation":ready},indent=2))
    os.chdir(old_cwd)
    if old_root is None: os.environ.pop("IDA_RE_PROJECT_ROOT",None)
    else: os.environ["IDA_RE_PROJECT_ROOT"]=old_root
    if old_id is None: os.environ.pop("IDA_RE_PROJECT_ID",None)
    else: os.environ["IDA_RE_PROJECT_ID"]=old_id
    return 0
if __name__=="__main__": raise SystemExit(main())
