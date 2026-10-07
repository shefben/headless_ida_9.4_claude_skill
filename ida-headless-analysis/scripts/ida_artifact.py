"""Execution-free artifact inventory and optional external-preprocessor bridge.

Use this before deep IDA analysis when package/container context matters. External adapter output is
kept as separate evidence and never silently promoted to IDA/native truth.
"""
from __future__ import annotations
import argparse, json, os, shutil, struct, subprocess, zipfile
from pathlib import Path
from typing import Any
from _common import ensure_state
from _provenance import sha256_file, semantic_id
from ida_evidence import record_evidence

MAX_MEMBERS=20000


def detect(path:Path)->dict[str,Any]:
    with path.open("rb") as f: head=f.read(16)
    fmt="unknown"; arch=None
    if head.startswith(b"MZ"): fmt="pe"
    elif head.startswith(b"\x7fELF"): fmt="elf"
    elif head[:4] in {b"\xcf\xfa\xed\xfe",b"\xfe\xed\xfa\xcf",b"\xca\xfe\xba\xbe",b"\xbe\xba\xfe\xca"}: fmt="mach-o"
    elif path.suffix.lower()==".apk" and head.startswith(b"PK"): fmt="apk"
    elif head.startswith(b"PK\x03\x04"): fmt="zip"
    elif path.suffix.lower()==".asar": fmt="asar"
    return {"path":str(path),"sha256":sha256_file(path),"size":path.stat().st_size,"format":fmt,"architecture":arch}


def inspect(path:Path,limit:int=MAX_MEMBERS)->dict[str,Any]:
    root=detect(path); members=[]; truncated=False; findings=[]
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i,info in enumerate(z.infolist()):
                if i>=limit: truncated=True; break
                members.append({"path":info.filename,"size":info.file_size,"compressed_size":info.compress_size,"crc32":f"{info.CRC:08x}","encrypted":bool(info.flag_bits & 1)})
            names={m["path"] for m in members}
            if "AndroidManifest.xml" in names: findings.append("android-apk-like")
            if any(n.endswith(".dex") for n in names): findings.append("contains-dex")
            if any(n.lower().endswith((".dll",".so",".dylib")) for n in names): findings.append("contains-native-libraries")
    return {**root,"members":members,"truncated":truncated,"findings":findings,"inventory_id":semantic_id("art",{"sha256":root["sha256"],"members":members})}


def adapter_command(adapter:str,path:Path,out_dir:Path|None)->list[str]:
    if adapter=="binwalk":
        exe=os.environ.get("IDA_RE_BINWALK") or shutil.which("binwalk")
        if not exe: raise RuntimeError("binwalk unavailable; set IDA_RE_BINWALK or install it separately")
        return [exe,str(path)]
    if adapter=="unblob":
        exe=os.environ.get("IDA_RE_UNBLOB") or shutil.which("unblob")
        if not exe: raise RuntimeError("unblob unavailable; set IDA_RE_UNBLOB or install it separately")
        if out_dir is None: raise ValueError("unblob requires --out-dir because it is an extracting adapter")
        return [exe,"-e",str(out_dir),str(path)]
    if adapter=="jadx":
        exe=os.environ.get("IDA_RE_JADX") or shutil.which("jadx")
        if exe:
            if out_dir is None: raise ValueError("jadx requires --out-dir")
            return [exe,"--output-dir",str(out_dir),str(path)]
        jar=os.environ.get("JADX_HEADLESS_JAR")
        java=os.environ.get("JAVA_BIN") or shutil.which("java")
        if not jar or not java: raise RuntimeError("jadx unavailable; set IDA_RE_JADX or JADX_HEADLESS_JAR plus JAVA_BIN/java")
        if out_dir is None: raise ValueError("jadx requires --out-dir")
        return [java,"-jar",jar,"--output-dir",str(out_dir),str(path)]
    raise ValueError(adapter)


def run_adapter(adapter:str,path:Path,out_dir:Path|None,timeout:int)->dict[str,Any]:
    command=adapter_command(adapter,path,out_dir); proc=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors="replace",timeout=timeout,check=False)
    return {"adapter":adapter,"command":command,"returncode":proc.returncode,"stdout":proc.stdout[:2_000_000],"stderr":proc.stderr[:2_000_000],"output_dir":None if out_dir is None else str(out_dir),"limitations":["external preprocessor output is separate evidence and must be corroborated before semantic claims"]}


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("binary"); sub=ap.add_subparsers(dest="cmd",required=True)
    i=sub.add_parser("inspect"); i.add_argument("--limit",type=int,default=MAX_MEMBERS)
    e=sub.add_parser("external"); e.add_argument("adapter",choices=("binwalk","unblob","jadx")); e.add_argument("--out-dir"); e.add_argument("--timeout",type=int,default=300)
    a=ap.parse_args(); path=Path(a.binary).expanduser().resolve(); root=ensure_state(path)
    if a.cmd=="inspect":
        result=inspect(path,a.limit); conf="observed"; authority="shipped-artifact"; operation="inspect_artifact"; params={"limit":a.limit}; limitations=["archive member inventory does not establish runtime behavior"] + (["inventory truncated"] if result["truncated"] else [])
    else:
        out_dir=Path(a.out_dir).expanduser().resolve() if a.out_dir else None
        if out_dir is not None: out_dir.mkdir(parents=True,exist_ok=True)
        result=run_adapter(a.adapter,path,out_dir,a.timeout); conf="observed"; authority="external-service"; operation=f"external_preprocessor.{a.adapter}"; params={"adapter":a.adapter}; limitations=result["limitations"]
    out=root/"queries"/f"artifact_{a.cmd}_{int(__import__('time').time())}.json"; out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    evidence_result={k:v for k,v in result.items() if k not in {"path","command","output_dir"}}
    ev=record_evidence(path,operation=operation,result=evidence_result,parameters=params,confidence=conf,authority=authority,predicate_type="ida.artifact",limitations=limitations)
    print(json.dumps({"saved":str(out),"evidence_id":ev["evidence_id"],"result":result if a.cmd=="inspect" else {"adapter":result["adapter"],"returncode":result["returncode"]}},indent=2,ensure_ascii=False)); return 0
if __name__=="__main__": raise SystemExit(main())
