"""Static validator and pure-Python conformance runner for the IDA 9.4 skill package."""
from __future__ import annotations
from pathlib import Path
import ast, json, subprocess, sys

ROOT=Path(__file__).resolve().parents[1]

def fail(msg:str)->None:
    print(f"FAIL: {msg}"); raise SystemExit(1)

skill=(ROOT/'SKILL.md').read_text(encoding='utf-8')
session=(ROOT/'scripts'/'_ida_session.py').read_text(encoding='utf-8')
query=(ROOT/'scripts'/'ida_query.py').read_text(encoding='utf-8')
dataflow=(ROOT/'scripts'/'ida_dataflow.py').read_text(encoding='utf-8')
ctree=(ROOT/'scripts'/'ida_ctree.py').read_text(encoding='utf-8')
path=(ROOT/'scripts'/'ida_path.py').read_text(encoding='utf-8')

for token in (
    'IDA Pro 9.4','auto_analysis=True','ida_auto.auto_wait()','ida_hexrays.init_hexrays_plugin()',
    'Exact-string rule','Default output budgets','Structured Hex-Rays evidence','ida_sourcesink.py',
    'Deterministic evidence, authority, and contradictions','Revisioned residual unknowns',
    'Fail-closed completion and reconstruction obligations','Typed call edges and bounded interprocedural values',
    'Controlled runtime comparison','Tool-effect contracts and conformance',
):
    if token not in skill: fail(f'SKILL.md missing required policy: {token}')
if '9.3_headless' in skill or '9.3_headless' in session: fail('stale IDA 9.3 headless path remains')
for token in ('auto_analysis=True','_wait_for_auto_analysis()','_initialize_hexrays()','with opened as db','database_lock_diagnostics','save_analysis_profile'):
    if token not in session: fail(f'_ida_session.py missing invariant/hardening: {token}')
for token in ('find_bytes_between','utf-16le','mode": "byte-search','_xref_context','get_all_imports'):
    if token not in query: fail(f'ida_query.py missing fast-search feature: {token}')
for token in ('db.pseudocode.decompile','walk_expressions','find_strings','member_offset'):
    if token not in ctree: fail(f'ida_ctree.py missing structured C-tree feature: {token}')
for token in ('db.microcode.generate','MicroMaturity','mba.instructions()','insn.operands()','call_info'):
    if token not in dataflow: fail(f'ida_dataflow.py missing microcode feature: {token}')
for token in ('find_paths','max_depth','max_nodes','Static reference path'):
    if token not in path: fail(f'ida_path.py missing bounded path feature: {token}')

required=(
 'reference/ida94.md','reference/platforms.md','reference/apple-dsc.md','reference/evidence-verification.md',
 'reference/reconstruction.md','reference/runtime-artifacts.md','scripts/ida_sourcesink.py','scripts/ida_value_trace.py',
 'scripts/ida_profile.py','scripts/ida_cache.py','scripts/ida_capture.py','scripts/ida_reference.py','scripts/ida_artifact.py',
 'scripts/ida_capabilities.py','scripts/conformance_test.py','schemas/evidence-envelope.schema.json',
 'schemas/residual-unknown.schema.json','schemas/completion-ledger.schema.json','schemas/reconstruction-obligation.schema.json',
)
for item in required:
    if not (ROOT/item).exists(): fail(f'missing required file: {item}')

for py in (ROOT/'scripts').glob('*.py'):
    try: ast.parse(py.read_text(encoding='utf-8'),filename=str(py))
    except SyntaxError as exc: fail(f'syntax error in {py.name}: {exc}')

# Scripts that touch IDA must route through the mandatory wrapper. Pure state/runtime/artifact tools do not.
pure={
 '_ida_session.py','_common.py','_provenance.py','validate_skill.py','conformance_test.py','ida_state.py',
 'ida_evidence.py','ida_project.py','ida_diff.py','ida_capture.py','ida_reference.py','ida_artifact.py','ida_capabilities.py','ida_cache.py',
}
for py in (ROOT/'scripts').glob('*.py'):
    if py.name in pure: continue
    text=py.read_text(encoding='utf-8')
    if 'from _ida_session import open_database' not in text: fail(f'{py.name} does not import mandatory open_database wrapper')
    if 'Database.open(' in text: fail(f'{py.name} calls Database.open() directly')

for schema_name in ('evidence-packet.schema.json','evidence-envelope.schema.json','residual-unknown.schema.json','completion-ledger.schema.json','reconstruction-obligation.schema.json'):
    try: json.loads((ROOT/'schemas'/schema_name).read_text(encoding='utf-8'))
    except Exception as exc: fail(f'invalid JSON schema {schema_name}: {exc}')
legacy=json.loads((ROOT/'schemas'/'evidence-packet.schema.json').read_text(encoding='utf-8'))
for field in ('compilation_unit','language_runtime','ctree_facts','microcode_facts','authority','analysis_profile_digest','limitations','evidence_links'):
    if field not in legacy.get('properties',{}): fail(f'evidence packet schema missing {field}')

# Run the no-IDA conformance suite to catch semantic-registry regressions.
proc=subprocess.run([sys.executable,str(ROOT/'scripts'/'conformance_test.py')],cwd=str(ROOT/'scripts'),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,check=False)
if proc.returncode!=0: fail('conformance_test.py failed:\n'+proc.stdout)

print('PASS: IDA 9.4 invariants, profile-bound caches, deterministic evidence, revisioned unknowns, fail-closed completion/reconstruction, typed value tracing, runtime/artifact helpers, and pure-Python conformance validated')
