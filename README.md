# Claude IDA Headless Reverse-Engineering Skill v2.0.0 (IDA 9.4)

This bundle targets IDA Pro 9.4 + ida-domain 0.5.x and keeps the always-loaded skill compact while
pushing deterministic extraction into reusable scripts.

Major features:

- mandatory `auto_analysis=True` on every open, including cached databases;
- mandatory `ida_auto.auto_wait()`;
- mandatory successful `ida_hexrays.init_hexrays_plugin()` before any helper runs;
- exact string search by bytes (ASCII/UTF-8/UTF-16LE), preserving the fast large-IDB technique;
- Domain 0.5 `db.imports` instead of manual import callbacks;
- structured C-tree fact extraction (`ida_ctree.py`);
- structured microcode extraction with selectable maturity (`ida_dataflow.py`);
- bounded Pathfinder-style static path tracing (`ida_path.py`);
- bounded source/sink candidate-path analysis (`ida_sourcesink.py`);
- post-decompilation string-seed harvesting for IDA 9.4 discoveries;
- persistent `.ida-re/` evidence cache and token budgets;
- IDA 9.4 language/platform references for Swift, Rust, Go, DSC, Hexagon/MBN and more;
- Domain API first, SDK fallback for unwrapped 9.4 capabilities.

Default IDA directories are resolved automatically, but you will be prompted if multiple versions are found.

## Installation

1. **Extract** this entire bundle to a temporary folder on your machine.
2. Open a terminal or command prompt in that extracted temporary folder.
3. **Run the setup script** for your operating system:
   - On Windows: Run `.\setup.ps1`
   - On Linux: Run `chmod +x setup.sh && ./setup.sh`

The setup script will:
- Copy the `ida-headless-analysis` skill into your `~/.claude/skills/` directory.
- Search your environment variables for IDA Pro 9.2, 9.3, or 9.4 and Python 3.13.* (prompting you if there are multiple matches).
- Automatically configure the installed skill files with the correct paths.
- Install necessary Python dependencies.

After setup completes, you can test the installation with:
```bash
python ~/.claude/skills/ida-headless-analysis/scripts/validate_skill.py
```
