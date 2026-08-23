# IDA 9.4 Language / Platform Awareness

Load only the relevant section for the current binary.

## Swift

IDA 9.4 improves Swift ABI/decompiler awareness, including Swift-specific calling convention
semantics. Preserve recovered `__swiftcall` behavior and special self/async/throws semantics.
Do not reinterpret special ABI registers as ordinary unexplained arguments merely to make a C-like
prototype look familiar.

## Rust

Preserve rustc/crate/panic metadata recovered by IDA when present. Crate and compiler-version
information can identify architecture/subsystems before deep decompilation. Do not replace strong
Rust ABI/type recovery with generic C prototypes unless instruction-level evidence requires it.

## Go

Preserve recovered build info, pclntab-derived names/types, dependencies, arguments, return types,
and compilation-unit grouping. Go metadata often provides higher-confidence function boundaries
and names than heuristic renaming.

## Objective-C / Apple

Preserve Objective-C selectors and recovered method prototypes. For Dyld Shared Cache work, load
`apple-dsc.md` and prefer IDA 9.4's new DSC model over old assumptions about missing/red xrefs.

## Qualcomm Hexagon / MBN

IDA 9.4 adds a Hexagon/QDSP6 processor module and Qualcomm MBN loader (including SBL/XBL and
multi-ELF scenarios). Let IDA's loader split/identify components first, then analyze each loaded
component according to its actual architecture. Hexagon packet execution means instruction order
and packet semantics require processor-aware verification.

## MCore / C-Sky V1

Use IDA's new stack tracking/stack-variable recovery. Avoid x86/ARM calling-convention assumptions.

## ARM / RISC-V / TriCore / V850

IDA 9.4 expands switch/ISA/type support across these families. Prefer processor-specific IDA
analysis for switches, stack/register semantics, and relocations, then verify decompiler output when
code uses newly supported extensions or unusual ABI behavior.
