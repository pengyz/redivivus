#!/usr/bin/env python3
"""Deep-body fixes (idempotent), for vc6_adapt_tree.sh:
 g) gbVFileSystem:: qualified calls → free calls (decls are free functions)
 h) TryExpand decl+def pad to5 params — A-LEVEL ADJUDICATED 2026-11-06 (see below)
 i) FUN_004014b0 void→int + real returns — A-LEVEL ADJUDICATED 2026-11-06 (see below)
 j) Rsrc_Dialog_6a_804 emission DELETED — A-LEVEL ADJUDICATED 2026-11-06 (see below)
 k) SQRT → sqrt macro (Ghidra intrinsic name; byte-match revisit item)
 l) FUN_004019f0 body: local variable named `this` (keyword clash) → this_local
"""
import re, glob

# g) strip gbVFileSystem:: call prefix (only call-qualified form)
n = 0
for f in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read()
    t2 = re.sub(r'\bgbVFileSystem::(?!gbVFileSystem\b)', '', t)   # keep nothing; ctor form handled below
    t2 = t2.replace('gbVFileSystem::gbVFileSystem(', 'gbVFileSystem(')
    if t2 != t: open(f, 'w').write(t2); n += 1
print('g) vfs:: strip:', n)

# h) TryExpand pad 3→5 (decl in .h + def in .cpp)
# EVIDENCE-A (2026-11-06 binary adjudication, objdump -d original/PAL3.exe):
#   0x4012c1: ret 0x14          → callee clears 0x14=20 bytes = 5 stack params
#                                  (__thiscall: this via ECX, 0x4012ae mov edi,ecx)
#   0x4012a4: mov ebp,[esp+0x18] = param_4 ; 0x4012a9: mov esi,[esp+0x18] = param_5
#                                  → both extra params are consumed in the body
#   ⇒ Ghidra 3-param decl is WRONG; 5-param is binary truth. All 6 call sites pass 5.
# BYTE-REVISIT: decl rendered as free fn (this = 1st arg, __cdecl); binary is __thiscall
#   (ECX). Declarator form is a link-stage ABI item, not a compile blocker.
old_decl = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3);'
new_decl = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3, uint32_t param_4, uint32_t param_5); /* nsfix-h: 5 params, A-evid 0x4012c1 ret 0x14 */'
old_def = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3) {'
new_def = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3, uint32_t param_4, uint32_t param_5) { /* nsfix-h */'
m = 0
for f in glob.glob('reconstruct-out/**/*.h', recursive=True) + glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    if old_decl in t: t = t.replace(old_decl, new_decl, 1); m += 1
    if old_def in t: t = t.replace(old_def, new_def, 1); m += 1
    if t != o: open(f, 'w').write(t)
print('h) TryExpand pad:', m)

# i) FUN_004014b0 void→int (decl+def) + REAL returns from eax dataflow
# EVIDENCE-A (2026-11-06, objdump -d 0x4014b0):
#   0x4014b3: eax = [edx+0x3c] (list head node). eax is NEVER clobbered afterwards
#   (0x4014bf/0x4014c9/0x4014cf write memory / ecx, not eax).
#   Empty path 0x4014ba: ret with eax==0 (it was just tested) ; tail 0x4014d2: ret (eax=head).
#   Callers: `iVar3 = FUN_004014b0(); while (iVar3 && *(int*)(iVar3+0x14)…)` — used as node ptr.
#   ⇒ int return CONFIRMED. `return 0;` / `return iVar1;` follow the eax dataflow exactly —
#   these are NOT fabricated placeholder returns.
m = 0
for f in glob.glob('reconstruct-out/**/*.h', recursive=True) + glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    t = t.replace('void FUN_004014b0();', 'int FUN_004014b0();')
    t = t.replace('void FUN_004014b0() {', 'int FUN_004014b0() { /* nsfix-i: ret int, A-evid eax path 0x4014b3/0x4014d2 */')
    # body: bare `return;` inside the empty-list guard → `return 0;` (eax==0 on that path)
    t = t.replace('int iVar1 = *(int*)(*(int*)(in_ECX + 4) + 0x3c);\n    if (!iVar1) {\n      return;\n    }',
                  'int iVar1 = *(int*)(*(int*)(in_ECX + 4) + 0x3c);\n    if (!iVar1) {\n      return 0; /* nsfix-i: eax==0 here (just tested) */\n    }')
    # body: tail → `return iVar1;` (eax still holds the head node)
    t = t.replace('*(int*)(*(int*)(in_ECX + 8) + 0x3c) = iVar1;\n}',
                  '*(int*)(*(int*)(in_ECX + 8) + 0x3c) = iVar1;\n    return iVar1; /* nsfix-i: eax untouched since 0x4014b3 */\n}', 1)
    if t != o: open(f, 'w').write(t); m += 1
print('i) FUN_004014b0→int + real returns:', m)

# j) Rsrc_Dialog_*: DELETE the emission entirely (was: bogus extern Dialog + struct kw —
#    that fix FABRICATED a global `Dialog` that does not exist and mis-typed a resource as a struct).
# EVIDENCE-A (2026-11-06, objdump -p + resource-dir parse of original/PAL3.exe):
#   .rsrc contains RT_DIALOG ID 0x6a LANG 0x804 (rva 0x149893c, 1438 bytes) — name
#   Rsrc_Dialog_6a_804 = resource-id_ langid. Ghidra marks it builtin DialogResource size=-1
#   ("Dialog stored as a Resource") — NOT a struct, NOT a C++ global.
#   Zero code references in product (grep Rsrc_Dialog → definition line only).
#   ⇒ Resource data belongs to .rsrc (compiled from .rc); C++ source must not define it.
# Idempotent across all historical states: raw emission, old-fix state, already-deleted.
m = 0
for f in ['reconstruct-out/_unnamespaced.cpp', 'reconstruct-out/globals/globals.cpp'] + glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    try: lines = open(f, errors='ignore').readlines()
    except OSError: continue
    out = [l for l in lines
           if ('Rsrc_Dialog' not in l)
           and ('extern struct DialogResource Dialog;' not in l)
           and not re.match(r'^(static )?struct DialogResource Rsrc_', l)]
    if len(out) != len(lines):
        open(f, 'w').writelines(out); m += len(lines) - len(out)
# drop the now-orphan fwd decl in globals.h (only if no other DialogResource use remains)
gh = 'reconstruct-out/globals/globals.h'
try:
    t = open(gh, errors='ignore').read()
    body = '\n'.join(l for l in t.splitlines() if 'struct DialogResource;' not in l)
    rest = open('reconstruct-out/_unnamespaced.cpp', errors='ignore').read()
    if 'DialogResource' not in rest:
        if t != body: open(gh, 'w').write(body + '\n'); m += 1
except OSError:
    pass
print('j) Rsrc_Dialog emission deleted:', m, 'lines')

# k) SQRT macro into d2_platform (via marker append)
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read()
if '#define SQRT' not in t:
    t += '\n/* Ghidra intrinsic name mapping (byte-match revisit: sqrtss vs sqrtsd) */\n#include <math.h>\n#define SQRT(x) sqrt(x)\n'
    open(f, 'w').write(t); print('k) SQRT ✓')

# l) FUN_004019f0 body: rename identifier `this` (keyword) → this_local
f = 'reconstruct-out/_unnamespaced.cpp'
lines = open(f, errors='ignore').readlines()
start = next((i for i, l in enumerate(lines) if l.startswith('void FUN_004019f0() {')), None)
if start is not None:
    depth = 0; end = None
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth == 0 and i > start: end = i; break
    if end:
        changed = False
        for i in range(start, end + 1):
            # `this` as bare identifier (not this_xxx, not this->? rename all bare uses incl this-> since local var)
            new = re.sub(r'\bthis\b(?!_)', 'this_local', lines[i])
            if new != lines[i]: lines[i] = new; changed = True
        if changed:
            open(f, 'w').writelines(lines); print('l) this→this_local ✓ (body %d-%d)' % (start+1, end+1))
print('deepfix done')
