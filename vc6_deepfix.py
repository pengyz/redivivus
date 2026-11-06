#!/usr/bin/env python3
"""Deep-body fixes (idempotent), for vc6_adapt_tree.sh:
 g) gbVFileSystem:: qualified calls → free calls (decls are free functions)
 h) TryExpand decl+def pad to5 params (call sites are decomp truth)
 i) FUN_004014b0 void→int (callers assign its result; Ghidra decl inconsistent)
 j) Dialog global missing from tree → extern decl + struct keyword on Rsrc line
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
old_decl = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3);'
new_decl = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3, uint32_t param_4, uint32_t param_5);'
old_def = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3) {'
new_def = 'uint32_t TryExpand(uint32_t param_1, float param_2, int param_3, uint32_t param_4, uint32_t param_5) {'
m = 0
for f in glob.glob('reconstruct-out/**/*.h', recursive=True) + glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    if old_decl in t: t = t.replace(old_decl, new_decl, 1); m += 1
    if old_def in t: t = t.replace(old_def, new_def, 1); m += 1
    if t != o: open(f, 'w').write(t)
print('h) TryExpand pad:', m)

# i) FUN_004014b0 void→int (decl+def)
m = 0
for f in glob.glob('reconstruct-out/**/*.h', recursive=True) + glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    t = t.replace('void FUN_004014b0();', 'int FUN_004014b0();')
    t = t.replace('void FUN_004014b0() {', 'int FUN_004014b0() {')
    if t != o: open(f, 'w').write(t); m += 1
print('i) FUN_004014b0→int:', m)

# j) Dialog extern + struct keyword
f = 'reconstruct-out/_unnamespaced.cpp'
t = open(f, errors='ignore').read(); o = t
if 'extern struct DialogResource Dialog;' not in t:
    t = re.sub(r'(?m)^(static )?DialogResource (Rsrc_\w+)',
               lambda mm: 'extern struct DialogResource Dialog;\n%sstruct DialogResource %s' % (mm.group(1) or '', mm.group(2)),
               t, count=1)
if t != o: open(f, 'w').write(t); print('j) Dialog extern ✓')

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
