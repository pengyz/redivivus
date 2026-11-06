#!/usr/bin/env python3
"""Post-fixes on the generated tree (idempotent), for vc6_adapt_tree.sh:
 1) repair `} // ns...}` lines (extra brace landed inside the comment)
 2) move module-header structs that _unnamespaced uses BY VALUE into _unnamespaced
 3) delete defs that duplicate VC6 SDK structs (C2011)"""
import re, glob, os
OUT = 'reconstruct-out'
H = OUT + '//_unnamespaced.h'

# 1) repair mangled closes: `} // comment}` → `} } // comment`
n = 0
for f in glob.glob(OUT + '/**/*.h', recursive=True) + glob.glob(OUT + '/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read()
    t2 = re.sub(r'^(\})\s*(//[^{}]*?)\}(\s*)$', r'\1} \2\3', t, flags=re.M)
    if t2 != t:
        open(f, 'w').write(t2); n += 1
if n: print('postfix: repaired closes in', n, 'files')
# missing semicolon after a def: `}` alone followed by a new type definition
for f in glob.glob(OUT + '/**/*.h', recursive=True):
    ls = open(f, errors='ignore').readlines()
    m2 = 0
    for i in range(len(ls)-1):
        if ls[i].rstrip('\n') == '}' and re.match(r'\s*(?:struct|class|union|enum)\s+\w+', ls[i+1]):
            ls[i] = '}\n'; m2 += 1   # marker: next loop appends below
    if m2:
        out = []
        for i, l in enumerate(ls):
            out.append(l)
            if l.rstrip('\n') == '}' and i+1 < len(ls) and re.match(r'\s*(?:struct|class|union|enum)\s+\w+', ls[i+1]):
                pass
        # simpler: rewrite directly
        out = []
        for i, l in enumerate(ls):
            if l.rstrip('\n') == '}' and i+1 < len(ls) and re.match(r'\s*(?:struct|class|union|enum)\s+\w+', ls[i+1]):
                out.append('};\n')
            else:
                out.append(l)
        open(f, 'w').writelines(out)
        print('postfix: semicolon repaired in', f)

# 2) SDK-dup defs to delete (C2011) — extend as errors reveal
DENY = {'HWAVEOUT__', 'waveformat_tag', 'pcmwaveformat_tag', '_EXCEPTION_RECORD'}
lines = open(H, errors='ignore').readlines()
def_span = {}
i = 0
while i < len(lines):
    m = re.match(r'\s*(?:struct|class|union|enum)\s+(\w+)\s*(?:final\s*)?\{', lines[i])
    if m and m.group(1) in DENY:
        d0, depth, j = i, 0, i
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            if depth <= 0 and j > d0: break
            j += 1
        def_span[m.group(1)] = (d0, j); i = j+1; continue
    i += 1
if def_span:
    for name, (a, b) in sorted(def_span.items(), key=lambda kv: -kv[1][0]):
        del lines[a:b+1]
        print('postfix: sdk-dup def removed:', name)
    open(H, 'w').writelines(lines)

# 3) move module-header structs used by value in _unnamespaced
lines = open(H, errors='ignore').readlines()
def first_by_value_use(name):
    for i, l in enumerate(lines):
        if re.match(r'\s*(?:/\*[^*]*\*/\s*)?%s\s+\w+\s*(?:\[[^\]]*\])?\s*;' % re.escape(name), l):
            return i
        if re.match(r'\s*(?:/\*[^*]*\*/\s*)?%s\s+\w+\s*\[' % re.escape(name), l):
            return i
    return None
moved = []
for mf in glob.glob(OUT + '/*/*.h'):
    if os.path.abspath(mf) == os.path.abspath(H): continue
    mt = open(mf, errors='ignore').read()
    for m in re.finditer(r'(?:struct|class|union)\s+(\w+)\s*(?:final\s*)?\{', mt):
        name = m.group(1)
        fu = first_by_value_use(name)
        if fu is None: continue
        # extract full def from module header
        start = m.start()
        depth, j = 0, m.end() - 1
        while j < len(mt):
            if mt[j] == '{': depth += 1
            elif mt[j] == '}':
                depth -= 1
                if depth == 0: break
            j += 1
        seg_text = mt[start:j+1]
        if j+1 < len(mt) and mt[j+1] == ';':
            seg_text += ';'
        # remove from module header
        mt = mt[:start] + mt[j+1:]
        open(mf, 'w').write(mt)
        # insert before the use's enclosing struct opener in H
        depth, op = 0, 0
        for i2 in range(fu):
            d0 = depth
            for ch in lines[i2]:
                if ch == '{': depth += 1
                elif ch == '}': depth -= 1
            if d0 == 0 and depth > 0: op = i2
            elif depth <= 0 and d0 > 0: op = i2 + 1
        lines[op:op] = [seg_text + '\n']
        moved.append(name)
        lines = open(H, errors='ignore').readlines() if False else lines
        break  # one per module header pass; rescan next loop
    # re-open logic: loop until no move per file
if moved: print('postfix: moved to _unnamespaced:', moved)
open(H, 'w').writelines(lines)
print('postfix done')
