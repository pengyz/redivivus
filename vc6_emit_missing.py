#!/usr/bin/env python3
"""VC6 post-codegen missing-type emitter — v4 (clean rewrite).
Emits definitions for fwd-declared-undefined AND transitively-referenced field
types missing from the tree. Data = reconstruct extraction snapshot (Ghidra
truth; no invented fields). Skips tree/SDK-defined names. Hoists defs whose
first use precedes them. Idempotent: replaces its own marker block."""
import re, json, glob, os, subprocess

OUT, H = 'reconstruct-out', 'reconstruct-out/_unnamespaced.h'
SNAP = '/home/peng/workspace/ghidra-reconstruct/project/.ghidra-mcp/codegen-snapshot/dataTypes.ndjson'
MS, ME = '// [vc6_adapt] missing-type definitions', '// [vc6_adapt] end missing-type definitions'
SDK = ['/home/peng/workspace/PAL3Decomp/tools/compilers/msvc6.0/Include',
       '/home/peng/workspace/PAL3Decomp/tools/vc6/Include']
TYPEMAP = {'byte':'unsigned char','word':'unsigned short','dword':'unsigned long',
           'string':'const char *','TerminatedCString':'const char *','string-utf8':'const char *',
           'undefined':'unsigned char','code':'void *'}
KINDS = ('STRUCTURE','UNION','ENUM')
FIELD_RE = re.compile(r'^\s+(?:/\*[^*]*\*/\s*)?([A-Za-z_]\w*)\s+(\*+\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;')

snap = {}
for line in open(SNAP):
    d = json.loads(line)
    if d.get('name'): snap[d['name']] = d

def base_of(dt): return re.sub(r'\[.*', '', dt).replace('*','').strip()
def map_type(dt):
    m = re.match(r'^(.+?)((?:\[\d+\])+)$', dt)
    if m: return '%s%s' % (map_type(m.group(1)), m.group(2))
    return TYPEMAP.get(dt.strip(), dt.strip())

_sdk = {}
# Windows DECLARE_HANDLE(H) expands to `struct H__ { int unused; }` under STRICT —
# the literal name never appears in SDK headers, so the grep below misses it and emit v4
# redefines the struct (C2011). Exempt the __-suffixed handle family up front.
_HANDLE_MACRO_NAMES = {
    'HWAVEOUT__', 'HWAVEIN__', 'HMIDI__', 'HMIDIIN__', 'HMIDIOUT__', 'HMIDISTRL__',
    'HMIXER__', 'HDRVR__', 'HWIDGET__', 'HACM__', 'HACMDRIVER__', 'HACMOBJ__',
    'HACMSTREAM__', 'HCONV__', 'HCONVLIST__', 'HDDE__', 'HSZ__', 'HKL__', 'HRAWINPUT__',
}
def sdk_def(n):
    if n in _HANDLE_MACRO_NAMES: return True
    if n in _sdk: return _sdk[n]
    hit = False
    for d in SDK:
        fs = glob.glob(d + '/*.h') + glob.glob(d + '/*.H')
        if not fs: continue
        r = subprocess.run(['grep','-l','-E',r'(struct|enum)\s+%s\b' % re.escape(n), *fs],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for hf in r.stdout.split():
            t = open(hf, errors='ignore').read()
            if re.search(r'(struct|enum)\s+%s\s*[\{\n]' % re.escape(n), t) or \
               re.search(r'typedef\s+(struct|enum)\s+%s\b' % re.escape(n), t):
                hit = True; break
        if hit: break
    _sdk[n] = hit
    return hit

lines = open(H, errors='ignore').readlines()

# 1) strip own previous block (idempotent)
s = next((i for i,l in enumerate(lines) if MS in l), None)
if s is not None:
    e = next((i for i in range(s+1, len(lines)) if ME in lines[i]), None)
    if e is None:   # v1/v2 forms without END marker: walk defs
        i, depth, e = s+1, 0, None
        while i < len(lines):
            st = lines[i].strip()
            if depth == 0 and st.startswith('struct '):
                depth += lines[i].count('{') - lines[i].count('}'); i += 1; continue
            if depth > 0:
                depth += lines[i].count('{') - lines[i].count('}')
                if depth <= 0 and st == '};':
                    j = i+1
                    while j < len(lines) and lines[j].strip() == '': j += 1
                    if j >= len(lines) or not (lines[j].strip().startswith('struct ') or MS in lines[j]):
                        e = i; break
                i += 1; continue
            if st == '': i += 1; continue
            e = i-1; break
        if e is None: e = len(lines)-1
    del lines[s:e+1]
    if s < len(lines) and lines[s].strip() == '': del lines[s]

# 2) defined set (this file post-strip + other headers on disk)
defined = set()
for l in lines:
    m = re.match(r'(?:typedef\s+)?(?:struct|class|union|enum)\s+(\w+)\s*[\{\n]', l)
    if m: defined.add(m.group(1))
    m = re.match(r'typedef\s+[\w\s\*]+?\b(\w+)\s*;', l)
    if m and not re.match(r'typedef\s+struct\s+\w+\s+\w+;', l): defined.add(m.group(1))  # fwd-equivalent typedef ≠ definition
for f in glob.glob(OUT + '/**/*.h', recursive=True):
    if os.path.abspath(f) == os.path.abspath(H): continue
    t = open(f, errors='ignore').read()
    defined |= set(re.findall(r'(?:struct|class|union|enum)\s+(\w+)\s*[\{\n]', t))
    defined |= set(re.findall(r'typedef\s+[^;]*?\b(\w+)\s*\(', t))
    defined |= set(re.findall(r'typedef\s+[\w\s\*]+?\b(\w+)\s*;', t))

# 3) closure: fwd-undefined ∪ field-types of every struct in this file ∪ transitive snap deps
emit = []
def add(n):
    if n and n not in emit and n not in defined and not sdk_def(n) and n in snap and snap[n].get('kind') in KINDS:
        emit.append(n); return True
    return False
for l in lines:
    m = re.match(r'^struct (\w+);\s*$', l)
    if m: add(m.group(1))
changed = True
while changed:
    changed = False
    for l in lines:
        m = FIELD_RE.match(l)
        if m and add(m.group(1)): changed = True
    # module headers' fields too (defs land in _unnamespaced; they include it)
    for hf in glob.glob(OUT + '/*/*.h'):
        if os.path.abspath(hf) == os.path.abspath(H): continue
        for l in open(hf, errors='ignore'):
            m = FIELD_RE.match(l)
            if m and add(m.group(1)): changed = True
    for n in list(emit):
        for f in (snap[n].get('fields') or []):
            if add(base_of(f.get('dataType',''))): changed = True

# 4) topo
ordered, seen = [], set()
def visit(n):
    if n in seen: return
    seen.add(n)
    for f in (snap.get(n) or {}).get('fields') or []:
        b = base_of(f.get('dataType',''))
        if b in emit and b != n: visit(b)
    ordered.append(n)
for n in emit: visit(n)

# 5) first real use + enclosing opener + include floor
def first_use_of(names):
    fu = None
    for i, l in enumerate(lines):
        for n in names:
            if re.match(r'^\s*struct\s+%s\s*;' % n, l): continue
            if re.search(r'\b%s\b' % re.escape(n), l):
                fu = i if fu is None else min(fu, i)
    return fu
def opener_before(idx):
    depth = 0; op = 0
    for i in range(idx):
        d0 = depth
        for ch in lines[i]:
            if ch == '{': depth += 1
            elif ch == '}': depth -= 1
        if d0 == 0 and depth > 0: op = i
        elif depth <= 0 and d0 > 0: op = i+1
    return op
floor = max([i for i,l in enumerate(lines) if l.startswith('#include')] or [0])

# 6) hoist: defs whose use precedes them OR that the pending block references —
#    all moved to just after the include block (floor+1): every body use is
#    below, so one placement satisfies every before-use constraint.
block_value_bases = set()
for n in ordered:
    for f in (snap.get(n) or {}).get('fields') or []:
        dt = f.get('dataType','')
        if '*' not in dt:
            block_value_bases.add(base_of(dt))
# transitive closure: a hoisted def whose OWN by-value members name later types must
# bring those along (gbVertexPool -> gbChain1D regression, 2026-11-07: nsfix decl
# insertions shift relative order between runs, so one-shot hoist order is not stable).
# Iterate: if a name in block_value_bases has a def whose own by-value members name a
# type NOT in the set, add it — until fixpoint.
for _ in range(10):
    grew = False
    for n in list(block_value_bases):
        for f in (snap.get(n) or {}).get('fields') or []:
            dt = f.get('dataType','')
            if '*' not in dt:
                b = base_of(dt)
                if b and b not in block_value_bases and b in snap:
                    block_value_bases.add(b); grew = True
    if not grew: break
def _scan_depth(line, depth):
    j, n = 0, len(line)
    while j < n:
        c = line[j]
        if c == '/' and j+1 < n and line[j+1] == '/': return depth, False
        if c == '/' and j+1 < n and line[j+1] == '*':
            k = line.find('*/', j+2); j = (k+2) if k >= 0 else n; continue
        if c == '"' or c == "'":
            q = c; j += 1
            while j < n and line[j] != q:
                j += 2 if line[j] == '\\' else 1
        elif c == '{': depth += 1
        elif c == '}': depth -= 1
        j += 1
    return depth, True
def collect_spans():
    spans, i = {}, 0
    while i < len(lines):
        m = re.match(r'\s*(?:typedef\s+)?(?:struct|class|union|enum)\s+(\w+)\s*(?:final\s*)?\{', lines[i])
        if m:
            name, d0 = m.group(1), i
            depth, j = 0, i
            while j < len(lines):
                depth, _ = _scan_depth(lines[j], depth)
                if depth <= 0 and j > d0: break
                j += 1
            spans[name] = (d0, j); i = j+1; continue
        i += 1
    return spans
if not ordered and not hoisted:
    print('emit v4: nothing'); raise SystemExit(0)

# 7) block
block = ['\n' + MS + '  (data: extraction snapshot; v4 idempotent)\n',
         'struct unkbyte10 { unsigned char b[10]; };\n']
for name in ordered:
    e = snap[name]
    if e.get('kind') == 'ENUM':
        vals = e.get('values') or e.get('enumerators') or []
        block.append('enum %s {\n' % name)
        if isinstance(vals, dict):
            for k, v in sorted(vals.items(), key=lambda kv: kv[1] if isinstance(kv[1], int) else 0):
                block.append('    %s = %s,\n' % (k, v))
        else:
            for v in vals:
                if isinstance(v, dict): block.append('    %s = %s,\n' % (v.get('name'), v.get('value', 0)))
        block.append('};\n'); continue
    block.append('struct %s {\n' % name)
    for f in sorted(e.get('fields') or [], key=lambda x: x.get('offset', 0)):
        dt = f.get('dataType', 'unsigned char')
        fn = f.get('name') or ('_f%d' % f.get('offset', 0))
        if re.match(r'^unkbyte\d+$', dt): decl = 'unsigned char %s[%s];' % (fn, dt[6:])
        else:
            mm = re.match(r'^(.+?)((?:\[\d+\])+)$', dt)
            decl = ('%s %s%s;' % (map_type(mm.group(1)), fn, mm.group(2))) if mm else '%s %s;' % (map_type(dt), fn)
        block.append('    /* 0x%04X */ %s\n' % (f.get('offset', 0), decl))
    block.append('};\n')
block.append(ME + '\n')

fu = first_use_of(ordered)
tgt = (opener_before(fu) if fu is not None else len(lines))
tgt = max(tgt, floor + 1)
lines[tgt:tgt] = block
open(H, 'w').writelines(lines)
print('emit v4: %d defs @%d (%s)' % (len(ordered)+1, tgt+1, ','.join(ordered)))

# 8) post-emit hoist: defs whose by-value use precedes their position — run AFTER the
#    emit block lands so positions include the block (gbVertexPool@emit-block uses
#    gbChain1D; if gbChain1D sits later (prev-run emit tail), move it above the user).
#    Target: immediately before the FIRST by-value user line.
hoisted2 = []
for _round in range(80):
    lines = open(H, errors='ignore').readlines()
    floor = max([i for i,l in enumerate(lines) if l.startswith('#include')] or [0])
    moved = False
    # collect spans
    spans = {}
    i = 0
    while i < len(lines):
        m = re.match(r'^(struct|enum)\s+(\w+)\s*\{', lines[i])
        if m:
            name = m.group(2); d0 = i; depth = 0; j = i
            while j < len(lines):
                depth += lines[j].count('{') - lines[j].count('}')
                if depth == 0 and j > i:
                    spans[name] = (d0, j); i = j + 1; break
                j += 1
            else:
                i += 1
            continue
        i += 1
    for name, (d0, d1) in sorted(spans.items(), key=lambda kv: kv[1][0]):
        if sdk_def(name): continue
        fu = None
        for i2, l2 in enumerate(lines):
            if d0 <= i2 <= d1: continue
            if re.match(r'\s*struct\s+%s\s*;' % name, l2): continue
            if re.match(r'\s*(?:/\*[^*]*\*/\s*)?%s\s+\w+\s*(?:\[[^\]]*\])?\s*;' % re.escape(name), l2):
                fu = i2; break
        if fu is not None and fu < d0:
            seg = lines[d0:d1+1]
            del lines[d0:d1+1]
            # target: right after the include floor — before ALL defs, stable and
            # cannot land inside another struct. Rescan (break) makes order converge:
            # dependencies get hoisted in later rounds, ending above their users.
            lines[floor+1:floor+1] = seg
            hoisted2.append(name); moved = True
            break
    if not moved: break
if hoisted2:
    open(H, 'w').writelines(lines)
    print('post-emit hoist:', hoisted2)
