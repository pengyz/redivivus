#!/usr/bin/env python3
"""VC6 post-codegen gap-fill: reconstruct's global-initializer renderer emits
per-byte values for unclaimed gaps, but its struct-def renderer walks fields
only → positional mismatch → C2078/C2440 cascade. Insert per-byte uint8_t
fillers into struct DEFS for every offset gap (incl. tail), using the
extraction snapshot's offset+size as truth. Idempotent (fillers carry offset
comments; a filled gap is no longer a gap)."""
import re, json, glob, os

OUT = 'reconstruct-out'
SNAP = '/home/peng/workspace/ghidra-reconstruct/project/.ghidra-mcp/codegen-snapshot/dataTypes.ndjson'
snap = {}
for line in open(SNAP):
    d = json.loads(line)
    if d.get('name') and d.get('kind') in ('STRUCTURE', 'UNION'):
        snap[d['name']] = d

FIELD_OFF = re.compile(r'^\s*/\* 0x([0-9A-Fa-f]+) \*/\s*(.+?);\s*$')
TYPE_SIZE = {'char':1,'unsigned char':1,'byte':1,'uint8_t':1,'int8_t':1,'bool':1,
             'short':2,'unsigned short':2,'uint16_t':2,'int16_t':2,'word':2,
             'int':4,'unsigned int':4,'long':4,'unsigned long':4,'uint32_t':4,'int32_t':4,
             'float':4,'dword':4,'longdouble':8,'double':8,'uint64_t':8,'int64_t':8,'__int64':8}
def decl_size(decl):
    m = re.match(r'^(.*?)\s*(\w+)((?:\[\d+\])+)\s*$', decl)
    if m:
        base, dims = m.group(1).strip(), re.findall(r'\[(\d+)\]', m.group(3))
        n = 1
        for d in dims: n *= int(d)
        b = base.replace('const','').replace('*','').strip()
        if b.endswith('*') or '*' in base: return 4 * n
        return TYPE_SIZE.get(b, 0) * n
    b = decl.replace('const','').strip()
    if '*' in b: return 4
    b = re.sub(r'\s*\w+$', '', b) if False else b
    # `type name` form: strip trailing identifier
    m2 = re.match(r'^(.*?)\s+\w+$', decl)
    core = (m2.group(1) if m2 else decl).replace('const','').strip()
    if '*' in core: return 4
    return TYPE_SIZE.get(core, 0)

def split_unnamed_pass(path):
    """def renders size>1 unnamed/undefined fields as ONE uint8_t scalar while
    the init renderer splits them per byte → count mismatch (C2078). Split such
    def members into N per-byte members (init names are comments; only the
    COUNT must match). Idempotent: skip when off+1 already has a member."""
    lines = open(path, errors='ignore').readlines()
    changed = False
    i = 0
    while i < len(lines):
        m = re.match(r'struct\s+(\w+)\s*\{', lines[i])
        if not m or m.group(1) not in snap:
            i += 1; continue
        start_i = i
        sf = {f.get('offset'): f for f in (snap[m.group(1)].get('fields') or [])}
        j = i + 1
        offs_present = set()
        member_idx = []
        while j < len(lines) and not re.match(r'\};', lines[j]):
            fm = FIELD_OFF.match(lines[j])
            if fm:
                o = int(fm.group(1), 16)
                offs_present.add(o)
                member_idx.append((j, o, fm.group(2)))
            j += 1
        did_this = False
        for idx, off, decl in reversed(member_idx):
            f = sf.get(off)
            if not f: continue
            sz = f.get('size') or 0
            unnamed = (f.get('name') is None) or f.get('dataType') == 'undefined'
            if sz <= 1 or not unnamed: continue
            if sz > 4096:
                # runaway-annotation suspect (e.g. gbBinkVideo 1835912族):
                # do NOT materialize; A-track binary-evidence adjudication item
                print('  split SKIP (runaway suspect): %s off=0x%X size=%d' % (m.group(1), off, sz))
                continue
            if (off + 1) in offs_present: continue   # already split
            block = ['    /* 0x%04X */ uint8_t fieldUndef_0x%X;\n' % (off + k, off + k) for k in range(sz)]
            lines[idx:idx + 1] = block
            offs_present.update(range(off, off + sz))
            changed = did_this = True
        # 下一 struct：本 struct 关闭行可能被插入推移——重扫描
        i = j + 1 if not did_this else None
        if did_this:
            # 从 struct 开始行后重新定位其关闭行
            k = i0 = None
            # 简化：从原 struct 开始行重新走
            k = start_i + 1
            depth = 0
            while k < len(lines):
                depth += lines[k].count('{') - lines[k].count('}')
                if depth <= 0 and k > start_i: break
                k += 1
            i = k + 1
        if changed:
            open(path, 'w').writelines(lines)
    return changed

total_split = 0
for _round in range(500):
    did = False
    for f in glob.glob(OUT + '/**/*.h', recursive=True):
        if split_unnamed_pass(f):
            did = True; total_split += 1
    if not did: break
print('unnamed-split: %d struct-file passes' % total_split)

total_filled = 0
for f in glob.glob(OUT + '/**/*.h', recursive=True):
    lines = open(f, errors='ignore').readlines()
    changed = False
    i = 0
    while i < len(lines):
        m = re.match(r'struct\s+(\w+)\s*\{', lines[i])
        if not m or m.group(1) not in snap:
            i += 1; continue
        name = m.group(1)
        # collect member lines (offset comments) until closing `};`
        j = i + 1
        members = []  # (idx, offset, decl)
        while j < len(lines) and not re.match(r'\};', lines[j]):
            fm = FIELD_OFF.match(lines[j])
            if fm:
                members.append((j, int(fm.group(1), 16), fm.group(2)))
            j += 1
        if j >= len(lines) or not members:
            i = j; continue
        # compute gaps from snapshot (offset+size) — match by position order
        sf = snap[name].get('fields') or []
        ins = []  # (before_idx, [(off), ...])
        prev_end = None
        for k, (idx, off, decl) in enumerate(members):
            # snapshot field aligned by offset
            sfields = [x for x in sf if x.get('offset') == off]
            sz = sfields[0].get('size') if sfields else decl_size(decl)
            if sz is None: sz = 0
            if prev_end is not None and off > prev_end:
                ins.append((idx, list(range(prev_end, off))))
            prev_end = off + sz if sz else off + decl_size(decl)
        # tail gap: snapshot size vs last end
        stot = snap[name].get('size') or 0
        if prev_end is not None and stot > prev_end:
            ins.append((j, list(range(prev_end, stot))))  # before `};` (j = close idx)
        if not ins:
            i = j; continue
        # insert (reverse order to keep idx valid)
        for idx, offs in reversed(ins):
            block = ['    /* 0x%04X */ uint8_t fieldGap_0x%X;\n' % (o, o) for o in offs]
            lines[idx:idx] = block
            total_filled += len(offs)
            changed = True
        if changed:
            open(f, 'w').writelines(lines)
        i = j + 1
print('gapfill: %d per-byte fillers inserted' % total_filled)
