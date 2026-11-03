"""地址配对器（PAL3 形 funcmap）：参照 functions.tsv × annotation 地址名表 × obj 符号
→ funcmap.tsv（schema 同 msvc8: start end name tu symbol method detail）。
用法: python3 funcmap_addr.py --ref functions.tsv --ann functions.json --objdir <dir> --out funcmap.tsv
method=addr（比 docblock 证据制更机械=更稳）"""
import argparse, json, os, struct

def bare_name(n):
    """键归一：MSVC6 mangled（?x@Cls@@...）/ 限定名（Cls::x）→ 裸名 x。"""
    if n.startswith('?'):
        n = n[1:].split('@')[0]
    return n.split('::')[-1].split('@@')[0]


def obj_symbols(path):
    """COFF obj 符号提取（stdlib only）：段内符号→符号名。"""
    syms = []
    try:
        d = open(path, 'rb').read()
        if len(d) < 20: return syms
        nsyms, = struct.unpack_from('<I', d, 12)
        symtab, = struct.unpack_from('<I', d, 8)
        strtab = symtab + 18 * nsyms
        for i in range(nsyms):
            o = symtab + 18 * i
            name, val, sec, typ, cls, naux = struct.unpack_from('<8sIhHBB', d, o)
            if sec > 0 and cls == 2:  # external, defined in section
                if name[:4] == b'\0\0\0\0':
                    off, = struct.unpack_from('<I', name, 4)
                    end = d.index(b'\0', strtab + off)
                    nm = d[strtab + off:end].decode('latin1')
                else:
                    nm = name.rstrip(b'\0').decode('latin1')
                syms.append((nm, val))
    except Exception:
        pass
    return syms

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', required=True); ap.add_argument('--ann', required=True)
    ap.add_argument('--objdir', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    raw = json.load(open(a.ann))
    # 三形通吃：pal3_names.json ({functions:[{address,name}]}) / functions.json (addr->{name}) / 混合
    ann = {}
    if isinstance(raw, dict) and isinstance(raw.get('functions'), list):
        for e in raw['functions']:
            if isinstance(e, dict) and e.get('address') and e.get('name'):
                ann[e['address'].lower()] = {'name': e['name']}
    elif isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict) and v.get('name'):
                ann[k.lower()] = v
    rows, unmatched = [], 0
    objsyms = {}
    for fn in sorted(os.listdir(a.objdir)):
        if fn.endswith('.obj') or fn.endswith('.o'):
            for nm, val in obj_symbols(os.path.join(a.objdir, fn)):
                objsyms.setdefault(nm, []).append((fn, val, nm))
                objsyms.setdefault(bare_name(nm), []).append((fn, val, nm))
    for ln in open(a.ref):
        p = ln.split('\t')
        if len(p) < 2 or p[0] == 'start': continue
        start, end = p[0], p[1]
        key = '0x' + start
        name = None
        for k in (key.lower(), key, '0x0' + start):
            if k in ann and isinstance(ann[k], dict):
                name = ann[k].get('name'); break
        if not name: unmatched += 1; continue
        hit = objsyms.get(name) or objsyms.get(bare_name(name)) or objsyms.get(name.lstrip('_'))
        if not hit: unmatched += 1; continue
        _obj, val, _mangled = hit[0]
        tu = _obj[:-4] if _obj.endswith('.obj') else _obj   # ourslib f.key = tu|mangled（tu 无扩展名）
        rows.append((start, end, name, tu, _mangled, 'addr', 'ann=%s' % key))
    with open(a.out, 'w') as fh:
        fh.write('start\tend\tname\ttu\tsymbol\tmethod\tdetail\n')
        for r in rows: fh.write('\t'.join(r) + '\n')
    print('funcmap_addr: paired=%d unmatched=%d -> %s' % (len(rows), unmatched, a.out))

if __name__ == '__main__':
    main()
