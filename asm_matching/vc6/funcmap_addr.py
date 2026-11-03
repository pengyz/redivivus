"""地址配对器（PAL3 形 funcmap）：参照 functions.tsv × annotation 地址名表 × obj 符号
→ funcmap.tsv（schema 同 msvc8: start end name tu symbol method detail）。
用法: python3 funcmap_addr.py --ref functions.tsv --ann functions.json --objdir <dir> --out funcmap.tsv
method=addr（比 docblock 证据制更机械=更稳）"""
import argparse, json, os, struct

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
    ann = json.load(open(a.ann)) if a.ann.endswith('.json') else {}
    rows, unmatched = [], 0
    objsyms = {}
    for fn in sorted(os.listdir(a.objdir)):
        if fn.endswith('.obj') or fn.endswith('.o'):
            for nm, val in obj_symbols(os.path.join(a.objdir, fn)):
                objsyms.setdefault(nm, []).append((fn, val))
    for ln in open(a.ref):
        p = ln.split('\t')
        if len(p) < 2 or p[0] == 'start': continue
        start, end = p[0], p[1]
        key = '0x' + start
        name = None
        for k in (key, '0x0' + start):
            if k in ann and isinstance(ann[k], dict):
                name = ann[k].get('name'); break
        if not name: unmatched += 1; continue
        hit = objsyms.get(name) or objsyms.get(name.lstrip('_'))
        if not hit: unmatched += 1; continue
        tu, val = hit[0]
        rows.append((start, end, name, tu, name, 'addr', 'ann=%s' % key))
    with open(a.out, 'w') as fh:
        fh.write('start\tend\tname\ttu\tsymbol\tmethod\tdetail\n')
        for r in rows: fh.write('\t'.join(r) + '\n')
    print('funcmap_addr: paired=%d unmatched=%d -> %s' % (len(rows), unmatched, a.out))

if __name__ == '__main__':
    main()
