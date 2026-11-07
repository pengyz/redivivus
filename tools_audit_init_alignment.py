#!/usr/bin/env python3
"""初始化器 vs 定义 成员对账审计（globals 渲染器专项的对账工具，2026-11-07）。

对每个 `struct T g_X = {` 型全局：提取定义成员序（_unnamespaced.h）与初始化器项序
（globals.cpp），按 offset 尾/名字对账，报首个错位 + 总错位数 + 项数差。
用法: python3 tools_audit_init_alignment.py [StructName ...]   （缺省扫全部）
"""
import re, sys

H = 'reconstruct-out/_unnamespaced.h'
CPP = 'reconstruct-out/globals/globals.cpp'

def audit(cls):
    h = open(H, errors='ignore').read()
    cpp = open(CPP, errors='ignore').read()
    m = re.search(r'^struct\s+%s\s*\{' % re.escape(cls), h, re.M)
    if not m:
        return None
    d0 = m.start()
    # TODO(下轮): brace-close 计数代替 '\n};' 首命中——inline union/struct 的 '};'
    # 会提前截断 def_blk（RoleSystem 4672 vs 应 7600 字节全展开的成员数）
    d1 = h.index('\n};', d0)
    def_members = []
    for l in h[d0:d1].splitlines():
        mm = re.match(r'\s*/\* (0x[0-9A-Fa-f]+) \*/ (.+?);', l)
        if mm:
            def_members.append((mm.group(1), mm.group(2).strip()))
    m2 = re.search(r'struct %s (\w+) = \{' % re.escape(cls), cpp)
    if not m2:
        return {'cls': cls, 'def': len(def_members), 'init': None, 'note': 'no initializer'}
    i0 = m2.start()
    depth = 0; j = i0
    while True:
        if cpp[j] == '{': depth += 1
        elif cpp[j] == '}':
            depth -= 1
            if depth == 0: break
        j += 1
    init_items = re.findall(r'/\* \.([\w]+) = \*/', cpp[i0:j])
    n = min(len(def_members), len(init_items))
    mism = 0; first = None
    for k in range(n):
        iname = init_items[k]
        mo = re.search(r'_0x([0-9a-fA-F]+)$', iname)
        bad = False
        if mo:
            if int(def_members[k][0], 16) != int(mo.group(1), 16): bad = True
        else:
            dn = re.search(r'(\w+)$', def_members[k][1].split('[')[0])
            if dn and dn.group(1) != iname: bad = True
        if bad:
            if first is None:
                first = (k, def_members[k], iname)
            mism += 1
    return {'cls': cls, 'def': len(def_members), 'init': len(init_items),
            'diff': len(init_items) - len(def_members), 'mismatches': mism, 'first': first}

def main():
    h = open(H, errors='ignore').read()
    cpp = open(CPP, errors='ignore').read()
    names = sys.argv[1:]
    if not names:
        names = sorted(set(re.findall(r'struct (\w+) (\w+) = \{', cpp) and
                          [c for _, c in re.findall(r'struct (\w+) (\w+) = \{', cpp)]))
    bad = 0
    for cls in names:
        r = audit(cls)
        if r is None: continue
        if r.get('init') is None: continue
        flag = 'OK ' if (r['diff'] == 0 and r['mismatches'] == 0) else 'BAD'
        if flag == 'BAD': bad += 1
        print(f"[{flag}] {cls}: def={r['def']} init={r['init']} diff={r['diff']} mism={r['mismatches']}"
              + (f" first@{r['first'][0]}: def {r['first'][1][0]} {r['first'][1][1][:30]!r} vs .{r['first'][2]}" if r['first'] else ''))
    print(f'--- {bad} misaligned / {len(names)} audited')

if __name__ == '__main__':
    main()
