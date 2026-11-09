#!/usr/bin/env python3
"""B-side namespace-function resolver (idempotent), for vc6_adapt_tree.sh (step after deepfix).

Problem: Ghidra FID tags statically-linked GBENGINE functions with class-qualified
names (gbVec3D::Length). reconstruct renders CALL SITES as `T::m(args)` but never
emits the declarations (extract skips FID/library functions → bodies absent too).
VC6 fails C2039/C2065 on every such call - a large family currently hidden behind
the C1003 truncation; fixing earlier errors surfaces them.

Signature source (A-level): original/gbengine.dll export table - 2038 C++ mangled
exports encode full signatures. Same code is statically linked into PAL3.exe
(FID byte-match), so dll signatures are binary truth for these functions.

Per matched (T, m):
  1) emit `ret m(params) const;` member decl into `struct T {...}` (provenance
     comment = mangled export name); idempotent via `/* nsfix:T */` marker.
  2) rewrite call sites `T::m(A0, rest)` -> `A0.m(rest)` when A0 starts with `&`
     (object), else `A0->m(rest)` (pointer). A0 == this (ECX, __thiscall).
ctor/operator forms: v1 SKIPPED (statement-level rewrite needed), counted.
Unmatched pairs reported, never guessed. No fabricated signatures.
Run from pal3-redivivus/: python3 vc6_ns_freefn.py [--dry]
"""
import re, sys, glob, subprocess

DLL = '/home/peng/workspace/PAL3Decomp/original/gbengine.dll'
OUT = 'reconstruct-out'
SKIP_PREFIX = ('std', 'GBENGINE_DLL', 'PAL3')
DRY = '--dry' in sys.argv

BASIC = {'X': 'void', 'M': 'float', 'H': 'int', 'I': 'unsigned int', 'N': 'bool',
         'D': 'char', 'E': 'unsigned char', 'K': 'unsigned long', 'J': 'long',
         'F': 'short', 'G': 'unsigned short'}

class TypeParser:
    """Minimal MSVC type-code parser (subset used by GBENGINE exports)."""
    def __init__(self, s, backrefs, enums=None):
        self.s, self.i, self.br, self.failed = s, 0, backrefs, False
        self.enums = enums
    def eat(self, tok):
        if self.s.startswith(tok, self.i): self.i += len(tok); return True
        return False
    def seg(self):  # name segment up to '@' (consumes the '@')
        j = self.s.find('@', self.i)
        if j < 0: self.failed = True; return None
        n = self.s[self.i:j]; self.i = j + 1; return n
    def _qualified(self, prefix3):
        # name segment follows; a digit segment is a backref into self.br
        self.i += len(prefix3)
        n = self.seg()
        if self.s[self.i:self.i + 1] == '@': self.i += 1
        if n and n.isdigit():
            idx = int(n)
            n = self.br[idx] if idx < len(self.br) else n
        return n
    def type(self):
        # MSVC rule: each P/A/R is followed by an A/B pointee modifier (A=near, B=const).
        # PAX = void*, PBD = const char*, AAU = struct&, ABU = const struct&, PAPAU = struct**
        mods = []
        while True:
            if self.eat('P'): mods.append('*')
            elif self.eat('A'): mods.append('&')
            elif self.eat('R'): mods.append('*&')
            else: break
            if self.eat('B'): mods.append('const ')
            else: self.eat('A')  # near pointee marker - no-op
        t = None
        c2 = self.s[self.i:self.i + 2]
        if self.s.startswith('?A', self.i) or self.s.startswith('?B', self.i):
            self.i += 2                        # by-value class return cv marker
        if c2 in ('AU', 'AV'):
            n = self._qualified(c2); t = n or '?'
        elif c2 == '_K': self.i += 2; t = '__int64'
        elif c2 == '_N': self.i += 2; t = 'bool'
        else:
            c = self.s[self.i:self.i + 1]
            if c in ('U', 'V'):  # bare struct/class (P/A + B already consumed)
                n = self._qualified(c); t = n or '?'
            elif c == 'W':       # enum: W4<name>@@
                self.i += 1
                self.eat('4') or self.eat('0') or self.eat('1') or self.eat('2')
                n = self.seg()
                if self.s[self.i:self.i + 1] == '@': self.i += 1
                t = n or '?'
                if getattr(self, 'enums', None) is not None: self.enums.add(n)
            elif c in BASIC: self.i += 1; t = BASIC[c]
            else:
                self.failed = True; return None
        for m in reversed(mods):
            t = t + m if m in ('*', '&', '*&') else (m + t)
        return t

lib_overloads = {}

def _const_tail(e):
    return ' const' if e.get('const') else ''

def load_siglib():
    out = subprocess.run(['objdump', '-p', DLL], capture_output=True, text=True).stdout
    mangled = re.findall(r'^\s*\[\s*\d+\]\s+(\?[A-Za-z_?][^ ]*)\s*$', out, re.M)
    lib, unsup = {}, 0
    for mn in mangled:
        e = parse_export(mn)
        if not e: unsup += 1; continue
        ret, params, ok = parse_sig(e)
        if not ok: unsup += 1; continue
        e['ret'], e['params'] = ret, params
        # overloads: same (cls, method), different arity/mangled — keep every one
        # (gbMatrixStack::Rotate has 1-arg (quaternion&) and 2-arg (float,vec3D&)
        # exports; setdefault-first kept only the first and Rotate call sites died
        # C2660 does-not-take-2, 2026-11-07)
        key = (e['cls'], e['method'], len(params))
        lib.setdefault(key, e)
        lib.setdefault((e['cls'], e['method']), e)  # primary alias → first seen
        lib_overloads.setdefault((e['cls'], e['method']), []).append(e)
        # Ghidra names the MSVC in-place default-ctor closure `??_FC@@QAEXXZ` as
        # `<Cls>::_default_constructor_closure_` — alias it so call-site scans match.
        if e['method'] == '??_F':
            lib.setdefault((e['cls'], '_default_constructor_closure_'), e)
        # ctor alias: `T::T(args)` call sites use meth=T, but the siglib key is
        # (cls, '??0'). Alias (cls, cls) so pass2/pass3 can find the entry.
        if e['kind'] == 'ctor':
            lib.setdefault((e['cls'], e['cls']), e)
    return lib, len(mangled), unsup, lib_overloads

def parse_export(mn):
    # ctor/op forms: `??<op><Class>@@` - op code glues directly to class name
    # (??0 ctor, ??1 dtor, ??2/3 new/delete, ??4 op=, ??8 op==, ??G op- ...). No '@' between.
    # Two-char ops: ??_F = in-place default-ctor closure (MSVC `??_FC@@QAEXXZ`,
    # Ghidra names it <Cls>::_default_constructor_closure_), ??_E/??_G = dtor variants;
    # the `_X` must be consumed as ONE op unit.
    m = re.match(r'\?\?(_[A-Z0-9]|[\dA-Za-z])([A-Za-z_][A-Za-z0-9]*)@@[AQUV][AB][EF]@?(.*)$', mn)
    if m:
        return {'cls': m.group(2), 'method': '??' + m.group(1), 'kind': 'ctor',
                'rest': m.group(3), 'mangled': mn}
    m = re.match(r'\?([A-Za-z_0-9]+)@([A-Za-z_0-9]+)@@[AQUV]([AB])[EF](.*)$', mn)
    if m:
        method = m.group(1)
        kind = 'op' if method.startswith('operator') else 'method'
        return {'cls': m.group(2), 'method': method, 'kind': kind, 'const': m.group(3) == 'B',
                'rest': m.group(4), 'mangled': mn}
    return None

def parse_sig(e):
    """Parse ret+params for non-ctor; ctor params only (ret=None).
    Backref table: plain methods `?m@C@@` seed [m, C] (slot1=C); ctor/op `??nC@@`
    seed [C] (slot0=C) - empirically confirmed on gbengine.dll exports
    (?DotProduct@gbVec3D@@…PBU1@ → 1=gbVec3D; ??4gbVec3D@@…ABU0@ → 0=gbVec3D)."""
    br = [e['cls']] if e['kind'] == 'ctor' else [e['method'], e['cls']]
    enums, named = set(), set()
    def _grow(s):
        # backref table grows with every fully-spelled named type (ret, then each param):
        # confirmed by ?GetColumn@gbMatrix4@@QBEPAUgbVec3D@@PAU2@H@Z (2 -> ret's gbVec3D)
        for tok in re.findall(r'[A-Za-z_]\w*', s):
            if tok not in ('void','char','int','float','bool','unsigned','long','short','const','struct','class'):
                if tok not in br: br.append(tok)
    rest = e['rest']
    if e['kind'] != 'ctor':
        p = TypeParser(rest, br, enums)
        ret = p.type()
        if p.failed or ret is None: return None, [], False
        rest = rest[p.i:]
        _grow(ret)
    else:
        ret = None
    params = []
    p = TypeParser(rest, br, enums)
    while not p.failed and p.i < len(rest):
        if p.eat('@') or p.eat('Z'): break
        c = p.s[p.i:p.i+1]
        if c.isdigit() and params:
            # bare digit at param position = TYPE backref: reuse an earlier param's type
            # (e.g. `IPAD0@Z` -> (unsigned, char*, char*): GetEventTime@gbActor)
            idx = int(c)
            if idx >= len(params): p.failed = True; break
            params.append(params[idx]); p.i += 1; continue
        t = p.type()
        if t is None or p.failed: return ret, params, False
        if t == 'void': break  # XZ form (empty param list)
        params.append(t)
        _grow(t)
    if p.failed: return ret, params, False
    # collect named struct/class occurrences from rendered strings (word tokens, not basic types)
    import re as _re
    for s in ([ret] if ret else []) + params:
        for tok in _re.findall(r'[A-Za-z_][A-Za-z0-9_]*', s):
            if tok not in ('void','char','int','float','bool','unsigned','long','short','const','struct','class'):
                named.add(tok)
    e['enums'], e['named'] = enums, named
    return ret, params, True

# ---------------------------------------------------------------------------

CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_~][A-Za-z0-9_]*)\s*\(')

def split_args(s, start):
    """s[start]=='(' → (first_arg, rest_str, idx_after_close). Depth-safe."""
    depth, j, first_end = 0, start, None
    while j < len(s):
        c = s[j]
        if c in '([{': depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0: break
        elif c == ',' and depth == 1 and first_end is None:
            first_end = j
        j += 1
    inner = s[start + 1:j]
    if first_end is None:
        return inner.strip(), '', j + 1
    return inner[:first_end - start - 1].strip(), inner[first_end - start:], j + 1

def brace_close(t, open_idx):
    depth = 0
    for j in range(open_idx, len(t)):
        if t[j] == '{': depth += 1
        elif t[j] == '}':
            depth -= 1
            if depth == 0: return j
    return -1

def find_struct_def(headers, cls):
    pat = re.compile(r'^struct\s+%s\s*\{' % re.escape(cls), re.M)
    for path, t in headers:
        m = pat.search(t)
        if m:
            close = brace_close(t, t.index('{', m.start()))
            if close > 0: return path, close
    return None

def main():
    lib, total, unsup, lib_overloads = load_siglib()
    print(f'nsfix: siglib {len(lib)} entries ({total} exports, {unsup} unsupported)')
    cpps = sorted(glob.glob(OUT + '/**/*.cpp', recursive=True))
    headers = {f: open(f, errors='ignore').read()
               for f in sorted(glob.glob(OUT + '/**/*.h', recursive=True))}

    # pass 0: generic member-visibility sweep — any struct member whose type name is first
    # declared AFTER the struct's own position gets a fwd at file top. KIND-AWARE + global:
    #   - name declared as struct/class anywhere -> safe to `struct X;` fwd (position fix)
    #   - name only ever enum/typedef -> NEVER struct-fwd (C2371 clash) — skip & count
    #   - name unknown everywhere -> fwd (missing-type gap, e.g. emit-v4 pointer members)
    #   By-value member gaps stay emit_missing's hoist responsibility.
    global_kinds = {}   # name -> set of decl kinds across ALL headers
    for t in headers.values():
        for m2 in re.finditer(r'^\s*(struct|class|union|enum)\s+(\w+)', t, re.M):
            global_kinds.setdefault(m2.group(2), set()).add(m2.group(1))
        for m2 in re.finditer(r'^\s*typedef\s+[^;]+?\s(\w+)\s*;', t, re.M):
            global_kinds.setdefault(m2.group(1), set()).add('typedef')
    member_fwd, skipped_kinds = {}, {}
    member_re = re.compile(r'^\s*/\*[^*]*\*/\s+(.+?);\s*$', re.M)
    for path, text in headers.items():
        first_off = {}
        for m2 in re.finditer(r'^\s*(?:struct|class|union|enum)\s+(\w+)', text, re.M):
            first_off.setdefault(m2.group(1), m2.start())
        for m2 in re.finditer(r'^\s*typedef\s+[^;]+?\s(\w+)\s*;', text, re.M):
            first_off.setdefault(m2.group(1), m2.start())
        names = member_fwd.setdefault(path, [])
        for m2 in re.finditer(r'^struct\s+(\w+)\s*\{', text, re.M):
            close2 = text.find('\n};', m2.start())
            if close2 < 0: continue
            for mm in member_re.finditer(text, m2.end(), close2):
                decl = mm.group(1)
                if '*' in decl or '&' in decl: is_indirect = True
                else: is_indirect = False
                toks = decl.replace('*', ' ').replace('&', ' ').split()
                if len(toks) < 2: continue
                head = toks[0]
                if head in ('unsigned','signed','long','short','struct','class','union','enum','const'):
                    if len(toks) < 3: continue
                    head = toks[1]
                if head in BASIC.values(): continue
                if head in ('DWORD','WORD','BYTE','BOOL','uint','ushort','size_t','wchar_t',
                            'uint8_t','uint16_t','uint32_t','uint64_t','int8_t','int16_t',
                            'int32_t','int64_t','LPARAM','WPARAM','HANDLE','HWND'): continue
                if not re.match(r'^[A-Za-z_]\w+$', head): continue
                if first_off.get(head, 1 << 60) < m2.start(): continue   # already visible here
                kinds = global_kinds.get(head, set())
                if kinds and not (kinds & {'struct', 'class', 'union'}):
                    skipped_kinds[head] = sorted(kinds); continue       # enum/typedef-only: no fwd
                if not is_indirect:
                    continue                                             # by-value: not fwd's business
                if head not in names:
                    names.append(head); first_off[head] = 0
    if skipped_kinds:
        top_k = sorted(skipped_kinds.items())[:6]
        print('nsfix pass0 skipped enum/typedef-name members:', top_k)
    # pass 1: which (cls, method) method-form calls exist (for stats + skip counting)
    wanted = {}   # cls -> set(method)  - from BOTH live `T::m(` sites and already-rewritten
                  # member calls, so decl emission is independent of call-site state (idempotent)
    unmatched, skips = {}, {'ctor': 0, 'op': 0}
    member_re = re.compile(r'(?:\.|->)([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    decl_cls = {}   # cls -> set(method) that dll exports and struct def exists (superset)
    for _k, e in lib.items():
        cls, meth = _k[0], _k[1]
        if e['kind'] == 'method' or e['method'] == '??_F':
            decl_cls.setdefault(cls, set()).add(meth if e['kind'] == 'method' else '_default_constructor_closure_')
    # overload siblings from lib_overloads (primary alias keeps only first-seen)
    for (ocls, ometh), ovs in lib_overloads.items():
        if any(e['kind'] == 'method' or e['method'] == '??_F' for e in ovs):
            decl_cls.setdefault(ocls, set()).add(ometh)
    for f in cpps:
        t = open(f, errors='ignore').read()
        for m in CALL_RE.finditer(t):
            cls, meth = m.group(1), m.group(2)
            if cls in SKIP_PREFIX: continue
            e = lib.get((cls, meth))
            if e is None and meth == cls: e = lib.get((cls, '??0'))          # T::T( → ??0 ctor
            if e is None and meth.startswith('~'): e = lib.get((cls, '??1')) # T::~T( → ??1 dtor
            if e is None: e = lib.get((cls, '??' + meth))                     # other ??-forms
            if e is None:
                unmatched[f'{cls}::{meth}'] = unmatched.get(f'{cls}::{meth}', 0) + 1
            elif e['kind'] == 'ctor':
                # ctors ARE real functions (dll exports) — declare them as void
                # methods with the class name. This fixes C2661 ctor-not-found.
                if e.get('params') is not None:
                    wanted.setdefault(cls, set()).add(meth)
                else:
                    skips['ctor'] += 1
            elif e['kind'] == 'op':   skips['op'] += 1
            else:
                wanted.setdefault(cls, set()).add(meth)
                # overload siblings: same (cls, meth), different arities — declare them
                # all so either call shape resolves (gbMatrixStack::Rotate 1/2-arg)
                for ov in lib_overloads.get((cls, meth), []):
                    wanted.setdefault(cls, set()).add(meth)
                    ov['params'] = ov.get('params') or []
    # already-rewritten sites keep their classes in `wanted` via the export superset below
    for cls in decl_cls:
        wanted.setdefault(cls, set(decl_cls[cls]))

    # pass1b: bare-call family scan — deepfix g) stripped `gbVFileSystem::` call prefixes
    # BEFORE nsfix existed, so those sites are bare `Read(FS, ...)`. Collect them so decls
    # are emitted (pass 2) and rewrites happen (pass 4). Evidence discipline: rewrite only
    # sites whose FIRST argument text names the class (cast/type token) — no blind renaming.
    BARE_FAMILY = ('gbVFileSystem',)
    bare_hits = 0
    for cls in BARE_FAMILY:
        meths = sorted({k[1] for k, e in lib.items() if k[0] == cls and e['kind'] == 'method'})
        for f in cpps:
            t = open(f, errors='ignore').read()
            for meth in meths:
                for m2 in re.finditer(r'(?<![\w.])' + meth + r'\s*\(', t):
                    a0, rest, after = split_args(t, m2.end() - 1)
                    if cls in a0:
                        wanted.setdefault(cls, set()).add(meth)
                        bare_hits += 1

    # pass 2: emit decl blocks. Visibility discipline (per-HEADER, position-aware):
    #   a type is usable only if declared in the SAME header before the block. Missing
    #   struct/class -> forward-declare at file TOP (before any use; later real def coexists
    #   legally). typedef'd names never get a struct fwd (C2371 clash). Missing enum passed
    #   by value -> int substitution (VC6 ABI-identical). By-value use of an undefined
    #   struct -> skip that decl (counted), never guessed.
    decl_ok, decl_skip = {}, []
    fwd_by_file = {}          # path -> ordered names to forward-declare at file top
    skipped_byval = 0
    # P0.1c-global (2026-11-09): find_struct_def 失败(宿主定义已被吞)的类的孤儿
    # marker 也必须清理——否则残留在错误宿主里的旧块会在后续轮次继续错位重建。
    _decl_re_g = re.compile(r'^\s*\S[^\n]*@@Z \*/\s*$')
    for _p, _t in list(headers.items()):
        _changed = False
        _guard = 0
        while _guard < 200:
            _guard += 1
            _m = re.search(r'/\* nsfix:([A-Za-z_]\w*) -', _t)
            if not _m:
                break
            _cls_o = _m.group(1)
            if _cls_o in wanted and find_struct_def(list(headers.items()), _cls_o) is not None:
                # 合法宿主存在——跳过此 marker 找下一个
                _t = _t[:_m.end()] + '\x00SKIP\x00' + _t[_m.end():]
                continue
            _ms = _m.start()
            _ls = _t.rfind('\n', 0, _ms) + 1
            _le = _t.find('\n', _ms)
            _seg = _le + 1
            while _seg < len(_t):
                _nl = _t.find('\n', _seg)
                _line = _t[_seg:_nl if _nl >= 0 else len(_t)]
                if _decl_re_g.match(_line):
                    _seg = _nl + 1
                else:
                    break
            _t = _t[:_ls] + _t[_seg:]
            _changed = True
        if _changed:
            _t = _t.replace('\x00SKIP\x00', '')
            headers[_p] = _t
            if not DRY:
                open(_p, 'w').write(_t)
            print(f'nsfix: P0.1c orphan sweep on {_p}')
    for cls, meths in sorted(wanted.items()):
        loc = find_struct_def(list(headers.items()), cls)
        if loc is None:
            decl_skip.append(cls); continue
        path, close = loc
        text = headers[path]
        marker = f'/* nsfix:{cls} -'
        if marker in text:
            # BLOCK REBUILD (supersedes incremental top-up): the block content is a
            # deterministic function of the CURRENT siglib — parse fixes change param
            # counts, and a mangled-keyed dedup guard would preserve stale wrong-param
            # lines forever (gbRay::IsColTriangle 3-param stale vs 4-param truth,
            # 2026-11-07). Delete the block, re-emit fresh below.
            # CRITICAL: after deletion `close` must be REPAIRED — the struct's `};`
            # now sits exactly where the marker started; a stale `close` (pre-deletion
            # offset) made the fresh insert land INSIDE THE NEXT STRUCT (multi-run
            # glue corruption, 2026-11-07/08).
            marker_start = text.index(marker)
            open_idx = text.rfind('struct ', 0, marker_start)
            # P0.1a (2026-11-09): 宿主一致性——rfind 找到的 struct 必须就是本类。
            # 历史 marker 可能被插进错误宿主(嵌套深处 24 空格缩进实证),此时
            # brace_close 从错误位置数 → 删除范围吞掉相邻定义(单次运行 -3 定义实证)。
            host_m = re.match(r'struct\s+([A-Za-z_]\w*)', text[open_idx:])
            host_name = host_m.group(1) if host_m else None
            if host_name != cls:
                # P0.1c (v2 2026-11-09): 孤儿块**迁移**而非删除——decl 行被调用点引用
                # (首版删除致 9431→3973 回退实证: 宿主错位≠内容无用)。搬去正确宿主。
                ls_ = text.rfind('\n', 0, marker_start) + 1
                le_ = text.find('\n', marker_start)
                seg = le_ + 1
                decl_re = re.compile(r'^\s*\S[^\n]*@@Z \*/\s*$')
                while seg < len(text):
                    nl = text.find('\n', seg)
                    line = text[seg:nl if nl >= 0 else len(text)]
                    if decl_re.match(line):
                        seg = nl + 1
                    else:
                        break
                block_lines = [l for l in text[ls_:seg].split('\n')]
                # 迁移去重: 宿主已有同名方法声明(C2535 实证)→丢弃该行;marker行保留
                _keep = []
                _body = headers and next((tt for pp, tt in headers.items() if re.search(r'^struct\s+' + re.escape(cls) + r'\s*\{', tt, re.M)), '')
                for _bl in block_lines:
                    if _bl.lstrip().startswith('/* nsfix:'):
                        _keep.append(_bl); continue
                    _nm = re.match(r'\s*(?:[A-Za-z_][\w\s\*&:<>]*?\s)?([A-Za-z_]\w*)\s*\(', _bl)
                    if _nm and _body and re.search(r'\b' + re.escape(_nm.group(1)) + r'\s*\(', _body):
                        continue  # 宿主已有
                    _keep.append(_bl)
                block = '\n'.join([l for l in _keep if l is not None])
                if not any(l.strip() and not l.lstrip().startswith('/*') for l in _keep):
                    # 全部重复→只删孤儿不搬
                    pass
                loc2 = find_struct_def(list(headers.items()), cls)
                if loc2 is not None:
                    path2, close2 = loc2
                    t2_ = headers[path2]
                    if path2 == path:
                        # 同文件: 先删后插(索引从后向前安全)
                        text = text[:ls_] + text[seg:]
                        text = text[:close2] + block + text[close2:]
                        headers[path] = text
                        if not DRY:
                            open(path, 'w').write(text)
                    else:
                        text = text[:ls_] + text[seg:]
                        t2_ = t2_[:close2] + block + t2_[close2:]
                        headers[path] = text
                        headers[path2] = t2_
                        if not DRY:
                            open(path, 'w').write(text)
                            open(path2, 'w').write(t2_)
                    print(f'nsfix: P0.1 orphan block for {cls} MIGRATED {host_name} -> {cls} ({"same" if path2 == path else path2})')
                else:
                    text = text[:ls_] + text[seg:]
                    headers[path] = text
                    if not DRY:
                        open(path, 'w').write(text)
                    print(f'nsfix: P0.1 orphan block for {cls} removed (no host; was {host_name})')
                continue
            open_idx = text.index('{', open_idx)
            close_idx = brace_close(text, open_idx)
            # P0.1b: marker 必须落在宿主体内(close_idx > marker_start 且闭合有效)
            if close_idx < 0 or close_idx <= marker_start:
                print(f'nsfix: P0.1 skip rebuild {cls}: brace_close={close_idx} vs marker_start={marker_start}')
                continue
            text = text[:marker_start] + text[close_idx:]
            close = marker_start          # `};` now occupies this exact position
            headers[path] = text
        if marker not in text:
            # position-aware visibility: name -> first declaration offset in THIS header
            first_off = {}
            for m2 in re.finditer(r'^\s*(?:struct|class|union|enum)\s+(\w+)', text, re.M):
                first_off.setdefault(m2.group(1), m2.start())
            for m2 in re.finditer(r'^\s*typedef\s+[^;]+?\s(\w+)\s*;', text, re.M):
                first_off.setdefault(m2.group(1), m2.start())
            lines = [f'    /* nsfix:{cls} - sigs from gbengine.dll exports (A-level); bodies pending extract (FID skip in B-track extract) */']
            fwd_names = fwd_by_file.setdefault(path, [])
            for meth in sorted(meths):
                # ctor overload: meth == cls → emit ALL ??0 (ctor) overloads
                if meth == cls:
                    ctor_ovs = []
                    for (oc, om), ovl in lib_overloads.items():
                        if oc == cls and any(e2['method'] == '??0' for e2 in ovl):
                            ctor_ovs = ovl; break
                    if ctor_ovs:
                        for ce in ctor_ovs:
                            if ce['kind'] != 'ctor': continue
                            ps = ', '.join(ce['params']) if ce['params'] else ''
                            d2 = f'    {cls}({ps}); /* {ce["mangled"]} */'
                            if d2 not in lines:
                                lines.append(d2)
                    continue
                ov_lists = [v for k2, v in lib_overloads.items() if k2[0] == cls and k2[1] == meth]
                ovs = [e2 for lst in ov_lists for e2 in lst] if ov_lists else [lib.get((cls, meth), lib.get((cls, "??0"), lib.get((cls, cls))))]
                # scrub stale lines (old parser wrong param counts), mangled-keyed
                for _i2 in range(len(lines) - 1, -1, -1):
                    _mm = re.search(r'/\* (\?[A-Za-z_?][^*]+) \*/\s*$', lines[_i2])
                    if _mm:
                        for _e2 in ovs:
                            if _e2['mangled'] == _mm.group(1):
                                _want = f'    {_e2["ret"] or "void"} {meth}({", ".join(_e2["params"])}{_const_tail(_e2)}); /* {_e2["mangled"]} */'
                                if lines[_i2].rstrip() != _want:
                                    lines[_i2] = _want + '\n'
                for ov_e in ovs:
                    e = ov_e
                    ret = e['ret'] or 'void'
                    skip = False
                    def ensure(tok, why):
                        nonlocal skip
                        if tok in ('void','char','int','float','bool','unsigned','long','short','const'): return
                        if first_off.get(tok, 1 << 60) < close: return   # declared before use point
                        # enum/typedef names never get a struct fwd (ECPKMode C2371)
                        ks = global_kinds.get(tok)
                        if ks and not (ks & {'struct','class','union'}): return
                        if tok not in fwd_names:
                            fwd_names.append(tok); first_off[tok] = 0    # batch sits at file top
                    for tok in re.findall(r'[A-Za-z_]\w*', ret):
                        if tok in e.get('enums', ()) and first_off.get(tok, 1 << 60) >= close:
                            ret = ret.replace(tok, 'int')   # by-value enum ret, undefined -> int (ABI-equal)
                            continue
                        ensure(tok, 'ret')
                    params = []
                    for pstr in e['params']:
                        p = pstr
                        is_ptr = p.rstrip().endswith('*') or p.rstrip().endswith('&')
                        for tok in re.findall(r'[A-Za-z_]\w*', pstr):
                            if tok in e.get('enums', ()):
                                if first_off.get(tok, 1 << 60) >= close:
                                    p = p.replace(tok, 'int') + ' /* nsfix: enum %s undefined -> int (VC6 ABI-equal) */' % tok
                                continue
                            ensure(tok, 'param')
                        if not is_ptr and p == pstr:
                            named = [t for t in re.findall(r'[A-Za-z_]\w*', pstr)
                                     if t not in ('int','float','char','bool','unsigned','long','short','const','void')]
                            if named: skip = True   # by-value named type: fwd is not enough
                        params.append(p)
                    if skip:
                        skipped_byval += 1
                        continue
                    ps = ', '.join(params)
                    constkw = ' const' if e.get('const') else ''
                    if e['kind'] == 'ctor':
                        # ctor name is always the CLASS name, never '~new' or similar
                        dline = f'    {cls}({ps}); /* {e["mangled"]} */'
                    else:
                        decl_name = '_default_constructor_closure_' if e['method'] == '??_F' else meth
                        dline = f'    {ret} {decl_name}({ps}){constkw}; /* {e["mangled"]} */'
                    if dline not in lines:
                        # P0.1d (2026-11-09): 宿主已有同名声明(渲染器原生/历史轮次)则不插
                        # — rebuild 与宿主存量撞名 → C2535(gbGeomNode EnableBlade ×2 实证)
                        _nm2 = re.match(r'\s*(?:[A-Za-z_][\w\s\*&:<>]*?\s)?([A-Za-z_]\w*)\s*\(', dline)
                        if _nm2:
                            _outside = text[:text.find(marker)] if marker in text else text
                            if re.search(r'\b' + re.escape(_nm2.group(1)) + r'\s*\(', _outside):
                                continue
                        lines.append(dline)
                insert = '\n'.join(lines) + '\n'
            text = text[:close] + insert + text[close:]
            if not DRY:
                open(path, 'w').write(text)
            headers[path] = text
        decl_ok[cls] = path
    # merge generic member fwd sweep into per-file batches
    for path, names in member_fwd.items():
        tgt = fwd_by_file.setdefault(path, [])
        for n in names:
            if n not in tgt: tgt.append(n)
    # hoist fwd batches to file top (before any struct def or use point)
    for path, names in fwd_by_file.items():
        if not names: continue
        text = headers[path]
        # merge-mode: an existing batch gets the missing names appended (v2 regen
        # wipes the file; old batch + new names must coexist — a skip guard leaked
        # gbSphere/IDirect3D* out of the batch, C2061/C2501 at 4938/7190, 2026-11-07)
        batch_re = re.compile(r'(/\* nsfix fwd batch[^*]*\*/\n)((?:struct \w+;\n)*)')
        mb = batch_re.search(text)
        if mb:
            have = set(re.findall(r'struct (\w+);', mb.group(2)))
            # scrub stale WRONG fwds from earlier runs (enum/typedef names a pre-filter
            # bug emitted as `struct X;` — ECPKMode C2371); kind table is authoritative
            _bad_kinds_h = {n for n, ks in global_kinds.items() if not (ks & {'struct','class','union'})}
            _orig = re.findall(r'struct (\w+);', mb.group(2))
            stale = [n for n in _orig if n in _bad_kinds_h]
            keep = [n for n in _orig if n not in _bad_kinds_h]
            add_names = [n for n in names if n not in have and n not in _bad_kinds_h]
            if stale:
                print(f'  [fwd-scrub] {path}: -{sorted(stale)}')
            if add_names:
                print(f'  [fwd-merge] {path}: +{len(add_names)} ({add_names[:5]}...)')
            if add_names or stale:
                newblock = mb.group(1) + ''.join(f'struct {n};\n' for n in keep + add_names)
                text = text[:mb.start()] + newblock + text[mb.end():]
                if not DRY:
                    open(path, 'w').write(text)
                headers[path] = text
            continue
        fwd_txt = ('/* nsfix fwd batch - forward decls for nsfix member decls; '
                   'defined elsewhere or later in this file */\n'
                   + '\n'.join(f'struct {n};' for n in names) + '\n')
        # insert AFTER `#pragma once` if present (MSVC: pragma once must precede any code),
        # else after the leading comment block
        lines = text.split('\n')
        k = 0
        po = next((j for j, l in enumerate(lines) if l.strip() == '#pragma once'), None)
        if po is not None:
            k = po + 1
        else:
            while k < len(lines) and (lines[k].startswith('//') or lines[k].strip() == ''):
                k += 1
        text = '\n'.join(lines[:k]) + '\n' + fwd_txt + '\n'.join(lines[k:])
        if not DRY:
            open(path, 'w').write(text)
        headers[path] = text
    if skipped_byval:
        print(f'nsfix: skipped by-value-undef decls: {skipped_byval}')
    # repair v3: earlier pass3 emissions without cast/parens tore on precedence:
    #   `(T*)*EXPR->m(...)` and `*EXPR->m(...)` both parse as `*(EXPR->m(...))`.
    # Repair to the parenthesized form. Guarded: only rewrites forms where the arrow
    # target name is a known siglib method (no blind deref rewriting).
    all_meths = sorted({k[1] for k, e in lib.items() if e['kind'] == 'method'}, key=len, reverse=True)
    meth_alt = '|'.join(re.escape(m2) for m2 in all_meths)
    # a) `(T*)*EXPR->m(` — capture T (the text inside the leading paren pair)
    rb1 = re.compile(r'\((?:\s*::\s*)?((?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*)\s*\*+\)\s*\*\s*([A-Za-z_]\w*)\s*->\s*(' + meth_alt + r')\s*\(')
    # b) bare `*EXPR->m(`
    rb2 = re.compile(r'(?<![\w)&])\*\s*([A-Za-z_]\w*)\s*->\s*(' + meth_alt + r')\s*\(')
    n_rep = 0
    for f in cpps:
        t = open(f, errors='ignore').read()
        o = t
        t = rb1.sub(r'((\1*)*\2)->\3(', t)
        t = rb2.sub(r'(*\1)->\2(', t)
        if not DRY and t != o:
            open(f, 'w').write(t); n_rep += 1
    if n_rep: print(f'nsfix: repaired deref-call precedence: {n_rep} files')

    # pass 3: rewrite call sites (only classes whose decl landed)
    n_rw = 0
    for f in cpps:
        t = open(f, errors='ignore').read()
        o = t
        pos = 0
        while True:
            m = CALL_RE.search(t, pos)
            if not m: break
            cls, meth = m.group(1), m.group(2)
            if cls not in decl_ok or meth not in wanted.get(cls, set()):
                pos = m.end(); continue
            op = t.index('(', m.end() - 1)
            a0, rest, after = split_args(t, op)
            if not a0: pos = m.end(); continue
            if a0.startswith('&'):
                newcall = f'{a0[1:].strip()}.{meth}({rest})'
            else:
                # this-arg is a pointer expr — assert the callee class type explicitly
                # (the original `T::m(a0,...)` form asserted it; cast also fixes precedence
                # for a0 like `(::X*)*puVar` or bare locals). `(T*)p->m` would tear again:
                # wrap EVERYTHING: ((T*)a0)->m(rest)
                newcall = f'(({cls}*){a0})->{meth}({rest})'
            # v3-repair note: pass4's parenthesized form also applies here for bare-call
            # rewrites; historical v1/v2 spellings are repaired by the fixpats block below.
            t = t[:m.start()] + newcall + t[after:]
            pos = m.start() + len(newcall)
            n_rw += 1
        if not DRY and t != o:
            open(f, 'w').write(t)

    # pass 4: bare-call rewrite for the deepfix-g legacy family (gbVFileSystem only).
    # `Read(FS, a, b)` -> `FS->Read(a, b)` when FS's text names the class. First arg == this.
    n_bare = 0
    for cls in BARE_FAMILY:
        if cls not in decl_ok: continue
        meths = sorted({k[1] for k, e in lib.items() if k[0] == cls and e['kind'] == 'method'})
        # pre-step: repair v1 output — `*(T**)EXPR->m(...)` parsed wrong (-> binds tighter
        # than *). The this-arg `*(gbVFileSystem**)g_pVFileSys` IS a pointer (deref of
        # T** yields T*), so the member form needs parens: `(*(T**)EXPR)->m(...)`.
        # two historical broken spellings, both repaired to `(*(T**)EXPR)->m(`:
        #   v1: `*(T**)EXPR->m(`   (-> bound tighter than *)
        #   v2: `(*T**EXPR)->m(`   (repair regex dropped cast parens)
        fixpats = [
            (re.compile(r'\*\(([A-Za-z_]\w*)\*\*\)([A-Za-z_]\w*)->([A-Za-z_]\w*)\('),
             r'(*(\1**)\2)->\3('),
            (re.compile(r'\(\*([A-Za-z_]\w*)\*\*([A-Za-z_]\w*)\)->([A-Za-z_]\w*)\('),
             r'(*(\1**)\2)->\3('),
            # v1 bare-call legacy: `(T*)&EXPR->M(` — the & and -> fight over precedence;
            # the original arg was `&EXPR` (address of pointer-to-T = T**-ish), passed as
            # this. Honest form: keep the address-of, cast it, THEN deref the member call:
            # `(*(T**)&EXPR)->M(`. EXPR here is a global POINTER slot (g_BaseVFileSystem),
            # so &EXPR is T** and one deref yields the T* this.
            (re.compile(r'\(([A-Za-z_][A-Za-z0-9_]*)\*\)&([A-Za-z_]\w*)->([A-Za-z_]\w*)\('),
             r'(*(\1**)&\2)->\3('),
        ]
        for f in cpps:
            t = open(f, errors='ignore').read()
            o = t
            for pat, rep in fixpats:
                t = pat.sub(rep, t)
            if not DRY and t != o:
                open(f, 'w').write(t)
        for f in cpps:
            t = open(f, errors='ignore').read()
            o = t
            pos = 0
            while True:
                best = None
                for meth in meths:
                    m2 = re.compile(r'(?<![\w.])' + meth + r'\s*\(').search(t, pos)
                    if m2 and (best is None or m2.start() < best.start()):
                        best = m2
                if not best: break
                meth = re.match(r'([A-Za-z_]\w*)', t[best.start():]).group(1)
                e = lib.get((cls, meth))
                if e is None or e['kind'] != 'method':
                    pos = best.end(); continue
                # guard: already a member call (`X->meth(`) — skip (idempotency)
                if t[max(0, best.start() - 2):best.start()] == '->':
                    pos = best.end(); continue
                a0, rest, after = split_args(t, best.end() - 1)
                if cls not in a0:
                    pos = best.end(); continue
                # parenthesize the this-expression: `->` binds tighter than `*`, and args
                # like `*(gbVFileSystem**)g_pVFileSys` (a POINTER, deref of T**) need it
                newcall = f'({a0})->{meth}({rest})'
                t = t[:best.start()] + newcall + t[after:]
                pos = best.start() + len(newcall)
                n_bare += 1
            if not DRY and t != o:
                open(f, 'w').write(t)
    print(f'nsfix: decl classes={len(decl_ok)} skip-nodef={len(decl_skip)} rewritten={n_rw} '
          f'bare-rewritten={n_bare} skip ctor={skips["ctor"]} op={skips["op"]}')
    top = sorted(unmatched.items(), key=lambda x: -x[1])[:12]
    print('nsfix unmatched top:', top)

if __name__ == '__main__':
    main()
