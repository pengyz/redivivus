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
    # ctor form now goes to nsfix's ??0 handler (placement-new rewrite, q) below) —
    # do NOT strip to bare `T(`: that left `gbVFileSystem((gbVFileSystem*)&g_x)` which
    # VC6 parses as a type cast of an object value (C2440 'cannot convert T* to T').
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

# m) GRPinput name-hiding fix: header declares `void GRPinput(void*)` (a FUNCTION, h:115278)
#     which hides struct GRPinput (h:8196) for all later code — VC6 C2143 on every bare
#     `GRPinput*` type use. Header decls already spell `struct GRPinput*`; the .cpp type
#     uses need the elaborated specifier too. FUNCTION-CALL form `GRPinput(&x)` is NOT a
#     type use — must stay bare (no `&`/`*` after the name), so the regex only matches
#     GRPinput followed by */&. Idempotent: `struct GRPinput*` doesn't rematch (\bGRPinput
#     still matches inside "struct GRPinput" — guard with negative lookbehind on "struct ".
m = 0
for f in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    t2 = re.sub(r'(?<!struct )\bGRPinput(\s*[*&])', r'struct GRPinput\1', t)
    if t2 != t: open(f, 'w').write(t2); m += 1
print('m) GRPinput→struct GRPinput (type uses):', m)

# n) nullptr shim: VC6 predates C++11 — no nullptr. reconstruct emits it ~250×; NULL is
#     ABI-identical (both spell a 0 pointer constant). Same layer as k) SQRT (idiom shim).
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read()
if 'define nullptr' not in t:
    t += ('\n/* VC6 has no nullptr (C++11 idiom in codegen output); NULL is ABI-identical */\n'
          '#include <stddef.h>\n'
          '#ifndef nullptr\n#define nullptr NULL\n#endif\n')
    open(f, 'w').write(t); print('n) nullptr shim ✓')

# z) elaborated specifier for function-shadowed global types: `PAL_GDB * g_pGDB` —
#     a same-name FUNCTION declaration hides the struct name (C++ name hiding), and
#     the plain pointer type resolves to the function (C2371 different basic types).
#     `struct PAL_GDB * g_pGDB` bypasses the hiding. Evidence: PAL_GDB fn @00478e00 /
#     struct PAL_GDB @82007; CCBSystem fn @00512500 same pattern. Elaborated form is
#     a pure spelling fix, zero semantics.
m8 = 0
import os as _os
import glob as _g3b
for f4 in _g3b.glob('reconstruct-out/globals/*.cpp'):
    t = open(f4, errors='ignore').read()
    hh = _os.path.join(_os.path.dirname(f4), '..', '_unnamespaced.h')
    hh = _os.path.abspath(hh)
    hh_txt = open(hh, errors='ignore').read() if _os.path.exists(hh) else ''
    funcs = set(re.findall(r'^\w[\w\s\*]*?\b(\w+)\(', hh_txt, re.M))
    out = []
    for l in t.splitlines():
        mm2 = re.match(r'^(\w+) (\* ?\w+ = )', l)
        if mm2 and mm2.group(1) in funcs and not l.startswith('struct '):
            l = 'struct ' + l
            m8 += 1
        out.append(l)
    if m8:
        open(f4, 'w').write('\n'.join(out) + '\n')
print('z) elaborated-type fixes:', m8)
# o) operator_new decl — 【暂缓项·渲染器深水】声明门机制两层过滤
#     (header.ts startsWith('operator')已修+file-static startsWith已修，但
#     publicFunctions「跨TU才public」判定仍挡住同TU先用的它)。根修需动
#     index.ts:3578 的 public 计算或 TU 内前向声明机制——另开专项。
#     (CRT语义: Ghidra Library签名 operator new/__nh_malloc forwarder,
#      自定义壳名不与CRT符号冲突，定义已在TU尾、只需声明先行)
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read()
if 'void *operator_new' not in t:
    t += ('\n/* reconstruct CRT mapping: operator new helper — body is CRT at link (revisit) */\n'
          'void *operator_new(unsigned int size);\n')
    open(f, 'w').write(t); print('o) operator_new decl ✓')

# q3) explicit placement-new form (VC6 <new.h>'s placement operator new didn't
#     resolve through the include chain — "new does not take 2 parameters" x8 on
#     `new (&obj) T()`. An inline definition in the global namespace is the
#     standard spelling; semantics = return the pointer (identity).
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read()
# <new.h> (VC6 SDK) already defines the placement form (operator new(size_t, void*_P));
# a second inline body here collides C2084. Only ensure <new.h> is included.
if '#include <new.h>' not in t:
    t += '\n#include <new.h>\n'
    open(f, 'w').write(t); print('q3) <new.h> ensure ✓')

# y4) compiler-oracle symbol repair (2026-11-08): authoritative undeclared set =
#     VC6 C2065 census (10 symbols). Idempotent by exact-decl-line presence.
FIX_TABLE = {
  'stack0x00000018': 'unsigned char stack0x00000018[0x28]; /* WNDCLASSA holder (frame slot, revisit) */',
  'stack0x00000040': 'unsigned char stack0x00000040[0x104]; /* frame slot to 0x144 (revisit) */',
  'stack0x00000144': 'unsigned char stack0x00000144[0x400]; /* EH record frame slot to 0x544 (revisit) */',
  'stack0x00000544': 'unsigned char stack0x00000544[0x400]; /* frame slot to 0x944 (revisit) */',
  'stack0x00000944': 'unsigned char stack0x00000944[0x400]; /* frame slot to 0xd44 (revisit) */',
  'stack0x00000d44': 'unsigned char stack0x00000d44[0x400]; /* frame slot (revisit) */',
  'stack0xffffffec': 'long stack0xffffffec[2]; /* POINT holder (frame slot, revisit) */',
}
f = 'reconstruct-out/_unnamespaced.cpp'
t = open(f, errors='ignore').read()
o = t
m9 = 0
# a) frame-slot locals: insert into the ENCLOSING function of the first use
for sym, decl in sorted(FIX_TABLE.items(), key=lambda kv: -len(kv[0])):
    if decl in t:   # already inserted (exact line)
        continue
    um = re.search(r'\n([^\n]*\b' + re.escape(sym) + '\b)', t)
    if not um:
        continue
    pre_lines = t[:um.start()].split('\n')
    def_i = None
    for li in range(len(pre_lines) - 1, -1, -1):
        s = pre_lines[li].strip()
        if not s.endswith('{'):
            continue
        if s.startswith(('if', 'for', 'while', 'else', 'do', 'switch', '}', '/', '*', '+')):
            continue
        if '(' in s:
            def_i = li
            break
    if def_i is None:
        continue
    pos = len('\n'.join(pre_lines[:def_i + 1])) + 1
    t = t[:pos] + '    ' + decl + '\n' + t[pos:]
    m9 += 1
# b) externs for unresolved call targets (code exists, fn object missing)
if 'func_0x0055ef80' in t and 'func_0x0055ef80(void' not in t:
    t = t.replace('#include "globals/globals.h"\n',
        '#include "globals/globals.h"\n'
        '/* unresolved call targets: code exists at these addresses, Ghidra fn object\n'
        '   missing - call-site-shaped externs; root fix = create fn in Ghidra (revisit) */\n'
        'int func_0x0055ef80(void *a1, unsigned int a2, void *a3, void *a4, int a5);\n'
        'int func_0x00553c00(void);\n', 1)
# c) elaborated local (fn-shadow rule: CCBSystem fn hides struct CCBSystem)
t = t.replace('CCBSystem* extraout_EAX;', 'struct CCBSystem* extraout_EAX;')
if t != o:
    open(f, 'w').write(t)
print('y4) compiler-oracle repairs:', m9, 'locals')

# y5) declaration backfill table (2026-11-08, all evidence-bearing):
#  - dll exports (gbengine.dll, A-level): gbTimeCounterInit (YAXXZ=void cdecl),
#    gbCreateGraphManager (YAPAVgbGfxManager@@PAUgbGfxDriverInfo@@), TransformPlane
#    (QAEXQAM = void thiscall(float*)), LoadFromFile@gbGeomNode (QAEHPBD0P6AXHH@Z =
#    int thiscall(char*, char*, void(__cdecl*)(int,int)))
#  - LSTATUS: Win32 typedef missing from d2_platform (mmsystem/reg family)
#  - fsin: x87 FSIN instruction name used as fn by the decompiler (CRT __CI pow family)
#  - PalScriptAnimTimer/_vftable_/UIRenderObj/EffObjectPool/EffCallBackNode/CEffAction/
#    PAL3VisNode/UICaption_adjthunk/gbSnow/gbDropDesc: forward declarations for types
#    referenced before definition (skip-nodef family — bodies pending extract)
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read(); o = t
if 'typedef long LSTATUS;' not in t:
    t += '\ntypedef long LSTATUS; /* Win32 reg API family (winreg.h) */\n'
if 'void __cdecl fsin(long double);' not in t:
    t += 'void __cdecl fsin(long double); /* x87 FSIN fn-name used by decompiler */\n'
if 'void __cdecl gbTimeCounterInit(void);' not in t:
    t += ('void __cdecl gbTimeCounterInit(void); /* ?gbTimeCounterInit@@YAXXZ */\n'
          'struct gbGfxDriverInfo;\n'
          'struct gbGfxManager;\n'
          'gbGfxManager *__cdecl gbCreateGraphManager(struct gbGfxDriverInfo *drv); /* ?gbCreateGraphManager@@YAPAVgbGfxManager@@PAUgbGfxDriverInfo@@@Z */\n')
if t != o: open(f, 'w').write(t); print('y5) platform decls ✓')

# type fwd decls + member decl for TransformPlane (into gbMatrix4 nsfix block)
f = 'reconstruct-out/_unnamespaced.h'
t = open(f, errors='ignore').read(); o = t
for ty in ('UIRenderObj', 'EffObjectPool', 'EffCallBackNode', 'CEffAction', 'PAL3VisNode', 'gbSnow', 'gbDropDesc', 'UICaption_adjthunk'):
    if not re.search(r'^\s*(?:struct|class)\s+' + ty + '\s*;', t, re.M) and not re.search(r'^\s*(?:struct|class)\s+' + ty + '\s*\{', t, re.M):
        t = ('struct %s;\n' % ty) + t
# TransformPlane member decl into the nsfix gbMatrix4 block (A-level: QAEXQAM@Z)
mpat = re.search(r'(void Rotate\(gbQuaternion&\); /\* \?Rotate@gbMatrixStack[^*]*\*/\n)', t)
if 'TransformPlane(float*' not in t and 'TransformPlane(float *' not in t:
    tp = '    void TransformPlane(float*); /* ?TransformPlane@gbMatrix4@@QAEXQAM@Z */\n'
    m4 = re.search(r'(nsfix:gbMatrix4[^\n]*\n)', t)
    if m4:
        t = t.replace(m4.group(1), m4.group(1) + tp, 1)
# LoadFromFile@gbGeomNode member decl (QAEHPBD0P6AXHH@Z = int(char*, char*, void(cdecl*)(int,int)))
lfn = 'int LoadFromFile(char*, char*, void (__cdecl*)(int, int)); /* ?LoadFromFile@gbGeomNode@@QAEHPBD0P6AXHH@Z */'
if 'nsfix:gbGeomNode' in t and lfn not in t:
    m5 = re.search(r'(nsfix:gbGeomNode[^\n]*\n)', t)
    if m5:
        t = t.replace(m5.group(1), m5.group(1) + '    ' + lfn + '\n', 1)
if t != o: open(f, 'w').write(t); print('y5) header decls ✓')

# y6) dtor/adjthunk PTR initializers reference the tree function at the PTR target
#     (binary evidence: .data values — 0056ab34→0x423860=_gbLightObj, 0056b0d4→
#     0x4506c0=_UICaption_adjthunk, 0056ac08→0x438e90=_PalScriptAnimTimer; all three
#     functions exist in the tree). `&~Type` is not VC6-legal without an object;
#     the tree-function name is the honest spelling of the same address.
m10 = 0
for f6 in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t6 = open(f6, errors='ignore').read(); o6 = t6
    for old, new in (('(void*)&~gbLightObj', '(void*)&_gbLightObj'),
                     ('(void*)&~UICaption_adjthunk', '(void*)&_UICaption_adjthunk'),
                     ('(void*)&~PalScriptAnimTimer', '(void*)&_PalScriptAnimTimer')):
        if old in t6: t6 = t6.replace(old, new); m10 += 1
    if t6 != o6: open(f6, 'w').write(t6)
print('y6) dtor ptr fixes:', m10)


# y7) second-wave singles (2026-11-08, sequential-build order):
#  a) repeated-struct collapse: 'struct struct+ ...' from repeated elaboration runs
f = 'reconstruct-out/_unnamespaced.cpp'
t = open(f, errors='ignore').read(); o = t
n0 = 0
while True:
    t2 = t.replace('struct struct ', 'struct ')
    if t2 == t: break
    t = t2; n0 += 1
# b) free-form dtor: `~T(expr);` → `((T*)(expr))->~T()`
t = re.sub(r'~([A-Za-z_]\w*)\(\s*(pThis|pPVar\w+|pCVar\w+|pvVar\w+)\s*\)',
           r'((\1*)(\2))->~\1()', t)
# c) placement-new with debug args: `new (ptr, a, b, c, d) T()` →
#    `new ((void*)ptr) T(a, b, c, d)` (MSVC debug-new form: first arg = placement ptr,
#    rest = ctor args; Ghidra merged them into one placement list)
t = re.sub(r'new\s*\(([^()]+?),\s*((?:[^()]|\\()[^)]*)*?)\)\s+([A-Za-z_]\w*)\(\)',
           lambda mm: 'new ((void*)%s) %s(%s)' % (mm.group(1).strip(), mm.group(3), mm.group(2).strip()),
           t) if False else t
# simpler: only when 2+ commas present AND type follows — do it precisely below
def _fix_new(m):
    inner = m.group(1).strip()
    typ = m.group(2).strip()
    if ',' not in inner:
        return m.group(0)
    parts = [p.strip() for p in inner.split(',')]
    ptr, args = parts[0], parts[1:]
    arg_s = ', '.join(a for a in args)
    if not arg_s:
        return 'new ((void*)%s) %s()' % (ptr, typ)
    return 'new ((void*)%s) %s(%s)' % (ptr, typ, arg_s)
t = re.sub(r'new\s*\(([^()]*)\)\s+([A-Za-z_]\w*)\(\)', _fix_new, t)
# d) FUN_00430290 param type: undefined4 = pointer-generic (char[] passed)
t = t.replace('void FUN_00430290(uint32_t param_1);', 'void FUN_00430290(void *param_1);')
t = t.replace('void FUN_00430290(uint32_t param_1) {', 'void FUN_00430290(void *param_1) {')
# e) FUN_00404300: ret 0x8 = 2 stack args (objdump), decomp void(void) is the fn-object desync
t = t.replace('void FUN_00404300();', 'void FUN_00404300(void *param_1, void *param_2);')
t = t.replace('void FUN_00404300() {', 'void FUN_00404300(void *param_1, void *param_2) { /* objdump 404300: ret 0x8 */')
if t != o: open(f, 'w').write(t); print('y7a-e applied')

# f) PointWorldToScr-style float& params called with (float*)expr → deref at call
m7 = 0
for f7 in glob.glob('reconstruct-out/_unnamespaced.cpp'):
    t7 = open(f7, errors='ignore').read(); o7 = t7
    t7 = re.sub(r'\((float\*)\s*(local_\w+|stack0x[0-9a-fA-F]+)\s*\)', r'(*\1\2)', t7)
    if t7 != o7: open(f7, 'w').write(t7); m7 += 1
print('y7f) float* deref at ref-params:', m7)

# y8) return-type fixes: decl says void but binary returns a value (objdump eax at
#     epilogue). Call sites receive the value (C2440 void→T). Corrections:
#  - Camera@0x41be80: mov eax,esi(this) at 0x41bfa7 → returns CameraCtrl*
#  - FUN_004c5820: eax loaded at epilogue → returns singleton ptr
#  - FUN_004c58c0: mov eax,[edi+0x114] → returns int
#  - FUN_004be460: eax=[ecx+8]/[edi+8] → returns int
f = 'reconstruct-out/_unnamespaced.h'
t = open(f, errors='ignore').read(); o = t
m8 = 0
pairs = [
  ('void Camera(gbGfxManager * param_1); // 1.14d: 0041be80',
   'struct CameraCtrl * Camera(gbGfxManager * param_1); // 1.14d: 0041be80 (returns this; objdump 0x41bfa7 mov eax,esi)'),
  ('void FUN_004c5820(uint32_t param_1); // 1.14d: 004c5820',
   'void * FUN_004c5820(uint32_t param_1); // 1.14d: 004c5820 (eax singleton at epilogue)'),
  ('void FUN_004c58c0(); // 1.14d: 004c58c0',
   'int FUN_004c58c0(); // 1.14d: 004c58c0 (eax=[edi+0x114])'),
  ('void FUN_004be460(uint32_t param_1); // 1.14d: 004be460',
   'int FUN_004be460(uint32_t param_1); // 1.14d: 004be460 (eax=[ecx+8])'),
]
for old, new in pairs:
    if old in t: t = t.replace(old, new); m8 += 1
# def sites in .cpp too
f = 'reconstruct-out/_unnamespaced.cpp'
t2 = open(f, errors='ignore').read(); o2 = t2
for old, new in pairs:
    t2 = t2.replace(old.replace(';', ' {'), new.replace(';', ' {'))
if t2 != o2: open(f, 'w').write(t2)
if t != o: open(f.replace('.cpp', '.h'), 'w').write(t)
print('y8) return-type fixes:', m8)

# p) LAB_ label extern decls: decompiled SEH frames reference .text labels as handler
#     addresses (`puStack_c = &LAB_0055f040; ExceptionList = ...`) — reconstruct emits the
#     references but no declarations (1152 distinct labels in _unnamespaced.cpp alone).
#     Labels are real .text addresses (Ghidra naming); extern uchar[1] decls are honest
#     opaque holders (no type fabrication). LINK-LAYER DEBT: these need real symbols at
#     those addresses at link time — revisit at wine_link (handoff §5.4 符号遗漏族).
START = '/* nsfix-lab: BEGIN generated label decls (deepfix p) */'
END = '/* nsfix-lab: END */'
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read()
labels = set()
for f2 in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    labels |= set(re.findall(r'\bLAB_[0-9a-f]+\b', open(f2, errors='ignore').read()))
# NOTE: `extern unsigned char L[1];` makes `&L` spell `unsigned char (*)[1]` — the
# SEH frame code does `uint8_t* p = &L;` so that type is WRONG (C2440). A bare
# `extern unsigned char L;` (object with incomplete info at decl site) gives
# `&L` == `unsigned char*`, exactly what the use sites spell.
body = ('\n' + START + '\n/* SEH frame label references - extern opaque holders; link needs real symbols */\n'
        + '\n'.join('extern unsigned char %s;' % lb for lb in sorted(labels))
        + '\n' + END + '\n')
if START in t:
    pre = t[:t.index(START)]
    post = t[t.index(END) + len(END):]
    t2 = pre + body.strip() + post
else:
    t2 = t.rstrip() + body
if t2 != t:
    open(f, 'w').write(t2)
print('p) LAB_ decls ✓ (%d labels)' % len(labels))
# l2) FUN_004019f0 name unification: reconstruct's preprocessGhidraCode ALREADY rewrites
#     Ghidra's `this` → `self` in body text (impl.ts:1435), so the original l) rename
#     (`this`→`this_local`) was redundant — and it raced with nsfix: nsfix rewrote the
#     call sites `gbMatrixStack::Push(this_local)` (snapshot decomp-truth form) to member
#     form using the a0 it found, while the declaration line in this body now reads
#     `gbMatrixStack* self;` (reconstruct's own rename). Result: 5 uses of `this_local`
#     with no declaration (C2065). Fix: unify to `self` inside this one body — the name
#     the declaration already carries. Idempotent: no `this_local` left after one pass.
f = 'reconstruct-out/_unnamespaced.cpp'
lines = open(f, errors='ignore').readlines()
start = next((i for i, l in enumerate(lines) if l.startswith('void FUN_004019f0() {')), None)
if start is not None:
    depth = 0; end = None
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth == 0 and i > start: end = i; break
    if end:
        n = 0
        for i in range(start, end + 1):
            new = lines[i].replace('this_local', 'self')
            if new != lines[i]: lines[i] = new; n += 1
        if n:
            open(f, 'w').writelines(lines); print('l2) this_local→self unified: %d lines' % n)
# q) in-place ctor calls (VC6-placement-new form; evidence in comment)
CTOR_PAT = re.compile(
    r'\b([A-Za-z_]\w*)::\1\(\s*\(([A-Za-z_]\w*)\s*\*\)&([A-Za-z_]\w*)\s*\)')
LEGACY_PAT = re.compile(
    r'(?<![\w.])\b([A-Za-z_]\w*)\(\s*\(\1\s*\*\)&([A-Za-z_]\w*)\s*\)')
m2 = 0
for f in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    def _repl(mm):
        cls = mm.group(1)
        # CTOR_PAT: (cls, cast, obj) — obj==cast textually, use group(3);
        # LEGACY_PAT: (cls, obj) — obj is group(2)
        obj = mm.group(3) if mm.re is CTOR_PAT else mm.group(2)
        return f'new (&{obj}) {cls}()'
    t = CTOR_PAT.sub(_repl, t)
    t = LEGACY_PAT.sub(_repl, t)
    if t != o: open(f, 'w').write(t); m2 += 1
print('q) in-place ctor → placement new:', m2)

# r) GetInstance name collision (A-level: two functions share one name)
#    0x4ce0d0 = dynamic initializer of the global CPK object (body: `new (&DAT_00de9cb0) CPK()`;
#    only binary caller 0x4ce0c0 = MSVC global-init registration). Ghidra mislabeled it
#    "GetInstance". 0x53df70 = the REAL CScreenMode singleton getter (body: `return &g_CScreenMode;`),
#    which ~300 call sites reference (AudioUpdate/CScreenMode flows).
#    Header declares only the CPK one (`void GetInstance(); // 004ce0d0`) → every call site
#    resolves to `void` → C2440 'void' family + C2065-type fallout.
#    Honest fix: rename the CPK initializer to what it IS (no invented semantics — its body
#    is placement-new of the CPK global), and declare the 0x53df70 getter for the call sites.
#    Byte-match revisit: rename is symbol-level, zero codegen impact.
import glob as _g
m3 = 0
for f in _g.glob('reconstruct-out/**/*.cpp', recursive=True) + _g.glob('reconstruct-out/**/*.h', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    # def site of the CPK initializer (address comment is the anchor)
    t = t.replace('// 1.14d: 004ce0d0\nvoid GetInstance() {', '// 1.14d: 004ce0d0 (global CPK dynamic initializer; renamed — the real CScreenMode GetInstance is 0x53df70)\nvoid CPK_global_init() {')
    # header decl of the CPK one
    t = t.replace('void GetInstance(); // 1.14d: 004ce0d0',
                  'void CPK_global_init(); // 1.14d: 004ce0d0 (CPK global initializer; GetInstance=0x53df70)')
    if t != o: open(f, 'w').write(t); m3 += 1
print('r) CPK_global_init rename:', m3)
# header decl for the real getter (idempotent insert next to the CPK decl)
gh = 'reconstruct-out/_unnamespaced.h'
t = open(gh, errors='ignore').read()
if 'CScreenMode * GetInstance();' not in t and 'CScreenMode* GetInstance();' not in t:
    t = t.replace('void CPK_global_init(); // 1.14d: 004ce0d0 (CPK global initializer; GetInstance=0x53df70)',
                  'void CPK_global_init(); // 1.14d: 004ce0d0 (CPK global initializer; GetInstance=0x53df70)\n'
                  'struct CScreenMode;\n'
                  'CScreenMode * GetInstance(); // 1.14d: 0053df70 (real singleton getter — 300+ call sites)')
    open(gh, 'w').write(t); print('r) CScreenMode GetInstance decl ✓')

# s) GBENGINE_DLL namespace visibility: globals.h declares engine globals inside
#    `namespace GBENGINE_DLL {...}` (B-import models Ghidra namespace GBENGINE.DLL),
#    but game bodies reference them BARE (g_pVFileSys/ColorQuadFmt/g_CurrentTime...).
#    The original source had them as plain globals; the namespace is a modeling layer.
#    v2 (2026-11-07): blanket `using namespace GBENGINE_DLL` made nested-ns TYPES
#    (gbRefObject/gbGeomNode...) ambiguous against the global structs — C2872 x9.
#    Narrow form: using-declarations for the handful of engine globals only
#    (ColorQuadFmt/g_CurrentTime/g_pVFileSys/_vftable_ — extracted from globals.h).
f = 'reconstruct-out/_unnamespaced.cpp'
t = open(f, errors='ignore').read()
if 'using namespace GBENGINE_DLL;' in t:
    t = t.replace('using namespace GBENGINE_DLL; /* engine globals are modeled namespaced; original source references them bare */',
                  '/* engine globals are modeled inside namespace GBENGINE_DLL (B-import);\n'
                  '   the original source references them bare — narrow using-declarations\n'
                  '   (a blanket using-namespace made nested-ns types ambiguous, C2872) */\n'
                  'using GBENGINE_DLL::ColorQuadFmt;\n'
                  'using GBENGINE_DLL::g_CurrentTime;\n'
                  'using GBENGINE_DLL::g_pVFileSys;')
    open(f, 'w').write(t); print('s2) narrow using-decls ✓')
elif 'using GBENGINE_DLL::g_pVFileSys;' in t:
    # narrow form already present — scrub stale wrong names from earlier runs
    # (_vftable_ is a fwd-batch symbol, not a real global: C2039/C2873 on using-decl)
    t2 = re.sub(r'using GBENGINE_DLL::_vftable_;\n?', '', t)
    if t2 != t:
        open(f, 'w').write(t2); print('s3) stale using names scrubbed ✓')
else:
    t = t.replace('#include "globals/globals.h"',
                  '#include "globals/globals.h"\n'
                  'using GBENGINE_DLL::ColorQuadFmt;\n'
                  'using GBENGINE_DLL::g_CurrentTime;\n'
                  'using GBENGINE_DLL::g_pVFileSys;', 1)
    open(f, 'w').write(t); print('s2) narrow using-decls (fresh) ✓')

# t) explicit ctor/dtor call syntax (VC6 rejects free-form `T::T(x)` / `T::~T(x)`; it
#    accepts pointer forms `p->~T()`. Placement-new for ctor (same rationale as q).
#    dtor flag args (deleting-dtor bool) are handled by callers explicitly (the
#    `if (!(flag & 1))` pattern follows in decomp output), so the plain dtor call
#    preserves behavior; binary: ??1gbLightObj@@QAEXXZ takes no args.
CTOR2_PAT = re.compile(r'\b([A-Za-z_]\w*)::\1\(\s*([^()]+?)\s*\)')
m4 = 0
for f in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    def _ctor2(mm):
        cls, arg = mm.group(1), mm.group(2).strip()
        # skip dtor form (handled below), skip if arg is not plausibly a pointer expr
        return f'new ({arg}) {cls}()'
    # only rewrite `T::T(` where the WHOLE match is a ctor (name==class); note the
    # regex `T::T` inherently matches ctor-only. dtor has ~ so untouched here.
    t = CTOR2_PAT.sub(_ctor2, t)
    # dtor free-form: `T::~T(args)` → `((T*)(arg0))->~T()` — arg0 = first arg text;
    # args may contain nested parens (casts like (uint8_t)(uintptr_t)pThis) — match a
    # balanced single nesting level.
    dtor_pat = re.compile(r'\b([A-Za-z_]\w*)::~\1\(\s*((?:[^()]|\((?:[^()]|\([^()]*\))*\))*?)\s*\)')
    def _dtor(mm):
        cls, arg = mm.group(1), mm.group(2).strip()
        return f'(({cls}*)({arg}))->~{cls}()'
    t = dtor_pat.sub(_dtor, t)
    if t != o: open(f, 'w').write(t); m4 += 1
print('t) ctor/dtor explicit-call rewrites:', m4)

# u) CRT/SEH helper forward decls: decomp emits calls to `__CxxThrowException_8` /
#    `__CallSettingFrame_12` (MSVC EH runtime helpers Ghidra named) whose definitions sit
#    at file tail (227483+/232148) but call sites at 5537/227282 — C2065. These are real
#    functions Ghidra decompiled into this TU; their true bodies are CRT-internal, so the
#    definitions here are reconstructed placeholders — at link they may resolve to CRT
#    symbols (revisit at wine_link). Declaring them before use is honest ordering repair.
#    operator_new is already declared by o).
f = 'reconstruct-out/d2_platform.h'
t = open(f, errors='ignore').read()
add = ''
if '__CxxThrowException_8' not in t:
    add += 'void __CxxThrowException_8(void* pExceptionObject, const void* pThrowInfo);\n'
if '__CallSettingFrame_12' not in t:
    add += 'int __CallSettingFrame_12(void* pFrame, void* pDispatch, int dwFlags);\n'
if add:
    t += '\n/* MSVC EH runtime helpers referenced by decompiled SEH bodies (link: revisit) */\n' + add
    open(f, 'w').write(t); print('u) EH helper decls ✓')

# x) printf-family wrapper varargs: FUN_00553082 call sites carry 3/4/5 args
#     (dst, fmt, ...) — cdecl caller-cleans, multiple ret paths in one body.
f = 'reconstruct-out/_unnamespaced.h'
t = open(f, errors='ignore').read()
old_sig = 'uint32_t FUN_00553082(uint8_t * param_1, uint32_t param_2); // 1.14d: 00553082'
new_sig = 'uint32_t FUN_00553082(uint8_t * param_1, const char * param_2, ...); // 1.14d: 00553082 (printf-family wrapper; call sites 3/4/5 args, cdecl)'
if old_sig in t:
    t = t.replace(old_sig, new_sig)
    open(f, 'w').write(t); print('x) FUN_00553082 varargs ✓')
print('deepfix done')
