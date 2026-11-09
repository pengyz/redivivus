#!/bin/bash
# post-codegen VC6 adaptation for reconstruct-out (D2 overrides 同哲学：适配在生成器下游)
# 幂等：sed 目标已被改写则为 no-op；头拷贝覆盖同内容。
set -e
OUT="$(dirname "$0")/reconstruct-out"
SHIM="$(dirname "$0")/vc6-shim"
[ -d "$OUT" ] || { echo "no tree: $OUT"; exit 1; }
# 1) long long → __int64（VC6 C2632）
grep -rl 'long long' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/unsigned long long/unsigned __int64/g; s/long long/__int64/g' "$f"
done
# 2) 变参宏中和（VC6 无 __VA_ARGS__；树内零使用）
sed -i 's|#define __snprintf_s(buf, size, count, \.\.\.) snprintf(buf, size, __VA_ARGS__)|#define __snprintf_s(buf, size, count) snprintf(buf, size) /* VC6: no variadic macros; 0 uses */|' "$OUT/d2_platform.h" || true
# 3) shim 头拷入树根——树根是第一个 -I，先于 SDK Include（SDK 有 wintrust/wincrypt 真头会抢先）
cp -f "$SHIM/cstdint" "$SHIM/cstring" "$SHIM/psapi.h" "$SHIM/wintrust.h" "$SHIM/wincrypt.h" "$OUT/"
# 4) GCC __attribute__(...) 剥（VC6 无·packed 语义风险记档=byte-match 期核）
grep -rl '__attribute__(' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/__attribute__(([^()]*))//g; s/__attribute__(([^()]*))//g' "$f"
done
# 5) 自由函数 __thiscall 剥（树无 class·decl/def 同剥=一致 __cdecl）
grep -rl ' __thiscall ' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/ __thiscall / /g' "$f"
done
# 6) 限定名点号（X.DLL:: → X_DLL::·仅限定形不动字符串）
grep -rl '[A-Za-z0-9_]\.DLL::' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/\([A-Za-z0-9_]\+\)\.DLL::/\1_DLL::/g' "$f"
done
# 7) C++17 嵌套命名空间定义展开（VC6 只认 A { B { 形）
python3 "$(dirname "$0")/vc6_nested_ns.py"
# 8) 解环：_unnamespaced 不再拉模块头；模块头反接 _unnamespaced（共享型定义）
sed -i '\|#include "GBENGINE.DLL/gbLightObj.h"|d' "$OUT/_unnamespaced.h"
for f in "$OUT"/*/*.h; do
  case "$(basename "$f")" in _unnamespaced.h) continue;; esac
  grep -q '_unnamespaced.h' "$f" || sed -i 's|#include "d2_platform.h"|#include "d2_platform.h"\n#include "_unnamespaced.h"|' "$f"
done
# 9) 型垃圾/默认函数体
grep -rl 'uint32_t __int8\|= default;' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/uint32_t __int8/uint32_t/g; s/) = default;/) {}/g' "$f"
done
# 9a) constexpr → static const（VC6 无 C++11·d2_enums.h 580 处·命名空间 const=内部链接）
grep -rl 'constexpr ' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/constexpr /static const /g' "$f"
done
# 9b) 删与 d2_platform typedef 撞名的 struct fwd（VC6 对冲突直接 C1001 自爆）
python3 - <<'PYEOF2'
import re
plat = open('reconstruct-out/d2_platform.h', errors='ignore').read()
tdefs = set(re.findall(r'typedef\s+[^;]*?\b(\w+)\s*\(', plat)) | set(re.findall(r'typedef\s+[\w\s\*]+?\b(\w+)\s*;', plat))
p = 'reconstruct-out/_unnamespaced.h'
lines = open(p, errors='ignore').readlines()
out = [l for l in lines if not (re.match(r'^struct (\w+);\s*$', l) and re.match(r'^struct (\w+);\s*$', l).group(1) in tdefs)]
open(p, 'w').writelines(out)
PYEOF2
# 9c) d2_platform.h VC6 全套适配（幂等·防树重生冲掉）
python3 "$(dirname "$0")/vc6_d2platform_fix.py"
# 9c2) WINUSER 宏撞名（CreateDialog 等）→ FID_conflict_ 前缀（D2 惯例）
grep -rl '\bCreateDialog\b' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/\bCreateDialog\b/FID_conflict_CreateDialog/g' "$f"
done
# 9d) 行尾注释括号修复+SDK重复定义删+跨文件按值型搬移
python3 "$(dirname "$0")/vc6_postfix.py"
# 9d0) 行尾 {0} 补逗号（init 渲染器缺分隔符→VC6 报 C2059 'constant'=裸数字记号类名）
grep -rl '{0}$' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/{0}$/\{0\},/' "$f"
done
# 9d1) 空初始化器 {} → {0}（VC6=C++98 无 {} 形）
grep -rl '= {}\|, {}' "$OUT" --include='*.h' --include='*.cpp' 2>/dev/null | while read -r f; do
  sed -i 's/= {};/= {0};/g; s/ = {} / = {0} /g; s/, {}/, {0}/g; s/{},/{0}/g' "$f"
done
# 9d2) 头文件裸 extern 补 struct 关键字（`extern PAL3 g;` → `extern struct PAL3 g;`）
python3 - <<'PYEOF2'
import re, glob
n = 0
for f in glob.glob('reconstruct-out/**/*.h', recursive=True):
    t = open(f, errors='ignore').read()
    fwds = set(re.findall(r'^struct (\w+);\s*$', t, re.M))
    o = t
    for name in fwds:
        t = re.sub(r'\bextern %s\b' % re.escape(name), 'extern struct %s' % name, t)
    if t != o: open(f, 'w').write(t); n += 1
print('裸 extern 修:', n)
PYEOF2
# 9d3) FUN_004b5d20 调用 4 参 vs 0 参声明（Ghidra 签名归因项·编译期剥参·字节匹配期回访）
sed -i 's/FUN_004b5d20([^)]*)/FUN_004b5d20()/g' reconstruct-out/_unnamespaced.cpp reconstruct-out/switchD_004b4e1e/switchD_004b4e1e.cpp 2>/dev/null || true
# 9e) .cpp 裸名全局定义补 struct（仅 g_* 行首形·防误伤语句）
python3 - <<'PYEOF2'
import re, glob
fwds = set()
for f in glob.glob('reconstruct-out/**/*.h', recursive=True):
    fwds |= set(re.findall(r'^struct (\w+);\s*$', open(f, errors='ignore').read(), re.M))
n = 0
for f in glob.glob('reconstruct-out/**/*.cpp', recursive=True):
    t = open(f, errors='ignore').read(); o = t
    for name in fwds:
        t = re.sub(r'(?m)^(\s*(?:static\s+|extern\s+|const\s+)*)%s(\s+)(g_\w+)' % re.escape(name), r'\1struct %s\2\3' % name, t)
    if t != o: open(f, 'w').write(t); n += 1
print('cpp g_* 裸名修:', n)
PYEOF2
# 9f) 缺口逐字节回填（init 逐字节渲染 vs def 字段渲染不一致=C2078 级联根）
python3 "$(dirname "$0")/vc6_gapfill.py"
# 9g-l) 深体六修（vfs::剥/TryExpand补参[A级0x4012c1 ret 0x14]/FUN014b0返型+真return[A级eax路径]/
#        Rsrc_Dialog删发射[A级RT_DIALOG 0x6a_804]/SQRT宏/this局部名）
python3 "$(dirname "$0")/vc6_deepfix.py"
# 10) 缺定义型补发（快照数据驱动）
python3 "$(dirname "$0")/vc6_emit_missing.py"
# 10b) Type::method→成员解析（gbengine.dll 导出表 A 级签名库；调用点 T::m(A0,..)→A0.m(..)/A0->m(..)；
#      pass0 通用成员可见性清扫兜底 emit-v4 defs 的指针成员缺口——故必须在 emit 之后）
# P0.2 确定性断言 (2026-11-09): nsfix 不得净删 struct/class 完整定义
#   (block-rebuild 曾吞相邻定义: 单次运行 176→173, gbTextureArray 等 5 个原生定义丢失)
NSFIX_BEFORE=$(grep -cE '^(struct|class) [A-Za-z_][A-Za-z0-9_]* \{' "$OUT/_unnamespaced.h")
python3 "$(dirname "$0")/vc6_ns_freefn.py"
NSFIX_AFTER=$(grep -cE '^(struct|class) [A-Za-z_][A-Za-z0-9_]* \{' "$OUT/_unnamespaced.h")
if [ "$NSFIX_AFTER" -lt "$NSFIX_BEFORE" ]; then
  echo "P0.2 FAIL: nsfix net-removed definitions ($NSFIX_BEFORE -> $NSFIX_AFTER) — block-rebuild boundary bug"; exit 1
fi
echo "P0.2 ok: definitions $NSFIX_BEFORE -> $NSFIX_AFTER"
echo "vc6_adapt_tree: ok ($(ls "$OUT"/cstdint "$OUT"/wintrust.h 2>/dev/null | wc -l) headers in tree root)"
