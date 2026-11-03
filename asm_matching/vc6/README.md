# oracle-vc6 — PAL3 对照层（VC6 适配面）

redivivus 对照核（msvc8 oracle）在 PAL3 上的适配层。比对核（compare/asmdiff/coffobj）
零改动继承；本目录只放 PAL3 特有件。

## 链（已跑通）
```
refimage.py --exe PAL3.exe        → build/ref/functions.tsv（1738 参照）
  [wine_cl.sh VC6 编 UT → build/obj/<TU>.obj + touch <TU>.d]   ← .d=完成标记（缺则跳过）
funcmap_addr.py --ref --ann(pal3_names.json) --objdir → funcmap.tsv（addr 配对）
audit.py --funcmap → audit.tsv（语义掩码判决：MATCH/INSN_MATCH/OUR±N + similarity）
```

## 形位契约（踩坑定谳，禁再犯）
- ourslib `f.key = tu|mangled_symbol`：tu 无扩展名；symbol 须 **MSVC6 mangled**
- `f[:-4]+'.d'` = obj 完成标记（load_all 无 .d 即跳过=「object not compiled」）
- 配对真源 = `asm/pal3/pal3_names.json`（addr→name），**非** functions.json（占位名分叉）
- 参照槽 = msvc8/reference/Game.exe → 符链 PAL3.exe；carve 缓存 = msvc8/build/ref/functions.tsv
- 跑位 = msvc8/ 目录内（ORACLE_CFLAGS env 触发 experiment 目录形）

## 首次校准读数（CCBAI.obj 单 obj，2026-11-03）
74 配对：MATCH ×1 · INSN_MATCH ×1 · INSN_COUNT_MATCH ×1 · 其余 OUR±N
（OUR-87 = ref 102 指令 vs our 15=codegen 早期态诚实读数——逐函数对拍语料）
