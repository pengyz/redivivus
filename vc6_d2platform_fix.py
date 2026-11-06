#!/usr/bin/env python3
"""d2_platform.h VC6 adaptation (idempotent; mirrors rounds6-11 manual fixes so
regen of the tree does NOT lose them — lesson: every fix must live HERE)."""
import re
p = 'reconstruct-out/d2_platform.h'
t = open(p, errors='ignore').read()
orig = t
subs = [
  # InterlockedCompareExchange: VC6 takes void** ; return cast to LONG
  ('InterlockedCompareExchange((LONG volatile*)pDestination, nExchange, nComperand)',
   'InterlockedCompareExchange((void**)pDestination, (void*)(intptr_t)nExchange, (void*)(intptr_t)nComperand)'),
  ('static LONG __stdcall d2_InterlockedCompareExchange(LONG* pDestination, LONG nExchange, LONG nComperand) { return InterlockedCompareExchange((void**)pDestination, (void*)(intptr_t)nExchange, (void*)(intptr_t)nComperand); }',
   'static LONG __stdcall d2_InterlockedCompareExchange(LONG* pDestination, LONG nExchange, LONG nComperand) { return (LONG)(intptr_t)InterlockedCompareExchange((void**)pDestination, (void*)(intptr_t)nExchange, (void*)(intptr_t)nComperand); }'),
  # same-name wrappers that collide with VC6 SDK overloads → delete (SDK native wins)
  ('static inline LONG InterlockedIncrement(int32_t volatile* p) { return InterlockedIncrement((LONG volatile*)p); }\n', ''),
  ('static inline LONG InterlockedDecrement(int32_t volatile* p) { return InterlockedDecrement((LONG volatile*)p); }\n', ''),
  ('static inline int MultiByteToWideChar(UINT cp, DWORD flags, LPCCH src, int srcLen, uint16_t* dst, int dstLen) {\n  return MultiByteToWideChar(cp, flags, src, srcLen, (LPWSTR)dst, dstLen);\n}\n', ''),
  ('static inline int WideCharToMultiByte(UINT cp, DWORD flags, const uint16_t* src, int srcLen, LPSTR dst, int dstLen, LPCCH dflt, LPBOOL usedDflt) {\n  return WideCharToMultiByte(cp, flags, (LPCWCH)src, srcLen, dst, dstLen, dflt, usedDflt);\n}\n', ''),
  # imm.h already defines it
  ('#define GL_ID_UNKNOWN 0', '#undef GL_ID_UNKNOWN\n#define GL_ID_UNKNOWN 0'),
  # VC6 has no typename-dependent return — uint64恒宽 (LE low-bytes equivalent)
  ('template <class T> static inline typename d2_bits_word<(sizeof(T) > sizeof(uintptr_t))>::type d2_bits_of(const T& tValue) { typename d2_bits_word<(sizeof(T) > sizeof(uintptr_t))>::type nBits = 0; memcpy(&nBits, &tValue, sizeof(T) < sizeof(nBits) ? sizeof(T) : sizeof(nBits)); return nBits; }',
   'template <class T> static inline uint64_t d2_bits_of(const T& tValue) { uint64_t nBits = 0; memcpy(&nBits, &tValue, sizeof(T) < sizeof(nBits) ? sizeof(T) : sizeof(nBits)); return nBits; }'),
  # variadic template → object macro (VC6 none; 0 template uses)
  (None, None),  # placeholder handled below
  # dup __wfopen (wchar_t- makes uint16_t* == wchar_t*)
  ('static inline FILE* __wfopen(const uint16_t* filename, const uint16_t* mode) { return _wfopen((const wchar_t*)filename, (const wchar_t*)mode); }\n', ''),
  # threadlocinfo CRT-internal forward decl
  ('extern "C" int ___init_ctype(threadlocinfo* _LocInfo);',
   'struct threadlocinfo; /* VC6: CRT-internal, forward-declared */\nextern "C" int ___init_ctype(threadlocinfo* _LocInfo);'),
  # GL... done; extern "C" __stdcall order (VC6 wants convention after return type)
]
for old, new in subs:
    if old is None: continue
    if old in t: t = t.replace(old, new, 1)
# variadic template (regex)
t = re.sub(r'template <typename\.\.\. Args> static inline int FID_conflict__sscanf\([^)]*\) \{[^}]*\}',
           '#define FID_conflict__sscanf sscanf /* VC6: no variadic templates */', t, count=1)
# extern "C" __stdcall reorder
t = re.sub(r'extern "C" __stdcall ([A-Za-z_][A-Za-z0-9_ *]*?) ([A-Za-z_][A-Za-z0-9_]*)\(',
           r'extern "C" \1 __stdcall \2(', t)
if t != orig:
    open(p, 'w').write(t); print('d2_platform fix: applied')
else:
    print('d2_platform fix: no change (already applied)')
