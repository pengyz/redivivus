#!/usr/bin/env python3
"""VC6: no C++17 nested namespace definitions (`namespace A::B {`).
Expand to `namespace A { namespace B {` + append the extra closing braces at
the matching close (brace-count with a lexer that skips comments/strings).
Idempotent: only matches single-line nested-namespace opens."""
import re, sys, glob, os

OPEN_RE = re.compile(r'^(\s*)namespace\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)\s*\{\s*$')
DOT_RE = re.compile(r'^(\s*)namespace\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\{\s*$')  # namespace X.DLL {

def find_match(lines, start):
    """Brace-match from line `start` (which contains '{'); return close-line index."""
    depth = 0
    for i in range(start, len(lines)):
        line = lines[i]
        j, n = 0, len(line)
        while j < n:
            c = line[j]
            if c == '/' and j+1 < n and line[j+1] == '/':
                break                      # line comment → rest ignored
            if c == '/' and j+1 < n and line[j+1] == '*':
                k = line.find('*/', j+2)
                j = (k+2) if k >= 0 else n
                continue
            if c == '"':
                j += 1
                while j < n and line[j] != '"':
                    j += 2 if line[j] == '\\' else 1
            elif c == "'":
                j += 1
                while j < n and line[j] != "'":
                    j += 2 if line[j] == '\\' else 1
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i
            j += 1
    return None

def process(path):
    with open(path, errors='ignore') as f:
        lines = f.readlines()
    changed = False
    i = 0
    while i < len(lines):
        m = OPEN_RE.match(lines[i]) or DOT_RE.match(lines[i])
        if m:
            indent, qname = m.group(1), m.group(2)
            segs = qname.split('::')
            # sanitize dots inside segments (GBENGINE.DLL)
            segs = ['_'.join(s.split('.')) for s in segs]
            close = find_match(lines, i)
            if close is None:
                print('  !! no match for %s in %s:%d' % (qname, path, i+1)); i += 1; continue
            lines[i] = ''.join('%snamespace %s {\n' % (indent, s) for s in segs)
            lines[close] = lines[close].rstrip('\n') + '}' * (len(segs)-1) + '\n'
            changed = True
        i += 1
    if changed:
        with open(path, 'w') as f:
            f.writelines(lines)
        print('  expanded:', os.path.basename(path))

for pat in ('reconstruct-out/*.h', 'reconstruct-out/*.cpp',
            'reconstruct-out/*/*.h', 'reconstruct-out/*/*.cpp'):
    for p in glob.glob(pat):
        process(p)
print('nested-ns expand done')
