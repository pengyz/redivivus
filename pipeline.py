#!/usr/bin/env python3
"""通用反编译工作流·统一入口（转正件，2026-11-03）。
配置驱动：config/projects.json（项目注册表）+ config/toolchains.json（编译器外置）。

用法:
  python3 pipeline.py --project pal3 status      # 各段就绪态
  python3 pipeline.py --project pal3 import      # Ghidra 库（analyzeHeadless 自动分析）
  python3 pipeline.py --project pal3 generate    # daemon 会话 → reconstruct → out/ 丑C 树
  python3 pipeline.py --project pal3 build       # VC6 编译 UT → obj（+.d 完成标记）
  python3 pipeline.py --project pal3 audit       # funcmap_addr + oracle audit → 判决表
  python3 pipeline.py --project pal3 quick       # build+audit 增量环
  python3 pipeline.py --project pal3 ref         # refimage 参照（首跑/换 exe 后）
纪律: L-lock（daemon↔headless 互斥）· .d 标记=obj 完成契约 · 形位契约见 asm_matching/vc6/README.md
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)                      # PAL3Decomp 根
CONFIG_DIR = os.path.join(HERE, 'config')
MSVC8 = os.path.join(HERE, 'asm_matching', 'msvc8')
VC6 = os.path.join(HERE, 'asm_matching', 'vc6')
GHIDRA_HOME = os.environ.get('GHIDRA_HOME', os.path.join(REPO, 'tools/ghidra/ghidra_12.1.2_PUBLIC'))


def load_config(project):
    projects = json.load(open(os.path.join(CONFIG_DIR, 'projects.json')))
    tcs = json.load(open(os.path.join(CONFIG_DIR, projects['toolchains_file'])))['toolchains']
    if project not in projects['projects']:
        sys.exit('未知项目 %r（受支持: %s）' % (project, list(projects['projects'])))
    p = projects['projects'][project]
    return p, tcs[p['active_toolchain']]


def sh(cmd, cwd=None, env=None, check=True):
    print('+ ' + cmd)
    r = subprocess.run(cmd, shell=True, cwd=cwd, env={**os.environ, **(env or {})})
    if check and r.returncode != 0:
        sys.exit('命令失败 exit=%d: %s' % (r.returncode, cmd))
    return r


def stage_status(p, tc):
    def ok(path):
        return '✓' if os.path.exists(path) else '✗'
    print('project: %s (%s)  toolchain: %s' % (p['exe'], p['binary'], tc['cc']))
    print('  ghidra proj   ', ok(os.path.join(HERE, 'ghidra_proj', '%s.gpr' % p['ghidra']['project'])))
    print('  reference     ', ok(os.path.join(MSVC8, 'reference', 'Game.exe')))
    print('  functions.tsv ', ok(os.path.join(MSVC8, 'build', 'ref', 'functions.tsv')))
    print('  out/ tree     ', ok(os.path.join(HERE, 'project', 'output')))
    print('  objs          ', ok(os.path.join(VC6, 'build', 'obj')))
    print('  funcmap       ', ok(os.path.join(VC6, 'build', 'funcmap.tsv')))
    print('  audit         ', ok(os.path.join(VC6, 'build', 'audit.tsv')))


def stage_ref(p, tc):
    os.makedirs(os.path.join(MSVC8, 'reference'), exist_ok=True)
    os.makedirs(os.path.join(MSVC8, 'build', 'ref'), exist_ok=True)
    link = os.path.join(MSVC8, 'reference', 'Game.exe')
    if not os.path.exists(link):
        os.symlink(os.path.abspath(os.path.join(REPO, p['binary'])), link)
    sh('python3 %s --exe %s --out %s' % (
        os.path.join(MSVC8, 'scripts', 'refimage.py'),
        os.path.join(REPO, p['binary']),
        os.path.join(MSVC8, 'build', 'ref', 'functions.tsv')), cwd=MSVC8)


def stage_import(p, tc):
    proj = os.path.join(HERE, 'ghidra_proj')
    os.makedirs(proj, exist_ok=True)
    sh('"%s/support/analyzeHeadless" %s %s -import %s' % (
        GHIDRA_HOME, proj, p['ghidra']['project'], os.path.join(REPO, p['binary'])), cwd=HERE)


def stage_generate(p, tc):
    # L-lock: 清 daemon 残会话后起本仓 daemon → 建会话 → reconstruct
    print('注意: generate 需 daemon（L-lock: 前置清旧会话/锁）。')
    print('  daemon: cd thirdparty/ghidra-mcp && GHIDRA_HOME=%s node packages/cli/dist/bin.js &' % GHIDRA_HOME)
    print('  会话:   create_session{binaryPath: ghidra_proj/%s.gpr, programPath: %s}' % (
        p['ghidra']['project'], p['ghidra']['program']))
    # 出码落位约定: cwd=车间根 ⇒ output/<TU>/<名>.cpp(.map)（派生可弃区，禁漂引擎目录）
    sh('GHIDRA_PROJECT_DIR=%s GHIDRA_PROJECT_PATH=ghidra://localhost:8432/%s '
       'GHIDRA_PROGRAM_PATH=%s GHIDRA_MCP_TOKEN=local-dev '
       'npx tsx %s' % (
           os.path.join(HERE, 'project'), p['ghidra']['project'], p['ghidra']['program'],
           os.path.join(HERE, 'thirdparty', 'ghidra-reconstruct', 'run.ts')),
       cwd=HERE)


def stage_build(p, tc):
    outdir = os.path.join(VC6, 'build', 'obj')
    os.makedirs(outdir, exist_ok=True)
    flags = ' '.join(tc['flags'])
    defines = ' '.join('/D ' + d for d in tc['defines'])
    roots = ['/I ' + os.path.join(REPO, 'include'), '/I ' + os.path.join(REPO, p.get('tree', ['pal3'])[0]),
             '/I ' + os.path.join(REPO, 'tools/compilers/msvc6.0/Include'),
             '/I ' + os.path.join(REPO, 'tools/vc6/Include')]
    srcs = []
    for root, _d, files in os.walk(os.path.join(REPO, p.get('tree', ['pal3'])[0])):
        srcs += [os.path.join(root, f) for f in files if f.endswith('.cpp')]
    ok = fail = 0
    for src in sorted(srcs):
        name = os.path.basename(src)[:-4]
        obj = os.path.join(outdir, name + '.obj')
        inc = list(roots) + ['/I ' + os.path.dirname(src)]
        r = sh('%s /nologo /c %s %s %s %s /Fo%s' % (
            tc['cc'], flags, defines, ' '.join(inc), src, obj), check=False)
        if r.returncode == 0:
            open(os.path.join(outdir, name + '.d'), 'w').close()   # .d=完成标记（ourslib 契约）
            ok += 1
        else:
            fail += 1
    print('build: ok=%d fail=%d（fail=既有 S2 阻塞族，见 probe_census）' % (ok, fail))


def stage_audit(p, tc):
    objdir = os.path.join(VC6, 'build', 'obj')
    sh('python3 %s --ref %s --ann %s --objdir %s --out %s' % (
        os.path.join(VC6, 'funcmap_addr.py'),
        os.path.join(MSVC8, 'build', 'ref', 'functions.tsv'),
        os.path.join(REPO, 'asm', 'pal3', 'pal3_names.json'),
        objdir, os.path.join(VC6, 'build', 'funcmap.tsv')), cwd=HERE)
    sh('python3 %s --funcmap %s --out %s' % (
        os.path.join(MSVC8, 'scripts', 'audit.py'),
        os.path.join(VC6, 'build', 'funcmap.tsv'),
        os.path.join(VC6, 'build', 'audit.tsv')),
       cwd=MSVC8, env={'ORACLE_CFLAGS': ' '.join(tc['flags'])})
    import csv
    from collections import Counter
    rows = list(csv.DictReader(open(os.path.join(VC6, 'build', 'audit.tsv')), delimiter='\t'))
    c = Counter('MATCH' if r['status'].startswith('MATCH') or r['status'].startswith('INSN') else 'DIFF' for r in rows)
    print('audit: %d 函数 | %s' % (len(rows), dict(Counter(r['status'] for r in rows)).keys().__len__() and 'see audit.tsv'))
    print('  判决概览:', dict(c))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--project', required=True)
    ap.add_argument('stage', choices=['status', 'ref', 'import', 'generate', 'build', 'audit', 'quick'])
    a = ap.parse_args()
    p, tc = load_config(a.project)
    {'status': lambda: stage_status(p, tc), 'ref': lambda: stage_ref(p, tc),
     'import': lambda: stage_import(p, tc), 'generate': lambda: stage_generate(p, tc),
     'build': lambda: stage_build(p, tc), 'audit': lambda: stage_audit(p, tc),
     'quick': lambda: (stage_build(p, tc), stage_audit(p, tc))}[a.stage]()


if __name__ == '__main__':
    main()
