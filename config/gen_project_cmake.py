"""项目配置 → CMake include（通用工作流同源消费）。
用法: python3 gen_project_cmake.py --project pal3 [--out cmake/project_config.cmake]
读 config/projects.json + 其 toolchains_file（编译器外置）"""
import argparse, json, os
p = argparse.ArgumentParser()
p.add_argument('--project', required=True)
p.add_argument('--config-dir', default=os.path.dirname(os.path.abspath(__file__)))
p.add_argument('--out', default=None)
a = p.parse_args()
cfg = json.load(open(os.path.join(a.config_dir, 'projects.json')))
tcs = json.load(open(os.path.join(a.config_dir, cfg['toolchains_file'])))['toolchains']
if a.project not in cfg['projects']:
    raise SystemExit('未知项目 %r（受支持: %s）' % (a.project, list(cfg['projects'])))
proj = cfg['projects'][a.project]
if proj['active_toolchain'] not in tcs:
    raise SystemExit('项目 %r 的 active_toolchain %r 不在 toolchains_file 中' % (a.project, proj['active_toolchain']))
out = ['# 由 gen_project_cmake.py 生成（源: projects.json v%d + %s）' % (cfg['schema_version'], cfg['toolchains_file']),
       'set(PROJECT_ID "%s")' % a.project,
       'set(PROJECT_EXE "%s")' % proj['exe'],
       'set(PROJECT_BINARY "%s")' % proj['binary'],
       'set(PROJECT_ARCH "%s")' % proj['arch'],
       'set(PROJECT_BASE "%s")' % proj['base'],
       'set(PROJECT_ACTIVE_TOOLCHAIN "%s")' % proj['active_toolchain'],
       'set(PROJECT_GHIDRA_PROJECT "%s")' % proj['ghidra']['project'],
       'set(PROJECT_GHIDRA_PROGRAM "%s")' % proj['ghidra']['program']]
for name, t in tcs.items():
    u = name.upper().replace('-', '_')
    out += ['set(TC_%s_KIND "%s")' % (u, t['kind']),
            'set(TC_%s_CC "%s")' % (u, t['cc']),
            'set(TC_%s_FLAGS "%s")' % (u, ' '.join(t['flags'])),
            'set(TC_%s_DEFINES "%s")' % (u, ';'.join(t['defines'])),
            'set(TC_%s_CAPABILITY "%s")' % (u, ';'.join(t.get('capability', [])))]
    if t.get('root_env'):
        out.append('set(TC_%s_ROOT_ENV "%s")' % (u, t['root_env']))
outp = a.out or os.path.join(a.config_dir, '..', 'cmake', 'project_config.cmake')
open(outp, 'w').write('\n'.join(out) + '\n')
print('project_config.cmake: project=%s exe=%s tc=%s toolchains=%d -> %s' % (
    a.project, proj['exe'], proj['active_toolchain'], len(tcs), outp))
