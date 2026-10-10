#!/usr/bin/env python3
"""build-standards-data.py — regenerate data/ from primary-source clones so it never goes stale.

usage: python3 -I build-standards-data.py --mastg DIR --maswe DIR --masvs DIR --vrt DIR --mt10 DIR
                                           [--attack-stix mobile-attack.json] [--cwe-top25 top25.html|csv]
                                           [--checklist checklist.csv] --out DIR
Run interpreters OUTSIDE the clones; every path is an argument. Needs PyYAML only.
Outputs (all CSV, UTF-8, header row, one source row per record) + versions.json + crosswalk.csv.
"""
import argparse, csv, glob, html as htmlmod, json, os, re, subprocess, sys, collections
import yaml

ap = argparse.ArgumentParser()
for k in ('mastg', 'maswe', 'masvs', 'vrt', 'mt10', 'out'): ap.add_argument('--' + k, required=True)
ap.add_argument('--attack-stix'); ap.add_argument('--cwe-top25'); ap.add_argument('--checklist')
ap.add_argument('--platforms', default='android,generic,network', help='MASTG platform tags to keep')
A = ap.parse_args(); os.makedirs(A.out, exist_ok=True)
KEEP = set(A.platforms.split(','))

def git_rev(d):
    try: return subprocess.run(['git', '-C', d, 'log', '-1', '--format=%H %cI'], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception: return ''

def naive_fm(block):
    d, cur = {}, None
    for line in block.split('\n'):
        m = re.match(r'^([A-Za-z0-9_-]+):\s*(.*)$', line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if v.startswith('[') and v.endswith(']'): d[k] = [x.strip().strip("'\"") for x in v[1:-1].split(',') if x.strip()]
            elif v == '': d[k] = []; cur = k; continue
            else: d[k] = v.strip("'\"")
            cur = None
        elif cur and line.strip().startswith('- '): d[cur].append(line.strip()[2:].strip().strip("'\""))
    return d

def fm(path):
    t = open(path, encoding='utf-8', errors='replace').read()
    m = re.match(r'^---\s*\n(.*?)\n---\s*\n?', t, re.S)
    if not m: return {}, t
    try:
        d = yaml.safe_load(m.group(1)) or {}
        if not isinstance(d, dict): d = naive_fm(m.group(1))
    except Exception: d = naive_fm(m.group(1))
    return d, t[m.end():]

def L(v):  # list -> 'a;b'
    if v is None: return ''
    if isinstance(v, (list, tuple)): return ';'.join(str(x) for x in v)
    return str(v)

def write(name, cols, rows):
    with open(os.path.join(A.out, name), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore'); w.writeheader(); w.writerows(rows)
    print(f'{name:36s} {len(rows):5d} rows')
    return len(rows)

SITE = 'https://mas.owasp.org'
counts = {}
# ------------------------------------------------------------------ MASTG
def mastg_records(sub, kind):
    out = []
    for p in sorted(glob.glob(os.path.join(A.mastg, sub), recursive=True)):
        d, body = fm(p); iid = str(d.get('id') or os.path.splitext(os.path.basename(p))[0])
        if not re.match(r'^MASTG-%s-\d{4}$' % kind, iid): continue
        rel = os.path.relpath(p, A.mastg); parts = rel.split(os.sep)
        dir_platform = parts[1] if len(parts) > 2 and parts[0] in ('tests', 'tests-beta', 'techniques', 'tools', 'knowledge', 'demos', 'apps') else ''
        plat = d.get('platform') or dir_platform
        rec = dict(id=iid, title=str(d.get('title', '')).strip(), platform=L(plat), dir_platform=dir_platform, status=str(d.get('status') or 'current'),
                   source_path=rel, group=next((x for x in parts if x.startswith('MASVS-')), ''), _fm=d, _body=body)
        out.append(rec)
    return out

def keep(rec):  # directory decides for tests/demos (site layout); frontmatter decides otherwise
    return (rec['dir_platform'] in KEEP) if rec['dir_platform'] else any(x in KEEP for x in rec['platform'].split(';')) or rec['platform'] in KEEP

tests = []
for sub, ver in (('tests/*/*/*.md', 'v1'), ('tests-beta/*/*/*.md', 'v2')):
    for r in mastg_records(sub, 'TEST'):
        if not keep(r): continue
        d = r['_fm']
        tests.append(dict(r, version=ver, masvs_v2_ids=L(d.get('masvs_v2_id')), masvs_v1_ids=L(d.get('masvs_v1_id')), maswe_ids=L(d.get('maswe')),
                          type=L(d.get('type')), profiles=L(d.get('profiles')), covered_by=L(d.get('covered_by')), deprecation_note=str(d.get('deprecation_note') or d.get('deprecation_reason') or '').strip(),
                          available_since=str(d.get('available_since') or ''), deprecated_since=str(d.get('deprecated_since') or ''), prerequisites=L(d.get('prerequisites')),
                          knowledge_ids=L(d.get('knowledge')), best_practice_ids=L(d.get('best-practices')), apis=L(d.get('apis')), note=str(d.get('note') or '').strip(),
                          url=f"{SITE}/MASTG/tests/{r['dir_platform']}/{r['group']}/{r['id']}/"))
counts['mastg-tests.csv'] = write('mastg-tests.csv', ['id', 'version', 'status', 'platform', 'group', 'title', 'masvs_v2_ids', 'maswe_ids', 'type', 'profiles', 'covered_by', 'deprecation_note', 'available_since', 'deprecated_since', 'prerequisites', 'knowledge_ids', 'best_practice_ids', 'apis', 'note', 'url', 'source_path'], tests)

techs = [dict(r, url=f"{SITE}/MASTG/techniques/{r['dir_platform']}/{r['id']}/") for r in mastg_records('techniques/*/*.md', 'TECH') if keep(r)]
counts['mastg-techniques.csv'] = write('mastg-techniques.csv', ['id', 'status', 'platform', 'title', 'url', 'source_path'], techs)
tools = [dict(r, source=str(r['_fm'].get('source') or ''), url=f"{SITE}/MASTG/tools/{r['dir_platform']}/{r['id']}/") for r in mastg_records('tools/*/*.md', 'TOOL') if keep(r)]
counts['mastg-tools.csv'] = write('mastg-tools.csv', ['id', 'status', 'platform', 'title', 'source', 'url', 'source_path'], tools)
knows = [dict(r, masvs_category=str(r['_fm'].get('masvs_category') or r['group']), url=f"{SITE}/MASTG/knowledge/{r['dir_platform']}/{r['group'] + '/' if r['group'] else ''}{r['id']}/") for r in mastg_records('knowledge/**/*.md', 'KNOW') if keep(r)]
counts['mastg-knowledge.csv'] = write('mastg-knowledge.csv', ['id', 'status', 'platform', 'masvs_category', 'title', 'url', 'source_path'], knows)
bests = [dict(r, knowledge_ids=L(r['_fm'].get('knowledge')), url=f"{SITE}/MASTG/best-practices/{r['id']}/") for r in mastg_records('best-practices/*.md', 'BEST') if keep(r)]
counts['mastg-best-practices.csv'] = write('mastg-best-practices.csv', ['id', 'status', 'platform', 'title', 'knowledge_ids', 'url', 'source_path'], bests)
apps = [dict(r, source=str(r['_fm'].get('source') or ''), url=f"{SITE}/MASTG/apps/{r['dir_platform']}/{r['id']}/") for r in mastg_records('apps/*/*.md', 'APP') if keep(r)]
counts['mastg-apps.csv'] = write('mastg-apps.csv', ['id', 'status', 'platform', 'title', 'source', 'url', 'source_path'], apps)

# demos: test id + rule files referenced by the demo folder
demos = []; rule_to_tests = collections.defaultdict(set)
for r in mastg_records('demos/**/MASTG-DEMO-*.md', 'DEMO'):
    if not keep(r): continue
    ddir = os.path.dirname(os.path.join(A.mastg, r['source_path'])); refs = set()
    for f in glob.glob(os.path.join(ddir, '*')):
        if f.endswith(('.sh', '.md', '.yml', '.yaml', '.txt')):
            try: refs |= set(re.findall(r'(mastg-android-[a-z0-9-]+\.ya?ml)', open(f, encoding='utf-8', errors='replace').read()))
            except Exception: pass
    t = str(r['_fm'].get('test') or '')
    for rf in refs: rule_to_tests[rf].add(t)
    demos.append(dict(r, test_id=t, rule_files=L(sorted(refs)), code=L(r['_fm'].get('code')), url=f"{SITE}/MASTG/demos/{r['dir_platform']}/{r['group']}/{r['id']}/{r['id']}/"))
counts['mastg-demos.csv'] = write('mastg-demos.csv', ['id', 'status', 'platform', 'group', 'title', 'test_id', 'rule_files', 'code', 'url', 'source_path'], demos)

rules = []
for p in sorted(glob.glob(os.path.join(A.mastg, 'rules', '*.y*ml'))):
    fn = os.path.basename(p)
    try: y = yaml.safe_load(open(p, encoding='utf-8')) or {}
    except Exception: y = {}
    for rr in (y.get('rules') or []) if isinstance(y, dict) else []:
        md = rr.get('metadata') or {}
        rules.append(dict(rule_id=rr.get('id'), rule_file=fn, severity=rr.get('severity'), languages=L(rr.get('languages')), masvs=L(md.get('masvs')), summary=str(md.get('summary') or '').strip(), test_ids=L(sorted(rule_to_tests.get(fn, []))), source_path='rules/' + fn))
counts['mastg-rules.csv'] = write('mastg-rules.csv', ['rule_id', 'rule_file', 'severity', 'languages', 'masvs', 'summary', 'test_ids', 'source_path'], rules)

# ------------------------------------------------------------------ MASWE / MASVS
test_by_maswe = collections.defaultdict(list)
for t in tests:
    for w in t['maswe_ids'].split(';'):
        if w: test_by_maswe[w].append(t['id'])
maswe = []
for p in sorted(glob.glob(os.path.join(A.maswe, 'weaknesses', '*', 'MASWE-*.md'))):
    d, body = fm(p); iid = str(d.get('id') or os.path.splitext(os.path.basename(p))[0]); mp = d.get('mappings') or {}
    plats = d.get('platform') or []
    if not any(x in KEEP for x in plats): continue
    maswe.append(dict(id=iid, title=str(d.get('title', '')).strip(), group=os.path.basename(os.path.dirname(p)), platform=L(plats), profiles=L(d.get('profiles')), requirement=str(d.get('requirement') or '').strip(),
                      masvs_v2_ids=L(mp.get('masvs-v2')), masvs_v1_ids=L(mp.get('masvs-v1')), cwe_ids=L([f'CWE-{c}' for c in (mp.get('cwe') or [])]), android_risks=L(mp.get('android-risks')),
                      threat=str(d.get('threat') or ''), attacks=L(d.get('attacks')), mastg_test_ids=L(sorted(test_by_maswe.get(iid, []))), url=f"{SITE}/MASWE/{os.path.basename(os.path.dirname(p))}/{iid}/", source_path=os.path.relpath(p, A.maswe)))
counts['maswe.csv'] = write('maswe.csv', ['id', 'title', 'group', 'platform', 'profiles', 'requirement', 'masvs_v2_ids', 'masvs_v1_ids', 'cwe_ids', 'android_risks', 'threat', 'attacks', 'mastg_test_ids', 'url', 'source_path'], maswe)
my = yaml.safe_load(open(os.path.join(A.masvs, 'OWASP_MASVS.yaml'), encoding='utf-8'))
masvs = [dict(id=c['id'], group=g['id'], group_title=g.get('title', ''), statement=c.get('statement', ''), url=f"{SITE}/MASVS/controls/{c['id']}/") for g in my['groups'] for c in g['controls']]
counts['masvs-controls.csv'] = write('masvs-controls.csv', ['id', 'group', 'group_title', 'statement', 'url'], masvs)

# ------------------------------------------------------------------ VRT
vj = json.load(open(os.path.join(A.vrt, 'vulnerability-rating-taxonomy.json')))
def flat(fn, key):
    mp = json.load(open(fn)); default = mp['metadata'].get('default'); out = {}
    def w(nodes, prefix, inh):
        for n in nodes:
            path = (prefix + '.' if prefix else '') + n['id']; val = n[key] if key in n else inh; out[path] = val; w(n.get('children') or [], path, val)
    w(mp['content'], '', default); return out, default
cwe_m, cwe_d = flat(os.path.join(A.vrt, 'mappings/cwe/cwe.json'), 'cwe'); v3_m, v3_d = flat(os.path.join(A.vrt, 'mappings/cvss_v3/cvss_v3.json'), 'cvss_v3')
v4_m, v4_d = flat(os.path.join(A.vrt, 'mappings/cvss_v4/cvss_v4.json'), 'cvss_v4'); rem_m, _ = flat(os.path.join(A.vrt, 'mappings/remediation_advice/remediation_advice.json'), 'remediation_advice')
vrows = []
def vw(nodes, prefix='', parent=''):
    for n in nodes:
        path = (prefix + '.' if prefix else '') + n['id']; ch = n.get('children') or []
        pr = ('varies' if n['priority'] is None else f"P{n['priority']}") if 'priority' in n else ''
        vrows.append(dict(vrt_path=path, name=n.get('name'), type=n.get('type'), priority=pr, has_children='true' if ch else 'false', parent=parent, cwe=L(cwe_m.get(path, cwe_d)), cvss_v3=v3_m.get(path, v3_d) or '', cvss_v4=v4_m.get(path, v4_d) or '', has_remediation_advice='true' if rem_m.get(path) else 'false', release=vj['metadata'].get('release_date', '')[:10]))
        vw(ch, path, path)
vw(vj['content'])
counts['vrt.csv'] = write('vrt.csv', ['vrt_path', 'name', 'type', 'priority', 'has_children', 'parent', 'cwe', 'cvss_v3', 'cvss_v4', 'has_remediation_advice', 'release'], vrows)
dep = json.load(open(os.path.join(A.vrt, 'deprecated-node-mapping.json')))
counts['vrt-deprecated-nodes.csv'] = write('vrt-deprecated-nodes.csv', ['old_path', 'vrt_version', 'new_path'], [dict(old_path=k, vrt_version=ver, new_path=v) for k, m in dep.items() for ver, v in m.items()])

# ------------------------------------------------------------------ OWASP Mobile Top 10 (2024 = 2023-risks folder in the project repo)
mt = []
idx = os.path.join(A.mt10, '2023-risks', 'index.md')
for m in re.finditer(r'- \[(M\d{1,2}): ([^\]]+)\]\(([^)]+)\)', open(idx, encoding='utf-8').read()):
    mt.append(dict(id=m.group(1), title=m.group(2), edition='2024', url=f"https://owasp.org/www-project-mobile-top-10/2023-risks/{m.group(3).replace('.md', '')}"))
counts['mobile-top10-2024.csv'] = write('mobile-top10-2024.csv', ['id', 'title', 'edition', 'url'], mt)

# ------------------------------------------------------------------ ATT&CK Mobile (optional, from STIX bundle)
versions = {'owasp-mastg': git_rev(A.mastg), 'maswe': git_rev(A.maswe), 'owasp-masvs': git_rev(A.masvs), 'vulnerability-rating-taxonomy': git_rev(A.vrt) + ' release ' + vj['metadata'].get('release_date', ''), 'www-project-mobile-top-10': git_rev(A.mt10)}
if A.attack_stix:
    stix = json.load(open(A.attack_stix)); objs = stix['objects']
    coll = next((o for o in objs if o['type'] == 'x-mitre-collection'), {}); versions['attack-mobile'] = f"{coll.get('x_mitre_version')} {coll.get('modified')}"
    arows = []
    for o in objs:
        if o['type'] != 'attack-pattern' or o.get('revoked') or o.get('x_mitre_deprecated'): continue
        ext = next((r for r in o.get('external_references', []) if r.get('source_name') == 'mitre-attack'), {})
        if not ext.get('external_id'): continue
        plats = o.get('x_mitre_platforms', [])
        if 'Android' not in plats: continue
        arows.append(dict(id=ext['external_id'], name=o['name'], tactics='|'.join(sorted({p['phase_name'] for p in o.get('kill_chain_phases', []) if p.get('kill_chain_name') == 'mitre-mobile-attack'})), is_subtechnique='true' if o.get('x_mitre_is_subtechnique') else 'false', platforms='|'.join(plats), technique_version=o.get('x_mitre_version', ''), modified=o.get('modified', '')[:10], attack_version=coll.get('x_mitre_version', ''), url=ext.get('url', '')))
    arows.sort(key=lambda r: r['id'])
    counts['attack-mobile-android.csv'] = write('attack-mobile-android.csv', ['id', 'name', 'tactics', 'is_subtechnique', 'platforms', 'technique_version', 'modified', 'attack_version', 'url'], arows)

# ------------------------------------------------------------------ CWE Top 25 (optional; HTML page from cwe.mitre.org or a csv rank,id,name)
if A.cwe_top25:
    crows = []; t = open(A.cwe_top25, encoding='utf-8', errors='replace').read()
    if A.cwe_top25.endswith('.csv'):
        crows = list(csv.DictReader(open(A.cwe_top25, newline='', encoding='utf-8')))
    else:
        year = (re.search(r'(20\d\d)[ _]CWE Top 25', t) or re.search(r'(20\d\d)', os.path.basename(A.cwe_top25)) or [None, ''])[1]
        for r in re.findall(r'<tr[^>]*>(.*?)</tr>', t, re.S):
            cells = [htmlmod.unescape(re.sub(r'<[^>]+>', '', c)).strip() for c in re.findall(r'<td[^>]*>(.*?)</td>', r, re.S)]
            m = re.search(r'CWE-(\d+)', r)
            if m and cells and cells[0].isdigit(): crows.append(dict(rank=int(cells[0]), id='CWE-' + m.group(1), name=cells[2] if len(cells) > 2 else '', year=year, url=f'https://cwe.mitre.org/data/definitions/{m.group(1)}.html'))
    counts['cwe-top25.csv'] = write('cwe-top25.csv', ['rank', 'id', 'name', 'year', 'url'], crows)

# ------------------------------------------------------------------ crosswalk from the checklist (standard id -> item ids)
if A.checklist:
    KINDS = 'TEST|TECH|TOOL|KNOW|DEMO|BEST|APP'; G = 'STORAGE|CRYPTO|AUTH|NETWORK|PLATFORM|CODE|RESILIENCE|PRIVACY'
    titles = {}
    for coll in (tests, techs, tools, knows, bests, apps, demos): titles.update({r['id']: r['title'] for r in coll})
    titles.update({r['id']: r['title'] for r in maswe}); titles.update({r['id']: r['statement'] for r in masvs}); titles.update({r['vrt_path']: r['name'] for r in vrows})
    for r in rules: titles[r['rule_id']] = r['summary']; titles[re.sub(r'\.ya?ml$', '', r['rule_file'])] = r['summary']
    if A.attack_stix: titles.update({r['id']: r['name'] for r in arows})
    VRT_ALL = {r['vrt_path'] for r in vrows}; VRT_TOP = {p.split('.')[0] for p in VRT_ALL}
    cite = collections.defaultdict(set)
    def expand(text):
        ids = set()
        for m in re.finditer(r'(?:MASTG-)?\b(%s)-(\d{4})((?:\s*[,/]\s*-?\d{4}(?!\d))*)((?:\s*[–-]\s*\d{4}(?!\d))?)' % KINDS, text):
            k, a = m.group(1), int(m.group(2)); ns = [a]
            if m.group(4):
                b = int(re.search(r'\d{4}', m.group(4)).group(0))
                if b > a and b - a <= 40: ns = list(range(a, b + 1))
            ns += [int(c) for c in re.findall(r'\d{4}', m.group(3) or '')]; ids |= {f'MASTG-{k}-{n:04d}' for n in ns}
        for m in re.finditer(r'MASWE-(\d{4})((?:\s*/\s*\d{4})*)', text): ids.add(f'MASWE-{m.group(1)}'); ids |= {f'MASWE-{x}' for x in re.findall(r'\d{4}', m.group(2) or '')}
        for m in re.finditer(r'MASVS-(%s)-(\d)((?:\s*/\s*\d)*)' % G, text): ids.add(f'MASVS-{m.group(1)}-{m.group(2)}'); ids |= {f'MASVS-{m.group(1)}-{d}' for d in re.findall(r'\d', m.group(3) or '')}
        ids |= {f'CWE-{x}' for x in re.findall(r'CWE-(\d+)', text)} | set(re.findall(r'\bT1\d{3}(?:\.\d{3})?\b', text))
        ids |= {x for x in re.findall(r'`([a-z_]+(?:\.[a-z0-9_]+)+)`', text) if x.split('.')[0] in VRT_TOP or x in VRT_ALL}  # real VRT paths; shorthand stays unresolved (known=false)
        ids |= {re.sub(r'\.ya?ml$', '', x) for x in re.findall(r'mastg-android-[a-z0-9-]+(?:\.ya?ml)?', text)}
        return ids
    for r in csv.DictReader(open(A.checklist, newline='', encoding='utf-8')):
        for k in expand((r.get('maps_to') or '') + ' ' + (r.get('vrt_path') or '')): cite[k].add(r['item_id'])
    def std(k): return 'MASTG-' + k.split('-')[1] if k.startswith('MASTG-') else 'MASWE' if k.startswith('MASWE') else 'MASVS' if k.startswith('MASVS') else 'CWE' if k.startswith('CWE') else 'ATTACK' if re.match(r'T1\d{3}', k) else 'RULE' if k.startswith('mastg-android') else 'VRT'
    xrows = [dict(standard=std(k), standard_id=k, title=titles.get(k, ''), known='true' if k in titles or std(k) in ('CWE',) else 'false', n_items=len(v), item_ids=' '.join(sorted(v))) for k, v in cite.items()]
    xrows.sort(key=lambda r: (r['standard'], r['standard_id']))
    counts['crosswalk.csv'] = write('crosswalk.csv', ['standard', 'standard_id', 'title', 'known', 'n_items', 'item_ids'], xrows)
json.dump({'versions': versions, 'row_counts': counts, 'platforms_kept': sorted(KEEP)}, open(os.path.join(A.out, 'versions.json'), 'w'), indent=1)
print('versions.json written')
