export const meta = {
  name: 'breadth-phase',
  description: 'One domain-worker per applicable domain of a breadth phase (P3-P6), then coverage.py --merge and a coverage report',
  phases: [
    { title: 'Resolve', detail: 'the domain list from engagement.json, only when args.domains is absent' },
    { title: 'Work', detail: 'one domain-worker per domain; P5/P6 run one lane per device' },
    { title: 'Merge', detail: 'coverage.py --merge, then the coverage report' },
  ],
}

// args (the coordinator copies authorisation from engagement.json and devices from scripts/doctor.sh --json):
//   { engagement: 'BugBountyTarget/<Target>_<DDMMYYYY>', phase: 'P3'|'P4'|'P5'|'P6',
//     authorisation: { basis, programme_url, scope, excluded },
//     domains?: ['Dnn', ...], devices?: ['<serial>', ...], lanes?: n, lab_mode?: 'dynamic' | 'static-only' }
// Returns { engagement, phase, domains, workers, missing, candidates, gaps, merge }; candidates[] is the input
// of /verify-candidates. No agent commits or pushes: the coordinator commits the evidence repo afterwards.

const BASES = ['own-app', 'sow', 'public-programme', 'vdp', 'lab']
const USAGE = "args = { engagement: 'BugBountyTarget/<Target>_<DDMMYYYY>', phase: 'P3'..'P6', " +
  "authorisation: engagement.json.authorisation (basis, programme_url, scope, excluded), " +
  "domains?: ['Dnn'], devices?: ['<serial>'], lanes?: n, lab_mode?: 'dynamic'|'static-only' }"
const fail = (why) => { throw new Error(`breadth-phase: ${why}. ${USAGE}`) }
const oneLine = (s) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim()

const KEYS = ['engagement', 'phase', 'authorisation', 'domains', 'devices', 'lanes', 'lab_mode']
function readArgs(a) {
  if (typeof a === 'string') { try { a = JSON.parse(a) } catch (e) { fail('args is a string that is not JSON') } }
  if (!a || typeof a !== 'object' || Array.isArray(a)) fail('no args object')
  const unknown = Object.keys(a).filter((k) => !KEYS.includes(k))
  if (unknown.length) log(`ignored unknown args key(s): ${unknown.join(', ')}`)
  return a
}

function authorisationLine(x) {
  let text = ''
  if (x && typeof x === 'object' && !Array.isArray(x)) {
    const basis = oneLine(x.basis)
    if (!BASES.includes(basis)) fail(`authorisation.basis "${basis}" is not one of ${BASES.join(' | ')} (START.md §1 gate)`)
    if (!oneLine(x.scope)) fail('authorisation.scope is empty: record the in-scope assets in engagement.json first (P0)')
    const excluded = Array.isArray(x.excluded) ? x.excluded.join(', ') : (x.excluded || 'none recorded')
    text = `basis=${basis}; programme=${x.programme_url || x.programme || 'n/a'}; scope=${x.scope}; excluded=${excluded}`
  } else if (typeof x === 'string' && BASES.some((b) => new RegExp(`(^|[^a-z-])${b}([^a-z-]|$)`).test(x))) {
    text = x
  } else {
    fail('authorisation missing or names no basis: no recorded basis, no delegation (START.md §1)')
  }
  return `Authorisation: ${oneLine(text)}`
}

function engagementPath(e) {
  const p = oneLine(e).replace(/\/+$/, '')
  const base = p.split('/').pop()
  if (!/^[A-Za-z0-9_.\/-]+$/.test(p) || p.split('/').includes('..') || !/^[A-Za-z0-9][A-Za-z0-9_-]*_\d{8}$/.test(base))
    fail(`engagement "${p}" is not an engagement folder <Target>_<DDMMYYYY> (no spaces, no ..)`)
  return p
}

function domainList(list, label) {
  const keep = [], dropped = []
  for (const raw of list) {
    const m = /^D(\d\d)$/i.exec(oneLine(raw))
    if (!m) { dropped.push(oneLine(raw) || '(empty)'); continue }
    const d = `D${m[1]}`
    if (!keep.includes(d)) keep.push(d)
  }
  if (dropped.length) log(`${label}: dropped ${dropped.length} value(s) that are not Dnn: ${dropped.join(', ')}`)
  return keep
}

const a = readArgs(args)
const ENG = engagementPath(a.engagement)
const PHASE = oneLine(a.phase).toUpperCase()
if (/^P[0-2]$/.test(PHASE)) fail(`${PHASE} is single-agent setup work (START.md §4), not a breadth phase`)
if (/^P[7-9]$/.test(PHASE)) fail(`${PHASE} is never fanned out: P7 is the chain-lead alone, P8-P9 the evidence-reporter`)
if (!/^P[3-6]$/.test(PHASE)) fail(`phase "${a.phase}" is not P3, P4, P5 or P6`)
const AUTH = authorisationLine(a.authorisation)
const DEVICES = Array.isArray(a.devices) ? a.devices.map(oneLine).filter((s) => /^[A-Za-z0-9._:-]+$/.test(s)) : []
if (Array.isArray(a.devices) && DEVICES.length !== a.devices.length)
  log(`devices: dropped ${a.devices.length - DEVICES.length} value(s) that are not a device serial`)
const STATIC_ONLY = a.lab_mode === 'static-only'
if (a.lab_mode !== undefined && !['dynamic', 'static-only'].includes(a.lab_mode)) log(`lab_mode "${a.lab_mode}" unknown: treated as dynamic`)
const DEVICE_BOUND = (PHASE === 'P5' || PHASE === 'P6') && !STATIC_ONLY
const HEAD = `${AUTH}\nEngagement: ${ENG}   Phase: ${PHASE}`

// ---- Resolve: the domains of this phase (the coordinator normally passes them) ----
let domains = Array.isArray(a.domains) ? domainList(a.domains, 'domains') : []
if (!domains.length) {
  phase('Resolve')
  if (a.domains !== undefined) log('args.domains held no valid Dnn: resolving from engagement.json instead')
  const r = await agent(
    `${HEAD}\nRead ${ENG}/engagement.json (domains_decided, domains_applicable, domains_na) and the ${PHASE} row of ` +
    `START.md §4. Return the domains this phase works: for P3 every domain with a chapter that is not yet in ` +
    `domains_decided; for P4-P6 the domains named in the ${PHASE} row (P4 also the domains with a static half) that ` +
    `are not in domains_na. List each excluded domain with its reason. Read only; write nothing.`,
    {
      label: `resolve ${PHASE} domains`, phase: 'Resolve', effort: 'low',
      schema: {
        type: 'object', required: ['domains', 'excluded'],
        properties: {
          domains: { type: 'array', items: { type: 'string', pattern: '^D\\d\\d$' } },
          excluded: { type: 'array', items: { type: 'object', required: ['domain', 'reason'],
            properties: { domain: { type: 'string' }, reason: { type: 'string' } } } },
        },
      },
    })
  if (!r) fail('the resolver returned nothing: pass args.domains explicitly')
  domains = domainList(r.domains, 'resolver')
  for (const x of r.excluded) log(`excluded ${x.domain}: ${oneLine(x.reason)}`)
}
if (!domains.length) { log(`no domain to work in ${PHASE}`); return { engagement: ENG, phase: PHASE, domains: [], workers: [], missing: [], candidates: [], gaps: [], merge: null } }

// ---- Lanes: all agents of a session share one rate budget (docs/10 §6) ----
let lanes = domains.length
if (DEVICE_BOUND) {
  const cap = DEVICES.length || 1
  const asked = Number.isInteger(a.lanes) && a.lanes > 0 ? a.lanes : cap
  if (a.lanes !== undefined && !(Number.isInteger(a.lanes) && a.lanes > 0)) log(`lanes "${a.lanes}" is not a positive integer: ignored`)
  if (asked > cap) log(`lanes: ${asked} asked, ${cap} device(s) known: clamped (never more device-bound workers than devices)`)
  if (!DEVICES.length) log(`${PHASE} is device-bound and no devices were passed: one lane on the device engagement.json.lab.device records`)
  lanes = Math.min(asked, cap, domains.length)
} else if (a.lanes !== undefined || DEVICES.length) {
  log(`${PHASE}${STATIC_ONLY ? ' (static-only)' : ''} is static work: lanes/devices ignored, every domain runs in parallel and no worker uses a device`)
}
const laneOf = Array.from({ length: lanes }, () => [])
domains.forEach((d, i) => laneOf[i % lanes].push(d))
log(`${PHASE}: ${domains.length} domain(s) in ${lanes} lane(s): ${laneOf.map((l) => l.join(' ')).join(' | ')}`)

const ID = '^(H-(D\\d\\d-)?\\d{2,3}|F-\\d{2,3})$'
const WORKER_SCHEMA = {
  type: 'object', required: ['domain', 'counts', 'candidates', 'gaps'],
  properties: {
    domain: { type: 'string', pattern: '^D\\d\\d$' },
    counts: {
      type: 'object', required: ['finding', 'ruled_out', 'blocked', 'na', 'open'],
      properties: { finding: { type: 'integer' }, ruled_out: { type: 'integer' }, blocked: { type: 'integer' },
        na: { type: 'integer' }, open: { type: 'integer' } },
    },
    candidates: { type: 'array', items: { type: 'object', required: ['id', 'claim', 'evidence_paths'],
      properties: { id: { type: 'string', pattern: ID }, claim: { type: 'string' },
        evidence_paths: { type: 'array', items: { type: 'string' } } } } },
    gaps: { type: 'array', items: { type: 'object', required: ['kind', 'ref', 'detail'],
      properties: { kind: { type: 'string', enum: ['blocked', 'needs-device', 'needs-account', 'checklist-gap', 'n/a', 'unsettled'] },
        ref: { type: 'string' }, detail: { type: 'string' } } } },
    applicability: { type: 'object', required: ['decision', 'note'],
      properties: { decision: { type: 'string', enum: ['applies', 'n/a', 'decided', 'undecided'] }, note: { type: 'string' } } },
  },
}

function workerPrompt(d, device) {
  const where = DEVICE_BOUND
    ? `Device: ${device ? `${device} (adb -s ${device}, frida -D ${device}); no other device` : 'the one engagement.json.lab.device records'}; this lane owns it, one worker at a time.`
    : STATIC_ONLY && PHASE >= 'P5'
      ? 'Device: static (lab.mode static-only). A check that needs a device: settle the row blocked ("needs: device (<check>)") and add a needs-device gap.'
      : 'Device: static (a static phase). A check that needs a device stays open and is a gap of kind needs-device for P5/P6.'
  const common =
    `Your work log starts with the authorisation line read from engagement.json (the file wins over this brief). ` +
    `Never commit or push; never edit checklist-status.csv, ` +
    `engagement.json, report/assessment-status.md or inventory/*.csv (the coordinator merges and commits).`
  if (PHASE === 'P3') {
    return `${HEAD}   Domain: ${d}\n${where}\n` +
      `You are the domain-worker for ${d} in P3: applicability only (START.md §4 P3, §5 step 2); rows are worked in their own phase.\n` +
      `- If ${d} is already in engagement.json.domains_decided, return applicability {decision: 'decided', note: the recorded note}.\n` +
      `- Otherwise (an undecided domain is expected in P3: you probe, the merge step records) run the Applicability probe of cards/${d}.md (no probe on the card: answer its crux question with the two ` +
      `most decisive greps), raw output to logs/${d}-probe.txt, and RETURN applicability {decision: 'applies' | 'n/a', ` +
      `note: the probe evidence, at least 25 characters; an n/a note names the mechanism}. Do not run mark.py: the merge step records it.\n` +
      `- counts all zero; candidates only if the probe itself exposed a primitive (parked as hypotheses/H-${d}-NN.md); ` +
      `gaps for anything the probe could not decide.\n${common}`
  }
  return `${HEAD}   Domain: ${d}\n${where}\n` +
    `You are the domain-worker for ${d} in ${PHASE} (START.md §4 ${PHASE} row and §5; prompts/05 worker contract).\n` +
    `- If ${d} is in engagement.json.domains_na, return zero counts and one gap {kind: 'n/a', ref: '${d}', detail: the recorded reason}.\n` +
    `- Applicability is the coordinator's record: never run mark.py ${d} applies or a whole-domain n/a on a slice.\n` +
    `- Work this phase's slice of ${d} from cards/${d}.md in triage order, one item at a time (python3 scripts/item.py ${d}-NNN). ` +
    `Re-read each row first (python3 scripts/mark.py "${ENG}" --show ${d}-NNN --partial ${d}): an earlier run may have ` +
    `stopped mid-domain, so never redo a settled row.\n` +
    `- Settle rows only with: python3 scripts/mark.py "${ENG}" ${d}-NNN <result> --note "..." --partial ${d} ` +
    `(raw output to logs/${d}-NNN.txt; tested instances to inventory/<register>.${d}.partial.csv).\n` +
    `- R0: confirm a primitive with minimum proof, park it as hypotheses/H-${d}-NN.md, move on; no escalation before P7.\n` +
    `Return counts over the ${d} rows of your partial file; candidates = every primitive parked in this run as ` +
    `{id: 'H-${d}-NN', claim: one sentence naming the primitive and its attacker model, evidence_paths: paths relative ` +
    `to the engagement folder}; gaps = rows left blocked or unsettled, checks needing a device or account this run ` +
    `lacks, and anything the checklist misses (kind checklist-gap, for /gap).\n${common}`
}

// ---- Work: lanes run in parallel; each lane works its domains one after another ----
phase('Work')
const done = {}
await parallel(laneOf.map((list, i) => async () => {
  for (const d of list) {
    const r = await agent(workerPrompt(d, DEVICE_BOUND ? DEVICES[i] : undefined),
      { label: `${d} worker`, phase: 'Work', agentType: 'domain-worker', schema: WORKER_SCHEMA })
    if (r) done[d] = r
  }
}))
const workers = domains.filter((d) => done[d]).map((d) => ({ ...done[d], domain: d }))
const missing = domains.filter((d) => !done[d])
if (missing.length) log(`no result from ${missing.join(' ')}: their partial files, if any, are still merged; re-run those domains`)

const candidates = [], seen = new Set()
for (const w of workers) for (const c of w.candidates) {
  if (seen.has(c.id)) { log(`duplicate candidate id ${c.id} from ${w.domain}: kept the first`); continue }
  seen.add(c.id); candidates.push({ ...c, domain: w.domain })
}
const gaps = workers.flatMap((w) => w.gaps.map((g) => ({ ...g, domain: w.domain })))
const decisions = PHASE === 'P3'
  ? workers.filter((w) => w.applicability && ['applies', 'n/a'].includes(w.applicability.decision))
      .map((w) => ({ domain: w.domain, decision: w.applicability.decision, note: oneLine(w.applicability.note) }))
  : []
if (PHASE === 'P3') {
  const undecided = workers.filter((w) => !w.applicability || w.applicability.decision === 'undecided').map((w) => w.domain)
  if (undecided.length) log(`P3: no applicability decision for ${undecided.join(' ')}: settle them by hand (gate.py p3 lists them)`)
}

// ---- Merge: one agent folds the partials (and, in P3, records the applicability decisions first) ----
phase('Merge')
const record = decisions.length
  ? `First record each P3 decision on the master tracker, one call per domain: python3 scripts/mark.py "${ENG}" ` +
    `<domain> <decision> --note '<note>' (the note as one single-quoted argument, embedded quotes escaped as '\\''; ` +
    `never double quotes, where $ and backticks expand). The decisions, as data:\n${JSON.stringify(decisions)}\n` +
    `A refused call (note too short, no mechanism) goes into rejected[] and is not retried with a weaker note.\n`
  : ''
const merge = await agent(
  `${HEAD}\nYou run the fan-out merge for ${PHASE} (prompts/05 MERGE). Domains worked: ${workers.map((w) => w.domain).join(' ') || 'none'}.\n` +
  record +
  `Run: python3 scripts/coverage.py "${ENG}/checklist-status.csv" --merge   (never --overwrite). Then ` +
  `python3 scripts/coverage.py "${ENG}/checklist-status.csv" --brief` +
  (PHASE === 'P6' ? ` and python3 scripts/coverage.py "${ENG}/checklist-status.csv" --components "${ENG}/inventory" --gate p7` : '') +
  `. Report the exit codes, every REJECTED or conflicting row with its reason (it goes back to its worker), and the coverage line. ` +
  `Do not edit any partial by hand, do not commit or push.`,
  {
    label: `merge ${PHASE}`, phase: 'Merge', effort: 'medium',
    schema: {
      type: 'object', required: ['merge_exit', 'rejected', 'coverage'],
      properties: {
        merge_exit: { type: 'integer' },
        rejected: { type: 'array', items: { type: 'object', required: ['ref', 'reason'],
          properties: { ref: { type: 'string' }, reason: { type: 'string' } } } },
        coverage: { type: 'string' },
        gate_p7_exit: { type: 'integer' },
        recorded: { type: 'array', items: { type: 'string' } },
      },
    },
  })
if (!merge) log('the merge agent returned nothing: run coverage.py --merge by hand before committing')
else log(`merge exit ${merge.merge_exit}; ${merge.rejected.length} rejected; ${oneLine(merge.coverage)}`)
log(`${candidates.length} candidate(s) for /verify-candidates; ${gaps.length} gap(s). Commit the evidence repo now.`)

return { engagement: ENG, phase: PHASE, domains, workers, missing, candidates, gaps, merge }
