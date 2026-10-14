export const meta = {
  name: 'verify-candidates',
  description: 'Three independent lenses per parked candidate (reproduce, guard, triage); a candidate survives when at least two of three do not refute it',
  phases: [
    { title: 'Verify', detail: 'verify-reproduce in device lanes; verify-guard and verify-triage in parallel' },
  ],
}

// args (the coordinator copies authorisation and lab.mode from engagement.json, devices from scripts/doctor.sh --json):
//   { engagement: 'BugBountyTarget/<Target>_<DDMMYYYY>',
//     authorisation: { basis, programme_url, scope, excluded },
//     candidates: [{ id: 'H-Dnn-NN' | 'H-NNN' | 'F-NNN' | 'X-NNN', claim, evidence_paths: ['logs/…', 'hypotheses/…'] }],
//     devices?: ['<serial>', ...], lanes?: n, lab_mode?: 'dynamic' | 'static-only' }
// Returns { engagement, rows, table, survived, refuted, incomplete, dropped }; `table` is the markdown verdict table
// for report/assessment-status.md. The lenses write nothing: the coordinator records the outcome and commits.

const BASES = ['own-app', 'sow', 'public-programme', 'vdp', 'lab']
const USAGE = "args = { engagement: 'BugBountyTarget/<Target>_<DDMMYYYY>', authorisation: engagement.json.authorisation, " +
  "candidates: [{ id, claim, evidence_paths }], devices?: ['<serial>'], lanes?: n, lab_mode?: 'dynamic'|'static-only' }"
const fail = (why) => { throw new Error(`verify-candidates: ${why}. ${USAGE}`) }
const oneLine = (s) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim()

const KEYS = ['engagement', 'authorisation', 'candidates', 'devices', 'lanes', 'lab_mode']
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

const a = readArgs(args)
const ENG = engagementPath(a.engagement)
const AUTH = authorisationLine(a.authorisation)
const STATIC_ONLY = a.lab_mode === 'static-only'
if (a.lab_mode !== undefined && !['dynamic', 'static-only'].includes(a.lab_mode)) log(`lab_mode "${a.lab_mode}" unknown: treated as dynamic`)
const DEVICES = Array.isArray(a.devices) ? a.devices.map(oneLine).filter((s) => /^[A-Za-z0-9._:-]+$/.test(s)) : []
if (Array.isArray(a.devices) && DEVICES.length !== a.devices.length)
  log(`devices: dropped ${a.devices.length - DEVICES.length} value(s) that are not a device serial`)

// ---- candidates: an id, a one-sentence claim and at least one evidence path inside the engagement (R5) ----
if (!Array.isArray(a.candidates) || !a.candidates.length) fail('candidates is empty')
const ID_RE = /^(H-(D\d\d-)?\d{2,3}|F-\d{2,3}|X-\d{2,3})$/
const cands = [], dropped = []
for (const c of a.candidates) {
  const id = oneLine(c && c.id)
  const claim = oneLine(c && c.claim)
  if (!ID_RE.test(id)) { dropped.push({ id: id || '(none)', why: 'id is not H-NNN, H-Dnn-NN, F-NNN or X-NNN' }); continue }
  if (cands.some((x) => x.id === id)) { dropped.push({ id, why: 'duplicate id: kept the first' }); continue }
  if (claim.length < 20) { dropped.push({ id, why: 'claim missing or shorter than one sentence' }); continue }
  const raw = Array.isArray(c.evidence_paths) ? c.evidence_paths.map(oneLine) : []
  const paths = raw.filter((p) => p && !/^[\/~]/.test(p) && !p.split('/').includes('..'))
  if (paths.length !== raw.length) log(`${id}: dropped ${raw.length - paths.length} evidence path(s) outside the engagement folder`)
  if (!paths.length) { dropped.push({ id, why: 'no evidence path inside the engagement: a claim without evidence is not a candidate (R5)' }); continue }
  cands.push({ id, claim, paths, domain: oneLine(c.domain) })
}
for (const d of dropped) log(`dropped ${d.id}: ${d.why}`)
if (!cands.length) fail('no valid candidate left')

// ---- the reproduce lens is the only one that touches a device: one lane per device (docs/10 §6) ----
let lanes = cands.length
if (!STATIC_ONLY) {
  const cap = DEVICES.length || 1
  const asked = Number.isInteger(a.lanes) && a.lanes > 0 ? a.lanes : cap
  if (asked > cap) log(`lanes: ${asked} asked, ${cap} device(s) known: clamped (never more device-bound workers than devices)`)
  if (!DEVICES.length) log('no devices passed: reproduce runs in one lane on the device engagement.json.lab.device records')
  lanes = Math.min(asked, cap, cands.length)
}
const laneOf = Array.from({ length: lanes }, () => [])
cands.forEach((c, i) => laneOf[i % lanes].push(c))

const VERDICT = {
  type: 'object', required: ['refuted', 'confidence', 'reasoning', 'missing_link', 'honest_severity'],
  properties: {
    refuted: { type: 'boolean' },
    confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
    reasoning: { type: 'string' },
    missing_link: { type: 'string' },
    honest_severity: { type: 'string', enum: ['P1', 'P2', 'P3', 'P4', 'P5', 'withhold'] },
  },
}
const RETURN = `Return the verdict: refuted, confidence, reasoning (what you ran or read and what it showed, with ` +
  `file:line), missing_link (the unproven link, or "none"), honest_severity (the VRT priority the proven part supports, ` +
  `docs/02 §6; "withhold" when it is not reportable). Write no tracked file in the engagement (gitignored build output only), edit no tracker, commit nothing.`

function brief(c, lens, device) {
  return `${AUTH}\nEngagement: ${ENG}   Candidate: ${c.id}${c.domain ? ` (${c.domain})` : ''}   Lens: ${lens}\n` +
    `Claim: ${c.claim}\nEvidence (relative to the engagement folder): ${c.paths.join(', ')}\nDevice: ${device}\n` +
    `You are one of three independent lenses; you do not see the others. Judge the claim, not the worker who wrote it.\n`
}
const LENS = {
  reproduce: (c, device) => brief(c, 'reproduce (1 of 3)', device) +
    `Re-run the proof yourself from the weakest attacker model that could work (docs/05; adb shell is not AM-03, R3). ` +
    `refuted=true when it does not reproduce, reproduces only from a stronger attacker than the claim states, rests ` +
    `on an emulator artefact (docs/02 §9), or cannot be run at all (say why in missing_link).\n${RETURN}`,
  guard: (c) => brief(c, 'guard (2 of 3)', 'static in this lens: if only a device run can settle it, say so in missing_link') +
    `Hunt for what kills the claim: the validator or permission check before the sink, a second implementation the ` +
    `claimed path does not reach, a server-side check, a platform gate (API level, targetSdk behaviour, OEM), a ` +
    `precondition that never holds in the shipped build. refuted=true when you find one (cite file:line or the ` +
    `platform rule); refuted=false only after naming where you looked.\n${RETURN}`,
  triage: (c) => brief(c, 'triage (3 of 3)', 'static in this lens') +
    `Read the claim as the programme's triager: is the asset in scope and not excluded (authorisation line above); ` +
    `which VRT node does the Proof land on (data/vrt.csv); is it in the docs/02 §4 graveyard standalone; does the ` +
    `attacker model and precondition survive the docs/06 ladder. refuted=true when a triager would close it as stated. ` +
    `A P5 primitive whose chain partner is named is not refuted on that ground: rate it P5 and name the partner in ` +
    `missing_link (R2).\n${RETURN}`,
}

// ---- Verify: reproduce lanes and the two reading lenses all run at once ----
phase('Verify')
const got = {}
for (const c of cands) got[c.id] = { reproduce: null, guard: null, triage: null }
const reproduceDevice = (i) => STATIC_ONLY
  ? 'static (lab.mode static-only): reproduce from the decompiled tree, requests/ and responses/ and the recorded evidence'
  : (DEVICES[i] ? `${DEVICES[i]} (adb -s ${DEVICES[i]}, frida -D ${DEVICES[i]}); this lane owns it, one lens at a time` : 'the one engagement.json.lab.device records')
await parallel([
  ...laneOf.map((list, i) => async () => {
    for (const c of list)
      got[c.id].reproduce = await agent(LENS.reproduce(c, reproduceDevice(i)),
        { label: `${c.id} reproduce`, phase: 'Verify', agentType: 'verify-reproduce', schema: VERDICT })
  }),
  ...cands.flatMap((c) => [
    async () => { got[c.id].guard = await agent(LENS.guard(c),
      { label: `${c.id} guard`, phase: 'Verify', agentType: 'verify-guard', schema: VERDICT }) },
    async () => { got[c.id].triage = await agent(LENS.triage(c),
      { label: `${c.id} triage`, phase: 'Verify', agentType: 'verify-triage', schema: VERDICT }) },
  ]),
])

// ---- Tally: survives with >= 2 of 3 not refuting; a lens with no verdict counts as neither ----
const ORDER = ['P1', 'P2', 'P3', 'P4', 'P5', 'withhold']
const cell = (s) => oneLine(s).replace(/\|/g, '\\|')
const rows = cands.map((c) => {
  const v = got[c.id]
  const given = ['reproduce', 'guard', 'triage'].filter((k) => v[k])
  const holds = given.filter((k) => !v[k].refuted), refutes = given.filter((k) => v[k].refuted)
  const verdict = holds.length >= 2 ? 'survives' : refutes.length >= 2 ? 'refuted' : 'incomplete'
  const severity = verdict === 'survives'
    ? holds.map((k) => v[k].honest_severity).sort((x, y) => ORDER.indexOf(y) - ORDER.indexOf(x))[0]
    : verdict === 'refuted' ? 'withhold' : '?'
  const links = [...new Set(given.map((k) => oneLine(v[k].missing_link)).filter((s) => s && !/^none\.?$/i.test(s)))]
  return { id: c.id, domain: c.domain, claim: c.claim, verdict, refutes: refutes.length, honest_severity: severity,
    missing_link: links.join(' / ') || 'none', lenses: v }
})
const lensCell = (x) => (x ? `${x.refuted ? 'refuted' : 'holds'} (${x.confidence})` : 'no verdict')
const table = [
  '| Candidate | Verdict | Reproduce | Guard | Triage | Honest severity | Missing link |',
  '|---|---|---|---|---|---|---|',
  ...rows.map((r) => `| ${r.id} | ${r.verdict} | ${lensCell(r.lenses.reproduce)} | ${lensCell(r.lenses.guard)} | ` +
    `${lensCell(r.lenses.triage)} | ${r.honest_severity} | ${cell(r.missing_link)} |`),
].join('\n')
const pick = (s) => rows.filter((r) => r.verdict === s).map((r) => r.id)
const survived = pick('survives'), refuted = pick('refuted'), incomplete = pick('incomplete')
log(`${survived.length} survive, ${refuted.length} refuted, ${incomplete.length} incomplete` +
  (incomplete.length ? ` (a lens returned nothing: re-run ${incomplete.join(' ')})` : '') +
  (dropped.length ? `; ${dropped.length} dropped before verification` : ''))

return { engagement: ENG, rows, table, survived, refuted, incomplete, dropped }
