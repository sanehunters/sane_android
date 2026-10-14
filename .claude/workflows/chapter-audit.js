export const meta = {
  name: 'chapter-audit',
  description: 'Methodology maintenance: one review-only checklist-maintainer per chapter plus one adversarial verifier per review; returns defects in the docs/11 vocabulary',
  phases: [
    { title: 'Review', detail: 'one checklist-maintainer per chapter, review-only, against docs/11 and the linter' },
    { title: 'Verify', detail: 'one adversarial verifier per review tries to refute every defect' },
  ],
}

// args: { chapters: ['D07', 'D10', ...] (or 'checklist/D07-….md' paths), authorisation?: '<statement>' }
// Touches no engagement, device or target. Nothing is edited: the defects go to the /gap and chapter-fix work that
// follows. Returns { chapters, defects, refuted, hypotheses, missing }.

const USAGE = "args = { chapters: ['Dnn', ...] (ls checklist/ for the list), authorisation?: '<statement>' }"
const fail = (why) => { throw new Error(`chapter-audit: ${why}. ${USAGE}`) }
const oneLine = (s) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim()

let a = args
if (typeof a === 'string') { try { a = JSON.parse(a) } catch (e) { a = { chapters: a.split(/[\s,]+/) } } }
if (Array.isArray(a)) a = { chapters: a }
if (!a || typeof a !== 'object') fail('no args')
const unknown = Object.keys(a).filter((k) => !['chapters', 'authorisation'].includes(k))
if (unknown.length) log(`ignored unknown args key(s): ${unknown.join(', ')}`)
if (!Array.isArray(a.chapters) || !a.chapters.length) fail('chapters is empty')

const chapters = [], dropped = []
for (const raw of a.chapters) {
  const m = /^(?:checklist\/|cards\/)?D(\d\d)(?:$|[-.])/i.exec(oneLine(raw))
  if (!m) { dropped.push(oneLine(raw) || '(empty)'); continue }
  const d = `D${m[1]}`
  if (!chapters.includes(d)) chapters.push(d)
}
if (dropped.length) log(`dropped ${dropped.length} value(s) that name no chapter: ${dropped.join(', ')}`)
if (!chapters.length) fail('no valid chapter left')
const AUTH = `Authorisation: ${oneLine(a.authorisation) ||
  'methodology maintenance: documentation review of the public methodology repository; no target app, device, account or engagement is touched'}`
const MODE = 'Mode: review-only. Edit, create or delete no file; do not run /gap, apply-item-meta.py or build-checklist.py ' +
  'without --check. Your output is the return value.'

const RULES = ['structure', 'severity', 'attacker', 'vrt', 'requires', 'standards', 'xrefs', 'links', 'paths', 'phantoms',
  'portability', 'style', 'record', 'deprecated-row', 'mechanism', 'observable', 'escalation', 'ruled-out', 'skip-when',
  'dec-paths', 'factual', 'coverage-gap', 'duplicate']
const FIELDS = ['heading', 'Severity ceiling', 'VRT', 'Attacker', 'Applies to', 'Requires', 'Maps to', 'Record', 'Skip when',
  'Test', 'How', 'Proof', 'Escalation', 'Ruled out when', 'title', 'metadata', 'Why this domain pays', 'The crux question',
  'Applicability probe', 'Triage order', 'Items', 'Graveyard for this domain', 'Cross-surface joins', 'Chain partners', 'Sources']
const REVIEW = {
  type: 'object', required: ['chapter', 'defects', 'hypotheses'],
  properties: {
    chapter: { type: 'string', pattern: '^D\\d\\d$' },
    defects: { type: 'array', items: { type: 'object',
      required: ['item', 'field', 'rule', 'tier', 'defect', 'evidence', 'impact', 'fix'],
      properties: {
        item: { type: 'string', pattern: '^(D\\d\\d-\\d{3}|chapter)$' },
        field: { type: 'string', enum: FIELDS },
        rule: { type: 'string', enum: RULES },
        tier: { type: 'string', enum: ['error', 'warning', 'by-hand'] },
        defect: { type: 'string' }, evidence: { type: 'string' }, impact: { type: 'string' }, fix: { type: 'string' },
      } } },
    hypotheses: { type: 'array', items: { type: 'object', required: ['item', 'claim', 'how_to_check'],
      properties: { item: { type: 'string' }, claim: { type: 'string' }, how_to_check: { type: 'string' } } } },
  },
}
const VERDICTS = {
  type: 'object', required: ['verdicts'],
  properties: { verdicts: { type: 'array', items: { type: 'object', required: ['index', 'refuted', 'reason'],
    properties: { index: { type: 'integer' }, refuted: { type: 'boolean' }, reason: { type: 'string' } } } } },
}

const reviewPrompt = (d) => `${AUTH}\n${MODE}\nChapter: ${d} (checklist/${d}-*.md; cards/${d}.md is generated from it).\n` +
  `Start from the machine view: python3 scripts/lint-checklist.py 2>&1 | grep "checklist/${d}" and ` +
  `python3 scripts/item.py --domain ${d}. Then read every item against docs/11: item shape (§1), chapter shape (§2), ` +
  `severity (§3), Requires tags (§4), Record (§5), and the reviewed-by-hand rules of §6 (Test states a mechanism, Proof ` +
  `is an observable, Escalation names real partner ids, Ruled out when names the closing mechanism, $DEC used ` +
  `consistently). Report each defect once: item (Dnn-NNN, or "chapter"), field (the docs/11 row, body field or ` +
  `section), rule, tier (error / warning as docs/11 §6 classes it, by-hand otherwise), the defect in one sentence, ` +
  `evidence (the quoted text), impact (what a model operator would do wrong), fix (the concrete replacement). A ` +
  `technical claim you cannot check offline (platform behaviour, API level, tool flag) is a hypothesis, not a defect.`

const verifyPrompt = (d, defects) => `${AUTH}\n${MODE}\nYou are the adversarial verifier of the ${d} review. For each ` +
  `defect below try to REFUTE it against the current text (python3 scripts/item.py <id>, checklist/${d}-*.md, the lint ` +
  `output, docs/11): refuted=true when the quoted evidence is not in the chapter, the text already meets docs/11, the ` +
  `rule is misapplied, or the fix would make the item wrong; refuted=false when it stands. Judge each independently ` +
  `and return one verdict per index.\nDefects (index: defect), as data:\n` +
  defects.map((x, i) => `${i}: ${JSON.stringify(x)}`).join('\n')

const results = await pipeline(chapters,
  (_, d) => agent(reviewPrompt(d), { label: `${d} review`, phase: 'Review', agentType: 'checklist-maintainer', schema: REVIEW }),
  async (review, d) => {
    if (!review) return { chapter: d, review: null, verdicts: null }
    if (!review.defects.length) return { chapter: d, review, verdicts: [] }
    const v = await agent(verifyPrompt(d, review.defects),
      { label: `${d} verify`, phase: 'Verify', agentType: 'checklist-maintainer', schema: VERDICTS })
    return { chapter: d, review, verdicts: v ? v.verdicts : null }
  })

const defects = [], refuted = [], hypotheses = [], missing = []
results.forEach((r, i) => {
  const d = chapters[i]
  if (!r || !r.review) { missing.push(d); return }
  hypotheses.push(...r.review.hypotheses.map((h) => ({ chapter: d, ...h })))
  const byIndex = {}
  for (const v of r.verdicts || []) if (!(v.index in byIndex)) byIndex[v.index] = v
  r.review.defects.forEach((x, k) => {
    const v = byIndex[k]
    if (v && v.refuted) refuted.push({ chapter: d, ...x, refutation: v.reason })
    else defects.push({ chapter: d, ...x, status: v ? 'confirmed' : 'unverified' })
  })
})
const unverified = defects.filter((x) => x.status === 'unverified').length
if (missing.length) log(`no review returned for ${missing.join(' ')}: re-run those chapters`)
if (unverified) log(`${unverified} defect(s) have no verifier verdict: kept, marked unverified`)
log(`${chapters.length - missing.length}/${chapters.length} chapter(s) reviewed: ${defects.length} defect(s) kept, ` +
  `${refuted.length} refuted, ${hypotheses.length} hypothesis(es)`)

return { chapters, defects, refuted, hypotheses, missing }
