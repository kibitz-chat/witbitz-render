// M2 — the persistent async Space's "agent-as-function" turn core (docs/async-spaces-m2.md).
//
// One DECRYPT-ONCE turn: open the room's sealed ledger with mk, append the incoming message, ask the brain, append
// the reply, re-seal + store. NO live call, no held socket — this is the function the async transport invokes when a
// turn actually happens (a human present in the Space posts a message). mk MUST be set (setMemoryKey) from the
// client's active window BEFORE this runs — the server never holds it, so the ledger is unreadable at rest and the
// agent can only act while a member is present. Reuses the SAME mk-sealed ledger as the live call (putLedger/getLedger),
// so an async Space and a live call share one conversation. Bounded; compaction is a later cut.
import { getLedger, putLedger, getDoc, putDoc } from './sessionStore.mjs'
import { getRoomKey } from './roomKey.mjs'
import { honestPhotoReply } from './photoClaim.mjs' // a reply must not claim a photo that was never attached
import { getImageBlob, openImageBlob } from './imageBlob.mjs' // open a ledger photo so the agent can SEE it, not guess from the label
import { respond as brainRespond, shouldReply as brainShouldReply } from './brain.mjs'

const MAX_ENTRIES = 400 // ledger cap (keep the newest); an mk-holder compacts older history into a summary later
const CONTEXT_ENTRIES = 40 // how many recent entries to feed the brain as context
// DETERMINISTIC "you're being addressed" — a HARD guarantee the agent replies (no silence judgment) when the message
// names it, @-mentions it (@Name / @agent / @ai / @bot / @assistant). Case-insensitive; the multi-word name also matches
// its @-form with the spaces stripped ("@travelagent"). Over-matching just means it answers when maybe-addressed — the safe side.
function addressesAgent(text, agentName) {
  const t = String(text || '').toLowerCase()
  const name = String(agentName || '').trim().toLowerCase()
  if (name && (t.includes(name) || t.includes('@' + name.replace(/\s+/g, '')))) return true
  return /(^|[^a-z0-9])@(agent|ai|bot|assistant)([^a-z0-9]|$)/.test(t)
}
// Shared media (images/files) rides INLINE in the sealed ledger entry so BOTH members receive it (poll ships full
// entries) and the agent perceives it natively THIS turn. Bounded hard — the whole ledger is re-sealed every turn, so
// oversized media would bloat every write. The client resizes images well under this; a v2 moves media to sealed blobs.
const MAX_IMAGES = 4
const MAX_FILES = 2
const MAX_MEDIA_B64 = 1_500_000 // ~1.1MB decoded per IMAGE
const MAX_FILE_B64 = 5_000_000 // ~3.7MB decoded per DOCUMENT — PDFs/Word/Excel run bigger than images; the turn POSTs
// straight to API Gateway (10MB cap) and the ledger lives server-side, so a single doc of this size is well within budget
// Appended to every turn's guidance (reaches ALL Spaces, including ones whose sealed persona predates this). The map
// pins each place at its REAL location and the server drops pins that fall outside a specific requested area — so the
// model must name the area precisely and not pass off an out-of-area place as being where it isn't.
const PLACES_GUIDANCE = '\n\nWhen recommending places, discover them from REAL data rather than memory, and focus on the SPECIFIC neighbourhood/area the user named (e.g. "Sarona, Tel Aviv"), not just the town — use that as the search `area`. Prefer genuinely well-rated places for "best/top" requests, honour any constraints (budget, cuisine, open-now), and never present a place as being somewhere it isn\'t. For HOTELS/accommodation, search lodging the same way and pass show_places a `stay` object (the trip\'s checkIn/checkOut dates + adults + rooms) so each hotel gets a one-tap Booking.com "Book" link pre-filled with the dates.'

// The Space chat renders the agent's replies as Markdown (client-side, XSS-safe), so tell the model to actually USE it —
// otherwise it writes plain prose and nothing gets formatted. Section labels like "Recommendation"/"Pros"/"Cons"/"Risks"/
// "Bottom line" become highlighted callout cards on the client, so nudge toward those where they fit.
const FORMAT_GUIDANCE = '\n\nWrite your replies in Markdown so they render clearly: use `##`/`###` headings for sections (e.g. "## Day 1: Paris"), **bold** for key names, dates and prices, `-` bullet or `1.` numbered lists for options and steps, and a Markdown table for any side-by-side comparison. When you weigh choices or advise, use plainly-labelled sections — "## Recommendation", "## Pros", "## Cons", "## Risks", "## Bottom line" — which render as highlighted cards. Prefer short, skimmable structure over long paragraphs. Do NOT wrap the whole reply in a code block.'

// A shared DOCUMENT (PDF/Word/Excel/CSV/text) is NOT perceived natively — its bytes live in the sealed ledger and the
// model reads them ON DEMAND via the read_file tool (agent/readFile.mjs). This keeps a 50-page PDF from blowing the
// native page-image budget, and is the only path for Word/Excel (the model can't read OOXML bytes). Tell the model so
// it actually calls the tool instead of guessing. Reaches ALL Spaces (appended each turn), and read_file is a platform
// tool granted to every Space, so even pre-existing Spaces gain this with no re-seal.
const FILE_GUIDANCE = '\n\nWhen a participant shares a document — you will see a "[shared file: NAME]" marker in the conversation — you CANNOT see its contents until you call the read_file tool. Call read_file (pass the file `name` if several were shared) to read the document, then summarize, answer about, or quote it. Shared files stay readable in later turns too. Supported: PDF, Word (.docx), Excel (.xlsx), CSV, and text.'

// A photo only exists if show_photo actually produced one. Fixing the tool's failure message was not enough: on a
// follow-up ("show me a different image") the model sometimes does not call the tool AT ALL and simply writes "here's
// another view" — so no tool result, and therefore no instruction, ever reaches it. This rides EVERY turn, which is
// also how it reaches Spaces whose sealed persona predates it (same trick as PLACES_GUIDANCE / FILE_GUIDANCE).
// Honest about its own limits: this is guidance, not a guarantee — a model can still ignore it. It is the strongest
// lever available short of rewriting the model's text after the fact, which would be worse.
const PHOTO_GUIDANCE = '\n\nPHOTOS: the ONLY way to show one is to call show_photo, and it appears only in the turn where that call succeeds. NEVER write "here\'s a photo", "here\'s another view", "this image shows" or anything implying a picture is visible unless show_photo SUCCEEDED in THIS turn — the person sees an empty message and loses trust in everything else you say. If someone asks for a different photo of the same subject, you MUST call show_photo again with the SAME `query` and `skip` raised by one; describing another photo instead of fetching it is never acceptable. If the tool reports it found nothing, say so plainly.'

const prune = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined))
/** Validate + bound a media array to [{ b64, mime?, name? }] — drops anything malformed or over the size cap. */
const sanitizeMedia = (arr, max, capB64 = MAX_MEDIA_B64) =>
  (Array.isArray(arr) ? arr : [])
    .slice(0, max)
    .map((m) =>
      m && typeof m.b64 === 'string' && m.b64 && m.b64.length <= capB64
        ? prune({ b64: m.b64, mime: typeof m.mime === 'string' ? m.mime.slice(0, 100) : undefined, name: typeof m.name === 'string' ? m.name.slice(0, 120) : undefined })
        : null,
    )
    .filter(Boolean)

/** Render ledger entries as "name: text" for the brain context (newest CONTEXT_ENTRIES). A media entry with no text
 *  still renders a marker ("[shared 1 image]") so the agent keeps continuity across turns — the pixels themselves are
 *  fed natively only for the CURRENT turn (re-feeding every past image each turn would be prohibitively expensive). */
export function renderLedger(ledger, limit = CONTEXT_ENTRIES) {
  const has = (a) => Array.isArray(a) && a.length
  return (ledger || [])
    .filter((e) => e && ((typeof e.text === 'string' && e.text.trim()) || has(e.images) || has(e.files)))
    .slice(-limit)
    .map((e) => {
      const who = e.name || (e.self ? 'you' : 'someone')
      // Split PICTURES from DOCUMENTS. They used to share one mark that ended "call read_file to read it" — but
      // read_file extracts TEXT (PDF/Word/Excel/CSV) and can only fail on a JPEG, so a photo in the chat pointed the
      // model at a tool guaranteed not to work and it concluded it could not access the picture. A photo's `alt` is
      // also the ONLY thing in the ledger that says what it depicts, so dropping it left the model blind to its own
      // output. Detect by explicit kind OR mime, so both agent-produced photos and member-shared images are covered.
      const isPic = (f) => f && (f.kind === 'image' || /^image\//i.test(String(f.mime || '')))
      const pics = has(e.files) ? e.files.filter(isPic) : []
      const docs = has(e.files) ? e.files.filter((f) => !isPic(f)) : []
      const picMark = pics.length && `[photo${pics.length > 1 ? 's' : ''} shown: ${pics.map((f) => f.alt || f.name || 'a photo').join('; ')}]`
      const docNames = docs.length && docs.map((f) => (f && f.name) || 'file').join(', ')
      const marks = [
        has(e.images) && `[shared ${e.images.length} image${e.images.length > 1 ? 's' : ''}]`,
        picMark,
        docNames && `[shared file${docs.length > 1 ? 's' : ''}: ${docNames} — call read_file to read ${docs.length > 1 ? 'them' : 'it'}]`,
      ].filter(Boolean).join(' ')
      const body = [(e.text || '').trim(), marks].filter(Boolean).join(' ')
      return `${who}: ${body}`.trimEnd()
    })
    .join('\n')
}

// How far back to look for a picture worth perceiving. A photo mentioned twenty messages ago is context, not the
// subject; the alt text in renderLedger still carries it.
const PERCEIVE_LOOKBACK = 8

/** The most recent picture in the ledger, as perceivable media — or undefined.
 *  WHY: only the INCOMING turn's media was ever perceived, so a photo the agent itself put in the chat was invisible to
 *  it one turn later. Asked "what is in the image", it said it could not inspect the pixels and then GUESSED from the
 *  alt label — confidently describing an old-town street when the picture was a modern residential road. Being wrong
 *  in that register is worse than saying nothing. Bounded to ONE image from the recent tail so a photo-heavy room does
 *  not drag its whole history through the model on every turn. Fails soft: an unopenable blob just means no image. */
async function recentLedgerImage(room, log) {
  try {
    const mk = getRoomKey()
    for (const e of (log || []).slice(-PERCEIVE_LOOKBACK).reverse()) {
      // an inline image (member-shared) is already perceivable as-is
      const inline = Array.isArray(e && e.images) && e.images.find((i) => i && typeof i.b64 === 'string')
      if (inline) return [{ b64: inline.b64, mime: inline.mime || 'image/jpeg', name: inline.name || 'image' }]
      const pic = Array.isArray(e && e.files) && e.files.find((f) => f && f.ref && (f.kind === 'image' || /^image\//i.test(String(f.mime || ''))))
      if (pic && mk) {
        const opened = await openImageBlob(await getImageBlob(room, pic.ref), mk)
        if (opened && opened.bytes && opened.bytes.length) {
          return [{ b64: Buffer.from(opened.bytes).toString('base64'), mime: opened.mime || 'image/jpeg', name: pic.name || 'photo.jpg' }]
        }
      }
    }
  } catch { /* perception is a bonus, never a reason a turn fails */ }
  return undefined
}

/** One async turn on a persistent Space. Returns { reply, entries } (entries = ledger length after the turn).
 *  Deps are injectable for tests: `respond` (the brain), `now`, `agentName`, `persona`. A blank incoming message (no
 *  text AND no media) or a blank reply is a no-op for that half. If mk isn't set, getLedger returns null / putLedger
 *  no-ops (fail-safe: no plaintext is ever written, and the turn simply can't persist). */
export async function runAsyncTurn(room, incoming, opts = {}) {
  const { respond = brainRespond, shouldReply = brainShouldReply, now = Date.now(), agentName = 'The Comedian', persona = '', artifacts = [], producedFiles = [], challengeJti } = opts
  const from = (incoming && incoming.from) || 'someone'
  const text = String((incoming && incoming.text) || '').trim()
  const images = sanitizeMedia(incoming && incoming.images, MAX_IMAGES)
  const files = sanitizeMedia(incoming && incoming.files, MAX_FILES, MAX_FILE_B64)
  const hasMedia = images.length > 0 || files.length > 0

  const stored = await getLedger(room) // decrypt-once with mk → the array snapshot (or null when empty / no key)
  const log = Array.isArray(stored) ? stored : []
  if (!text && !hasMedia) return { reply: '', entries: log.length }

  // SINGLE-USE challenge (anti-replay): the turn op verified the challenge is authentic + fresh; here we enforce it's
  // used ONCE. The accepted entry is stamped `id: 'chal:<jti>'`, so a replay of the same (challenge, turn, signature)
  // is caught by a matching id already in the sealed ledger → rejected, ledger untouched. Freshness (the challenge
  // TTL) bounds how far back this needs to look; the ledger is bounded anyway.
  const memberId = challengeJti ? `chal:${challengeJti}` : `async:${now}`
  if (challengeJti && log.some((e) => e && e.id === memberId)) return { reply: '', entries: log.length, replayed: true }

  // Location share: a member dropped their CURRENT-location pin. Seal it into the shared `location` doc (both members'
  // location widgets poll it) and tag THIS entry with a location card so it renders for everyone. The town label is
  // reverse-geocoded UPSTREAM off the server's IP (never the member's), same privacy stance as the /maptile proxy.
  let locWidget = null
  const loc = incoming && incoming.location
  if (loc && Number.isFinite(Number(loc.lat)) && Number.isFinite(Number(loc.lng))) {
    const lat = Number(loc.lat), lng = Number(loc.lng)
    const label = (loc.label && String(loc.label).slice(0, 80)) || `${lat.toFixed(4)}, ${lng.toFixed(4)}`
    const by = loc.by ? String(loc.by).slice(0, 64) : from
    try {
      const cur = (await getDoc(room, 'location')) || { v: 0, state: { people: [] } }
      const people = (Array.isArray(cur.state && cur.state.people) ? cur.state.people : []).filter((p) => p && p.by !== by) // one live pin per member
      people.push(prune({ by, who: from, label, lat, lng, ts: now, live: loc.live ? true : undefined }))
      const summary = `A member shared their current location: ${label} (lat ${lat.toFixed(5)}, lng ${lng.toFixed(5)}). Treat this town/area as the place for "near me" suggestions.`
      await putDoc(room, 'location', { v: (cur.v || 0) + 1, state: { people }, summary, by: 'member', at: now })
      locWidget = { name: 'location', kind: 'location', title: label }
    } catch { /* a location share must never break a turn */ }
  }

  // The member's turn — text and/or shared media. Media rides in the entry so both members see it (poll ships full
  // entries) and future turns can reference it; it is ALSO perceived natively this turn (passed in ctx below).
  log.push(prune({ kind: hasMedia ? 'media' : 'text', id: memberId, ts: now, name: from, verified: incoming && incoming.verified ? true : undefined, text, images: images.length ? images : undefined, files: files.length ? files : undefined, widgets: locWidget ? [locWidget] : undefined }))
  // PUBLISH the member's message NOW — before the brain runs — so the OTHER participants see it on their next poll instead
  // of waiting for the whole turn (the agent's reply can take many seconds). The reply is stored again at the end. Best-
  // effort: if this store fails, the final putLedger below is still the source of truth.
  try { await putLedger(room, log.length > MAX_ENTRIES ? log.slice(-MAX_ENTRIES) : log) } catch { /* the final store below still lands the turn */ }
  // Read-only view of the Space's shared MCP-app widget (if any): fold its short summary into the brain context so the
  // agent can reference "the shared cart" — without being able to change it. Guarded (key is live here); no widget → no-op.
  let widgetCtx = ''
  try {
    const w = await getDoc(room, 'widget')
    if (w && typeof w.summary === 'string' && w.summary.trim()) widgetCtx = `\n[shared widget] ${w.summary.trim()}`
  } catch { /* a missing/unopenable widget doc must never break a turn */ }
  // Fold the shared location (if any) into context so "find dinner near me" resolves to the shared town.
  try {
    const l = await getDoc(room, 'location')
    if (l && typeof l.summary === 'string' && l.summary.trim()) widgetCtx += `\n[member location] ${l.summary.trim()}`
  } catch { /* missing/unopenable location doc must never break a turn */ }
  // SMART CHIME-IN: in a GROUP (2+ distinct human speakers), if the message isn't directly aimed at the agent (no name /
  // @-mention), a DEDICATED cheap gate decides whether it should reply — biased hard to silence, and ISOLATED from the
  // "be helpful" reply framing that otherwise drags it into answering people talking to each other. SILENT → post nothing
  // (the member's message was already published above). Solo Spaces / direct addresses skip the gate and always reply.
  const isGroup = new Set(log.filter((e) => e && !e.self && e.name).map((e) => String(e.name).toLowerCase())).size >= 2
  if (isGroup && !addressesAgent(text, agentName)) {
    let speak = true
    try { speak = await shouldReply({ agentName, context: renderLedger(log), request: text, speaker: from }) } catch { speak = true }
    if (!speak) { const b = log.length > MAX_ENTRIES ? log.slice(-MAX_ENTRIES) : log; return { reply: '', entries: b.length, silent: true } }
  }
  const rawReply = String(
    (await respond({
      kind: 'reply',
      longform: true, // an async Space is a TEXT chat, not a spoken turn → allow a full multi-paragraph answer (not the 320-char voice clip)
      request: text || (files.length ? `I shared a document (${files.map((f) => f.name || 'file').join(', ')}). Read it with read_file and give me a short summary.` : 'Take a look at what I just shared.'), // media-only turn → a nudge so the model engages the file/pixels
      speaker: from,
      context: renderLedger(log) + widgetCtx,
      guidance: persona + PLACES_GUIDANCE + PHOTO_GUIDANCE + FORMAT_GUIDANCE + (files.length ? FILE_GUIDANCE : ''),
      images: images.length ? images : await recentLedgerImage(room, log), // perceived natively (brainTools → image_url / input_image)
      // NOTE: shared FILES (documents) are deliberately NOT sent natively — the model reads them via read_file (see
      // FILE_GUIDANCE). They're still stored in the ledger entry above so read_file can reach them now and later.
    })) || '',
  ).trim()
  // ★ A reply must not claim a photo that was never attached. `producedFiles` is filled by the room's tool executor
  // DURING respond() above, so by here we know exactly what this turn really showed. PHOTO_GUIDANCE asks the model not
  // to do this; observed live, it sometimes does anyway — so this is the deterministic backstop it cannot ignore.
  // Only ASSERTIONS are removed; offers ("I can show you one") are true and stay.
  const reply = honestPhotoReply(rawReply, producedFiles)
  // Tag the reply with any widgets this turn produced (show_places/add_place) → the client renders a live card per
  // widget-bearing message. `artifacts` is populated by the room's tool executor DURING respond() above.
  const hasProduced = Array.isArray(producedFiles) && producedFiles.length
  if (reply || hasProduced) log.push(prune({ kind: 'text', id: `async:${now}:r`, ts: now + 1, name: agentName, text: reply || (hasProduced ? `📄 ${producedFiles.map((f) => f.name).join(', ')}` : ''), self: true, widgets: Array.isArray(artifacts) && artifacts.length ? artifacts.slice() : undefined, files: hasProduced ? producedFiles.slice() : undefined }))

  const bounded = log.length > MAX_ENTRIES ? log.slice(-MAX_ENTRIES) : log
  await putLedger(room, bounded)
  return { reply, entries: bounded.length }
}
