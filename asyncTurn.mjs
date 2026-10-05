// M2 — the persistent async Space's "agent-as-function" turn core (docs/async-spaces-m2.md).
//
// One DECRYPT-ONCE turn: open the room's sealed ledger with mk, append the incoming message, ask the brain, append
// the reply, re-seal + store. NO live call, no held socket — this is the function the async transport invokes when a
// turn actually happens (a human present in the Space posts a message). mk MUST be set (setMemoryKey) from the
// client's active window BEFORE this runs — the server never holds it, so the ledger is unreadable at rest and the
// agent can only act while a member is present. Reuses the SAME mk-sealed ledger as the live call (putLedger/getLedger),
// so an async Space and a live call share one conversation. Bounded; compaction is a later cut.
import { runWithTurnUsage, turnUsageRecord } from './turnUsage.mjs' // the reply's sealed usage record (docs/tenant-billing.md § 8.1)
import { runWithTurnEvidence, envStampSigner, certifyReply } from './turnCert.mjs' // the reply's signed TURN CERTIFICATE in an enclave (docs/turn-certificates.md)
import { logRoom } from './logRoom.mjs' // a log names a room by a hash, never the id (the log privacy audit)
import { createHash } from 'node:crypto'
import { fileId } from './readFile.mjs' // a shared file's stable id, shown in context beside its name
import { getLedger, readLedgerDefinitive, putLedger, appendLedger, rewriteLedgerEntries, getDoc, putDoc, putPartial, putStopSig, getStopSig, ledgerV3WriteEnabled, claimTurnId } from './sessionStore.mjs'
import { getRoomKey } from './roomKey.mjs'
import { storeAttachments, migrateInlineAttachments, openAttachment, isStored } from './attachmentBlobs.mjs' // member attachments live OUT OF LINE (a pointer in the entry, sealed bytes in a blob)
import { seal as sealEnvelope } from './envelope.mjs' // the in-progress reply is sealed like everything else — the store never sees plaintext
import { roomStreamPublisher } from './roomStream.mjs' // ROOM STREAMS (prototype): what this turn writes, pushed to the room's stream channel
import { honestPhotoReply } from './photoClaim.mjs' // a reply must not claim a photo that was never attached
import { getImageBlob, openImageBlob } from './imageBlob.mjs' // open a ledger photo so the agent can SEE it, not guess from the label
import { imageCost } from './imageTokens.mjs' // per-turn image count + estimated vision tokens (cost visibility on image-heavy Spaces)
import { respond as brainRespond, shouldReply as brainShouldReply, summarizeHistory as brainSummarize, describeImage as brainDescribeImage, COULD_NOT_FINISH } from './brain.mjs'

// The entry kinds a member's OWN TURN writes (see the `log.push` in runAsyncTurn) — and therefore the only kinds that
// count as a person SPEAKING when the chime-in gate asks whether a room is a group. An allowlist on purpose: a new
// entry kind that carries a name is NOT a speaker until it is named here. agent/speakerAllowlist.test.mjs.
const SPEAKER_KINDS = new Set(['text', 'media', 'mcp'])

// Mark every entry so far as belonging to a COMPLETED turn. Best-effort: a failed marker costs a peer a
// stale indicator until its safety timeout, never a lost message — so it must never throw into the turn.
// `memberEntry` is the turn's own member message (already early-published); `reseal` = its describe-once caption
// arrived after that publish, so the stored box is rewritten IN PLACE by id (rewriteLedgerEntries keeps every box a
// concurrent writer appended meanwhile — a whole-ledger reseal from this turn's log would have dropped them).
async function resolved(room, memberEntry, reseal) {
  try {
    if (reseal && memberEntry && memberEntry.id != null) await rewriteLedgerEntries(room, (e) => (e && e.id != null && String(e.id) === String(memberEntry.id)) ? memberEntry : null)
    await appendLedger(room, [], { done: 'all' }) // everything stored so far has been through a completed turn
  } catch { /* the indicator falls back to its timeout */ }
}

const MAX_ENTRIES = 400 // ledger cap (keep the newest); an mk-holder compacts older history into a summary later
const CONTEXT_ENTRIES = 40 // how many recent entries to feed the brain as context
const OUT_OF_TIME_NOTE = 'I ran out of time on that one and stopped here. Ask again for a smaller piece and I will pick it up.' // the turn-budget note (asyncTurn TURN BUDGET)
// DETERMINISTIC "you're being addressed" — a HARD guarantee the agent replies (no silence judgment) when the message
// names it, @-mentions it (@Name / @agent / @ai / @bot / @assistant). Case-insensitive; the multi-word name also matches
// its @-form with the spaces stripped ("@travelagent"). Over-matching just means it answers when maybe-addressed — the safe side.
// Does the message speak TO the agent, or merely ABOUT it? (agent/addressedNotMentioned.test.mjs, 2026-09-27.) The
// predicate lives in agent/addressed.mjs — byte-equal with spaces/public/addressed.js, which the PAGE uses to predict
// this gate's answer (no "thinking…" bubble on a message the server will post silently). Two copies, one test holds
// them equal (agent/addressedVectors.test.mjs). This file is the enforcer; the page is a prediction.
import { addressesAgent } from './addressed.mjs'
import { pendingProposals } from './delegatedAuthority.mjs' // a turn that proposed but said nothing names what is waiting

/** "I've suggested X — it's waiting for your approval." for the actions a turn proposed without a word about them. */
export function proposalNote(actions) {
  const label = (a) => (a && a.type === 'connection_call' ? `${String(a.method || 'GET').toUpperCase()} ${a.path || ''}`.trim() : String((a && a.type) || 'an action').replace(/_/g, ' '))
  const names = [...new Set((actions || []).map(label))]
  const list = names.length <= 1 ? (names[0] || 'an action') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
  return `I've suggested ${list} — it's waiting for your approval.`
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
const FORMAT_GUIDANCE = '\n\nWrite your replies in Markdown so they render clearly: use `##`/`###` headings for sections (e.g. "## Day 1: Paris"), **bold** for key names, dates and prices, `-` bullet or `1.` numbered lists for options and steps, and a Markdown table for any side-by-side comparison. When you weigh choices or advise, use plainly-labelled sections — "## Recommendation", "## Pros", "## Cons", "## Risks", "## Bottom line" — which render as highlighted cards. Prefer short, skimmable structure over long paragraphs. Do NOT wrap the whole reply in a code block. MATH: write every formula and equation as LaTeX — inline `$…$` (e.g. $E=mc^2$) and display `$$…$$` on its own line (e.g. $$x = \\frac{-b \\pm \\sqrt{b^2-4ac}}{2a}$$); the chat renders it properly. Never Unicode superscripts, ASCII sqrt, or code blocks for math. LINK PLACES INLINE: whenever you name a specific place in prose — a restaurant, café, hotel, sight — make the NAME itself an inline Markdown link (a hotel → its Booking.com search; anything else → Google Maps), e.g. [Ramen Hayashida Shinjuku](https://www.google.com/maps/search/?api=1&query=Ramen+Hayashida+Shinjuku+Tokyo). Do this EVERY time you write a place name, INCLUDING the heading/bold name of each item in a list — and do it EVEN WHEN you also put the place on the shared map: the map pin and the underlined name-link are complementary, so do both (never drop the inline link just because it is on the map). The app renders [Name](url) as a clean tappable chip with the site\'s icon. NEVER paste a raw URL as the visible text, and NEVER add a separate table COLUMN of links — put the link on the name where you mention it.'

// A shared DOCUMENT (PDF/Word/Excel/CSV/text) is NOT perceived natively — its bytes live in the sealed ledger and the
// model reads them ON DEMAND via the read_file tool (agent/readFile.mjs). This keeps a 50-page PDF from blowing the
// native page-image budget, and is the only path for Word/Excel (the model can't read OOXML bytes). Tell the model so
// it actually calls the tool instead of guessing. Reaches ALL Spaces (appended each turn), and read_file is a platform
// tool granted to every Space, so even pre-existing Spaces gain this with no re-seal.
// ⚑ INJECTED ONLY WHILE A LANE IS LINKED — never sealed into a persona.
//
// A private lane is linked and unlinked at will, and on THIS DEVICE only, so the agent's role changes without its
// room changing. A sealed persona cannot express that: it is fixed at genesis, so an existing assistant room can
// never be told it has become a lane, and a lane that gets unlinked can never be told it stopped being one.
//
// So the role arrives as guidance, the same way PLACES/PHOTO/FILE guidance does — present exactly while the turn
// carries a bridge, gone the moment it does not. That also fixes it for rooms that already exist: nothing has to be
// re-created, and unlinking silently restores ordinary assistant behaviour.
//
// What it is actually correcting: without it the agent writes a helpful reply full of "you could say…" options, and
// the member forwards the WHOLE thing, so the other party reads the coaching. The split below is the point — coach
// freely here, and put ONLY the message in the crossing.
const LANE_GUIDANCE = '\n\nYOU ARE A PRIVATE ASSISTANT IN A LINKED LANE. Your member is also in a SEPARATE SHARED room with other people. '
  + 'Everything you write here is seen by YOUR MEMBER ALONE — the other party never sees it. Messages labelled "from the shared room" are what the other party actually said.\n'
  + 'To send something to the other party you MUST call the cross_to_shared tool. Nothing you write in your reply ever reaches them, no matter how it is phrased or labelled.\n'
  + 'The `text` you pass to cross_to_shared IS the message they will read, word for word. Put ONLY that message in it: no options, no "you could say", no explanation of your reasoning, no notes to your member, no headings introducing the draft. Write it as your member would send it.\n'
  + 'In your reply here, coach freely — explain what the other party meant, weigh choices, suggest alternatives, say what you would send and why. That is what this lane is for. Keep it OUT of the crossing.\n'
  + 'If the member has not asked you to send anything yet, do not call the tool; just help them think.\n'
  + 'ONE EXCEPTION, and it is explicit: a message containing the ✍️ marker IS the ask. The member tapped "Draft" in '
  + 'their lane, which means "turn this into a message for the shared room". Call cross_to_shared for it — do not '
  + 'reply asking whether they want it sent. Anything they wrote alongside the marker is their steer on what it '
  + 'should say; if there is nothing beside the marker, draft from the shared conversation so far.\n'
  + 'REVISING A DRAFT: if the member asks you to change one you already proposed — shorter, warmer, firmer, drop a '
  + 'detail — call cross_to_shared AGAIN with the full revised message. Do not merely describe the change or ask '
  + 'whether they want it re-proposed: they already asked. The revision replaces the previous draft.\n'
  + 'FORMATTING STILL APPLIES: your private reply is Markdown too. Follow the formatting rules above in full — in '
  + 'particular, whenever you name a specific place (a sight, restaurant, café, hotel), make the NAME itself an inline '
  + 'Markdown link (hotel → Booking.com search; anything else → Google Maps), EVERY time, exactly as you would in the '
  + 'shared room. Coaching your member privately is no reason to drop the underlined place-links — they help them here just as much.'

const FILE_GUIDANCE = '\n\nWhen a participant shares a document — you will see a "[shared file: NAME]" marker in the conversation — you CANNOT see its contents until you call the read_file tool. Call read_file (pass the file `name` if several were shared) to read the document, then summarize, answer about, or quote it. Shared files stay readable in later turns too. Supported: PDF, Word (.docx), Excel (.xlsx), CSV, and text.'

// Two halves, and for a long time only the second existed.
//
// WHEN TO SHOW: the whole out-of-line image path — thumb in the ledger, sealed blob fetched once — was built so rooms
// would be full of pictures, and then the agent almost never produced one unless asked. The reason was here: this
// string was ALL guardrail. Every clause said "do not claim a photo you did not fetch", none said "here is when to
// fetch one", and its only emotional weight was the downside of getting it wrong — which reads to a careful model as
// a reason to avoid the tool. Compare the map guidance, which is prescriptive ("to recommend or change places you
// MUST call the tools in the same turn") and fires reliably. Same structure, applied to photos.
//
// NOT TO CLAIM: the original half. On a follow-up ("show me a different image") the model sometimes does not call the
// tool AT ALL and simply writes "here's another view" — so no tool result, and therefore no instruction, ever reaches
// it. This rides EVERY turn, which is also how it reaches Spaces whose sealed persona predates it (same trick as
// PLACES_GUIDANCE / FILE_GUIDANCE).
//
// Honest about its own limits: this is guidance, not a guarantee — a model can still ignore it, in either direction.
// It is the strongest lever available short of rewriting the model's text after the fact, which would be worse.
const PHOTO_GUIDANCE = '\n\nPHOTOS — SHOW THEM. Whenever you name something a person would want to SEE — a dish, a landmark, a building or monument, a hotel, a restaurant, a neighbourhood, a viewpoint, a city or a country, a natural feature (a mountain, a river, a coastline), an animal or a plant, a work of art, a historical figure or artifact, an invention, a vehicle, a product, any object with a recognisable look — call show_photo for it IN THAT TURN, passing kind:"thing" for anything that is not somewhere on a map. This is NOT only for places or trips: it applies just as much to INFORMATIONAL and encyclopedic answers — an overview of a country, a slice of history, a "tell me about X", a "what is Y" — where you should show what the things you mention look like. A picture is usually what makes an answer land, and an all-text explainer of a visual subject is exactly the boring wall of text to avoid. If someone asks what a cuisine includes, show the dishes. Do not wait to be asked, and do not offer ("would you like a photo?") — just show it. One photo per SUBJECT, not one per reply: if your answer names several — four Italian dishes, three landmarks, two hotels, the Great Wall and the Forbidden City — show each of them; the chat lays them out as a strip you swipe. Never stack several photos of the SAME thing, and never pad a reply with images that add nothing. Skip photos only when the turn is genuinely about logistics rather than a subject you can picture — prices, dates, bookings, availability, directions, a step-by-step how-to; an overview or an explainer is NOT logistics, so never treat "this is just explaining something" as a reason to go all-text. PHOTOS — NEVER CLAIM ONE: the ONLY way to show one is to call show_photo, and it appears only in the turn where that call succeeds. NEVER write "here\'s a photo", "here\'s another view", "this image shows" or anything implying a picture is visible unless show_photo SUCCEEDED in THIS turn — the person sees an empty message and loses trust in everything else you say. If someone asks for a different photo of the same subject, you MUST call show_photo again with the SAME `query` and `skip` raised by one; describing another photo instead of fetching it is never acceptable. If the tool reports it found nothing, say so plainly.'

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

// THE MODEL HAS NO CLOCK. A turn is a cold read of exactly the tokens sent in, fresh every time — nothing carries
// over between calls except what is in this text. Without a grounded "now" among those tokens, "what date is it"
// has no answer the model can reason its way to; the one date-shaped string it can find (an itinerary line written
// weeks earlier) is not a clock, and reading it as one is a stale-plan guess wearing the shape of an answer.
// agent/renderLedgerNow.test.mjs — including the real-model probe that found and confirmed this.
//
// Every ledger entry already carries a server-stamped `ts` (spaceTransport.mjs: always Date.now() on the Lambda's
// own clock, never client-supplied) and it was already permanent — the ledger keeps it whether or not anything
// renders it. So this adds NO new stored fact. It is rendered in UTC, deliberately: a bare instant carries no
// location (unlike a timezone would — that IS worth keeping out of a permanent, sealed, shared record), and UTC
// lets the model do the same offset arithmetic a person reading a phone clock would, off a real anchor instead of
// a plan someone wrote weeks ago. Minute precision — enough to answer "what date/time is it", no more.
const utcStamp = (ts) => {
  if (!Number.isFinite(ts)) return '' // a synthetic/legacy entry with no known time makes no claim about one — same rule as an undefined speaker kind
  const d = new Date(ts)
  const p2 = (n) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())} UTC`
}

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
      const docNames = docs.length && docs.map((f) => `${(f && f.name) || 'file'} (id ${fileId(e.id, e.files.indexOf(f))})`).join(', ') // the id is what read_file resolves by — a name like pasted.md can belong to several files
      // A member photo carries a one-time TEXT description (brain.describeImage, stored on upload) so it stays in
      // context after it scrolls out of the native-perception window — the pixels are gone but what it showed isn't.
      const imgDescs = has(e.images) ? e.images.map((i) => i && typeof i.desc === 'string' && i.desc.trim()).filter(Boolean).join('; ') : ''
      const marks = [
        has(e.images) && `[shared ${e.images.length} image${e.images.length > 1 ? 's' : ''}${imgDescs ? ': ' + imgDescs : ''}]`,
        picMark,
        docNames && `[shared file${docs.length > 1 ? 's' : ''}: ${docNames} — call read_file with the id to read ${docs.length > 1 ? 'one' : 'it'}]`,
      ].filter(Boolean).join(' ')
      // A REPLY IS CONTEXT, a reaction is not. "yes, book it" answering a three-day-old ticket message is unreadable
      // without knowing what it answers, so the quote goes to the model. Reactions are deliberately absent: they live
      // on the entry as a `reactions` map this renderer never reads, so a room full of 👍 costs the prompt nothing.
      const quoted = e.replyTo && e.replyTo.excerpt
        ? `[replying to ${e.replyTo.name || 'an earlier message'}: "${e.replyTo.excerpt}"] `
        : ''
      const body = quoted + [(e.text || '').trim(), marks].filter(Boolean).join(' ')
      const when = utcStamp(e.ts)
      return `${who}: ${body}${when ? ` [${when}]` : ''}`.trimEnd()
    })
    .join('\n')
}

// ── BULK COMPACTION (flag: SPACE_COMPACTION=1) ────────────────────────────────────────────────────────────────────
// Build the model CONTEXT from the ledger. OFF ⇒ the historical behaviour (renderLedger's last-CONTEXT_ENTRIES window;
// note renderLedger(forModel(log)) == renderLedger(log) since CONTEXT_ENTRIES < MAX_ENTRIES). ON ⇒ a stored, sealed
// RUNNING SUMMARY of the oldest messages + a GROWING verbatim window of the recent ones. The window only trims in BULK
// — the oldest COMPACT_CHUNK entries at a time, once it exceeds COMPACT_HIGH — so the prompt PREFIX stays byte-stable
// across turns and OpenAI's prefix cache keeps hitting, instead of the old sliding window that shifted every turn and
// re-billed the whole context uncached. Measured 29% → ~96% cache on a real 149-msg Space. (See agent/llmLog usageTotals.)
const COMPACT_ON = () => process.env.SPACE_COMPACTION === '1'
const COMPACT_HIGH = Number(process.env.SPACE_COMPACT_HIGH || 60)   // TRIGGER: only START folding once the window exceeds this
const COMPACT_LOW = Number(process.env.SPACE_COMPACT_LOW || 30)     // TARGET: once triggered, drain the window down to THIS (hysteresis)
const COMPACT_CHUNK = Number(process.env.SPACE_COMPACT_CHUNK || 30) // fold at most this-many entries per summarize call
export async function compactedContext(room, log, { getDoc: gd = getDoc, putDoc: pd = putDoc, summarize = brainSummarize } = {}) {
  if (!COMPACT_ON()) return renderLedger(log)
  let doc = null
  try { doc = await gd(room, 'summary') } catch { /* no key/store → behave like the window below */ }
  let cursor = Math.min(Math.max(0, (doc && doc.cursor) | 0), log.length)
  let text = (doc && typeof doc.text === 'string') ? doc.text : ''
  let changed = false
  // HYSTERESIS (HIGH triggers, LOW is the target). Only START folding once the window exceeds HIGH — but then drain it
  // all the way down to LOW, not merely to just-under-HIGH. Without the LOW floor a catch-up that lands the window at
  // HIGH-1 re-folds on the very NEXT message, rewriting the summary (a prompt-prefix change) and busting the prompt
  // cache two turns running. Draining to LOW leaves ~(HIGH-LOW) turns of runway before the next fold, so folds are rare
  // and the prefix stays byte-stable in between. `take` is clamped so the last (partial) chunk never folds below LOW.
  if (log.length - cursor > COMPACT_HIGH) {
    while (log.length - cursor > COMPACT_LOW) {
      const take = Math.min(COMPACT_CHUNK, log.length - cursor - COMPACT_LOW)
      const piece = await summarize(renderLedger(log.slice(cursor, cursor + take), take))
      if (!piece) break // summariser failed → keep the raw window this turn (fail-safe: no data loss, just no compaction)
      text = text ? text + '\n' + piece : piece
      cursor += take
      changed = true
    }
  }
  if (changed) { try { await pd(room, 'summary', { cursor, text }) } catch { /* best-effort; retried next turn */ } }
  const recent = renderLedger(log.slice(cursor), COMPACT_HIGH)
  return text ? `[EARLIER — running summary of the first ${cursor} messages]\n${text}\n\n[RECENT MESSAGES]\n${recent}` : recent
}

// WHAT THE AGENT SEES OF A SHARED VIEW. This used to be the doc's `summary`, which is a one-line UI label capped at
// 400 characters — fine for a list row, wrong as model context. Measured: a 14-day plan serialises to ~1600 chars, so
// the agent received 5 days of 14, cut mid-sentence, and could neither reason about the rest nor notice a member
// editing day 9. Render from the STATE instead, and give it a real budget.
const widgetForAgent = (w) => {
  const st = w && w.state
  if (st && Array.isArray(st.days) && st.days.length) {
    const head = st.title ? String(st.title) + '\n' : ''
    return (head + st.days.map((d) => `${(d && d.name) || 'Day'}: ${((d && d.items) || []).map((i) => `${i && i.when ? i.when + ' — ' : ''}${(i && i.text) || ''}`).filter(Boolean).join('; ')}`).join('\n')).slice(0, 3500)
  }
  if (st && Array.isArray(st.places) && st.places.length) {
    // names + the rating it actually chose on + who shortlisted what — the parts a follow-up question is about
    return st.places.map((p) => `${(p && p.name) || 'place'}${p && Number.isFinite(p.rating) ? ` ★${p.rating}` : ''}${p && p.chosen ? ' (shortlisted)' : ''}`).join(', ').slice(0, 1200)
  }
  return w && typeof w.summary === 'string' ? w.summary.trim() : ''
}

// ── SHARED-WIDGET CONTEXT ─────────────────────────────────────────────────────────────────────────────────────────
// The itinerary/map/places cards a turn needs are NOT in the conversation ledger — their live state lives in separate
// sealed docs. This assembles the agent's view of them, and it is DELIBERATELY independent of compactedContext: the
// names are read from the FULL `log` (not the recency window) and each widget's CURRENT state is fetched fresh via
// getDoc, so trimming/compacting the conversation can never drop a widget the room still holds. The itinerary is a
// singleton and the thing most often discussed, so it is pinned in even past the last-few window — a room with four
// maps must not cost the agent the plan. Exported + dependency-injected (getDoc) so the invariant is unit-testable.
export async function widgetContext(room, log, { getDoc: gd = getDoc } = {}) {
  let widgetCtx = ''
  try {
    const names = []
    for (const e of log) for (const w of (Array.isArray(e && e.widgets) ? e.widgets : [])) {
      const n = w && w.name
      if (typeof n === 'string' && n && !names.includes(n)) names.push(n)
    }
    if (!names.length) names.push('widget') // legacy rooms whose widgets predate recordWidget
    // The ITINERARY is a singleton and the thing most often being discussed, so it is never allowed to fall out of the
    // recency window — a room with four maps must not cost the agent the plan.
    const keep = names.slice(-4)
    if (names.includes('itinerary') && !keep.includes('itinerary')) keep.push('itinerary')
    let budget = 6000
    for (const n of keep) {
      const w = await gd(room, n)
      const text = widgetForAgent(w)
      if (!text) continue
      const line = `\n[shared widget: ${n}] ${text}`
      if (line.length > budget) { widgetCtx += line.slice(0, Math.max(0, budget)); budget = 0; break }
      widgetCtx += line; budget -= line.length
    }
  } catch { /* a missing/unopenable widget doc must never break a turn */ }
  // A PRIVATE LANE cannot see the shared room's views. Its widget docs live in the OTHER room, sealed under a key this
  // turn does not hold, and the mirror carries only text/files/images — so a lane agent asked about the itinerary had
  // never been told one exists. The device (which holds BOTH keys, and is already what joins the two rooms) writes a
  // rendering into the LANE as its own sealed doc; this folds that in. Same shape as the location doc below.
  try {
    const sv = await gd(room, 'sharedviews')
    // state.text first: `summary` is capped at 400 bytes by op:'state', so reading it truncated the plan mid-day-2.
    // The fallback keeps working for copies written before this moved.
    const text = String((sv && sv.state && sv.state.text) || (sv && sv.summary) || '').trim()
    if (text) widgetCtx += `\n[the shared room's views] ${text.slice(0, 12000)}`
  } catch { /* missing/unopenable must never break a turn */ }
  // Fold the shared location (if any) into context so "find dinner near me" resolves to the shared town.
  try {
    const l = await gd(room, 'location')
    if (l && typeof l.summary === 'string' && l.summary.trim()) widgetCtx += `\n[member location] ${l.summary.trim()}`
  } catch { /* missing/unopenable location doc must never break a turn */ }
  return widgetCtx
}

// How far back to look for a picture worth perceiving. A photo mentioned twenty messages ago is context, not the
// subject; the alt text in renderLedger still carries it.
const PERCEIVE_LOOKBACK = 8

/** The most recent MEMBER-shared picture in the ledger, as perceivable media — or undefined.
 *  WHY: a member's photo must stay perceivable a few turns after they send it ("what's in that photo you shared?").
 *  MEMBER-ONLY: agent-produced photos (self) are the room's own show_photo/show_places STOCK images — the agent
 *  fetched them and already has their name/alt, so re-feeding those pixels every turn is ~1–1.4k vision tokens of pure
 *  waste AND a prompt-cache break (the perceived image changes as new places are shown). Measured on a real Space: 27
 *  of 30 stored images were agent stock photos. So skip `self` entries; only a MEMBER photo is worth the pixels here.
 *  Older member photos are carried as TEXT instead (brain.describeImage → the image's `desc`, surfaced by renderLedger).
 *  Bounded to ONE image from the recent tail. Fails soft: an unopenable blob just means no image. */
export async function recentLedgerImage(room, log, { getImageBlob: gib = getImageBlob, openImageBlob: oib = openImageBlob, getRoomKey: grk = getRoomKey } = {}) {
  try {
    const mk = grk()
    for (const e of (log || []).slice(-PERCEIVE_LOOKBACK).reverse()) {
      if (e && e.self) continue // agent-produced stock photo — the alt/name carries it; don't pay to re-perceive pixels
      // an inline image (member-shared) is already perceivable as-is
      const inline = Array.isArray(e && e.images) && e.images.find((i) => i && typeof i.b64 === 'string')
      if (inline) return [{ b64: inline.b64, mime: inline.mime || 'image/jpeg', name: inline.name || 'image' }]
      // a member photo stored OUT OF LINE (attachmentBlobs) — the entry holds a pointer; open the blob
      const storedPic = Array.isArray(e && e.images) && e.images.find((i) => isStored(i))
      if (storedPic && mk) {
        const o = await openAttachment(room, mk, storedPic, { get: gib, open: oib })
        if (o && o.b64) return [{ b64: o.b64, mime: o.mime || 'image/jpeg', name: o.name || 'image' }]
      }
      const pic = Array.isArray(e && e.files) && e.files.find((f) => f && f.ref && (f.kind === 'image' || /^image\//i.test(String(f.mime || ''))))
      if (pic && mk) {
        const opened = await oib(await gib(room, pic.ref), mk)
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
// Every turn runs inside a usage collector (turnUsage.mjs): what its model calls used rides in the AI reply, sealed.
export function runAsyncTurn(room, incoming, opts = {}) { return runWithTurnUsage(() => runWithTurnEvidence(() => runAsyncTurnInner(room, incoming, opts))) }
async function runAsyncTurnInner(room, incoming, opts = {}) {
  const { respond = brainRespond, shouldReply = brainShouldReply, describeImage = brainDescribeImage, now = Date.now(), agentName = 'Assistant', persona = '', artifacts = [], producedFiles = [], producedSources = [], challengeJti, bridgeContext = '', turnInstructions = '', bridged = false, agentReplies = true, mode = 'auto', stopKey = '', participants = null, turnBudgetMs = null } = opts // config-less fallback = the generic Assistant, NOT a random 'Comedian' (an M1 leftover) — a room whose config didn't reach the turn (e.g. the enclave-tier config-seal gap) degrades sensibly. `stopKey` = the prompter's per-turn cancel nonce (see STOP below)
  const stream = opts.roomStream ? roomStreamPublisher({ mk: getRoomKey(), gate: opts.roomStream === true ? null : opts.roomStream }) : null // off unless SPACE_STREAM_URL is set; a gated room passes { room, gen } and streams behind a grant
  const from = (incoming && incoming.from) || 'someone'
  let text = String((incoming && incoming.text) || '').trim()
  const images = sanitizeMedia(incoming && incoming.images, MAX_IMAGES)
  const files = sanitizeMedia(incoming && incoming.files, MAX_FILES, MAX_FILE_B64)
  const hasMedia = images.length > 0 || files.length > 0
  // App→agent MCP CALL (parsed + whitelisted in spaceHandler): a declared skill the embedded app invoked over the bridge,
  // NOT a chat message. Stored as a `kind:'mcp'` ledger entry the MODEL sees + acts on this turn (renderLedger surfaces
  // it; request below directs it), but the chat UI + embed events never render it. Sealed + exportable like any entry.
  // REPLY — the message this one answers (docs: message actions). The excerpt is stored WITH the entry rather than
  // looked up at render, so a quote still shows when the original has scrolled out of the loaded window or off the
  // MAX_ENTRIES cap. That is a deliberate copy, and therefore bounded: an unbounded excerpt would let a client grow
  // the ledger without limit by quoting itself. `key` is the target's entryKey — opaque here, matched by the client.
  const replyTo = (incoming && incoming.replyTo && typeof incoming.replyTo === 'object' && incoming.replyTo.key)
    ? prune({
      key: String(incoming.replyTo.key).slice(0, 200),
      name: String(incoming.replyTo.name || '').trim().slice(0, 80) || undefined,
      excerpt: String(incoming.replyTo.excerpt || '').replace(/\s+/g, ' ').trim().slice(0, 120) || undefined,
    })
    : undefined
  const mcp = (incoming && incoming.mcp && typeof incoming.mcp === 'object' && incoming.mcp.name)
    ? { name: String(incoming.mcp.name).slice(0, 64), args: (incoming.mcp.args && typeof incoming.mcp.args === 'object') ? incoming.mcp.args : {} }
    : null
  // A validated MCP call carries a compact, HUMAN-READABLE chip label as its text — so it renders transparently (as a
  // tool chip, never hidden), reaches the model as context, and needs no special-case to survive the empty-turn guard.
  if (mcp && !text) {
    const summary = Object.values(mcp.args || {}).map((v) => (typeof v === 'string' ? `"${v}"` : (() => { try { return JSON.stringify(v) } catch { return '' } })())).filter(Boolean).join(', ').slice(0, 100)
    text = `⚙ ${mcp.name}${summary ? ' · ' + summary : ''}`
  }

  // ⚠ DEFINITIVE READ, then append. The old line took `getLedger`'s null — which means empty OR no-key OR decrypt
  // failure OR any throw — as `[]`, appended this turn, and wrote it back as the WHOLE ledger. One failed read
  // therefore replaced a room's history with a single turn (observed live: 10 entries → 4). Refuse instead: a
  // failed turn is recoverable, a clobbered ledger is not.
  const read = await readLedgerDefinitive(room)
  // FAIL-CLOSED ONLY WHERE IT IS SAFE. Throwing on every non-ok read took EVERY turn down in normal Spaces — the
  // guard is worth having, an outage is not: a room that cannot answer at all is worse than one that occasionally
  // loses an entry. So refuse only where we KNOW a ledger exists to protect (a decrypt failure means stored bytes
  // we could not open); for anything else, log loudly with the underlying error and proceed as before.
  // WIDENED once "absent" became distinguishable. Until s3:ListBucket was granted, S3 answered a GetObject on a
  // MISSING key with AccessDenied rather than NoSuchKey, so read_failed fired on every new room and refusing on it
  // took every turn down. With the IAM fix in place, absent classifies as ok/empty and read_failed means a genuine
  // failure — so refusing on it is now safe, and it is what actually closes the truncation.
  // `no_store` stays permissive on purpose: persistence is off, putLedger no-ops, there is nothing to lose.
  if (!read.ok && read.reason !== 'no_store') { const e = new Error('ledger unreadable (' + read.reason + (read.err ? ' · ' + read.err : '') + ') — refusing to write over it'); e.code = 'ledger_unreadable'; throw e }
  const log = read.ok ? read.entries : []
  // v3 decouples what we STORE from what the MODEL sees: the STORED ledger is FULL + append-only (never front-trimmed —
  // its box indices must stay stable for sinceCount polls), while the model still gets only the last-MAX_ENTRIES window
  // (cost / context bound). For v2 both are the same trimmed array, so `forStore` is behaviour-neutral off the flag.
  const forStore = (l) => (ledgerV3WriteEnabled() ? l : (l.length > MAX_ENTRIES ? l.slice(-MAX_ENTRIES) : l))
  const forModel = (l) => (l.length > MAX_ENTRIES ? l.slice(-MAX_ENTRIES) : l)
  if (!text && !hasMedia) return { reply: '', entries: log.length }

  // SINGLE-USE challenge (anti-replay): the turn op verified the challenge is authentic + fresh; here we enforce it's
  // used ONCE. The accepted entry is stamped `id: 'chal:<jti>'`, so a replay of the same (challenge, turn, signature)
  // is caught by a matching id already in the sealed ledger → rejected, ledger untouched. Freshness (the challenge
  // TTL) bounds how far back this needs to look; the ledger is bounded anyway.
  // A signed (attributed) turn gets a STABLE id derived from its signature, so a replay of the identical signed turn is
  // deduped against the sealed ledger — not only when requireChallenge is on. Two genuinely-different messages differ in
  // ts/id → different sig → different key, so this never merges distinct turns. Open/unsigned turns keep async:<now>
  // (no identity to dedup on, and open mode admits any mk-holder anyway).
  const replayKey = challengeJti ? `chal:${challengeJti}` : (incoming && incoming.sig ? `sig:${createHash('sha256').update(String(incoming.sig)).digest('base64url').slice(0, 22)}` : null)
  const memberId = replayKey || `async:${now}`
  if (replayKey && log.some((e) => e && e.id === memberId)) return { reply: '', entries: log.length, replayed: true }
  // ★ AND CLAIM IT before anything runs (the independent review, 2026-10-05): the check above reads a snapshot, so two
  // copies of one signed message sent together both passed it and both ran the model. The claim is a compare-and-set on
  // the room's sealed claims doc — one copy wins, the other is a replay. A store that cannot answer refuses the turn:
  // running it unclaimed is exactly the duplicate this exists to stop.
  if (replayKey) {
    let claimed
    try { claimed = await claimTurnId(room, memberId) } catch (e) { const err = new Error('turn claim unavailable — ' + String((e && e.message) || e).slice(0, 120)); err.code = 'store_unavailable'; throw err }
    if (!claimed) return { reply: '', entries: log.length, replayed: true }
  }

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
  // `spk` = the member's VERIFIED signing key (spaceService stamps `incoming.vspk` only on a path that actually
  // verified a signing key — never client-injectable). Persisting it makes the room ROSTER (name→spk) derivable from
  // the ledger, which a membership fork needs to seal a forward pointer to each keeper (docs/spaces-membership-fork.md).
  // ★ THE ENTRY CARRIES POINTERS, NOT BYTES. A photo or a PDF goes into a sealed, content-addressed blob (attachmentBlobs
  //   → imageBlob) and the entry keeps `{ref|parts, mime, name, size}`; the in-memory `images`/`files` (with bytes) still
  //   feed THIS turn's perception, describe-once and read_file. Measured 2026-09-18: rooms whose ledgers had grown to
  //   5–11 MB of inline attachments, re-downloaded by every device on every cold load. A blob that fails to store stays
  //   inline (storeAttachments never drops one) — the room must not lose a member's file because S3 hiccuped.
  const mkNow = getRoomKey()
  const [storedImages, storedFiles] = await Promise.all([storeAttachments(room, mkNow, images), storeAttachments(room, mkNow, files)])
  log.push(prune({ kind: mcp ? 'mcp' : (hasMedia ? 'media' : 'text'), id: memberId, ts: now, name: from, replyTo, mcpName: mcp ? mcp.name : undefined, mcpArgs: mcp ? mcp.args : undefined, verified: incoming && incoming.verified ? true : undefined, user: incoming && incoming.verified && typeof incoming.user === 'string' && incoming.user ? incoming.user : undefined, spk: incoming && incoming.vspk ? incoming.vspk : undefined, md: incoming && incoming.md === true ? true : undefined, voice: incoming && incoming.voice && typeof incoming.voice === 'object' ? incoming.voice : undefined, text, images: storedImages.length ? storedImages : undefined, files: storedFiles.length ? storedFiles : undefined, widgets: locWidget ? [locWidget] : undefined }))
  // PUBLISH the member's message NOW — before the brain runs — so the OTHER participants see it on their next poll instead
  // of waiting for the whole turn (the agent's reply can take many seconds). The reply is stored again at the end. Best-
  // effort: if this store fails, the final putLedger below is still the source of truth.
  // ⚠ NOT SILENT. "The final putLedger still lands the turn" is only true if the turn REACHES it — and when it does
  // not (a tool that outruns the tier's budget, a crash), this was the only chance to keep the member's own message.
  // Losing someone's message and saying nothing about it is the worst outcome here, so the failure is logged with its
  // reason. Still best-effort by design: refusing the turn because the OTHERS' copy is late would be worse.
  // ★ APPEND-ONLY + CONDITIONAL (appendLedger, 2026-09-25): only the member's NEW entry goes to the store, behind
  // whatever anyone else appended since this turn read the room — a concurrent write from another member (or another
  // turn) is never overwritten, and this entry is never lost to theirs. `publishedAt` marks what this turn has stored so
  // far; the final write below appends only what came after it.
  const memberEntry = log[log.length - 1]
  let earlyOk = false
  try { const ap = await appendLedger(room, forStore([memberEntry])); earlyOk = !!(ap && ap.ok); if (!earlyOk) console.log('LEDGER early-publish FAILED — the member message is not stored yet: ' + ((ap && ap.reason) || 'unknown')) } catch (e) { console.log('LEDGER early-publish FAILED — the member message is not stored yet: ' + String((e && e.message) || e).slice(0, 200)) }
  const publishedAt = log.length
  if (stream && earlyOk) stream.publish({ k: 'entries' }) // the member's message is in the ledger — everyone viewing polls it once
  // MIGRATE OLDER ENTRIES' inline attachments out of the ledger, a bounded amount per turn, in parallel with the reply
  // (S3 puts against an LLM wait — free latency). Only entries with an `id` are rewritable in place (rewriteLedgerEntries
  // finds them by id in the CURRENT stored ledger, so a box appended meanwhile by someone else is kept). Awaited before
  // the final store, which then appends the reply on top of the rewritten boxes.
  const migP = (async () => {
    try {
      const r = await migrateInlineAttachments(room, mkNow, log)
      if (r.migrated.length) console.log(`📎 ATTACHMENTS[migrate] room=${logRoom(room)} entries=${r.migrated.length} bytes=${r.bytes}`)
      return r
    } catch (e) { console.log('  attachment migration skipped: ' + String((e && e.message) || e).slice(0, 160)); return { log, migrated: [], bytes: 0 } }
  })()
  // AUTO-DESCRIBE member photos ONCE, in PARALLEL with the reply. Perceive-once → store a text caption on the entry so
  // EVERY later turn recalls what the photo showed without re-feeding the pixels (native perception is ~1–1.4k vision
  // tokens AND a prompt-cache break when the image changes). `images` is the SAME array the member entry above holds, so
  // attaching `desc` persists on the final store; the client renders the photo, not `desc`, so it stays non-visible.
  // Runs concurrently with respond() → ~no added latency (a cheap mini vision call finishes before the gpt-5.5 reply).
  // `descChanged` → the member entry was sealed WITHOUT the caption in the early publish above, so the store that
  // persists the turn must RESEAL it (v3 append would otherwise keep the caption-less box). See putLedgerV3.
  let descChanged = false
  const descP = (process.env.SPACE_IMAGE_DESCRIBE !== '0' && images.length)
    ? Promise.all(images.map(async (im) => {
        try {
          const b64 = String((im && im.b64) || '').replace(/^data:[^,]*,/, '')
          const d = b64 && (await describeImage(b64, (im && im.mime) || 'image/jpeg', { detailed: true }))
          if (d) { im.desc = d; const st = storedImages[images.indexOf(im)]; if (st && st !== im) st.desc = d; descChanged = true } // the ENTRY holds the stored copy — caption both
        } catch { /* alt/name still carries it */ }
      }))
    : null
  // Read-only view of the Space's shared widgets (itinerary/map/places), the shared-views bridge, and the shared
  // location — folded into the brain context so the agent can reference "the shared cart"/"the plan" without being able
  // to change them. Sourced from the FULL log + fresh getDoc (see widgetContext), so it is independent of the compacted
  // conversation window above: trimming/compacting chat never drops a widget the room still holds, and the itinerary is
  // pinned in even past the last-few window. Guarded (key is live here); no widget → empty string.
  const widgetCtx = await widgetContext(room, log)
  // SMART CHIME-IN: in a GROUP (2+ distinct human speakers), if the message isn't directly aimed at the agent (no name /
  // @-mention), a DEDICATED cheap gate decides whether it should reply — biased hard to silence, and ISOLATED from the
  // "be helpful" reply framing that otherwise drags it into answering people talking to each other. SILENT → post nothing
  // (the member's message was already published above). Solo Spaces / direct addresses skip the gate and always reply.
  // OBSERVER venue (a Bridge SHARED room, docs/spaces-private-lane.md): the agent only OBSERVES here — the member's
  // message is already published above, so post nothing. The private-lane agent still speaks (its own room), and
  // crossings still append. Config-guarded, so every normal Space (agentReplies defaults true) is unchanged.
  // ⚑ RECORD THE SILENCE. The member's message was published above, so a PEER is already showing the
  // agent-thinking bubble. Choosing not to speak appends nothing, so without this write the ledger never
  // changes again and the peer has no event to observe — it sat there "thinking" until a timeout fired.
  // `done` is the only thing that moves, and it moves within a second of the decision.
  // ★ A SILENCE MUST SAY WHY. `silent: true` on its own is indistinguishable from an assistant that FAILED — the first
  // outside builder lost a day to exactly that, pointed at our server while his own renderer was the second fault
  // (2026-09-21). The turn knows the cause at each of the three points it can choose not to speak, so it now carries
  // it out: `silentReason` is a STABLE CODE to branch on, `reason` is prose to show a person (the house style
  // elsewhere here — `error` is the code, `reason` is the sentence), and the facts the decision was made on ride
  // along. Never the message text: a diagnostic must not become a second copy of the content. agent/silentReason.test.mjs
  const quiet = (b, code, reason, facts = {}) => ({ reply: '', entries: b.length, silent: true, silentReason: code, reason, ...facts })
  if (agentReplies === false) { if (descP) await descP; const b = forStore(log); await resolved(room, memberEntry, descChanged); return quiet(b, 'agent_muted', 'This room is an observing venue — its assistant never replies here. That is how the room was created, not a failure.') }
  // RESPONSE MODE — a user control in the composer (default 'auto' → behavior unchanged from before this).
  //   'always'   — reply to every message.
  //   'ondemand' — reply ONLY when the message addresses the agent (name / @-mention); otherwise post it silently.
  //   'auto'     — smart chime-in: reply if solo or addressed; in a GROUP not aimed at the agent, a cheap brain gate decides.
  // (The `agentReplies === false` hard-mute above still wins — an observer venue never speaks regardless of mode.)
  // An MCP skill invocation is a DIRECT, typed call to the agent (app.invoke) — always answer it. Otherwise the chime-in
  // gate below can silence a SECOND invoke: once the agent has replied, the room looks like a 2-speaker "group" and the
  // ⚙ chip isn't addressed by name, so it stays silent (broke re-invoke / a second search or re-curate).
  const addressed = !!mcp || addressesAgent(text, agentName, { mentionOnly: mode === 'ondemand' }) // ondemand: an explicit @-mention only — talking ABOUT the assistant is not talking TO it
  let speak = true
  let decidingP = null, decidingSeq = 0 // Auto's "Deciding whether to reply…" status while its gate runs (below)
  let speakers = null   // distinct HUMAN speakers, computed only on the 'auto' path — reported so a wrong room shape is visible
  let speakersFrom = '' // 'roster' | 'ledger' — WHICH rule produced that number; they are debugged in different places
  let quietCode = ''    // which of the two 'did not speak' causes this was
  if (mode === 'ondemand') { speak = addressed; if (!speak) quietCode = 'not_addressed' }
  else if (mode !== 'always') { // 'auto' (default)
    // `source !== 'shared'` — a PRIVATE LANE mirrors the shared room's messages (docs/spaces-private-lane.md), which carry
    // the SHARED participants' names. Counting them made a 1:1 lane look like a "group" (you + the mirrored others), so
    // `auto` ran the chime-in gate and stayed SILENT on a casual message — the assistant wouldn't answer you in your OWN
    // lane. The group-ness must reflect the lane's OWN speakers: exclude mirrored entries → a lane where only you speak is
    // solo → `auto` always replies. The mirrored messages stay as CONTEXT; they just no longer make the lane "a crowd".
    // ★ AND A SPEAKER IS A HUMAN SAYING SOMETHING. Not every named entry is a person. The config op appends a VISIBLE
    // system line ("⚙️ … changed the assistant’s data collections") stamped `name:'system'`, and a row write is stamped
    // with its writer's `by` — both were counted, so ONE of either made a 1:1 lane a "group". The ledger is append-only,
    // so it then stayed one: every later unaddressed turn went to the silence gate, and the lane's assistant went quiet
    // for ever with nothing to see — a gated silence is HTTP 200 with `ok:true` and `silent:true`. The first outside
    // builder lost a working lane to `configure({data})` this way (2026-09-21) and could not recover it from the client,
    // because nothing he could do removes an entry. See agent/laneSilence.test.mjs.
    // ★★ AND IT IS AN ALLOWLIST, NOT A DENYLIST. Three incidents came from "every named entry, minus the kinds we have
    // learned aren't people" (mirrored → sys → data): each fix subtracted one more, and the NEXT entry kind carrying a
    // name would join the bug the day it shipped. So: a speaker is a human entry of a kind a member's OWN TURN
    // produces — exactly the three stamped on `log.push` above (`text`, `media`, `mcp`). `self`/`sys`/`source` are
    // orthogonal flags on those kinds. `undefined` kind is LEGACY text (rooms from 2026-07-26 until `26276b6d` stamped
    // none), and excluding it would make every such group room read as solo — the opposite failure. Dated and
    // asserted in agent/speakerAllowlist.test.mjs, including the one test a denylist cannot have: an invented kind.
    const speaks = (e) => e && !e.self && !e.sys && e.name && e.source !== 'shared' && (e.kind === undefined || SPEAKER_KINDS.has(e.kind))
    // ★★ THE ROSTER FIRST. A verified room knows who was admitted (`participants`, from the sealed allow-list via
    // spaceService → agent/rosterCount.mjs), so "is this a group" is answered by that number WHETHER OR NOT they have
    // spoken — the owner's rule (2026-09-21). None of the ledger-counting failures above can reach it. The ledger count
    // remains for rooms whose shape cannot know (open, invite, a domain wildcard, an empty list ⇒ null), and anything
    // that is not a non-negative integer is treated as unknown, never as a count. agent/rosterGroup.test.mjs.
    if (Number.isInteger(participants) && participants >= 0) { speakers = participants; speakersFrom = 'roster' }
    else { speakers = new Set(log.filter(speaks).map((e) => String(e.name).toLowerCase())).size; speakersFrom = 'ledger' }
    if (speakers >= 2 && !addressed) {
      // "Deciding whether to reply…" on every member's screen while the gate runs (the owner, 2026-10-04: Auto felt slow —
      // 1.7–3.2 s of gate with nothing shown). Only the status: the main model does NOT start until the gate says yes
      // (starting it beside the gate was built and taken out — a no still bills the main model's whole prompt, 2026-10-05).
      decidingP = (async () => {
        try {
          const s = JSON.stringify({ v: 1, phase: 'deciding', since: now })
          await putPartial(room, null, ++decidingSeq, JSON.stringify(await sealEnvelope(s, { mk: getRoomKey() })))
          if (stream) stream.partial({ pseq: decidingSeq, text: '', step: JSON.parse(s) })
        } catch { /* a status never costs the turn */ }
      })()
      try { speak = await shouldReply({ agentName, context: renderLedger(forModel(log)), request: text, speaker: from }) } catch { speak = true }
      try { await decidingP } catch { /* */ }
    }
    if (!speak) quietCode = 'group_gate'
  }
  if (!speak) {
    if (decidingP) { // the gate said no: clear its status everywhere, as a finished turn does
      try { await putPartial(room, null, ++decidingSeq) } catch { /* */ }
      if (stream) { try { stream.publish({ k: 'end' }); await stream.flush() } catch { /* */ } }
    }
    if (descP) await descP
    const b = forStore(log); await resolved(room, memberEntry, descChanged)
    // `speakers` is the smoking gun when the count is wrong for the room — someone seeing 2 on a room they know holds
    // one person learns more from that number than from any sentence we could write.
    const why = quietCode === 'not_addressed'
      ? `The assistant replies only when @-mentioned in this room (reply mode “ondemand”) — write ${agentName ? `“@${String(agentName).replace(/\s+/g, '')}”` : '“@ai”'} or “@ai” to get an answer; talking about it does not count.`
      : `${speakers} people have spoken in this room, and this message did not address the assistant, so it stayed out of the conversation (reply mode “auto”). Set the reply mode to “always” if it should answer every message.`
    return quiet(b, quietCode, why, { mode, ...(speakers != null ? { speakers } : {}), ...(speakersFrom ? { speakersFrom } : {}) })
  }
  // PROGRESSIVE REPLY. Text is sealed and published as it is generated so a reader can start reading before the turn
  // finishes — the value is not a shorter wait, it is starting to process the answer sooner.
  //
  // THROTTLED, because each flush is a seal + a write: at PARTIAL_EVERY_MS the client's ~1s poll always has something
  // new, and a fast model cannot turn one reply into hundreds of writes. Flushed on a time boundary rather than per
  // delta so a burst of tokens costs one write, not fifty.
  let partialText = '', partialFlushed = '', partialSeq = decidingSeq, partialAt = 0, partialInFlight = null
  const stepSince = now // when this turn started (its own timestamp: the reply is stamped now + 1) — on every status, so a member who comes back mid-turn counts from it, and a page can tell a finished turn's status (a reply with ts > since is here) from a live one
  // STOP (docs/spaces-stop-turn.md). The prompter holds a random `stopKey` (sent with the turn, never in the ledger). A
  // stop request writes it to the per-room marker; here, WHILE streaming, we poll that marker and — only when the key
  // matches OUR stopKey — abort the in-flight model call. The per-turn nonce is the auth ("only the one that prompted")
  // AND the concurrency guard (we can only ever match our own turn). On abort, the text streamed SO FAR becomes the reply
  // (a truncated-but-real message), exactly like the desktop assistants' Stop. No stopKey ⇒ none of this runs (unchanged).
  const abort = new AbortController()
  let stopped = false, stopPolledAt = 0, stopPolling = false
  // TURN BUDGET (2026-09-26). One prod turn ran to the Lambda's 150 s kill: the model answered with a tool call, the
  // tool ran, and then nothing — the signal above fires only on the member's Stop, and nothing bounded the turn's wall
  // clock, so a stalled model call ran until Lambda killed the process and the room saw a turn that answered nothing.
  // Now the turn aborts its OWN model call at a budget below the Lambda's limit and finalizes exactly like a Stop: what
  // streamed lands, plus an honest note. (A synchronous block cannot be caught this way — data_query got its own worker
  // deadline in dataTools.mjs for that.) SPACE_TURN_BUDGET_MS per environment; 120 s under prod's 150 s.
  const budgetMs = (Number.isFinite(turnBudgetMs) && turnBudgetMs > 0) ? turnBudgetMs : (Number(process.env.SPACE_TURN_BUDGET_MS) || 120_000)
  let timedOut = false
  const budgetTimer = setTimeout(() => { timedOut = true; console.log(`⏱️ TURN-BUDGET exceeded after ${budgetMs}ms — model call aborted, finalizing with what streamed`); try { abort.abort() } catch { /* */ } }, budgetMs)
  const STOP_POLL_MS = 700
  const pollStop = () => {
    if (!stopKey || stopped || stopPolling) return
    stopPolling = true
    getStopSig(room)
      .then((s) => { if (s && s.key === stopKey && (s.at || 0) >= now) { stopped = true; try { abort.abort() } catch { /* */ } } }) // match OUR nonce + written after this turn began (a prior turn's leftover can't match a fresh random key anyway)
      .catch(() => {})
      .finally(() => { stopPolling = false })
  }
  const partialMs = Number(process.env.SPACE_PARTIAL_MS) // `|| 700` would make 0 unusable — 0 is a legitimate "flush every delta"
  // 350ms, matching the client's POLL_STREAM: the reveal can only ever be as fresh as the last flush, and a 700ms
  // flush against a 350ms poll meant every other poll carried nothing new. Smaller, more frequent writes cost more
  // seals but keep the cursor from chasing stale text.
  const PARTIAL_EVERY_MS = Number.isFinite(partialMs) && partialMs >= 0 ? partialMs : 350
  // TURN PROGRESS (docs/turn-progress.md): what the turn is doing right now — { phase: 'thinking' }, { tool: name } or
  // { phase: 'writing' } — sealed under the room key like the text and written in the same record, so every member's
  // screen says "Working on it…" / "Searching places…" long before the first word. Never the model's thinking itself.
  let step = null, stepFlushed = '', stepBox = null, stepTimer = null, stepEnded = false
  const flushPartial = () => {
    if (stepEnded) return // the turn has cleared its record — nothing may write it back
    if (partialInFlight) return // a write is already going; the trailing flush below catches whatever arrives meanwhile
    const snapshot = partialText
    const stepNow = step ? JSON.stringify({ v: 1, ...step, since: stepSince }) : ''
    partialInFlight = (async () => {
      try {
        if (stepNow !== stepFlushed) { stepBox = stepNow ? JSON.stringify(await sealEnvelope(stepNow, { mk: getRoomKey() })) : null; stepFlushed = stepNow }
        // No text yet → no `box`: an empty sealed string would reach an older client as a blank reply.
        await putPartial(room, snapshot ? JSON.stringify(await sealEnvelope(snapshot, { mk: getRoomKey() })) : null, ++partialSeq, stepBox)
        partialFlushed = snapshot
        if (stream) stream.partial({ pseq: partialSeq, text: snapshot || '', step: stepNow ? JSON.parse(stepNow) : null }) // the reply as it streams (only the new text), and what the turn is doing
      }
      catch { /* a failed partial never costs the reply */ }
      finally {
        partialInFlight = null
        // TRAILING FLUSH. Deltas that arrived during the write were dropped by the guard above; without this the
        // reader watches the text stop growing and stay stale until the finished entry lands — which is exactly the
        // dead wait progressive replies exist to remove.
        if (partialText !== partialFlushed || (step ? JSON.stringify({ v: 1, ...step }) : '') !== stepFlushed) flushPartial()
      }
    })()
  }
  const onDelta = (d, opts) => {
    // RETRACT. The model step re-asks once when the gateway's upstream verification window had lapsed
    // (agent/attestedRetry.mjs), and the failed attempt already streamed its text here. This sink ACCUMULATES, so
    // without dropping what it sent the reader would watch the answer written twice. Flush immediately: the reveal
    // must go back to empty before the second attempt starts writing, not at the next throttled tick.
    if (opts && opts.reset) { partialText = ''; flushPartial(); return }
    if (opts && opts.step) { step = opts.step; flushPartial(); return } // a tool starting, or thinking again after one — shown at once, not throttled (a few per turn)
    if (d && !(step && step.phase === 'writing')) step = { phase: 'writing' } // the answer has begun; rides the next flush
    partialText += d
    const t = Date.now()
    if (stopKey && !stopped && t - stopPolledAt > STOP_POLL_MS) { stopPolledAt = t; pollStop() } // watch for a stop request while the answer streams (throttled → a few extra reads per turn)
    if (t - partialAt < PARTIAL_EVERY_MS) return
    partialAt = t
    flushPartial()
  }
  const ctxText = await compactedContext(room, log) // OFF ⇒ last-window (unchanged); ON ⇒ running summary + growing window (prefix-cache friendly)
  // IMAGE VISIBILITY. Native perception drags a photo into the prompt each turn (the incoming media, or ONE recent
  // ledger image), and on an image-heavy Space those pixels can dwarf the text AND break the prompt cache when they
  // change turn-to-turn — a cost compaction can't touch. Log the count + bytes + estimated vision tokens so we can size
  // it against the LLM-USAGE input. Counts only (no pixels) → CloudWatch-safe like the usage line.
  const perceivedImages = images.length ? images : await recentLedgerImage(room, log) // perceived natively (brainTools → image_url / input_image)
  try { const ic = imageCost(perceivedImages); if (ic.n) console.log(`🖼️ IMAGES[turn] n=${ic.n} bytes=${ic.bytes} ~vision_tokens=${ic.tokens}${images.length ? ' src=incoming' : ' src=recent-ledger'}`) } catch { /* visibility must never break a turn */ }
  const sources = [] // hosted web_search url-citations, collected via onCitations during respond() → attached to the entry below
  const trimDangling = (t) => String(t || '').replace(/(^|\n)[ \t]*(#{1,6}|[-*+]|\d+[.)])[ \t]*$/, '$1').trimEnd() // a Stop mid-heading/-bullet leaves a bare "##"/"-"; drop a trailing marker-only line so the truncated reply isn't an empty heading
  // Poll the stop marker on a TIMER too — not only in onDelta. A model between text deltas (a tool call like image
  // generation, or a reasoning pause) emits no deltas, so a stop tapped THEN would go undetected until the next delta (or
  // never). The interval catches it and aborts; the in-flight/next fetch rejects. Cleared in finally so it never outlives the turn.
  const stopTimer = stopKey ? setInterval(pollStop, STOP_POLL_MS) : null
  let respondOut = null
  const turnStartedAt = Date.now() // proposals made from here on belong to THIS turn (see the proposal note below)
  // WHAT THIS TURN PROPOSED, for the turn's result (2026-09-30, a builder: "the model says it proposed, but no card
  // arrives"). The platform knows for certain; the model's words are not evidence. Filled by makeProposingBrain as each
  // proposal is actually created, so a page can tell "a card is coming" from "the text only said so".
  const proposedThisTurn = []
  step = { phase: 'thinking' }; flushPartial() // "Working on it…" on every member's screen from the first poll, not after the model's first word
  // HEARTBEAT: a model can think for a minute without a single write. Rewriting the record every 10 s keeps its `at`
  // fresh, and the poll drops a status older than 45 s — so a turn that died without clearing cannot leave a
  // "Working on it…" on anyone's screen (spacePoll.withTurnProgress).
  stepTimer = setInterval(flushPartial, 10_000)
  try {
    respondOut = await respond({
      kind: 'reply',
      onDelta,
      onProposed: (p) => { proposedThisTurn.push(p) },
      signal: abort.signal, // STOP: aborting this rejects the model fetch → the tool loop ends; we finalize with the streamed text below
      onCitations: (cites) => { for (const c of (cites || [])) sources.push(c) },
      longform: true, // an async Space is a TEXT chat, not a spoken turn → allow a full multi-paragraph answer (not the 320-char voice clip)
      agentName, // the Space's own name for its assistant ("Site Assistant"), so the prompt never names it by the platform default
      request: mcp
        ? `The app has invoked your "${mcp.name}" MCP skill (a typed tool call over the bridge, NOT a chat message) with arguments: ${JSON.stringify(mcp.args)}. Handle it NOW using your tools, then reply with one short line.`
        : (text || (files.length ? `I shared a document (${files.map((f) => f.name || 'file').join(', ')}). Read it with read_file and give me a short summary.` : 'Take a look at what I just shared.')), // media-only turn → a nudge so the model engages the file/pixels
      speaker: from,
      ...(turnInstructions ? { turnInstructions } : {}), // the app's per-turn instructions — never stored, see brain.buildPrompt
      context: ctxText + widgetCtx + (bridgeContext ? '\n\n' + bridgeContext : ''), // compacted (summary + window) or the last-window; + the SHARED room on a bridged lane turn
      guidance: persona + PLACES_GUIDANCE + PHOTO_GUIDANCE + FORMAT_GUIDANCE + (files.length ? FILE_GUIDANCE : '') + (bridged ? LANE_GUIDANCE : ''),
      images: perceivedImages, // perceived natively (brainTools → image_url / input_image)
      // NOTE: shared FILES (documents) are deliberately NOT sent natively — the model reads them via read_file (see
      // FILE_GUIDANCE). They're still stored in the ledger entry above so read_file can reach them now and later.
    })
  } catch (e) { if (!stopped && !timedOut) throw e } // a genuine model error still fails the turn; a STOP- or BUDGET-abort falls through to the streamed text below
  finally { if (stopTimer) clearInterval(stopTimer); clearTimeout(budgetTimer); clearInterval(stepTimer) }
  // On STOP, the text streamed SO FAR is the reply — NOT respond()'s return. brainTools swallows the abort to null and
  // brain.respondWithTools then yields its "I couldn't complete that one" note; using that would OVERWRITE what the reader
  // already watched appear. So when stopped, take partialText (trimming a dangling heading/bullet marker left mid-format).
  // SAME REASONING FOR A DROPPED STREAM, not just for Stop. When the upstream stream dies mid-answer (observed live:
  // "openai-responses stream ended without response.completed"), brainTools swallows it to null and respondWithTools
  // returns its "I couldn't complete that one" note — which REPLACED several paragraphs the reader had already watched
  // appear, leaving them with an apology where their answer had been. The reader watched that text arrive either way,
  // so keep it. Only when there is nothing meaningful streamed does the honest note stand on its own.
  const salvage = trimDangling(partialText).trim()
  const failedMidStream = !stopped && salvage.length >= 200 && String(respondOut || '') === COULD_NOT_FINISH
  const rawReply = (stopped || timedOut || failedMidStream ? trimDangling(partialText) : String(respondOut || '')).trim()
  // ★ A reply must not claim a photo that was never attached. `producedFiles` is filled by the room's tool executor
  // DURING respond() above, so by here we know exactly what this turn really showed. PHOTO_GUIDANCE asks the model not
  // to do this; observed live, it sometimes does anyway — so this is the deterministic backstop it cannot ignore.
  // Only ASSERTIONS are removed; offers ("I can show you one") are true and stay.
  let reply = honestPhotoReply(rawReply, producedFiles)
  // ⛔ A TURN THAT PROPOSED BUT SAID NOTHING (2026-09-29, a builder, confidential tier: "the assistant proposed the right
  // card but its text reply was empty, twice"). The card is real and waiting; "I couldn't complete that one" would be
  // the opposite of the truth, and silence reads as a hang. Name what is waiting — deterministic, so it cannot be blank.
  if (!stopped && (!reply || reply === COULD_NOT_FINISH)) {
    try {
      const made = (await pendingProposals(room)).filter((p) => p && p.at >= turnStartedAt)
      if (made.length) reply = proposalNote(made.map((p) => p.action))
    } catch { /* the note is a courtesy; a store hiccup keeps whatever the turn had */ }
  }
  if (timedOut) reply = reply ? reply + '\n\n_' + OUT_OF_TIME_NOTE + '_' : OUT_OF_TIME_NOTE // the reader is told why it ends there — never silence
  // Tag the reply with any widgets this turn produced (show_places/add_place) → the client renders a live card per
  // widget-bearing message. `artifacts` is populated by the room's tool executor DURING respond() above.
  const hasProduced = Array.isArray(producedFiles) && producedFiles.length
  // Dedupe the collected web_search sources by URL + cap (a Sources footer, not a bibliography). Sealed into the entry
  // like any field → both members see the same citations; the client renders favicon chips (via the /api/favicon proxy).
  const srcSeen = new Set(); const srcOut = []
  for (const s of [...producedSources, ...sources]) { if (s && s.url && !srcSeen.has(s.url)) { srcSeen.add(s.url); srcOut.push(s) } } // fetch_url's links first: the room sees where the agent went
  // The turn's sealed usage record — and, in a room its admin funds (roomFunding.mjs), the cost reported back so the member's
  // monthly line grows by it (`funded` marks the record, so ⋯ → Usage can say who paid). Best-effort: never fails the turn.
  const turnRecord = (() => { const r = turnUsageRecord({ by: from }); return r && opts.funded ? { ...r, funded: true } : r })()
  if (typeof opts.onUsage === 'function' && turnRecord) { try { await opts.onUsage(turnRecord) } catch { /* the reply still lands */ } }
  if (typeof opts.usageReceipt === 'function' && turnRecord) { try { await opts.usageReceipt(turnRecord) } catch { /* the reply still lands */ } } // the sender's sealed receipt (usageReceipt.mjs)
  if (reply || hasProduced) {
    const replyEntry = prune({ kind: 'text', id: `async:${now}:r`, ts: now + 1, name: agentName, text: reply || (hasProduced ? `📄 ${producedFiles.map((f) => f.name).join(', ')}` : ''), self: true, stopped: stopped ? true : undefined, timedOut: timedOut ? true : undefined, widgets: Array.isArray(artifacts) && artifacts.length ? artifacts.slice() : undefined, files: hasProduced ? producedFiles.slice() : undefined, sources: srcOut.length ? srcOut.slice(0, 12) : undefined, usage: turnRecord })
    // THE TURN CERTIFICATE (docs/turn-certificates.md): inside the enclave only (no stamp signer anywhere else), signed over
    // this reply's text, this build's PCRs, every verified model receipt and every tool call with where it ran. The
    // attestation doc that binds the signing key rides once per room per enclave boot. Best-effort: a failure here costs
    // the certificate, never the reply — and the page counts a missing certificate after certified ones as a failure.
    try {
      const signer = await envStampSigner()
      if (signer) {
        const docAlreadyInRoom = log.some((e) => e && e.certDoc && e.cert && e.cert.kid === signer.kid)
        const out = await certifyReply({ signer, room, entry: replyEntry, docAlreadyInRoom })
        if (out) { replyEntry.cert = out.cert; if (out.certDoc) replyEntry.certDoc = out.certDoc }
      }
    } catch (e) { console.log('  turn certificate failed: ' + String((e && e.message) || e).slice(0, 160)) }
    log.push(replyEntry)
  }

  if (descP) await descP // the member-photo captions must be attached before we persist the entry (they ran in parallel with the reply)
  // The migrated entries replace their originals in `log` (same indices), and the SAME entries are rewritten in the
  // stored ledger by id — so the append below sees a stored prefix that matches its own log. Skipped entirely when
  // nothing moved (the steady state: one cheap scan).
  const mig = await migP
  if (mig.migrated.length) {
    const byId = new Map()
    for (const i of mig.migrated) { const e = mig.log[i]; if (e && e.id != null) { byId.set(String(e.id), e); log[i] = e } }
    try { const n = await rewriteLedgerEntries(room, (e) => (e && e.id != null ? byId.get(String(e.id)) || null : null)); if (n !== byId.size) console.log(`📎 ATTACHMENTS[migrate] rewrote ${n} of ${byId.size} boxes`) } catch (e) { console.log('  attachment migration rewrite failed: ' + String((e && e.message) || e).slice(0, 160)) }
  }
  const bounded = forStore(log)
  // THE FINAL WRITE APPENDS ONLY WHAT THIS TURN ADDED SINCE ITS EARLY PUBLISH (the reply; plus the member message if that
  // publish failed) — never the whole log, which is this turn's STALE view of a room others may have written to
  // meanwhile (Tomer, 2026-09-25: a write during a turn lost itself or one of the turn's entries). `descChanged` → the
  // member photo entry (sealed caption-less in the early publish) is rewritten IN PLACE by id so its describe-once
  // caption persists — rewriteLedgerEntries keeps every concurrently appended box; a whole-ledger reseal would not.
  if (descChanged && memberEntry && memberEntry.id != null) { try { await rewriteLedgerEntries(room, (e) => (e && e.id != null && String(e.id) === String(memberEntry.id)) ? memberEntry : null) } catch { /* the caption is a nicety; the reply must still land */ } }
  const fresh = forStore(log.slice(earlyOk ? publishedAt : publishedAt - 1))
  // ★ THE REPLY COUNTS ONLY ONCE IT IS STORED (the independent review, 2026-10-05, finding 1: this result was ignored, so
  // a store that failed here returned the reply as a success — it showed, then vanished on the next poll, and no one else
  // ever saw it). appendLedger already retries conflicts; a store FAILURE gets two more tries with a backoff, and if the
  // reply still is not in the ledger the turn says so (`notStored`, the text handed back) instead of claiming success.
  let stored = null
  for (let i = 0; i < 3; i++) {
    try { stored = await appendLedger(room, fresh, { done: 'all' }) } catch (e) { stored = { ok: false, reason: String((e && e.message) || e).slice(0, 120) } } // a reply resolves the turn too — `done` tracks EVERY completion, not just silences
    if (stored && (stored.ok || stored.reason === 'no_store' || stored.reason === 'no_key')) break // no store on this tier: nothing to lose
    if (i < 2) await new Promise((r) => setTimeout(r, 150 * (i + 1)))
  }
  const notStored = !!(stored && !stored.ok && stored.reason !== 'no_store' && stored.reason !== 'no_key' && fresh.length)
  if (notStored) console.log(`LEDGER final append FAILED — the reply is NOT stored: ${(stored && stored.reason) || 'unknown'} ${logRoom(room)}`)
  // CLEAR LAST, and unconditionally. The finished entry is now in the ledger, so a live bubble left behind would
  // duplicate it on screen. This also covers the failure path: a stream that died after emitting deltas leaves text
  // the reader can see with no entry coming, and that has to disappear too.
  stepEnded = true; clearInterval(stepTimer); try { await partialInFlight } catch { /* */ } // no progress write may land after the clear
  try { await putPartial(room, null, ++partialSeq) } catch { /* */ }
  if (stream) { stream.publish({ k: 'entries' }); stream.publish({ k: 'end' }); await stream.flush() } // the finished reply, then "no reply in progress"
  if (stopKey) { try { await putStopSig(room, null) } catch { /* */ } } // clear the cancel marker so a stale one can't affect a later turn
  if (notStored) return { reply, entries: bounded.length, stopped, timedOut, proposed: proposedThisTurn, notStored: true, storeReason: (stored && stored.reason) || 'unknown' }
  return { reply, entries: bounded.length, stopped, timedOut, proposed: proposedThisTurn }
}
