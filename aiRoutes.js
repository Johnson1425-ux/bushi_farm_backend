/* ══════════════════════════════════════════════════════════════
   AI ROUTES  —  mounted at /api/ai  (admin only, see the gate below)

   GET    /api/ai/status                 is AI configured?
   POST   /api/ai/reports/period         narrative period report   (SSE)
   GET    /api/ai/reports                list saved reports
   GET    /api/ai/reports/:id            read one saved report
   DELETE /api/ai/reports/:id            delete a report           (admin)
   GET    /api/ai/briefing               today's briefing (cached)
   POST   /api/ai/briefing               regenerate the briefing   (SSE)
   GET    /api/ai/cows/:id/summary       latest saved cow summary
   POST   /api/ai/cows/:id/summary       generate cow summary      (SSE)
   POST   /api/ai/chat                   ask-the-data chat         (SSE)

   Generation endpoints stream Server-Sent Events so the UI can render
   text as it is written instead of waiting on a long request.
══════════════════════════════════════════════════════════════ */
const express = require('express');
const { pool } = require('./db');
const { verifyToken, requireAdmin } = require('./auth');
const ctx = require('./aiContext');
const ai  = require('./aiClient');

const router = express.Router();

/* ══════════════════════════════════
   ADMIN ONLY

   Every AI surface reads across the whole farm — production, health, sales,
   inventory and processing together — so none of it can be handed to a role
   that is restricted to one of those areas. A vet with chat access could just
   ask what last month's sales were. Rather than scope each report and tool per
   role, the entire router is limited to admins, who can already see all of it.

   This gate covers every route below, including any added later.
══════════════════════════════════ */
router.use(verifyToken, requireAdmin);

/** Reject early with a clear message when the API key is missing. */
function requireAi(req, res, next) {
  if (!ai.aiConfigured()) {
    return res.status(503).json({
      error: 'AI features are not configured. Set ANTHROPIC_API_KEY in the backend .env file.',
    });
  }
  next();
}

/** Open an SSE response and return writer helpers. */
function openStream(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();

  let closed = false;
  const abortHandlers = [];

  /* The client-went-away signal must come from the RESPONSE, not the request.
     Since Node 16, `req` emits 'close' as soon as the request body has been
     fully read — for a small JSON POST that is immediately — so listening on
     `req` would mark every stream dead before it wrote a single byte. */
  res.on('close', () => {
    if (closed) return;            // we ended it ourselves; nothing to abort
    closed = true;
    for (const fn of abortHandlers) {
      try { fn(); } catch { /* abort is best-effort */ }
    }
  });

  const send = (event, data) => {
    if (closed) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  const end = () => {
    if (closed) return;
    closed = true;
    res.end();
  };
  return {
    send,
    end,
    fail: (err) => {
      send('error', { error: err?.message || 'Generation failed' });
      end();
    },
    /** Register a callback to stop in-flight work if the client disconnects. */
    onAbort: (fn) => abortHandlers.push(fn),
    get closed() { return closed; },
  };
}

/**
 * Run a streamed generation and push it down an SSE response, then persist it.
 * Shared by the period report, the briefing and the cow summary.
 */
async function streamAndSave(req, res, { system, user, maxTokens, effort, save }) {
  const stream = openStream(res);

  try {
    const result = await ai.generate({
      system, user, maxTokens, effort,
      onText: (delta) => stream.send('delta', { text: delta }),
      onAbortHandle: (abort) => stream.onAbort(abort),
    });

    // Client navigated away mid-generation — don't save a report nobody asked for.
    if (stream.closed) return;

    if (result.refused) {
      stream.send('error', {
        error: 'Claude declined this request.',
        category: result.stopDetails?.category || null,
      });
      return stream.end();
    }

    if (result.stopReason === 'max_tokens') {
      stream.send('warning', {
        message: 'The report hit the output limit and may be cut short.',
      });
    }

    const saved = await save(result);
    stream.send('done', {
      reportId: saved?.id ?? null,
      model: result.model,
      usage: result.usage,
      stopReason: result.stopReason,
    });
    stream.end();
  } catch (err) {
    if (stream.closed) return;   // aborted by the client, not a real failure
    console.error('[ai] generation failed:', err);
    stream.fail(err);
  }
}

function periodLabel(from, to) {
  return from === to ? from : `${from} to ${to}`;
}

/* ══════════════════════════════════
   STATUS
══════════════════════════════════ */
router.get('/status', verifyToken, (req, res) => {
  res.json({
    configured: ai.aiConfigured(),
    model: ai.MODEL,
    /* The router is admin-only, so anyone who reaches this can generate. */
    can_generate: true,
  });
});

/* ══════════════════════════════════
   NARRATIVE PERIOD REPORT
══════════════════════════════════ */

const PERIOD_SYSTEM = `
Write a farm performance report in GitHub-flavoured Markdown.

Structure it with these level-2 headings, in this order, and no others:

## Headline
Two or three sentences. What the period looked like overall and the single most
important thing the manager should know.

## Production
Total and average output, the trend across the period, and how it compares with
the previous period. Name the cows that stand out in either direction and give
their figures. Flag thin sample sizes rather than reading trends into them.

## Herd health
Diseases recorded, treatments given, and veterinary findings. Connect health
events to production changes where the dates line up — and say plainly when they
do not line up rather than implying a link.

## Breeding
Births in the period, new conceptions, and pregnancies due soon. Include the
cow names and dates.

## Sales and stock
Volume sold, revenue, average price, and how those moved against the previous
period. Note any gap between litres produced and litres sold. Call out items
that are out of stock or being consumed quickly.

## Processing unit
Milk received, packed, issued, damaged, and closing stock, using the
reconciliation figures rather than re-deriving them. Give the yield and the
damage rate. If a stock line closes below zero, say so — it is a counting error
in the source sheet, not stock. Skip this section entirely if there is no
processing data.

## What to do next
Between three and six specific actions, as a bullet list. Each one names the
cow, item, or figure that triggered it. No generic farm advice.

Omit any section where the data is genuinely empty, apart from Headline and
What to do next, which are always required.
`.trim();

router.post('/reports/period', verifyToken, requireAi, async (req, res) => {
  let snapshot;
  try {
    snapshot = await ctx.farmSnapshot({ from: req.body?.from, to: req.body?.to });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  const { from, to, days } = snapshot.period;
  const focus = typeof req.body?.focus === 'string' ? req.body.focus.trim().slice(0, 500) : '';

  const user = [
    `Report period: ${from} to ${to} (${days} days).`,
    `The previous period used for comparison is ${snapshot.period.prevFrom} to ${snapshot.period.prevTo}.`,
    focus ? `\nThe manager specifically asked about: ${focus}\nGive that extra weight, but still produce the full report.` : '',
    '\nFarm data:\n',
    '```json',
    JSON.stringify(snapshot, null, 1),
    '```',
  ].filter(Boolean).join('\n');

  await streamAndSave(req, res, {
    system: PERIOD_SYSTEM,
    user,
    maxTokens: 16000,
    effort: 'high',
    save: (result) => ai.saveReport({
      kind: 'period',
      title: `Farm report — ${periodLabel(from, to)}`,
      content: result.text,
      params: { from, to, days, focus: focus || null },
      model: result.model,
      usage: result.usage,
      periodFrom: from,
      periodTo: to,
      userId: req.user.id,
    }),
  });
});

/* ══════════════════════════════════
   PROCESSING UNIT REPORT

   The whole-farm report gives the processing unit one section among seven,
   which is enough to say what happened and not enough to say why. This one
   does the reconciliation properly: milk in against packs out, what the
   write-offs cost, and whether the stock balance can be believed.
══════════════════════════════════ */

const PROCESSING_SYSTEM = `
Write a report on the milk processing unit for one month, in GitHub-flavoured
Markdown. Use these level-2 headings, in this order, and no others:

## Headline
Two or three sentences: how the month went and the one thing worth acting on.

## Milk in, packs out
Litres taken in (farm, Mwabulugu, purchased, plus anything carried in) against
litres packed, and the yield that implies. Say which products absorbed the milk.
The gap between milk available and litres packed is spillage, residue and
keying error together — a few percent is ordinary, so only call it out when it
is not.

## Damage
Packs written off and raw milk spoiled before packing, as figures and as a share
of what was made. Name the products carrying the losses. Say plainly if damage
is concentrated in one line rather than spread across the range.

## Stock
Opening balance, what was produced, what was issued, and what should be left,
per product where it matters. If any line closes negative, lead with that: it
means more was issued or written off than ever existed, so it is a counting
mistake in the sheet, not stock. Name those lines and say what to check.

## What to do next
Between three and six specific actions as a bullet list, each naming the product,
figure, or day that prompted it. No generic advice about dairy hygiene.

Two things to hold on to:
- Litres for packed, issued and damaged goods are derived from the pack size,
  not typed in, so they cannot disagree with the unit counts. Do not present
  them as an independent measurement.
- When a month was read from the farm's own hand-kept workbook (read_from is
  "legacy"), the figures carry whatever inconsistencies that sheet had. Say so
  once if you rely on a number that looks wrong, rather than reasoning around it.
`.trim();

router.post('/reports/processing', verifyToken, requireAi, async (req, res) => {
  const requested = typeof req.body?.month === 'string' ? req.body.month.trim() : '';

  let processing;
  try {
    /* No month given means the most recent one, which is what someone
       clicking "generate" from the page they are already looking at wants. */
    if (requested) {
      processing = await ctx.processingMonth(requested);
      if (processing.error) return res.status(404).json(processing);
    } else {
      const recent = await ctx.processingContext(1);
      if (!recent.months?.length) {
        return res.status(404).json({ error: 'No processing unit data has been uploaded yet.' });
      }
      processing = await ctx.processingMonth(recent.months[0].label);
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  // The aggregate view carries the reconciliation arithmetic; the detail view
  // carries the daily rows. The report needs both.
  const summary = await ctx.processingContext(6);
  const thisMonth = summary.months.find(m => m.label === processing.label) || null;
  const previous = summary.months.filter(m => m.label !== processing.label).slice(0, 1);

  const user = [
    `Processing month: ${processing.label}.`,
    previous.length ? `The month before it, for comparison, is ${previous[0].label}.` : '',
    '\nReconciliation for this month:\n',
    '```json', JSON.stringify(thisMonth, null, 1), '```',
    '\nDaily detail:\n',
    '```json', JSON.stringify(processing, null, 1), '```',
    previous.length ? '\nPrevious month, for comparison:\n' : '',
    previous.length ? '```json' : '',
    previous.length ? JSON.stringify(previous[0], null, 1) : '',
    previous.length ? '```' : '',
  ].filter(Boolean).join('\n');

  await streamAndSave(req, res, {
    system: PROCESSING_SYSTEM,
    user,
    maxTokens: 12000,
    effort: 'high',
    save: (result) => ai.saveReport({
      kind: 'processing',
      title: `Processing unit — ${processing.label}`,
      content: result.text,
      params: { month: processing.label },
      model: result.model,
      usage: result.usage,
      periodFrom: null,
      periodTo: null,
      userId: req.user.id,
    }),
  });
});

/* ══════════════════════════════════
   DAILY BRIEFING
══════════════════════════════════ */

const BRIEFING_SYSTEM = `
Write this morning's briefing for the farm manager, in GitHub-flavoured Markdown.

This replaces a threshold-based alert list. The alerts tell you what tripped;
your job is to say what it means and what to do about it. Do not simply restate
the signals.

Rules:
- Open with one sentence on the overall state of the farm today.
- Then a "## Needs attention today" section as a bullet list, ordered by urgency.
  Each bullet: what is happening, the figure behind it, and the action to take.
- Group related signals into one bullet rather than repeating a theme. Several
  cows dropping output at once is one observation, not five.
- A cow with no recent milk record is usually a missed data entry, not a sick
  animal. Say so, and do not escalate it into a health warning.
- The processing signals cover the most recent month uploaded, not today. Raise
  them only when something is actually wrong — a stock line closing below zero,
  damage well above its usual share, or a month that has gone unrecorded for
  weeks. A month sitting there with ordinary figures is not an action item.
- If nothing genuinely needs attention, say that in one line and stop. Do not
  manufacture items to fill the section.
- Keep the whole briefing under 300 words. It is read standing up.
`.trim();

async function buildBriefing(req, res) {
  let signals, snapshot;
  try {
    [signals, snapshot] = await Promise.all([
      ctx.alertSignals(),
      ctx.farmSnapshot({}),   // trailing 30 days, for context behind the signals
    ]);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  const today = new Date().toISOString().slice(0, 10);
  const user = [
    `Today is ${today}.`,
    '\nCurrent alert signals:\n',
    '```json', JSON.stringify(signals, null, 1), '```',
    '\nFor context, here is the last 30 days of farm data:\n',
    '```json', JSON.stringify(snapshot, null, 1), '```',
  ].join('\n');

  await streamAndSave(req, res, {
    system: BRIEFING_SYSTEM,
    user,
    maxTokens: 8000,
    effort: 'medium',
    save: (result) => ai.saveReport({
      kind: 'briefing',
      title: `Daily briefing — ${today}`,
      content: result.text,
      params: { date: today },
      model: result.model,
      usage: result.usage,
      periodFrom: today,
      periodTo: today,
      userId: req.user.id,
    }),
  });
}

/** Returns today's cached briefing, or 404 so the client knows to generate one. */
router.get('/briefing', verifyToken, async (req, res) => {
  try {
    const existing = await ai.findTodaysReport('briefing');
    if (!existing) {
      return res.status(404).json({
        error: 'No briefing generated today',
        configured: ai.aiConfigured(),
      });
    }
    res.json({
      id: existing.id,
      title: existing.title,
      content: existing.content,
      model: existing.model,
      created_at: existing.created_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/briefing', verifyToken, requireAi, buildBriefing);

/* ══════════════════════════════════
   PER-COW HEALTH SUMMARY
══════════════════════════════════ */

const COW_SYSTEM = `
Write a summary of one cow for the farm's veterinary staff, in GitHub-flavoured
Markdown. Use these level-2 headings and no others:

## At a glance
Breed, how long she has been recorded, her average output, and how that compares
with the herd average. One short paragraph.

## Production history
The shape of her lactation over time using the monthly figures. Point out where
output rose or fell and roughly when. Note her consistency using the standard
deviation — a high spread means erratic yield, which is itself worth flagging.

## Health record
Diseases, treatments, and veterinary examination findings in date order. Include
clinical values (temperature, pulse, body weight, PCV) where they were recorded
and say whether they sit inside normal bovine ranges. Note any milk withdrawal
dates that are still in effect.

## Breeding record
Conceptions, expected due dates, and births. If she is currently pregnant, give
the due date and days remaining.

## Assessment
Three to five sentences. How this cow is doing, what to watch, and anything the
record is missing that someone should go and check.

If a section has no data, write a single line saying so instead of the section
body. Do not diagnose beyond what the record supports — describe what is there
and what it suggests.
`.trim();

router.get('/cows/:id/summary', verifyToken, async (req, res) => {
  const cowId = parseInt(req.params.id, 10);
  if (!Number.isInteger(cowId)) return res.status(400).json({ error: 'Invalid cow id' });

  try {
    const { rows } = await pool.query(`
      SELECT r.*, c.name AS cow_name FROM ai_reports r
      LEFT JOIN cows c ON c.id = r.cow_id
      WHERE r.kind = 'cow_summary' AND r.cow_id = $1
      ORDER BY r.created_at DESC LIMIT 1
    `, [cowId]);
    if (!rows[0]) return res.status(404).json({ error: 'No summary generated for this cow yet' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cows/:id/summary', verifyToken, requireAi, async (req, res) => {
  const cowId = parseInt(req.params.id, 10);
  if (!Number.isInteger(cowId)) return res.status(400).json({ error: 'Invalid cow id' });

  let dossier;
  try {
    dossier = await ctx.cowDossier(cowId);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
  if (!dossier) return res.status(404).json({ error: 'Cow not found' });

  const user = [
    `Summarise ${dossier.cow.name}. Today is ${new Date().toISOString().slice(0, 10)}.`,
    '\nComplete record for this cow:\n',
    '```json', JSON.stringify(dossier, null, 1), '```',
  ].join('\n');

  await streamAndSave(req, res, {
    system: COW_SYSTEM,
    user,
    maxTokens: 12000,
    effort: 'high',
    save: (result) => ai.saveReport({
      kind: 'cow_summary',
      title: `${dossier.cow.name} — health summary`,
      content: result.text,
      params: { cow_name: dossier.cow.name },
      model: result.model,
      usage: result.usage,
      cowId,
      userId: req.user.id,
    }),
  });
});

/* ══════════════════════════════════
   ASK-THE-DATA CHAT
══════════════════════════════════ */

/**
 * Typed tools rather than raw SQL. The model cannot compose arbitrary queries,
 * which keeps the injection surface at zero, and each tool returns data already
 * shaped for reading.
 */
const CHAT_TOOLS = [
  {
    name: 'list_cows',
    description:
      'List every cow in the herd with tag, breed, lifetime average yield, and the date '
      + 'she was last milked. Call this first when the question mentions a cow by a name '
      + 'you have not seen yet, or when you need to know how large the herd is. Animals '
      + 'that have died, been sold or been culled come back separately under '
      + 'no_longer_in_herd with the date they left — they are not part of the herd size, '
      + 'and should never be described as currently producing.',
    input_schema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'get_farm_data',
    description:
      'Farm data for a date range: production totals and per-cow figures, health events, '
      + 'breeding, sales, inventory, and the processing unit. Call this for any question '
      + 'about what happened over a period, comparisons between periods, or farm-wide '
      + 'totals. Request only the sections you need — each one costs tokens.',
    input_schema: {
      type: 'object',
      properties: {
        from: { type: 'string', description: 'Start date, YYYY-MM-DD. Defaults to 30 days before "to".' },
        to:   { type: 'string', description: 'End date, YYYY-MM-DD. Defaults to today.' },
        sections: {
          type: 'array',
          description: 'Which sections to return. Omit for all of them.',
          items: {
            type: 'string',
            enum: ['production', 'health', 'pregnancies', 'sales', 'inventory', 'processing'],
          },
        },
      },
      required: [],
    },
  },
  {
    name: 'get_cow_dossier',
    description:
      'Everything recorded about one cow: full production history by month, recent daily '
      + 'records, diseases, treatments, veterinary examinations, pregnancies, and logged '
      + 'events. Call this whenever the question is about a specific animal.',
    input_schema: {
      type: 'object',
      properties: {
        cow_name: { type: 'string', description: 'The cow\'s name or tag. Matching is case-insensitive.' },
      },
      required: ['cow_name'],
    },
  },
  {
    name: 'get_processing_month',
    description:
      'One month of processing-unit records in full detail: milk taken in each day, packs '
      + 'made, issued and written off each day by product and size, and the stock balance '
      + 'per line. Call this when a question is about the processing unit specifically — '
      + 'which day something happened, which product is short, how a balance was arrived '
      + 'at. Use get_farm_data instead for month totals across several months.',
    input_schema: {
      type: 'object',
      properties: {
        month: {
          type: 'string',
          description: 'The month label, like "JUNE 2026". If you do not know which months '
            + 'exist, pass any value — the reply lists the available ones.',
        },
      },
      required: ['month'],
    },
  },
  {
    name: 'get_alerts',
    description:
      'Current warning signals: cows whose recent yield is more than 20 percent below '
      + 'their own average, births due within three weeks, items out of stock, cows with '
      + 'no milk record for several days, and diseases logged in the last fortnight. '
      + 'Call this for questions about what needs attention right now.',
    input_schema: { type: 'object', properties: {}, required: [] },
  },
];

/** Resolve a free-text cow reference to a row, matching name then tag. */
async function findCow(nameOrTag) {
  const q = String(nameOrTag || '').trim();
  if (!q) return null;
  const { rows } = await pool.query(`
    SELECT id, name FROM cows
    WHERE LOWER(name) = LOWER($1) OR LOWER(tag) = LOWER($1)
    UNION ALL
    SELECT id, name FROM cows WHERE name ILIKE '%' || $1 || '%'
    LIMIT 1
  `, [q]);
  return rows[0] || null;
}

async function runChatTool(name, input) {
  switch (name) {
    case 'list_cows':
      return ctx.herdContext();

    case 'get_alerts':
      return ctx.alertSignals();

    case 'get_processing_month':
      return ctx.processingMonth(input?.month);

    case 'get_cow_dossier': {
      const cow = await findCow(input?.cow_name);
      if (!cow) {
        return {
          error: `No cow matches "${input?.cow_name}". Call list_cows to see the available names.`,
        };
      }
      return ctx.cowDossier(cow.id);
    }

    case 'get_farm_data': {
      const period = ctx.resolvePeriod(input?.from, input?.to);
      const want = Array.isArray(input?.sections) && input.sections.length
        ? new Set(input.sections)
        : new Set(['production', 'health', 'pregnancies', 'sales', 'inventory', 'processing']);

      const out = { period };
      const jobs = [];
      if (want.has('production'))  jobs.push(ctx.productionContext(period).then(v => { out.production = v; }));
      if (want.has('health'))      jobs.push(ctx.healthContext(period).then(v => { out.health = v; }));
      if (want.has('pregnancies')) jobs.push(ctx.pregnancyContext(period).then(v => { out.pregnancies = v; }));
      if (want.has('sales'))       jobs.push(ctx.salesContext(period).then(v => { out.sales = v; }));
      if (want.has('inventory'))   jobs.push(ctx.inventoryContext(period).then(v => { out.inventory = v; }));
      if (want.has('processing'))  jobs.push(ctx.processingContext().then(v => { out.processing = v; }));
      await Promise.all(jobs);
      return out;
    }

    default:
      return { error: `Unknown tool: ${name}` };
  }
}

const CHAT_SYSTEM = `
You are answering questions about Bushi Farm's records using the tools provided.

- Always fetch data before answering. Never answer a factual question about the
  farm from memory or from earlier turns alone if a tool can confirm it.
- Today's date is available to you in the user turn. Resolve relative dates
  ("last month", "this week") against it before calling a tool.
- Answer in prose. Use a short Markdown table only when the answer is genuinely
  a list of comparable rows, and keep explanation in the surrounding sentences
  rather than inside cells.
- Give the numbers. "Bella averaged 14.2 litres" beats "Bella did well".
- If the data does not answer the question, say exactly what is missing and
  which page of the app would let someone record it. Do not speculate.
- Keep answers short. Most questions deserve two to four sentences.
`.trim();

const MAX_CHAT_ITERATIONS = 8;

router.post('/chat', verifyToken, requireAi, async (req, res) => {
  const question = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!question) return res.status(400).json({ error: 'message is required' });
  if (question.length > 2000) return res.status(400).json({ error: 'message is too long' });

  // Prior turns from the client, trimmed to text only so nothing unexpected
  // gets replayed into the model.
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-10) : [];
  const messages = history
    .filter(m => (m?.role === 'user' || m?.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
    .map(m => ({ role: m.role, content: m.content.slice(0, 4000) }));

  messages.push({
    role: 'user',
    content: `Today is ${new Date().toISOString().slice(0, 10)}.\n\n${question}`,
  });

  const stream = openStream(res);

  let client;
  try {
    client = ai.getClient();
  } catch (err) {
    return stream.fail(err);
  }

  let emittedText = false;

  try {
    for (let i = 0; i < MAX_CHAT_ITERATIONS; i++) {
      if (stream.closed) return;

      const turn = client.beta.messages.stream({
        model: ai.MODEL,
        // Thinking is on by default on Opus 5 and shares this budget with the
        // reply. Tool results here are large, so leave real headroom — too low
        // and the turn is spent thinking, returning neither text nor a tool call.
        max_tokens: 16000,
        betas: [ai.FALLBACK_BETA],
        fallbacks: 'default',
        output_config: { effort: 'medium' },
        // Tool results are the bulk of the prompt on the second pass. Caching
        // the prefix means the follow-up turn reads them instead of re-paying.
        cache_control: { type: 'ephemeral' },
        system: `${ai.HOUSE_STYLE}\n\n${CHAT_SYSTEM}`,
        tools: CHAT_TOOLS,
        messages,
      });

      stream.onAbort(() => turn.abort());
      turn.on('text', (delta) => { emittedText = true; stream.send('delta', { text: delta }); });

      const message = await turn.finalMessage();
      if (stream.closed) return;

      const toolUses = message.content.filter(b => b.type === 'tool_use');
      console.log(
        `[ai] chat turn ${i + 1}: stop=${message.stop_reason} `
        + `tools=${toolUses.map(t => t.name).join(',') || 'none'} `
        + `text=${emittedText} in=${message.usage?.input_tokens} out=${message.usage?.output_tokens} `
        + `cache_read=${message.usage?.cache_read_input_tokens ?? 0}`
      );

      if (message.stop_reason === 'refusal') {
        stream.send('error', {
          error: 'Claude declined to answer that.',
          category: message.stop_details?.category || null,
        });
        return stream.end();
      }

      messages.push({ role: 'assistant', content: ai.sanitizeForEcho(message.content) });

      if (!toolUses.length) {
        // A turn that ran out of budget mid-thought returns no text and no tool
        // call. Without this the UI would show an empty bubble and look hung.
        if (!emittedText) {
          stream.send('error', {
            error: message.stop_reason === 'max_tokens'
              ? 'Ran out of room before answering. Try a narrower question.'
              : `No answer came back (stop reason: ${message.stop_reason}).`,
          });
          return stream.end();
        }
        stream.send('done', { model: message.model, usage: message.usage });
        return stream.end();
      }

      const results = [];
      for (const call of toolUses) {
        stream.send('tool', { name: call.name, input: call.input });
        try {
          const data = await runChatTool(call.name, call.input);
          const payload = JSON.stringify(data);
          console.log(`[ai]   ${call.name} -> ${(payload.length / 1024).toFixed(1)} KB`);
          results.push({
            type: 'tool_result',
            tool_use_id: call.id,
            content: payload,
          });
        } catch (err) {
          console.error(`[ai] tool ${call.name} failed:`, err);
          results.push({
            type: 'tool_result',
            tool_use_id: call.id,
            content: `Query failed: ${err.message}`,
            is_error: true,
          });
        }
      }
      messages.push({ role: 'user', content: results });
    }

    stream.send('error', { error: 'Gave up after too many lookups. Try a narrower question.' });
    stream.end();
  } catch (err) {
    if (stream.closed) return;   // aborted by the client, not a real failure
    console.error('[ai] chat failed:', err);
    stream.fail(err);
  }
});

/* ══════════════════════════════════
   SAVED REPORTS
══════════════════════════════════ */

router.get('/reports', verifyToken, async (req, res) => {
  try {
    const rows = await ai.listReports({
      kind:  req.query.kind || undefined,
      cowId: req.query.cow_id ? parseInt(req.query.cow_id, 10) : undefined,
      limit: req.query.limit,
    });
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reports/:id', verifyToken, async (req, res) => {
  try {
    const report = await ai.getReport(parseInt(req.params.id, 10));
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/reports/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await ai.deleteReport(parseInt(req.params.id, 10));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
