/* ══════════════════════════════════════════════════════════════
   CLAUDE CLIENT + REPORT PERSISTENCE

   One place that knows how to talk to Claude, and one place that
   knows how to store what came back. Routes should not construct
   API requests directly.
══════════════════════════════════════════════════════════════ */
require('dotenv').config();
const Anthropic = require('@anthropic-ai/sdk');
const { pool }  = require('./db');

const MODEL = process.env.ANTHROPIC_MODEL || 'claude-opus-5';

/* Server-side refusal fallback: if Claude's safety classifiers decline a
   request, the API transparently re-runs it on Anthropic's recommended
   fallback model instead of handing us a dead response. Farm data should
   never trip a classifier, but this costs nothing when it never fires. */
const FALLBACK_BETA = 'server-side-fallback-2026-07-01';

let _client = null;

/** Thrown when ANTHROPIC_API_KEY is not configured. Routes turn this into a 503. */
class AiUnavailableError extends Error {
  constructor(msg) { super(msg); this.name = 'AiUnavailableError'; }
}

function getClient() {
  if (_client) return _client;
  if (!process.env.ANTHROPIC_API_KEY) {
    throw new AiUnavailableError(
      'AI features are not configured. Set ANTHROPIC_API_KEY in the backend .env file.'
    );
  }
  _client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  return _client;
}

function aiConfigured() {
  return Boolean(process.env.ANTHROPIC_API_KEY);
}

/* ══════════════════════════════════
   SHARED PROMPT VOICE
══════════════════════════════════ */

/**
 * Prepended to every system prompt. Opus 5 writes long and expands scope by
 * default, so the length and scope guidance here is load-bearing — without it
 * reports run two to three times longer than anyone wants to read.
 */
const HOUSE_STYLE = `
You are the analyst for Bushi Farm, a dairy farm that tracks milk production,
animal health, breeding, sales, inventory, and a milk processing unit.

You are writing for the farm manager and veterinary staff. They know the farm;
they do not need cattle husbandry explained to them. They need to know what the
numbers say and what to do about it.

How to write:
- Lead with the outcome. The first sentence answers "what happened" — the thing
  the reader would ask for if they said "just give me the headline".
- Ground every claim in the data you were given. Cite the actual figure. If the
  data does not support a conclusion, say what is missing instead of guessing.
- Keep it tight. Cover the substance and stop. No filler sections, no restating
  the same finding in a summary at the end, no boilerplate.
- Write complete sentences in plain language. No arrow chains, no invented
  abbreviations, no jargon the reader has not already seen in the app.
- Use figures the reader can act on: litres, dates, cow names, percentages.
- Deliver what was asked at the scope asked. Do not append extra analysis,
  recommendations, or sections that were not requested.

Data caveats you must respect:
- Sparse data is not the same as bad performance. If a cow has three records in
  the period, say the sample is thin rather than declaring a trend.
- Currency is unlabelled in the database. Write amounts as plain numbers and do
  not invent a currency symbol.
- The processing unit is organised by monthly upload, not calendar date, so it
  may not line up with the report period. Note this if you cite it.
`.trim();

/* ══════════════════════════════════
   GENERATION
══════════════════════════════════ */

/**
 * Stream a single-turn generation from Claude.
 *
 * @param {object}   opts
 * @param {string}   opts.system      System prompt (HOUSE_STYLE is prepended).
 * @param {string}   opts.user        User turn content.
 * @param {number}   [opts.maxTokens] Caps thinking + response together.
 * @param {string}   [opts.effort]    low | medium | high | xhigh | max
 * @param {Function} [opts.onText]    Called with each text delta as it arrives.
 * @param {Function} [opts.onAbortHandle] Receives a function that cancels the
 *        in-flight request, so a disconnected client stops costing tokens.
 * @returns {Promise<{text, model, usage, stopReason, stopDetails, refused}>}
 */
async function generate({
  system, user, maxTokens = 16000, effort = 'high', onText, onAbortHandle,
}) {
  const client = getClient();

  const stream = client.beta.messages.stream({
    model: MODEL,
    max_tokens: maxTokens,
    betas: [FALLBACK_BETA],
    fallbacks: 'default',
    output_config: { effort },
    system: `${HOUSE_STYLE}\n\n${system}`,
    messages: [{ role: 'user', content: user }],
  });

  onAbortHandle?.(() => stream.abort());
  if (onText) stream.on('text', onText);

  const message = await stream.finalMessage();

  if (message.stop_reason === 'refusal') {
    return {
      text: '',
      model: message.model,
      usage: message.usage,
      stopReason: 'refusal',
      stopDetails: message.stop_details || null,
      refused: true,
    };
  }

  const text = message.content
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('');

  return {
    text,
    model: message.model,
    usage: message.usage,
    stopReason: message.stop_reason,
    stopDetails: message.stop_details || null,
    refused: false,
  };
}

/**
 * Strip blocks that must not be echoed back after a mid-output fallback.
 * Everything before the last `fallback` block that is model-internal
 * (thinking, unresolved tool use) is dropped; text and post-boundary
 * blocks pass through unchanged.
 */
function sanitizeForEcho(content) {
  const lastFallback = content.map(b => b.type).lastIndexOf('fallback');
  if (lastFallback === -1) return content;

  const DROP = new Set(['thinking', 'redacted_thinking', 'tool_use', 'server_tool_use']);
  return content.filter((b, i) => !(i < lastFallback && DROP.has(b.type)));
}

module.exports = {
  MODEL,
  FALLBACK_BETA,
  HOUSE_STYLE,
  AiUnavailableError,
  getClient,
  aiConfigured,
  generate,
  sanitizeForEcho,
};

/* ══════════════════════════════════
   PERSISTENCE — ai_reports
══════════════════════════════════ */

async function initAiTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_reports (
      id            SERIAL PRIMARY KEY,
      -- 'period' | 'briefing' | 'cow_summary'
      kind          TEXT NOT NULL,
      title         TEXT NOT NULL,
      content       TEXT NOT NULL,
      -- request parameters, so a report can be reproduced or matched to a cache key
      params        JSONB DEFAULT '{}',
      model         TEXT,
      usage         JSONB DEFAULT '{}',
      period_from   DATE,
      period_to     DATE,
      cow_id        INTEGER REFERENCES cows(id) ON DELETE CASCADE,
      generated_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_ai_reports_kind    ON ai_reports(kind);
    CREATE INDEX IF NOT EXISTS idx_ai_reports_created ON ai_reports(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_ai_reports_cow     ON ai_reports(cow_id);
  `);
  console.log('✓ AI reports table ready');
}

async function saveReport({
  kind, title, content, params = {}, model, usage = {},
  periodFrom = null, periodTo = null, cowId = null, userId = null,
}) {
  const { rows } = await pool.query(`
    INSERT INTO ai_reports
      (kind, title, content, params, model, usage, period_from, period_to, cow_id, generated_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    RETURNING id, kind, title, created_at
  `, [
    kind, title, content, JSON.stringify(params), model, JSON.stringify(usage),
    periodFrom, periodTo, cowId, userId,
  ]);
  return rows[0];
}

async function listReports({ kind, cowId, limit = 50 } = {}) {
  const where = [];
  const args  = [];
  if (kind)  { args.push(kind);  where.push(`r.kind = $${args.length}`); }
  if (cowId) { args.push(cowId); where.push(`r.cow_id = $${args.length}`); }
  args.push(Math.min(Number(limit) || 50, 200));

  const { rows } = await pool.query(`
    SELECT r.id, r.kind, r.title, r.model,
           TO_CHAR(r.period_from, 'YYYY-MM-DD') AS period_from,
           TO_CHAR(r.period_to,   'YYYY-MM-DD') AS period_to,
           r.cow_id, c.name AS cow_name,
           u.username AS generated_by,
           r.created_at,
           LEFT(r.content, 240) AS excerpt
    FROM ai_reports r
    LEFT JOIN cows  c ON c.id = r.cow_id
    LEFT JOIN users u ON u.id = r.generated_by
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY r.created_at DESC
    LIMIT $${args.length}
  `, args);
  return rows;
}

async function getReport(id) {
  const { rows } = await pool.query(`
    SELECT r.*, c.name AS cow_name, u.username AS generated_by_username
    FROM ai_reports r
    LEFT JOIN cows  c ON c.id = r.cow_id
    LEFT JOIN users u ON u.id = r.generated_by
    WHERE r.id = $1
  `, [id]);
  return rows[0] || null;
}

async function deleteReport(id) {
  await pool.query('DELETE FROM ai_reports WHERE id = $1', [id]);
}

/** Most recent report of a kind generated today — used to avoid re-billing briefings. */
async function findTodaysReport(kind, cowId = null) {
  const { rows } = await pool.query(`
    SELECT * FROM ai_reports
    WHERE kind = $1
      AND ($2::int IS NULL OR cow_id = $2)
      AND created_at::date = CURRENT_DATE
    ORDER BY created_at DESC LIMIT 1
  `, [kind, cowId]);
  return rows[0] || null;
}

Object.assign(module.exports, {
  initAiTables,
  saveReport,
  listReports,
  getReport,
  deleteReport,
  findTodaysReport,
});
