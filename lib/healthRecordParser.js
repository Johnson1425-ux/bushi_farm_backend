/* ══════════════════════════════════════════════════════════════
   INDIVIDUAL HEALTH RECORD — READING A FILLED .docx BACK

   Reads an uploaded copy of the form into the same shape the in-app form
   posts, using healthRecordForm.js for every label it looks for.

   It reads the document as tables, not as a stream of text. The old parser
   took mammoth's raw text, where a table collapses into a column of lines
   and a label, its answer, and the label below it are indistinguishable —
   so it had to guess which line was an answer, and on a form where a vet
   had left a box empty it would take the next field's label as the value.
   mammoth's HTML keeps the cell boundaries, so "the answer" is "the cell
   after the label", which is not a guess.

   Ruled lines are still read from the raw text, for forms typed straight
   onto the original sheet rather than into the template this app hands
   out: there, "Major complaint" and the answer really are one line.
══════════════════════════════════════════════════════════════ */

const mammoth = require('mammoth');
const {
  SECTIONS, SYSTEMS, SYSTEM_STATUSES, SYSTEM_ALIASES, TEXT_FIELDS, lookupsFor,
} = require('./healthRecordForm');

/* ─── text handling ───────────────────────────────────────────── */

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };

function stripTags(html) {
  return html
    .replace(/<\/(p|div|br)>/gi, ' ')
    .replace(/<[^>]*>/g, '')
    .replace(/&[a-z#0-9]+;/gi, m => ENTITIES[m.toLowerCase()] ?? m)
    .replace(/\s+/g, ' ')
    .trim();
}

/** Punctuation and case carry no meaning in a label, only the words do. */
function norm(s) {
  return String(s || '').toUpperCase().replace(/[^A-Z0-9]+/g, ' ').trim();
}

/**
 * A cell that is blank, or a ruled line the vet typed nothing onto.
 * A row of underscores is how the printed form draws an empty answer.
 */
function isBlank(s) {
  const t = String(s || '').trim();
  return t === '' || /^[_.\-\s]+$/.test(t);
}

function clean(s) {
  if (isBlank(s)) return null;
  return String(s).replace(/^[\s:_]+/, '').replace(/[\s_]+$/, '').trim() || null;
}

/* ─── document shape ──────────────────────────────────────────── */

/**
 * The document's tables, each as an array of rows of plain-text cells.
 *
 * Nested tables would defeat the non-greedy close-tag match; the form has
 * none, and Word has no way to produce one from this template.
 */
function extractTables(html) {
  const tables = [];
  for (const [, inner] of html.matchAll(/<table[^>]*>([\s\S]*?)<\/table>/gi)) {
    const rows = [];
    for (const [, rowHtml] of inner.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)) {
      const cells = [...rowHtml.matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi)]
        .map(m => stripTags(m[1]));
      if (cells.length) rows.push(cells);
    }
    if (rows.length) tables.push(rows);
  }
  return tables;
}

/**
 * Every wording that is a label somewhere on the form.
 *
 * Used to tell an answer from the next question: a cell holding one of
 * these is a label the vet was asked to fill in beside, never the value
 * of the field above it.
 */
const KNOWN_LABELS = new Set([
  ...TEXT_FIELDS.flatMap(f => lookupsFor(f).map(norm)),
  ...SYSTEMS.map(norm),
  ...Object.keys(SYSTEM_ALIASES).map(norm),
  ...Object.values(SECTIONS).map(norm),
  ...['SYSTEM', 'STATUS NORMAL ABNORMAL', 'SPECIFIC OBSERVATIONS',
      'DRUG VACCINE', 'PRESCRIPTION DOSE DOSAGE AND ROUTE', 'BLOOD SMEAR'].map(norm),
]);

/**
 * A line that heads a section rather than answering a question.
 *
 * The catalogue knows the form's own headings; this also catches one a
 * farm has added, which would otherwise be read as the answer to whatever
 * field the heading happens to follow. Several words, all capitals, no
 * digits — an answer in that shape ("PREGNANT") is one word and survives.
 */
function isHeading(line) {
  const t = String(line || '').trim();
  if (KNOWN_LABELS.has(norm(t))) return true;
  return /^[A-Z][A-Z\s,&()\/.-]{10,}$/.test(t) && t.split(/\s+/).length > 1;
}

/** Does this cell hold `label`, either exactly or as its opening words? */
function labelMatch(cellText, label) {
  const c = norm(cellText), l = norm(label);
  if (!c || !l) return null;
  if (c === l) return 'exact';
  /* The space makes it a word boundary: "PCV (%)" is the PCV field,
     "Agent" is not the Age field. */
  if (c.startsWith(l + ' ')) return 'prefix';
  return null;
}

/* ─── finding one field ───────────────────────────────────────── */

/**
 * The answer to `field`, looked for in the document's tables.
 *
 * Two layouts count as an answer, and only these two: the first non-blank
 * cell to the right of the label — the label-and-box rows that make up
 * most of the form — and, where nothing sits to its right, the cell
 * directly beneath it, which is how the vitals strip is laid out.
 *
 * The cell beneath is only taken when it is not itself a label. That is
 * the case the old parser got wrong: in a label-and-box table where the
 * vet left a box empty, what sits below the label is the next question.
 */
function fromTables(tables, field, { exactOnly }) {
  for (const lookup of lookupsFor(field)) {
    for (const rows of tables) {
      for (let r = 0; r < rows.length; r++) {
        for (let c = 0; c < rows[r].length; c++) {
          const kind = labelMatch(rows[r][c], lookup);
          if (!kind || (exactOnly && kind !== 'exact')) continue;

          /* An answer typed after the label inside the same cell — but only
             where the cell is not simply a longer label. The form carries
             short aliases of its own headings ("Bacteriology" for
             "Bacteriology culture & senstivity results"), and without this
             the tail of the printed label reads as the vet's answer. */
          if (kind === 'prefix' && !KNOWN_LABELS.has(norm(rows[r][c]))) {
            const rest = clean(String(rows[r][c]).slice(matchedLength(rows[r][c], lookup)));
            if (rest) return rest;
          }

          /* Scan right for the answer, stopping at the next heading: on the
             vitals strip the five labels share one row, and without this
             "Body temperature" reads the pulse-rate heading as its value. */
          let answer = null;
          for (let k = c + 1; k < rows[r].length; k++) {
            if (isBlank(rows[r][k])) continue;
            if (KNOWN_LABELS.has(norm(rows[r][k]))) break;
            answer = clean(rows[r][k]);
            break;
          }
          if (answer) return answer;

          const below = rows[r + 1]?.[c];
          if (below !== undefined && !isBlank(below) && !KNOWN_LABELS.has(norm(below)))
            return clean(below);
        }
      }
    }
  }
  return null;
}

/**
 * The answer to `field` on a ruled line — "Major complaint_____ off feed".
 *
 * Anchored at the start of the line so "Date" cannot match the tail of
 * "Milk withdraw end date", which is how the old parser dated records to
 * the withdrawal period.
 */
function fromLines(lines, field, { allowNextLine }) {
  for (const lookup of lookupsFor(field)) {
    for (let i = 0; i < lines.length; i++) {
      const kind = labelMatch(lines[i], lookup);
      if (!kind) continue;

      if (kind === 'prefix' && !KNOWN_LABELS.has(norm(lines[i]))) {
        /* Slice by words rather than by length: the line's punctuation and
           the catalogue's need not agree for the label to have matched. */
        const rest = clean(lines[i].slice(matchedLength(lines[i], lookup)));
        if (rest) return rest;
      }
      if (!allowNextLine) continue;

      const next = lines[i + 1];
      if (next && !isBlank(next) && !isHeading(next)) return clean(next);
    }
  }
  return null;
}

/**
 * How much of `line` the label consumed, counting the line's own
 * characters rather than the catalogue label's.
 */
function matchedLength(line, label) {
  const wanted = norm(label).split(' ').length;
  let seen = 0, i = 0;
  while (i < line.length && seen < wanted) {
    while (i < line.length && !/[A-Za-z0-9]/.test(line[i])) i++;
    while (i < line.length && /[A-Za-z0-9]/.test(line[i])) i++;
    seen++;
  }
  return i;
}

/* ─── the tables that are not label-and-box ───────────────────── */

/**
 * The twelve-row examination grid: system, status, observations.
 *
 * Found by its heading rather than by position, so a vet who adds a note
 * above it does not shift the reading.
 */
function readFindings(tables, lines) {
  const grid = tables.find(rows =>
    rows[0]?.some(c => norm(c) === 'SYSTEM') &&
    rows[0]?.some(c => norm(c).startsWith('STATUS'))
  );

  const out = [];
  if (grid) {
    for (const row of grid.slice(1)) {
      const name = clean(row[0]);
      if (!name) continue;
      const system = SYSTEM_ALIASES[name] ||
                     SYSTEMS.find(s => norm(s) === norm(name)) || name;
      const status = SYSTEM_STATUSES.find(s => norm(s) === norm(row[1])) || null;
      const observations = clean(row[2]);
      if (status || observations) out.push({ system, status, observations });
    }
    return out;
  }

  /* No grid — a form typed as plain paragraphs. Fall back to the system
     name followed by its verdict on the next line. */
  for (const system of SYSTEMS) {
    const names = [system, ...Object.keys(SYSTEM_ALIASES).filter(a => SYSTEM_ALIASES[a] === system)];
    for (let i = 0; i < lines.length; i++) {
      if (!names.some(n => labelMatch(lines[i], n))) continue;
      const status = SYSTEM_STATUSES.find(s => norm(s) === norm(lines[i + 1]));
      if (!status) continue;
      const next = lines[i + 2];
      const observations = next && !isHeading(next) ? clean(next) : null;
      out.push({ system, status, observations });
      break;
    }
  }
  return out;
}

/** The prescription table: a drug and what was given. */
function readTreatments(tables) {
  const grid = tables.find(rows =>
    rows[0]?.some(c => norm(c) === norm('Drug/vaccine'))
  );
  if (!grid) return [];

  const head = grid[0].findIndex(c => norm(c) === norm('Drug/vaccine'));
  return grid.slice(1)
    .map(row => ({ drug: clean(row[head]), prescription: clean(row[head + 1]) || '' }))
    .filter(t => t.drug && !KNOWN_LABELS.has(norm(t.drug)));
}

/* ─── the whole form ──────────────────────────────────────────── */

/**
 * Every text field, looked for in the order that puts the most reliable
 * reading first: an exact label in a table beats a partial one, and any
 * table beats a ruled line, where what counts as the answer is down to
 * where the vet's cursor happened to be.
 */
function readTextFields(tables, lines) {
  const out = {};
  const order = [
    t => fromTables(tables, t, { exactOnly: true }),
    t => fromTables(tables, t, { exactOnly: false }),
    t => fromLines(lines, t, { allowNextLine: false }),
    t => fromLines(lines, t, { allowNextLine: true }),
  ];
  for (const field of TEXT_FIELDS) {
    let value = null;
    for (const attempt of order) {
      value = attempt(field);
      if (value) break;
    }
    out[field.key] = value;
  }
  return out;
}

/**
 * Read a filled form.
 *
 * Takes the uploaded file itself rather than text already pulled out of
 * it, because it needs the document both ways — as tables and as lines —
 * and a caller that extracted only one of them could not say so.
 */
async function parseHealthDocx(buffer) {
  const [htmlRes, textRes] = await Promise.all([
    mammoth.convertToHtml({ buffer }),
    mammoth.extractRawText({ buffer }),
  ]);

  const tables = extractTables(htmlRes.value);
  const lines  = textRes.value.split('\n').map(l => l.trim()).filter(l => !isBlank(l));

  return {
    fields: {
      ...readTextFields(tables, lines),
      clinical_findings: readFindings(tables, lines),
      treatments:        readTreatments(tables),
    },
    warnings: [...htmlRes.messages, ...textRes.messages],
  };
}

module.exports = { parseHealthDocx, extractTables, norm, isBlank };
