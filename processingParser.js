/* ══════════════════════════════════════════════════════════════
   PROCESSING UNIT WORKBOOK PARSER

   Reads a month of processing-unit figures out of a spreadsheet and hands
   back structured data. Two shapes of workbook are accepted:

   TEMPLATE — the workbook produced by processingTemplate.js. Sections are
     located by hidden ##ANCHOR## markers in column A, never by row number,
     so adding a note above a block cannot shift figures into the wrong row.

   LEGACY — the farm's own BUSH_PROCESSING_UNIT.xlsx, which has no anchors:
     one sheet per month with the blocks stacked under free-text banners, a
     separate "DAMEGE <MONTH>" sheet for write-offs, and a SUMMARY sheet of
     formulas. Blocks are found by recognising runs of catalogue rows and
     classifying them by the nearest banner above. Years of history live in
     these files, so refusing them would mean retyping all of it.

   Both paths produce the same result: one entry per month, with opening
   balance, daily milk received, and daily packed / damaged packs.

   ISSUED is read where a sheet has it, but it is not the app's answer to
   how much went out. Stock leaves the store on an issue note naming the
   branch it went to, and that ledger is the record. The sheet's figure is
   kept for the months before anyone was raising issue notes — otherwise
   every month of the farm's own history reads as nothing issued at all,
   which is worse than the imperfect figure it actually has.

   Which of the two a month uses is decided on read, not here — see
   lib/processingReconcile.js. The block is optional in both layouts: new
   template sheets no longer carry one.
   Litres are always derived from the pack size, never read from the sheet,
   so a stale litres column in an old file cannot contradict the units.

   Problems are separated by severity. `errors` mean the file cannot be
   trusted and nothing is imported; `warnings` are things the operator
   should look at but which do not put the figures in doubt.
══════════════════════════════════════════════════════════════ */

const XLSX = require('xlsx');
const {
  RECEIVED_SOURCES, PRODUCT_ROWS, MONTHS,
  norm, canonical, lookupProductRow, litresFor, daysInMonth,
} = require('./processingCatalog');

const MAX_DAYS = 31;
const SKIP_SHEETS = new Set(['INSTRUCTIONS', 'SUMMARY', 'NOTES']);
const SOURCE_SET = new Set(RECEIVED_SOURCES.map(canonical));

/* ── cell access ─────────────────────────────────────────── */

const ref = (col, row) => XLSX.utils.encode_cell({ c: col - 1, r: row - 1 });

function rawAt(ws, col, row) {
  const cell = ws[ref(col, row)];
  return cell ? cell.v : undefined;
}

function strAt(ws, col, row) {
  const v = rawAt(ws, col, row);
  return v == null ? '' : String(v);
}

/**
 * Numeric value of a cell, or null when the cell is empty.
 *
 * Hand-kept sheets are full of cells that look empty but are not — a lone
 * "o" typed instead of a zero, a run of spaces, a dash. Those come back as
 * `{ bad: <text> }` so the caller can warn about them by cell reference
 * instead of silently reading them as nothing.
 */
function numAt(ws, col, row) {
  const v = rawAt(ws, col, row);
  if (v == null || v === '') return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  const s = String(v).trim();
  if (s === '' || s === '-' || s === '—') return null;
  const n = Number(s);
  if (Number.isFinite(n)) return n;
  return { bad: s };
}

function decodeRange(ws) {
  return XLSX.utils.decode_range(ws['!ref'] || 'A1:A1');
}

/** Every non-empty string in a row, upper-cased — used to read banners. */
function rowText(ws, row, maxCol) {
  const parts = [];
  for (let c = 1; c <= maxCol; c++) {
    const v = rawAt(ws, c, row);
    if (typeof v === 'string' && v.trim()) parts.push(v.trim().toUpperCase());
  }
  return parts.join(' ');
}

/* ── month naming ────────────────────────────────────────── */

/** Pull "JUNE 2026" out of a sheet name, however it is decorated. */
function monthFromSheetName(name) {
  const n = norm(name);
  const month = Object.keys(MONTHS).find(m => n.includes(m));
  const yearMatch = n.match(/\b(20\d{2})\b/);
  if (!month || !yearMatch) return null;
  return { month, monthNum: MONTHS[month], year: Number(yearMatch[1]) };
}

/* ── shared accumulator ──────────────────────────────────── */

function emptyMonth(period, sheetName, source) {
  return {
    month: period.month,
    monthNum: period.monthNum,
    year: period.year,
    label: `${period.month} ${period.year}`,
    sheets: [sheetName],
    source,
    opening: [],
    openingFreshLitres: 0,
    received: [],
    packed: [],
    issued: [],
    damaged: [],
    freshDamage: [],
  };
}

const SECTION_KEY = { PACKED: 'packed', ISSUED: 'issued', DAMAGED: 'damaged' };

/** Record one pack figure, deriving litres from the size. */
function pushPack(month, section, { day, product, size, units }) {
  if (!units) return;
  month[SECTION_KEY[section]].push({
    day, product, size, units, litres: litresFor(size, units),
  });
}

/* ══════════════════════════════════════════════════════════
   TEMPLATE PATH — anchor driven
══════════════════════════════════════════════════════════ */

const DAY_COL_START = 4;

function findAnchors(ws) {
  const anchors = {};
  const rng = decodeRange(ws);
  for (let r = rng.s.r; r <= rng.e.r; r++) {
    const m = /^##(.+?)##$/.exec(strAt(ws, 1, r + 1).trim());
    if (m) anchors[m[1].toUpperCase()] = r + 1;
  }
  return anchors;
}

/**
 * Read a block of catalogue rows starting at `row`, stopping at the first
 * row that is not a recognised product. Returns the row after the block.
 *
 * A row whose product/size cannot be matched at all is an error — it means
 * a label was overtyped and its figures would be dropped. A catalogue row
 * that is simply absent is only a warning: earlier templates were issued
 * without VANILLA 2L, and those workbooks are still being filled in. The
 * missing size imports as zero, which is what it is.
 */
function readTemplateRows(ws, row, handler, ctx) {
  const seen = new Set();
  while (seen.size < PRODUCT_ROWS.length) {
    const product = strAt(ws, 2, row);
    const size = strAt(ws, 3, row);
    if (!product.trim() && !size.trim()) break;          // end of block
    /* The block's own total line. Normally never reached — the loop stops
       once every product has been seen — but when a label has been edited
       one product is never seen, and the loop would read the total as a
       second unknown product and report it, burying the real problem. */
    if (/^TOTAL\b/.test(norm(product)) && !size.trim()) break;

    const entry = lookupProductRow(product, size);
    if (!entry) {
      ctx.errors.push(
        `[${ctx.sheet}/${ctx.section}] row ${row} reads "${product} / ${size}", which is not a product `
        + `this app knows. Restore the original label, or download a fresh template.`
      );
      row++;
      continue;
    }
    const key = `${entry.product}|${entry.size}`;
    if (seen.has(key)) {
      ctx.errors.push(`[${ctx.sheet}/${ctx.section}] row ${row}: "${entry.product} ${entry.size}" appears twice in the same block.`);
      row++;
      continue;
    }
    seen.add(key);
    handler(entry, row);
    row++;
  }

  const missing = PRODUCT_ROWS.filter(r => !seen.has(`${r.product}|${r.size}`));
  if (missing.length) {
    ctx.warnings.push(
      `[${ctx.sheet}/${ctx.section}] this sheet has no row for `
      + `${missing.map(r => `${r.product} ${r.size}`).join(', ')}; those imported as zero. `
      + `Download a fresh template to record them.`
    );
  }
  return row;
}

function parseTemplateSheet(ws, sheetName, out) {
  const anchors = findAnchors(ws);
  if (!anchors.META) return false;   // not a template sheet

  const month = canonical(strAt(ws, 3, anchors.META));
  const year = numAt(ws, 5, anchors.META);
  const yearNum = typeof year === 'number' ? year : null;

  if (!MONTHS[month]) {
    out.errors.push(`[${sheetName}] cell C${anchors.META} should hold the month name, but reads "${strAt(ws, 3, anchors.META)}".`);
    return true;
  }
  if (!yearNum) {
    out.errors.push(`[${sheetName}] cell E${anchors.META} should hold the year, but is empty or not a number.`);
    return true;
  }

  const period = { month, monthNum: MONTHS[month], year: yearNum };
  const m = emptyMonth(period, sheetName, 'template');
  const days = daysInMonth(period.monthNum, period.year);
  const ctx = { sheet: sheetName, section: '', errors: out.errors, warnings: out.warnings };

  /* Reads one day cell, rejecting negatives and flagging junk text. */
  const dayValue = (row, day, what) => {
    const v = numAt(ws, DAY_COL_START + day - 1, row);
    if (v == null) return 0;
    if (typeof v === 'object') {
      out.warnings.push(`[${sheetName}/${ctx.section}] ${what} day ${day}: ignored "${v.bad}" — not a number.`);
      return 0;
    }
    if (v < 0) {
      out.errors.push(`[${sheetName}/${ctx.section}] ${what} day ${day}: negative value ${v}.`);
      return 0;
    }
    if (v > 0 && day > days) {
      out.errors.push(`[${sheetName}/${ctx.section}] ${what}: ${period.month} ${period.year} has ${days} days, but day ${day} has a figure.`);
      return 0;
    }
    return v;
  };

  /* ── opening balance ── */
  if (anchors.OPENING) {
    ctx.section = 'OPENING';
    let row = anchors.OPENING + 2;
    row = readTemplateRows(ws, row, (entry, r) => {
      const v = numAt(ws, DAY_COL_START, r);
      const units = typeof v === 'number' && v > 0 ? v : 0;
      if (units) m.opening.push({ ...entry, units, litres: litresFor(entry.size, units) });
    }, ctx);
    // The fresh-milk line sits directly under the product rows.
    if (canonical(strAt(ws, 2, row)) === 'FRESH MILK') {
      const v = numAt(ws, DAY_COL_START, row);
      if (typeof v === 'number' && v > 0) m.openingFreshLitres = v;
    }
  }

  /* ── milk received ── */
  if (!anchors.RECEIVED) {
    out.errors.push(`[${sheetName}] the MILK RECEIVED section marker is missing — column A was edited or the block was deleted.`);
  } else {
    ctx.section = 'RECEIVED';
    let row = anchors.RECEIVED + 2;
    const seen = new Set();
    for (let i = 0; i < RECEIVED_SOURCES.length; i++, row++) {
      const src = canonical(strAt(ws, 3, row));
      if (!SOURCE_SET.has(src)) break;
      seen.add(src);
      for (let d = 1; d <= MAX_DAYS; d++) {
        const litres = dayValue(row, d, src);
        if (litres) m.received.push({ day: d, source: src, litres });
      }
    }
    for (const s of RECEIVED_SOURCES) {
      if (!seen.has(canonical(s))) out.errors.push(`[${sheetName}/RECEIVED] the "${s}" row is missing.`);
    }
  }

  /* ── packed / issued / damaged ──
     PROCESSED is the name the first version of this template gave the
     packed block. Workbooks handed out under that name are still in use,
     so it is accepted as a fallback when there is no PACKED block. */
  const blocks = [
    ['PACKED', anchors.PACKED || anchors.PROCESSED, true],
    ['ISSUED', anchors.ISSUED, false],
    ['DAMAGED', anchors.DAMAGED, false],
  ];
  for (const [section, anchorRow, required] of blocks) {
    if (!anchorRow) {
      if (required) {
        out.errors.push(`[${sheetName}] the ${section} section marker is missing — column A was edited or the block was deleted.`);
      } else if (section === 'DAMAGED') {
        out.warnings.push(`[${sheetName}] no DAMAGED block on this sheet; write-offs will be recorded as zero.`);
      }
      // No ISSUED block is expected: issuing is recorded in the app.
      continue;
    }
    ctx.section = section;
    readTemplateRows(ws, anchorRow + 2, (entry, r) => {
      for (let d = 1; d <= MAX_DAYS; d++) {
        const units = dayValue(r, d, `${entry.product} ${entry.size}`);
        pushPack(m, section, { day: d, ...entry, units });
      }
    }, ctx);
  }

  /* ── fresh milk damaged ── */
  if (anchors.FRESHDAMAGE) {
    ctx.section = 'FRESH MILK DAMAGED';
    const row = anchors.FRESHDAMAGE + 2;
    for (let d = 1; d <= MAX_DAYS; d++) {
      const litres = dayValue(row, d, 'fresh milk');
      if (litres) m.freshDamage.push({ day: d, litres });
    }
  }

  out.months.push(m);
  return true;
}

/* ══════════════════════════════════════════════════════════
   LEGACY PATH — the farm's own BUSH_PROCESSING_UNIT layout
══════════════════════════════════════════════════════════ */

/**
 * A day-header row is one carrying a long ascending run of day numbers.
 * Returns { colToDay, openingCol } — openingCol is the "B/D" column when
 * the sheet carries last month's balance in front of day 1.
 */
function readDayHeader(ws, row, maxCol) {
  const colToDay = new Map();
  let openingCol = null;
  let last = 0;
  for (let c = 1; c <= maxCol; c++) {
    const v = rawAt(ws, c, row);
    if (typeof v === 'string' && norm(v) === 'B D') { openingCol = c; continue; }
    if (typeof v !== 'number' || !Number.isInteger(v)) continue;
    if (v < 1 || v > MAX_DAYS) continue;
    if (v <= last) continue;                 // must ascend; ignore stray numbers
    colToDay.set(c, v);
    last = v;
  }
  return colToDay.size >= 20 ? { colToDay, openingCol } : null;
}

/**
 * Classify a block of catalogue rows from the free text above it.
 *
 * The distinction that matters most is PACKED versus the "PROCESSED MILK
 * LITRES" mirror directly below it: both hold the same products in the same
 * order, and counting the mirror as production would roughly double every
 * month's output.
 */
function classifyBlock(bannerText, sheetIsDamage) {
  if (sheetIsDamage) return 'DAMAGED';
  const t = bannerText;
  if (/\bDAM[EA]GE/.test(t)) return 'DAMAGED';
  if (/\bLITRES?\b/.test(t)) return 'SKIP_LITRES';
  if (/\bSTOCK\b/.test(t)) return 'SKIP_STOCK';
  if (/\bISSUED\b/.test(t)) return 'ISSUED';
  if (/\bPACKED\b/.test(t) || /PROCESS(ED|ING) MILK/.test(t)) return 'PACKED';
  return null;
}

/**
 * Column C reads like a pack size — "1L", "150ML", "0.5 CHUPA", "PACT O.5L" —
 * whether or not the catalogue knows it.
 *
 * This is how a product row the app has never heard of is told apart from
 * the other things that sit in and around a block: a TOTAL line carries a
 * number or nothing in column C, a note carries words with no quantity. A
 * new product added to the workbook carries a size, because every product
 * row does.
 */
function looksLikeSize(text) {
  const t = norm(text);
  return /\d/.test(t) && /(ML|L\b|LTR|LITRE|CUP|CHUPA|PACK|PACT)/.test(t);
}

/**
 * Walk a legacy sheet and return its blocks:
 *   { kind, headerRow, rows: [{ row, product, size }] }
 *
 * A block is a run of rows whose column C holds a catalogue pack size;
 * column B names the product only on its first row, so the product is
 * carried down. Single blank rows inside a run are tolerated — the source
 * workbook has a few, left over from deleted sizes.
 *
 * A row that looks like a product row but names something the catalogue
 * does not know stays part of the block, listed under `unknown` rather
 * than `rows`. It used to end the block instead: appended at the bottom it
 * was then skipped without a word, and its whole month of figures vanished
 * from an upload that reported success; placed in the middle it split the
 * block in two, and the upload was refused for having "a second PACKED
 * block" — true, and no help at all in finding the row that caused it.
 */
function findLegacyBlocks(ws, sheetIsDamage, maxCol, maxRow) {
  const blocks = [];
  const headers = [];        // day-header rows, in order

  for (let r = 1; r <= maxRow; r++) {
    const h = readDayHeader(ws, r, maxCol);
    if (h) headers.push({ row: r, ...h });
  }

  let r = 1;
  let lastProduct = '';
  let prevEnd = 0;           // last row the previous block consumed
  while (r <= maxRow) {
    const entry = lookupProductRow(strAt(ws, 2, r) || lastProduct, strAt(ws, 3, r));
    if (!entry) { r++; lastProduct = strAt(ws, 2, r - 1) || lastProduct; continue; }

    /* Unknown products sitting directly above the first known row belong to
       this block too. Walked back only as far as the previous block, so a
       row is never claimed twice. */
    let first = r;
    while (first - 1 > prevEnd
           && looksLikeSize(strAt(ws, 3, first - 1))
           && !lookupProductRow(strAt(ws, 2, first - 1), strAt(ws, 3, first - 1))) {
      first--;
    }
    const unknown = [];
    let carried = '';
    for (let u = first; u < r; u++) {
      if (strAt(ws, 2, u).trim()) carried = strAt(ws, 2, u);
      unknown.push({ row: u, product: carried.trim() || '(unnamed)', size: strAt(ws, 3, u).trim() });
    }

    // Start of a run.
    const rows = [];
    let blank = 0;
    let product = '';
    let cur = r;
    while (cur <= maxRow) {
      const bText = strAt(ws, 2, cur);
      if (bText.trim()) product = bText;
      const size = strAt(ws, 3, cur);
      const e = lookupProductRow(product, size);
      if (e) { rows.push({ row: cur, ...e }); blank = 0; cur++; continue; }
      // Reads like a product, but not one the catalogue knows: keep it with
      // the block so it can be reported, and keep walking.
      if (looksLikeSize(size)) {
        unknown.push({ row: cur, product: product.trim() || '(unnamed)', size: size.trim() });
        blank = 0; cur++; continue;
      }
      if (size.trim() === '' && blank < 1) { blank++; cur++; continue; }
      break;
    }
    prevEnd = cur - 1;

    /* Banner: walk up for the nearest heading that actually names a section.
       The rows immediately above a block are the day numbers and a bare
       "DATE" caption, so the first non-empty row above is almost never the
       heading — the search has to keep going until something classifies. */
    let banner = '';
    let kind = null;
    let nearestText = '';
    for (let up = first - 1; up >= Math.max(1, first - 12); up--) {
      const t = rowText(ws, up, maxCol);
      if (!t) continue;
      if (readDayHeader(ws, up, maxCol)) continue;      // day numbers, not a heading
      if (!nearestText) nearestText = t;
      const k = classifyBlock(t, sheetIsDamage);
      if (k) { kind = k; banner = t; break; }
    }

    const header = headers.filter(h => h.row < first).pop();
    blocks.push({
      kind,
      banner: banner || nearestText,
      header,
      rows,
      unknown,
    });

    r = cur;
    lastProduct = '';
  }
  return blocks;
}

function parseLegacySheet(ws, sheetName, period, out, monthsByLabel) {
  const rng = decodeRange(ws);
  const maxCol = rng.e.c + 1;
  const maxRow = rng.e.r + 1;
  const sheetIsDamage = /DAM[EA]GE/.test(norm(sheetName));
  const label = `${period.month} ${period.year}`;

  let m = monthsByLabel.get(label);
  if (!m) {
    m = emptyMonth(period, sheetName, 'legacy');
    monthsByLabel.set(label, m);
    out.months.push(m);
  } else if (!m.sheets.includes(sheetName)) {
    m.sheets.push(sheetName);
  }

  const days = daysInMonth(period.monthNum, period.year);

  /* ── milk received: rows keyed by source rather than pack size ── */
  if (!sheetIsDamage) {
    for (let r = 1; r <= maxRow; r++) {
      const src = canonical(strAt(ws, 2, r));
      if (!SOURCE_SET.has(src)) continue;
      // Use the day header above this row to map columns to dates.
      let header = null;
      for (let up = r - 1; up >= Math.max(1, r - 8); up--) {
        header = readDayHeader(ws, up, maxCol);
        if (header) break;
      }
      if (!header) {
        out.warnings.push(`[${sheetName}] found a "${src}" milk row at row ${r} but no date header above it — that row was skipped.`);
        continue;
      }
      for (const [col, day] of header.colToDay) {
        const v = numAt(ws, col, r);
        if (typeof v !== 'number' || v <= 0) continue;
        if (day > days) continue;
        m.received.push({ day, source: src, litres: v });
      }
      // "B/D" on the received block is fresh milk carried in from last month.
      if (header.openingCol) {
        const v = numAt(ws, header.openingCol, r);
        if (typeof v === 'number' && v > 0) m.openingFreshLitres += v;
      }
    }
  }

  /* ── pack blocks ── */
  const blocks = findLegacyBlocks(ws, sheetIsDamage, maxCol, maxRow);
  const counted = { PACKED: 0, ISSUED: 0, DAMAGED: 0 };
  /* Products on the sheet the catalogue does not know, gathered across the
     blocks that are actually read so each is reported once, with what was
     left out of each section. */
  const notImported = new Map();

  for (const block of blocks) {
    if (block.kind === 'SKIP_LITRES' || block.kind === 'SKIP_STOCK') continue;
    if (!block.kind) {
      out.warnings.push(
        `[${sheetName}] a block of product rows at row ${block.rows[0].row} could not be identified `
        + `(heading read as "${block.banner.slice(0, 60) || 'blank'}") and was skipped.`
      );
      continue;
    }
    if (!block.header) {
      out.errors.push(`[${sheetName}] the ${block.kind} block at row ${block.rows[0].row} has no date header row above it.`);
      continue;
    }
    // A second PACKED block on one sheet means the layout is not what it
    // appears to be; importing both would double the month.
    if (counted[block.kind] && block.kind !== 'DAMAGED') {
      out.errors.push(
        `[${sheetName}] found a second ${block.kind} block at row ${block.rows[0].row}. `
        + `Only one is expected per month — check the sheet before importing. If there is `
        + `only one on the sheet, a row inside it that is not a product row (a note, or a `
        + `line with no pack size) has split it in two.`
      );
      continue;
    }
    counted[block.kind]++;

    for (const u of block.unknown) {
      let units = 0;
      for (const [col, day] of block.header.colToDay) {
        const v = numAt(ws, col, u.row);
        if (typeof v === 'number' && v > 0 && day <= days) units += v;
      }
      const key = `${norm(u.product)}|${norm(u.size)}`;
      if (!notImported.has(key)) notImported.set(key, { ...u, sections: [] });
      notImported.get(key).sections.push({ kind: block.kind, units });
    }

    for (const { row, product, size } of block.rows) {
      for (const [col, day] of block.header.colToDay) {
        const v = numAt(ws, col, row);
        if (v == null) continue;
        if (typeof v === 'object') {
          out.warnings.push(`[${sheetName}] ${product} ${size}, day ${day}: ignored "${v.bad}" — not a number.`);
          continue;
        }
        if (v <= 0) continue;
        if (day > days) {
          out.warnings.push(`[${sheetName}] ${product} ${size}: ${period.month} has ${days} days, so the figure in day ${day} was skipped.`);
          continue;
        }
        pushPack(m, block.kind, { day, product, size, units: v });
      }
      // Opening balance lives in the B/D column of the packed block.
      if (block.kind === 'PACKED' && block.header.openingCol) {
        const v = numAt(ws, block.header.openingCol, row);
        if (typeof v === 'number' && v > 0) {
          m.opening.push({ product, size, units: v, litres: litresFor(size, v) });
        }
      }
    }
  }

  /* A warning, not an error: the rest of the month is sound and there is no
     reason to turn it away. But it has to be said out loud — a product's
     figures leaving an upload that otherwise reports success is exactly how
     a month ends up short without anyone knowing why. */
  const LABEL = { PACKED: 'packed', ISSUED: 'issued', DAMAGED: 'damaged' };
  for (const u of notImported.values()) {
    const moved = u.sections.filter(x => x.units > 0);
    const what = moved.length
      ? moved.map(x => `${x.units} ${LABEL[x.kind]}`).join(', ')
      : 'no figures entered';
    out.warnings.push(
      `[${sheetName}] "${u.product} ${u.size}" (row ${u.row}) is not a product the app knows, `
      + `so it was not imported — ${what}. If it is new, add it to the product catalogue `
      + `(processingCatalog.js) and upload the month again; if it is a misspelling of an `
      + `existing product, correct it on the sheet.`
    );
  }

  /* ── fresh milk written off ──
     On the damage sheet this is a lone litres figure below the totals, with
     no category beside it. The farm's SUMMARY sheet reads that same cell as
     fresh milk damage, so it is taken that way here — and flagged, because
     an unlabelled cell is a thin thing to rely on. */
  if (sheetIsDamage) {
    const lastBlock = blocks.filter(b => b.rows.length).pop();
    const from = lastBlock ? lastBlock.rows[lastBlock.rows.length - 1].row + 1 : 1;
    for (let r = from; r <= maxRow; r++) {
      if (strAt(ws, 2, r).trim() || strAt(ws, 3, r).trim()) continue;
      for (let c = 1; c <= maxCol; c++) {
        const v = numAt(ws, c, r);
        if (typeof v === 'number' && v > 0) {
          m.freshDamage.push({ day: null, litres: v });
          out.warnings.push(
            `[${sheetName}] cell ${XLSX.utils.encode_cell({ c: c - 1, r: r - 1 })} holds ${v} with no label; `
            + `it was read as fresh milk written off for the month, matching the SUMMARY sheet.`
          );
          break;
        }
      }
    }
  }
}

/* ══════════════════════════════════════════════════════════
   ENTRY POINT
══════════════════════════════════════════════════════════ */

/** Collapse duplicate rows so a month has one figure per day/product/size. */
function consolidate(m) {
  const roll = (rows, keyFn) => {
    const map = new Map();
    for (const r of rows) {
      const k = keyFn(r);
      if (!map.has(k)) map.set(k, { ...r });
      else {
        const cur = map.get(k);
        cur.units = (cur.units || 0) + (r.units || 0);
        cur.litres = (cur.litres || 0) + (r.litres || 0);
      }
    }
    return [...map.values()];
  };
  m.packed = roll(m.packed, r => `${r.day}|${r.product}|${r.size}`);
  m.issued = roll(m.issued, r => `${r.day}|${r.product}|${r.size}`);
  m.damaged = roll(m.damaged, r => `${r.day}|${r.product}|${r.size}`);
  m.opening = roll(m.opening, r => `${r.product}|${r.size}`);

  const recMap = new Map();
  for (const r of m.received) {
    const k = `${r.day}|${r.source}`;
    recMap.set(k, { ...r, litres: (recMap.get(k)?.litres || 0) + r.litres });
  }
  m.received = [...recMap.values()];

  m.freshDamageLitres = m.freshDamage.reduce((a, r) => a + r.litres, 0);
  return m;
}

/**
 * What the sheet accounts for, per product/size: opening + packed − damaged.
 *
 * This is NOT the closing balance. The sheet cannot know it, because issuing
 * happens on issue notes in the app and carries on after the workbook is
 * filed. Closing is worked out on every read as this figure less what the
 * ledger issued that month — see lib/processingReconcile.js.
 *
 * A figure below zero here means more was written off than was ever made,
 * which is a counting mistake on the sheet rather than real stock.
 */
function computeStock(m, warnings) {
  const acc = new Map();
  const bump = (product, size, field, units) => {
    const k = `${product}|${size}`;
    if (!acc.has(k)) acc.set(k, { product, size, opening: 0, packed: 0, damaged: 0 });
    acc.get(k)[field] += units;
  };
  for (const r of m.opening) bump(r.product, r.size, 'opening', r.units);
  for (const r of m.packed) bump(r.product, r.size, 'packed', r.units);
  for (const r of m.damaged) bump(r.product, r.size, 'damaged', r.units);

  m.stock = [...acc.values()].map(s => {
    /* Deliberately not less issued: which source a month's issuing comes
       from is settled on read, and subtracting the sheet's figure here
       would take it off a second time. */
    const available = s.opening + s.packed - s.damaged;
    if (available < 0) {
      warnings.push(
        `[${m.label}] ${s.product} ${s.size} accounts for ${available}: `
        + `${s.damaged} written off against ${s.opening + s.packed} made and carried in.`
      );
    }
    return {
      ...s,
      issued: 0,
      available,
      opening_litres: litresFor(s.size, s.opening),
      available_litres: litresFor(s.size, available),
    };
  }).filter(s => s.opening || s.packed || s.damaged);

  return m;
}

/**
 * Parse a processing workbook.
 *
 * @param {Buffer} buffer  .xlsx bytes
 * @returns {{ ok:boolean, months:Array, errors:string[], warnings:string[] }}
 */
function parseProcessingWorkbook(buffer) {
  const out = { ok: false, months: [], errors: [], warnings: [] };

  let wb;
  try {
    wb = XLSX.read(buffer, { type: 'buffer', cellDates: false });
  } catch (e) {
    out.errors.push(`That file could not be opened as a spreadsheet: ${e.message}`);
    return out;
  }

  const sheets = wb.SheetNames.filter(n => !SKIP_SHEETS.has(norm(n)));
  if (!sheets.length) {
    out.errors.push('The workbook has no month sheets.');
    return out;
  }

  const legacyByLabel = new Map();
  let handled = 0;

  for (const name of sheets) {
    const ws = wb.Sheets[name];
    if (!ws) continue;

    // Template sheets announce themselves with ##META## in column A.
    if (parseTemplateSheet(ws, name, out)) { handled++; continue; }

    const period = monthFromSheetName(name);
    if (!period) {
      out.warnings.push(`Sheet "${name}" is not a month sheet (its name needs a month and a year, like "JUNE 2026") and was skipped.`);
      continue;
    }
    parseLegacySheet(ws, name, period, out, legacyByLabel);
    handled++;
  }

  if (!handled) {
    out.errors.push(
      'No usable month sheets were found. Use the "Download template" button on the Processing Unit '
      + 'page, or upload the farm workbook with its sheets named like "JUNE 2026".'
    );
    return out;
  }

  for (const m of out.months) {
    consolidate(m);
    computeStock(m, out.warnings);
    if (!m.received.length && !m.packed.length && !m.issued.length) {
      out.warnings.push(`[${m.label}] no figures were found on this sheet.`);
    }
  }
  out.months = out.months.filter(m =>
    m.received.length || m.packed.length || m.issued.length
    || m.damaged.length || m.opening.length);

  if (!out.months.length && !out.errors.length) {
    out.errors.push('The workbook is laid out correctly but no figures have been entered in it yet.');
  }

  out.ok = out.errors.length === 0;
  return out;
}

module.exports = { parseProcessingWorkbook, norm };
