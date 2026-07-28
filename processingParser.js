// processingParser.js
// MilkTrack — Processing Unit workbook parser.
// Layout: one sheet per month; each month sheet stacks four sections
// (RECEIVED, PROCESSED, PACKED, ISSUED). Sections are located by hidden
// anchor markers in column A (##RECEIVED## etc.), so the parser never
// guesses where a section starts — this is what prevents the old data loss.
// Requires: npm i xlsx

const XLSX = require('xlsx');

const SECTION_GROUPS = {
  RECEIVED: { 'MILK RECEIVED': ['FARM MWABULUGU', 'FARM', 'PURCHASED'] },
  PROCESSED: {
    'VANILLA':      ['150ML', '0.5L CUP', '0.5L CHUPA', '1L', '3L', '5L'],
    'STRAWBERRY':   ['150ML', '0.5L', '1L', '2L', '3L', '5L'],
    'MTINDI BONGE': ['PACK 0.5L', '0.5L CUP', '0.5L CHUPA', '1L', '2L', '3L', '5L', '10L'],
  },
};
SECTION_GROUPS.PACKED = SECTION_GROUPS.PROCESSED;
SECTION_GROUPS.ISSUED = SECTION_GROUPS.PROCESSED;

const SECTION_ORDER = ['RECEIVED', 'PROCESSED', 'PACKED', 'ISSUED'];
const DAYS = 31;
const DAY_START_COL = 4;              // col D = day 1 (1-based)
const NON_MONTH_SHEETS = new Set(['INSTRUCTIONS']);

const MONTHS = { JANUARY:1,FEBRUARY:2,MARCH:3,APRIL:4,MAY:5,JUNE:6,JULY:7,
  AUGUST:8,SEPTEMBER:9,OCTOBER:10,NOVEMBER:11,DECEMBER:12 };

function norm(s) {
  return String(s == null ? '' : s)
    .toUpperCase()
    .replace(/O(?=\.?\d)/g, '0')      // O.5 -> 0.5
    .replace(/\s+/g, ' ')
    .trim();
}
const ref = (col, row) => XLSX.utils.encode_cell({ c: col - 1, r: row - 1 });

function numAt(ws, col, row) {
  const cell = ws[ref(col, row)];
  if (!cell || cell.v === '' || cell.v == null) return null;
  const n = Number(cell.v);
  return Number.isFinite(n) ? n : null;
}
function strAt(ws, col, row) {
  const cell = ws[ref(col, row)];
  return cell ? String(cell.v) : '';
}

// Find every ##MARKER## in column A → { MARKER: row }
function findAnchors(ws) {
  const anchors = {};
  const rng = XLSX.utils.decode_range(ws['!ref'] || 'A1:A1');
  for (let r = rng.s.r; r <= rng.e.r; r++) {
    const v = strAt(ws, 1, r + 1).trim();
    const m = /^##(.+?)##$/.exec(v);
    if (m) anchors[m[1].toUpperCase()] = r + 1; // 1-based row
  }
  return anchors;
}

function parseMonthSheet(ws, sheetName, out) {
  const anchors = findAnchors(ws);

  // --- metadata ---
  if (!anchors.META) {
    out.errors.push(`[${sheetName}] missing ##META## anchor — sheet structure altered.`);
    return;
  }
  const metaRow = anchors.META;
  const month = norm(strAt(ws, 3, metaRow)); // C
  const year  = numAt(ws, 5, metaRow);       // E
  if (!MONTHS[month]) out.errors.push(`[${sheetName}] invalid/empty MONTH "${month}"`);
  if (!year)          out.errors.push(`[${sheetName}] invalid/empty YEAR`);

  const period = { month, monthNum: MONTHS[month] || null, year };

  for (const section of SECTION_ORDER) {
    const anchorRow = anchors[section];
    if (!anchorRow) {
      out.errors.push(`[${sheetName}] missing ##${section}## section anchor.`);
      continue;
    }
    // data rows start 2 below the anchor (anchor row = banner, +1 = day header, +2 = first data)
    let row = anchorRow + 2;
    const groups = SECTION_GROUPS[section];
    const expected = new Map();
    for (const [g, cats] of Object.entries(groups))
      for (const c of cats) expected.set(`${norm(g)}|${norm(c)}`, { group: g, cat: c });

    const seen = new Set();
    const totalRows = Object.values(groups).reduce((a, c) => a + c.length, 0);

    for (let i = 0; i < totalRows; i++, row++) {
      const g = strAt(ws, 2, row), c = strAt(ws, 3, row);
      const key = `${norm(g)}|${norm(c)}`;
      if (!expected.has(key)) {
        out.errors.push(`[${sheetName}/${section}] row ${row}: unexpected "${g} / ${c}" — layout altered.`);
        continue;
      }
      seen.add(key);
      const { group, cat } = expected.get(key);
      for (let d = 1; d <= DAYS; d++) {
        const qty = numAt(ws, DAY_START_COL + d - 1, row);
        if (qty == null) continue;
        if (qty < 0) { out.errors.push(`[${sheetName}/${section}] ${group}/${cat} day ${d}: negative ${qty}`); continue; }
        out.records.push({
          month: period.month, monthNum: period.monthNum, year: period.year,
          section, group, category: cat, day: d, quantity: qty,
        });
      }
    }
    for (const [key, { group, cat }] of expected)
      if (!seen.has(key))
        out.errors.push(`[${sheetName}/${section}] missing row "${group} / ${cat}".`);
  }
}

/**
 * Parse a processing workbook buffer (multiple month sheets).
 * @param {Buffer} buffer
 * @returns {{ ok:boolean, records:Array, months:Array, errors:Array }}
 */
function parseProcessingWorkbook(buffer) {
  const out = { ok: false, records: [], months: [], errors: [] };
  let wb;
  try { wb = XLSX.read(buffer, { type: 'buffer', cellDates: false }); }
  catch (e) { out.errors.push(`Could not open file: ${e.message}`); return out; }

  const monthSheets = wb.SheetNames.filter(n => !NON_MONTH_SHEETS.has(n.toUpperCase()));
  if (monthSheets.length === 0) out.errors.push('No month sheets found in workbook.');

  for (const name of monthSheets) {
    const before = out.records.length;
    parseMonthSheet(wb.Sheets[name], name, out);
    if (out.records.length > before) out.months.push(name);
  }
  out.ok = out.errors.length === 0;
  return out;
}

module.exports = { parseProcessingWorkbook, SECTION_GROUPS, norm };
