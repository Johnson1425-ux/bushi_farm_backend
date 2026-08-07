/* ══════════════════════════════════════════════════════════════
   PROCESSING UNIT WORKBOOK TEMPLATE

   Generates the blank workbook the farm fills in each month, so the file
   people type into and the file the parser expects can never drift apart —
   both are built from processingCatalog.js.

   Layout of a month sheet, top to bottom:

     ##META##          month, year, days in the month
     ##OPENING##       stock carried in from last month (the B/D column on
                       the old sheet), plus fresh milk in the tank
     ##RECEIVED##      raw milk in, by source, per day, in litres
     ##PACKED##        packs produced, per product and size, per day
     ##ISSUED##        packs sent out, per product and size, per day
     ##DAMAGED##       packs written off, per product and size, per day
     ##FRESHDAMAGE##   raw milk lost before packing, per day, in litres
     ##CLOSING##       opening + packed - issued - damaged, all formulas

   Column A carries the ##ANCHOR## markers and is hidden. The parser finds
   every section by its anchor rather than by row number, so inserting a
   product or a note above a block cannot silently shift data into the
   wrong row — the failure mode that lost figures on the old sheet.

   CLOSING is written entirely as formulas and is not read back: it is
   there so the person filling the sheet sees the same balance the app
   will show, and can spot a keying error before uploading.
══════════════════════════════════════════════════════════════ */

const ExcelJS = require('exceljs');
const {
  RECEIVED_SOURCES, PRODUCT_ROWS, LITRES_PER_PACK, MONTHS, MONTH_NAMES,
  canonical, daysInMonth,
} = require('./processingCatalog');

const DAY_COL_START = 4;          // column D holds day 1
const MAX_DAYS = 31;
const TOTAL_UNITS_COL = DAY_COL_START + MAX_DAYS;        // AI
const TOTAL_LITRES_COL = TOTAL_UNITS_COL + 1;            // AJ

/* ── palette ─────────────────────────────────────────────── */
const INK = 'FF1F2A24';
const GREEN = 'FF2E6B4F';
const GREEN_SOFT = 'FFE3EFE8';
const INPUT = 'FFFFF6D6';         // the yellow "type here" fill
const COMPUTED = 'FFF1F0EC';
const BORDER = 'FFD8D5CE';

const thin = { style: 'thin', color: { argb: BORDER } };
const boxed = { top: thin, left: thin, bottom: thin, right: thin };

const colLetter = (n) => {
  let s = '';
  while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = (n - m - 1) / 26; }
  return s;
};

/* ── cell helpers ────────────────────────────────────────── */

function fill(cell, argb) {
  cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb } };
}

function banner(ws, row, text) {
  const cell = ws.getCell(row, 2);
  cell.value = text;
  cell.font = { name: 'Calibri', size: 12, bold: true, color: { argb: 'FFFFFFFF' } };
  fill(cell, GREEN);
  ws.mergeCells(row, 2, row, TOTAL_LITRES_COL);
  ws.getRow(row).height = 20;
}

function labelCell(ws, row, col, text, { bold = false } = {}) {
  const cell = ws.getCell(row, col);
  cell.value = text;
  cell.font = { name: 'Calibri', size: 10, bold, color: { argb: INK } };
  cell.border = boxed;
  return cell;
}

function inputCell(ws, row, col) {
  const cell = ws.getCell(row, col);
  fill(cell, INPUT);
  cell.border = boxed;
  cell.numFmt = '0.##';
  return cell;
}

function formulaCell(ws, row, col, formula, numFmt = '0.##') {
  const cell = ws.getCell(row, col);
  cell.value = { formula };
  fill(cell, COMPUTED);
  cell.border = boxed;
  cell.numFmt = numFmt;
  cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: INK } };
  return cell;
}

/**
 * Day header strip: "CATEGORY | 1 .. 31 | TOTAL [| LITRES]".
 * Days past the end of the month are greyed so nobody fills a 31st of June.
 */
function dayHeader(ws, row, days, { litres = false } = {}) {
  labelCell(ws, row, 3, 'CATEGORY', { bold: true });
  for (let d = 1; d <= MAX_DAYS; d++) {
    const cell = ws.getCell(row, DAY_COL_START + d - 1);
    cell.value = d;
    cell.font = { name: 'Calibri', size: 9, bold: true, color: { argb: d > days ? 'FFB0ADA6' : INK } };
    cell.alignment = { horizontal: 'center' };
    cell.border = boxed;
    fill(cell, d > days ? COMPUTED : GREEN_SOFT);
  }
  labelCell(ws, row, TOTAL_UNITS_COL, 'TOTAL', { bold: true });
  fill(ws.getCell(row, TOTAL_UNITS_COL), GREEN_SOFT);
  if (litres) {
    labelCell(ws, row, TOTAL_LITRES_COL, 'LITRES', { bold: true });
    fill(ws.getCell(row, TOTAL_LITRES_COL), GREEN_SOFT);
  }
  ws.getRow(row).height = 15;
}

/**
 * One daily block: a labelled row per catalogue entry, 31 day cells, a
 * TOTAL formula, and — for pack blocks — a LITRES total derived from the
 * pack size so litres are never typed twice and never disagree.
 */
function dailyBlock(ws, startRow, days, rows, { litres }) {
  let row = startRow;
  for (const r of rows) {
    labelCell(ws, row, 2, r.product);
    labelCell(ws, row, 3, r.size);
    for (let d = 1; d <= MAX_DAYS; d++) {
      const cell = inputCell(ws, row, DAY_COL_START + d - 1);
      if (d > days) { fill(cell, COMPUTED); cell.protection = { locked: true }; }
    }
    const first = colLetter(DAY_COL_START);
    const last = colLetter(DAY_COL_START + MAX_DAYS - 1);
    formulaCell(ws, row, TOTAL_UNITS_COL, `SUM(${first}${row}:${last}${row})`);
    if (litres) {
      const factor = LITRES_PER_PACK[canonical(r.size)] || 0;
      formulaCell(ws, row, TOTAL_LITRES_COL, `${colLetter(TOTAL_UNITS_COL)}${row}*${factor}`, '0.00');
    }
    row++;
  }
  return row;
}

/** Trailing "TOTAL" line under a daily block, summing the rows above it. */
function blockTotal(ws, row, firstRow, lastRow, label, { litres }) {
  labelCell(ws, row, 2, label, { bold: true });
  for (let c = DAY_COL_START; c <= (litres ? TOTAL_LITRES_COL : TOTAL_UNITS_COL); c++) {
    const L = colLetter(c);
    formulaCell(ws, row, c, `SUM(${L}${firstRow}:${L}${lastRow})`);
  }
  return row + 1;
}

/* ── sheets ──────────────────────────────────────────────── */

function buildInstructions(wb) {
  const ws = wb.addWorksheet('INSTRUCTIONS', {
    views: [{ showGridLines: false }],
  });
  ws.getColumn(2).width = 116;

  const lines = [
    ['MILKTRACK — PROCESSING UNIT WORKBOOK', 'title'],
    ['', ''],
    ['HOW TO USE', 'head'],
    ['1. Each MONTH is its own sheet, named like "JUNE 2026". To add a month, right-click a month tab, choose', ''],
    ['   "Move or Copy", tick "Create a copy", rename it, then clear the old yellow values and update the month', ''],
    ['   and year in row 1.', ''],
    ['2. Fill ONLY the yellow cells. Columns 1–31 are the days of that month; days that do not exist in the', ''],
    ['   month are greyed out.', ''],
    ['3. Leave a cell BLANK when there is no activity that day. Do not type 0, a dash, or a space.', ''],
    ['4. Grey cells calculate themselves — totals, litres, and the closing balance. Do not type over them.', ''],
    ['5. Column A is hidden and holds the section markers the app reads. Never unhide, edit, or delete it, and', ''],
    ['   do not delete rows or reorder the blocks.', ''],
    ['', ''],
    ['WHAT EACH SECTION MEANS', 'head'],
    ['OPENING BALANCE — packs and fresh milk carried in from the end of last month (the old "B/D" column).', ''],
    ['MILK RECEIVED — raw milk taken in each day, in litres, split by where it came from.', ''],
    ['PACKED — packs produced each day. This is the old "PROCESSING MILK" / "PROCESSED MILK PACKED" block.', ''],
    ['ISSUED — packs sent out of the processing unit each day.', ''],
    ['DAMAGED — packs written off each day. This replaces the separate "DAMEGE" sheet.', ''],
    ['FRESH MILK DAMAGED — raw milk lost before it was packed, in litres.', ''],
    ['CLOSING BALANCE — opening + packed − issued − damaged. Calculated for you; check it against your own', ''],
    ['   figures before uploading.', ''],
    ['', ''],
    ['Litres are worked out from the pack size, so you never type a litre figure for packed goods:', 'head'],
    ['   150ML = 0.15 L    0.5L / CUP / CHUPA / PACK 0.5L = 0.5 L    1L = 1 L    2L = 2 L    3L = 3 L', ''],
    ['   5L = 5 L    10L = 10 L', ''],
  ];

  lines.forEach(([text, kind], i) => {
    const cell = ws.getCell(i + 2, 2);
    cell.value = text;
    if (kind === 'title') cell.font = { name: 'Calibri', size: 15, bold: true, color: { argb: GREEN } };
    else if (kind === 'head') cell.font = { name: 'Calibri', size: 11, bold: true, color: { argb: INK } };
    else cell.font = { name: 'Calibri', size: 10, color: { argb: INK } };
  });
  return ws;
}

function buildMonthSheet(wb, monthName, year) {
  const month = String(monthName).toUpperCase();
  const days = daysInMonth(MONTHS[month], year);
  const ws = wb.addWorksheet(`${month} ${year}`, { views: [{ showGridLines: false, state: 'frozen', xSplit: 3, ySplit: 0 }] });

  ws.getColumn(1).width = 2;
  ws.getColumn(1).hidden = true;
  ws.getColumn(2).width = 16;
  ws.getColumn(3).width = 13;
  for (let c = DAY_COL_START; c < DAY_COL_START + MAX_DAYS; c++) ws.getColumn(c).width = 5.5;
  ws.getColumn(TOTAL_UNITS_COL).width = 10;
  ws.getColumn(TOTAL_LITRES_COL).width = 10;

  const anchor = (row, name) => {
    const cell = ws.getCell(row, 1);
    cell.value = `##${name}##`;
    cell.font = { size: 8, color: { argb: 'FFBBBBBB' } };
  };

  /* ── META ── */
  let row = 1;
  anchor(row, 'META');
  labelCell(ws, row, 2, 'MONTH', { bold: true });
  const monthCell = inputCell(ws, row, 3);
  monthCell.value = month;
  monthCell.numFmt = 'General';
  labelCell(ws, row, 4, 'YEAR', { bold: true });
  const yearCell = inputCell(ws, row, 5);
  yearCell.value = year;
  yearCell.numFmt = '0';
  labelCell(ws, row, 6, 'DAYS', { bold: true });
  formulaCell(ws, row, 7, `DAY(EOMONTH(DATEVALUE("1 "&C1&" "&E1),0))`, '0');

  /* ── OPENING ── */
  row = 3;
  anchor(row, 'OPENING');
  banner(ws, row, 'OPENING BALANCE (B/D) — carried in from the end of last month');
  row++;
  labelCell(ws, row, 3, 'CATEGORY', { bold: true });
  labelCell(ws, row, DAY_COL_START, 'UNITS', { bold: true });
  labelCell(ws, row, DAY_COL_START + 1, 'LITRES', { bold: true });
  fill(ws.getCell(row, DAY_COL_START), GREEN_SOFT);
  fill(ws.getCell(row, DAY_COL_START + 1), GREEN_SOFT);
  row++;
  const openingFirst = row;
  for (const r of PRODUCT_ROWS) {
    labelCell(ws, row, 2, r.product);
    labelCell(ws, row, 3, r.size);
    inputCell(ws, row, DAY_COL_START);
    const factor = LITRES_PER_PACK[canonical(r.size)] || 0;
    formulaCell(ws, row, DAY_COL_START + 1, `${colLetter(DAY_COL_START)}${row}*${factor}`, '0.00');
    row++;
  }
  const openingLast = row - 1;
  // Fresh milk is measured in litres, not packs, so it gets its own line.
  labelCell(ws, row, 2, 'FRESH MILK', { bold: true });
  labelCell(ws, row, 3, 'LITRES');
  inputCell(ws, row, DAY_COL_START);
  const openingFreshRow = row;
  row += 2;

  /* ── RECEIVED ── */
  anchor(row, 'RECEIVED');
  banner(ws, row, 'MILK RECEIVED — raw milk in, litres');
  row++;
  dayHeader(ws, row, days);
  row++;
  const recFirst = row;
  for (const src of RECEIVED_SOURCES) {
    labelCell(ws, row, 2, 'MILK RECEIVED');
    labelCell(ws, row, 3, src);
    for (let d = 1; d <= MAX_DAYS; d++) {
      const cell = inputCell(ws, row, DAY_COL_START + d - 1);
      if (d > days) fill(cell, COMPUTED);
    }
    const f = colLetter(DAY_COL_START), l = colLetter(DAY_COL_START + MAX_DAYS - 1);
    formulaCell(ws, row, TOTAL_UNITS_COL, `SUM(${f}${row}:${l}${row})`);
    row++;
  }
  row = blockTotal(ws, row, recFirst, row - 1, 'GRAND TOTAL', { litres: false });
  row++;

  /* ── PACKED / ISSUED / DAMAGED ── */
  const blocks = [
    ['PACKED', 'PACKED — packs produced, by product and size'],
    ['ISSUED', 'ISSUED — packs sent out'],
    ['DAMAGED', 'DAMAGED — packs written off'],
  ];
  const blockRows = {};
  for (const [name, title] of blocks) {
    anchor(row, name);
    banner(ws, row, title);
    row++;
    dayHeader(ws, row, days, { litres: true });
    row++;
    const first = row;
    row = dailyBlock(ws, row, days, PRODUCT_ROWS, { litres: true });
    const last = row - 1;
    blockRows[name] = { first, last };
    row = blockTotal(ws, row, first, last, `TOTAL ${name}`, { litres: true });
    row++;
  }

  /* ── FRESH MILK DAMAGED ── */
  anchor(row, 'FRESHDAMAGE');
  banner(ws, row, 'FRESH MILK DAMAGED — raw milk lost before packing, litres');
  row++;
  dayHeader(ws, row, days);
  row++;
  labelCell(ws, row, 2, 'FRESH MILK');
  labelCell(ws, row, 3, 'LITRES');
  for (let d = 1; d <= MAX_DAYS; d++) {
    const cell = inputCell(ws, row, DAY_COL_START + d - 1);
    if (d > days) fill(cell, COMPUTED);
  }
  formulaCell(ws, row, TOTAL_UNITS_COL,
    `SUM(${colLetter(DAY_COL_START)}${row}:${colLetter(DAY_COL_START + MAX_DAYS - 1)}${row})`);
  row += 2;

  /* ── CLOSING (all formulas — read by the person, not by the app) ── */
  anchor(row, 'CLOSING');
  banner(ws, row, 'CLOSING BALANCE — opening + packed − issued − damaged (calculated)');
  row++;
  labelCell(ws, row, 3, 'CATEGORY', { bold: true });
  labelCell(ws, row, DAY_COL_START, 'UNITS', { bold: true });
  labelCell(ws, row, DAY_COL_START + 1, 'LITRES', { bold: true });
  fill(ws.getCell(row, DAY_COL_START), GREEN_SOFT);
  fill(ws.getCell(row, DAY_COL_START + 1), GREEN_SOFT);
  row++;
  const T = colLetter(TOTAL_UNITS_COL);
  const D = colLetter(DAY_COL_START);
  PRODUCT_ROWS.forEach((r, i) => {
    labelCell(ws, row, 2, r.product);
    labelCell(ws, row, 3, r.size);
    const open = `${D}${openingFirst + i}`;
    const packed = `${T}${blockRows.PACKED.first + i}`;
    const issued = `${T}${blockRows.ISSUED.first + i}`;
    const damaged = `${T}${blockRows.DAMAGED.first + i}`;
    formulaCell(ws, row, DAY_COL_START, `${open}+${packed}-${issued}-${damaged}`);
    const factor = LITRES_PER_PACK[canonical(r.size)] || 0;
    formulaCell(ws, row, DAY_COL_START + 1, `${D}${row}*${factor}`, '0.00');
    row++;
  });
  const closingFirst = row - PRODUCT_ROWS.length;
  labelCell(ws, row, 2, 'BALANCE STOCK', { bold: true });
  formulaCell(ws, row, DAY_COL_START, `SUM(${D}${closingFirst}:${D}${row - 1})`);
  formulaCell(ws, row, DAY_COL_START + 1,
    `SUM(${colLetter(DAY_COL_START + 1)}${closingFirst}:${colLetter(DAY_COL_START + 1)}${row - 1})`, '0.00');
  row++;
  labelCell(ws, row, 2, 'FRESH MILK', { bold: true });
  labelCell(ws, row, 3, 'LITRES');
  formulaCell(ws, row, DAY_COL_START,
    `${D}${openingFreshRow}+${T}${recFirst + RECEIVED_SOURCES.length}`
    + `-${colLetter(TOTAL_LITRES_COL)}${blockRows.PACKED.last + 1}`, '0.00');

  return ws;
}

/**
 * Build a processing workbook.
 *
 * @param {object}   [opts]
 * @param {string[]} [opts.months]  Month sheets to create, e.g. ['JUNE','JULY'].
 *                                  Defaults to the current month and the next one.
 * @param {number}   [opts.year]    Defaults to the current year.
 * @returns {Promise<Buffer>} .xlsx bytes
 */
async function buildProcessingTemplate({ months, year } = {}) {
  const now = new Date();
  const y = Number(year) || now.getUTCFullYear();

  let sheetMonths = Array.isArray(months) && months.length
    ? months.map(m => String(m).toUpperCase())
    : [MONTH_NAMES[now.getUTCMonth()], MONTH_NAMES[(now.getUTCMonth() + 1) % 12]];

  const unknown = sheetMonths.filter(m => !MONTHS[m]);
  if (unknown.length) throw new Error(`Unknown month name(s): ${unknown.join(', ')}`);

  const wb = new ExcelJS.Workbook();
  wb.creator = 'MilkTrack';
  wb.created = now;

  buildInstructions(wb);
  for (const m of sheetMonths) {
    // A December sheet followed by January belongs to the next year.
    const rollover = sheetMonths.indexOf(m) > 0 && MONTHS[m] < MONTHS[sheetMonths[0]];
    buildMonthSheet(wb, m, rollover ? y + 1 : y);
  }

  const buf = await wb.xlsx.writeBuffer();
  return Buffer.from(buf);
}

module.exports = { buildProcessingTemplate };
