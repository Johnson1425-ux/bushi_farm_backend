/* ══════════════════════════════════════════════════════════════
   THE UNIT SOLD WORKBOOK, READ BACK

   Reads the farm's "UNIT SOLD" workbook — "2026 SEPTEMBER UNIT SOLD.xlsx"
   — and hands back one flat list: on this day, this much of this went
   out, in litres.

   Each month has a sheet of its own (JAN, FEBRUARY … SEPTEMBER), a row
   per thing sold and a column per day of the month, 1 to 31, then TOTAL:

     • Fresh milk first, a row per outlet: the two shops (BMH FRESH MILK,
       BUSH MILK MJINI) and the bulk buyers (BULK SALE ISAMILO, BULK FRESH
       MILK OMARY, ROYAL ( MJINI) …), down to TOTAL FRESH MILK.

     • Then processed milk, a row per pack — VANILLA 150ML, 0.5L CUP, 1L …
       — with the product written once and the packs beneath it, down to
       TOTAL PROCESSED MILK SOLD.

   Every figure is litres, packs included: 188 cups of 150ml vanilla are
   written 28.2. Units are worked out from the pack size, never the other
   way about, so the litres are exactly what the sheet says.

   What the sheets cannot say is who sold the processed milk: it is the
   farm's total for the day. Fresh milk is by outlet, and the outlets
   that also appear in the sales book are linked to it by name.

   Nothing is read from a fixed cell. The month is the sheet's name — the
   banner over it is copied from month to month and often wrong ("UNIT
   SOLD JULY" over AUGUST and SEPTEMBER) — the day columns are found by
   their numbers under DATE, and the sections by their TOTAL rows. The
   YEARLY and MONTHLY sheets are sums of these and are not read; anything
   below TOTAL PROCESSED MILK SOLD (production, damages, calves) is not a
   sale.

   `errors` mean nothing is imported, `warnings` are for the operator.
══════════════════════════════════════════════════════════════ */

const XLSX = require('xlsx');
const { norm, MONTHS, monthLabel } = require('./expenseCatalog');
const { sheetRows, isBlank, toNum, text, A1 } = require('./expensesWorkbook');
const { unitFor } = require('./salesWorkbook');

const litre = (n) => Math.round((Number(n) || 0) * 1000) / 1000;

/* ── what a row is ───────────────────────────────────────── */

/* The month a sheet is for, from its name: JAN, FEBRUARY, "SEPT". */
function monthOfSheet(name) {
  const n = norm(name);
  if (!n) return null;
  for (const [word, num] of Object.entries(MONTHS)) {
    if (n === word || (n.length >= 3 && word.startsWith(n)) || n.startsWith(word)) return num;
  }
  return null;
}

/**
 * The fresh-milk outlets, by the names the sheet gives them.
 *
 * `unit` is the same buyer in the sales book, so its litres and its
 * shillings can sit side by side; an outlet the sales book has no column
 * for keeps its own name and no link. Matched on letters and digits,
 * whole name first, then by the words it contains — the same buyer is
 * "MOUNT MERU (MTEJA MPYA)/ BUYOMBE" on one sheet and "MTEJA MPYA/BUYOMBE"
 * on another.
 */
const OUTLETS = [
  { name: 'Bushi Milk House M9', unit: 'Bushi Milk House M9', match: ['BMHFRESHMILK', 'BMH', 'BUSHMILKHOUSE'] },
  { name: 'Bushi Milk Town',     unit: 'Bushi Milk Town',     match: ['BUSHMILKMJINI', 'BUSHIMILKMJINI', 'BUSHMILKTOWN'] },
  { name: 'Isamilo',             unit: 'Isamilo',             match: ['BULKSALEISAMILO'] },
  { name: 'Maliasili Isamilo',   unit: null,                  match: ['MALIASILIISAMILO', 'MALIASILI'] },
  { name: 'Omar',                unit: 'Omar',                match: ['BULKFRESHMILKOMARY', 'OMARY', 'OMAR'] },
  { name: 'Royal Mjini',         unit: 'Royal Mjini',         match: ['ROYALMJINI'] },
  { name: 'Pasiansi Royal',      unit: null,                  match: ['PASIANSIROYAL'] },
  { name: 'Kona ya Buyombe',     unit: 'Kona ya Buyombe',     match: ['BUYOMBE', 'MOUNTMERU'] },
  { name: 'Mji Mwema',           unit: 'Mji Mwema',           match: ['MJIMWEMA'] },
  { name: 'Mnadani',             unit: 'Mnadani',             match: ['MNADANI'] },
  { name: 'Kiseke',              unit: null,                  match: ['KISEKE'] },
  { name: 'Kwanza Milk',         unit: null,                  match: ['KWANZAMILK'] },
  { name: 'Misungwi',            unit: null,                  match: ['MISUNGWI'] },
  { name: 'Bugando',             unit: null,                  match: ['DRBUGANDO', 'BUGANDO'] },
  { name: 'Nyasaka',             unit: null,                  match: ['NYASAKA'] },
  { name: 'Eveline Mwaloni',     unit: null,                  match: ['EVELINEMWALONI', 'MWALONI'] },
  { name: 'Mr Denis home milk',  unit: null,                  match: ['MRDENIS', 'DENIS'] },
];

function outletFor(heading) {
  const n = norm(heading);
  for (const o of OUTLETS) if (o.match.includes(n)) return { ...o, known: true };
  /* Longest contained name wins, so "PASIANSI ROYAL" is not Royal Mjini. */
  let best = null, len = 0;
  for (const o of OUTLETS) {
    for (const m of o.match) if (m.length > len && n.includes(m)) { best = o; len = m.length; }
  }
  if (best) return { ...best, known: true };
  /* Not one the app knows — still read, under its own name; and if the
     sales book knows it, linked. */
  const u = unitFor(heading);
  return { name: u.name, unit: u.known ? u.name : null, known: false };
}

/**
 * Litres in one pack: "150ML", "0.5L CUP", "PACT O.5L", "0.5 CHUPA", "10L".
 * A letter O typed for a nought is read as one. A pack with no size on it
 * ("MILK CEAM") has its litres but no unit count.
 */
function litresPerPack(pack) {
  const v = String(pack ?? '').toUpperCase().replace(/\bO(?=\.\d)/g, '0');
  const m = v.match(/(\d*\.?\d+)\s*(MLS?|LTRS?|L)?\b/);
  if (!m) return null;
  const n = Number(m[1]);
  if (!n) return null;
  if (m[2] && m[2].startsWith('M')) return n / 1000;
  /* A bare number is litres if it is pack-sized; "150" alone would be ml. */
  return m[2] || n <= 20 ? n : n / 1000;
}

/** How a pack is shown: spacing tidied, a typed O put back to a nought. */
const packLabel = (pack) => text(pack).toUpperCase().replace(/\bO(?=\.\d)/g, '0').replace(/\s+/g, ' ');

/** "VANILLA", "KARF MILK" / "KERF MILK" (one product, spelt both ways). */
function productLabel(name) {
  const n = norm(name);
  if (n === 'KARFMILK' || n === 'KERFMILK') return 'Kerf milk';
  const t = text(name).toLowerCase();
  return t.charAt(0).toUpperCase() + t.slice(1);
}

const isTotal = (v, word) => norm(v).startsWith('TOTAL') && norm(v).includes(word);

/* ── one month ───────────────────────────────────────────── */

function parseMonth(ws, sheetName, month, year, issues) {
  const rows = sheetRows(ws);

  /* The row of day numbers: 1, 2, 3 … under DATE, then TOTAL. */
  let dayRow = null, labelCol = null;
  for (let r = 0; r < Math.min(rows.length, 15) && dayRow === null; r++) {
    const row = rows[r] || [];
    for (let c = 0; c < row.length - 2; c++) {
      if (row[c] === 1 && row[c + 1] === 2 && row[c + 2] === 3) { dayRow = r; break; }
    }
  }
  if (dayRow === null) {
    issues.warnings.push(`${sheetName}: no row of day numbers (1, 2, 3 …) was found, so nothing on it was read.`);
    return null;
  }
  const dayCols = [];
  let totalCol = null;
  (rows[dayRow] || []).forEach((v, c) => {
    if (typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 31) dayCols.push({ col: c, day: v });
    if (totalCol === null && norm(v) === 'TOTAL') totalCol = c;
  });

  /* The DETAILS column: where the first row's name sits. */
  for (let r = dayRow + 1; r < rows.length && labelCol === null; r++) {
    const row = rows[r] || [];
    for (let c = 0; c < dayCols[0].col; c++) {
      if (typeof row[c] === 'string' && /[A-Z]/i.test(row[c])) { labelCol = c; break; }
    }
  }
  if (labelCol === null) return null;
  const packCol = labelCol + 1;

  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const iso = (d) => `${year}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;

  const lines = [];
  const checks = [];
  let section = 'fresh', product = null;

  for (let r = dayRow + 1; r < rows.length; r++) {
    const row = rows[r] || [];
    const label = row[labelCol];

    if (isTotal(label, 'FRESH')) {
      checks.push({ section: 'fresh', row, r });
      section = 'processed';
      continue;
    }
    if (isTotal(label, 'PROCESSED')) { checks.push({ section: 'processed', row, r }); break; }
    if (norm(label).includes('TOTALMILKSOLD')) break;

    let item, pack = null, perPack = null, outlet = null;
    if (section === 'fresh') {
      if (isBlank(label)) continue;
      outlet = outletFor(label);
      item = outlet.name;
    } else {
      if (!isBlank(label)) product = productLabel(label);
      if (!product || isBlank(row[packCol])) continue;
      pack = packLabel(row[packCol]);
      perPack = litresPerPack(row[packCol]);
      item = product;
    }

    let sum = 0, any = false;
    for (const { col, day } of dayCols) {
      const v = toNum(row[col]);
      if (!v) continue;
      if (day > lastDay) {
        issues.warnings.push(`${sheetName}!${A1(r, col)}: a figure under day ${day}, which ${monthLabel(month, year)} does not have. Left out.`);
        continue;
      }
      any = true;
      sum += v;
      lines.push({
        date: iso(day), section, item, pack,
        unit: outlet?.unit || null,
        litres: litre(v),
        units: perPack ? Math.round((v / perPack) * 100) / 100 : null,
        litres_per_pack: perPack,
        sheet: sheetName, cell: A1(r, col),
      });
    }

    if (any && section === 'fresh' && !outlet.known) {
      issues.warnings.push(`${sheetName}: "${text(label)}" is not an outlet the app knows. Its litres were kept under "${item}".`);
    }
    if (any && section === 'processed' && !perPack) {
      issues.warnings.push(`${sheetName}: ${item} "${pack}" has no pack size the app can read, so its litres were kept but no units counted.`);
    }

    /* The row's own TOTAL, against its days. A TOTAL typed in by hand
       with no days behind it (MALIASILI in February) is the commonest. */
    const written = totalCol === null ? null : toNum(row[totalCol]);
    if (written !== null && Math.abs(written - sum) > 0.05) {
      issues.warnings.push(
        `${sheetName}: ${item}${pack ? ` ${pack}` : ''} — the TOTAL column says ${written.toLocaleString()} L, `
        + `its days add up to ${litre(sum).toLocaleString()} L. The days were imported.`
      );
    }
  }

  /* The section totals, day by day, against the rows above them. */
  for (const { section: sec, row, r } of checks) {
    const off = [];
    for (const { col, day } of dayCols) {
      if (day > lastDay) continue;
      const written = toNum(row[col]);
      if (written === null) continue;
      const read = lines.filter(l => l.section === sec && l.date === iso(day)).reduce((a, l) => a + l.litres, 0);
      if (Math.abs(written - read) > 0.05) off.push(`${day} (${written} against ${litre(read)})`);
    }
    if (off.length) {
      issues.warnings.push(
        `${sheetName}: the TOTAL ${sec.toUpperCase()} row (row ${r + 1}) disagrees with the rows above it on day `
        + `${off.slice(0, 6).join(', ')}${off.length > 6 ? ', …' : ''}. The rows were imported.`
      );
    }
  }

  return { sheet: sheetName, month, lines };
}

/* ── the workbook ────────────────────────────────────────── */

/** The year: a banner or the MONTHLY sheet says it, failing that the file name. */
function yearOf(wb, filename) {
  const seen = new Map();
  for (const name of wb.SheetNames) {
    const rows = sheetRows(wb.Sheets[name]).slice(0, 8);
    for (const row of rows) for (const v of row || []) {
      const m = String(v ?? '').match(/\b(20\d{2})\b/);
      if (m) seen.set(m[1], (seen.get(m[1]) || 0) + 1);
    }
  }
  if (seen.size) {
    /* The YEARLY sheet lists every year as a column; the most-written wins. */
    return Number([...seen.entries()].sort((a, b) => b[1] - a[1])[0][0]);
  }
  const m = String(filename || '').match(/\b(20\d{2})\b/);
  return m ? Number(m[1]) : null;
}

function parseUnitsSoldWorkbook(buffer, hint = {}) {
  const issues = { errors: [], warnings: [] };
  let wb;
  try {
    wb = XLSX.read(buffer, { type: 'buffer' });
  } catch (err) {
    return { ok: false, errors: [`The file could not be opened as a spreadsheet: ${err.message}`], warnings: [] };
  }

  const fromName = String(hint.filename || '').match(/\b(20\d{2})\b/);
  const year = fromName ? Number(fromName[1]) : yearOf(wb, hint.filename);
  if (!year) {
    return { ok: false, errors: ['The workbook does not say which year it is for — put the year in the file name, e.g. "2026 SEPTEMBER UNIT SOLD".'], warnings: [] };
  }

  const months = new Map();
  const skipped = [];
  for (const name of wb.SheetNames) {
    const ws = wb.Sheets[name];
    const month = monthOfSheet(name);
    if (!month) {
      const n = norm(name);
      const why = n.includes('YEAR') || n.includes('MONTHLY')
        ? 'a summary of the month sheets — read from them instead'
        : (ws['!ref'] || 'A1:A1') === 'A1:A1' ? 'empty' : 'not named after a month';
      skipped.push({ sheet: name, why });
      continue;
    }
    if (months.has(month)) {
      issues.errors.push(`Two sheets are both for ${monthLabel(month, year)}: "${months.get(month).sheet}" and "${name}". Delete or rename one and upload again.`);
      continue;
    }
    const found = parseMonth(ws, name, month, year, issues);
    if (!found) { skipped.push({ sheet: name, why: 'no day columns on it' }); continue; }
    if (!found.lines.length) { skipped.push({ sheet: name, why: 'nothing sold written on it yet' }); continue; }
    months.set(month, found);
  }

  if (!issues.errors.length && !months.size) {
    issues.errors.push(
      'No units sold could be recognised in this file. The workbook keeps a sheet per month (JAN, FEBRUARY …) '
      + 'with the days 1 to 31 across the top, fresh milk by outlet and processed milk by pack down the side. '
      + `Sheets in the file: ${wb.SheetNames.join(', ') || 'none'}.`
    );
  }
  if (issues.errors.length) return { ok: false, ...issues, skipped };

  const lines = [...months.values()].flatMap(m => m.lines);
  const sum = (arr) => litre(arr.reduce((a, l) => a + l.litres, 0));

  return {
    ok: true,
    year,
    lines,
    months: [...months.values()].sort((a, b) => a.month - b.month).map(m => ({
      month: `${year}-${String(m.month).padStart(2, '0')}`,
      label: monthLabel(m.month, year),
      sheet: m.sheet,
      days: new Set(m.lines.map(l => l.date)).size,
      fresh: sum(m.lines.filter(l => l.section === 'fresh')),
      processed: sum(m.lines.filter(l => l.section === 'processed')),
      litres: sum(m.lines),
    })),
    litres: sum(lines),
    skipped,
    ...issues,
  };
}

module.exports = { parseUnitsSoldWorkbook, litresPerPack, outletFor };
