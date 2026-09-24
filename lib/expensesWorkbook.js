/* ══════════════════════════════════════════════════════════════
   THE EXPENSES WORKBOOK, READ BACK

   Reads a month's expenses workbook — "2026 SEPTEMBER EXPENSES.xlsx" —
   and hands back one flat list of entries, each on a category.

   The workbook is kept by hand, and every sheet in it was laid out by
   whoever needed it, so nothing about the layout is fixed:

     • FARM MWANZA carries three categories side by side, each its own
       block of five columns with its own banner and its own TOTAL row.
     • HOME AFFAIRS has DATE / DETAILS / AMOUNT. BMH has QTY and RATE
       between them. SCANIA and MIN TRACTOR have a DATE header and
       nothing else — the description sits in an unlabelled column with
       a blank one before it.
     • A date is written once and the rows beneath it belong to that day
       until the next date appears.
     • Sheets are prepared for a month whether or not anything is spent:
       most of CSR is empty rows whose AMOUNT cell holds a formula that
       evaluates to zero.

   So blocks are found by shape rather than by position: a DATE header
   opens one, the columns are classified by what their headers say and,
   where they say nothing, by what the rows underneath them hold, and the
   block runs to its own TOTAL row. Nothing is read from a fixed cell.

   Two things this deliberately does NOT import, because both would count
   the same money a second time — the payment sheets, which are the same
   spending arranged by supplier, and the consumption sheets, which value
   what the herd ate rather than record what was paid. expenseCatalog.js
   lists them with the reason, and the reason is reported rather than
   swallowed: a sheet ignored in silence looks like a sheet missed.

   Problems are separated by severity, as in the processing parser:
   `errors` mean nothing is imported, `warnings` are for the operator to
   look at without putting the figures in doubt.
══════════════════════════════════════════════════════════════ */

const XLSX = require('xlsx');
const {
  norm, categoryFor, ignoredSheet, periodFromText,
  monthLabel, MONTH_NAMES, MONTHS,
} = require('./expenseCatalog');

/* ── cells ───────────────────────────────────────────────── */

const A1 = (row, col) => XLSX.utils.encode_cell({ c: col, r: row });

/**
 * A sheet as a grid of rows, indexed from column A and row 1.
 *
 * sheet_to_json normally starts at the sheet's own used range, so a sheet
 * whose first written cell is B3 comes back with column B at index 0 —
 * and every cell reference worked out from it then points one column to
 * the left of the figure it describes. Forcing the range back to A1
 * makes the array index and the spreadsheet's own address the same
 * thing, which is what lets an entry carry "BMH!G56" back to the operator.
 */
function sheetRows(ws) {
  const range = XLSX.utils.decode_range(ws['!ref'] || 'A1:A1');
  range.s.c = 0; range.s.r = 0;
  return XLSX.utils.sheet_to_json(ws, {
    header: 1, raw: true, blankrows: true, range: XLSX.utils.encode_range(range),
  });
}

const isBlank = (v) => v === null || v === undefined || String(v).trim() === '';

/** A cell's number, or null. Dashes and stray letters are not zeroes. */
function toNum(v) {
  if (isBlank(v)) return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (v instanceof Date) return null;
  const s = String(v).trim().replace(/,/g, '');
  if (s === '-' || s === '—') return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

const text = (v) => (isBlank(v) ? '' : String(v).trim());

const money = (n) => Math.round((Number(n) || 0) * 100) / 100;

/** Excel's own serial dates, real Dates, and anything typed as text. */
function toDate(v) {
  if (isBlank(v)) return null;
  if (v instanceof Date) {
    return Number.isNaN(v.getTime()) ? null
      : `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`;
  }
  if (typeof v === 'number') {
    /* Serial 1 is 1900-01-01 in Excel's reckoning, with its famous
       phantom 29 February 1900 built into the offset below. */
    if (v < 1 || v > 80000) return null;
    const d = new Date(Math.round((v - 25569) * 86400 * 1000));
    return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
  }
  const s = String(v).trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/**
 * The row that closes a block — the one carrying its TOTAL.
 *
 * Matched on the whole cell, not on its first word. The payroll prints
 * "TOTAL DEDUCTION" and "TOTAL EARNINGS" as column headings, and reading
 * either as a total row ended the payroll on its own header, before the
 * first employee — silently, because a block that stops early looks the
 * same as a block that has run out of rows. Every genuine total in the
 * farm's workbooks is the bare word, "TOTAL" or "GRAND TOTAL".
 */
const isTotalRow = (row) =>
  row.some(v => typeof v === 'string' && /^(GRAND\s+)?TOTALS?\s*[:.\-]?\s*$/i.test(v.trim()));

/* ── column headers ──────────────────────────────────────── */

const HEADER = {
  date:    ['DATE'],
  details: ['DETAILS', 'DETAIL', 'NARATION', 'NARRATION', 'PARTICULARS', 'DESCRIPTION', 'ITEM'],
  qty:     ['UNITY', 'UNIT', 'QTY', 'QUANTITY', 'WEIGHTKGS', 'WEIGHT'],
  price:   ['PRICE', 'RATE'],
  amount:  ['AMOUNT', 'VALUE', 'TOTAL'],
};

const headerIs = (v, kind) => HEADER[kind].includes(norm(v));

/* ── one block of columns ────────────────────────────────── */

/**
 * Work out what each column in a block holds.
 *
 * Headers are believed where they exist. Where they do not — SCANIA and
 * MIN TRACTOR label only the date — the rows underneath decide it: the
 * rightmost column that is mostly numbers is the amount, a pair of
 * numeric columns before it is quantity and price, and whatever text is
 * left describes the spending.
 *
 * Anything unclaimed stays in `textCols` and is joined into the
 * description, which is what keeps CSR's NARATION beside its DETAILS and
 * why SCANIA's blank column costs nothing.
 */
function classifyColumns(rows, headerRow, from, to) {
  const head = rows[headerRow] || [];
  const cols = { date: from, details: null, qty: null, price: null, amount: null, textCols: [] };

  for (let c = from + 1; c <= to; c++) {
    const h = head[c];
    if (isBlank(h)) continue;
    if (cols.details === null && headerIs(h, 'details')) cols.details = c;
    else if (cols.qty    === null && headerIs(h, 'qty'))    cols.qty = c;
    else if (cols.price  === null && headerIs(h, 'price'))  cols.price = c;
    else if (cols.amount === null && headerIs(h, 'amount')) cols.amount = c;
  }

  /* What the rows themselves look like, for the columns nothing was said
     about. Twenty-five rows is enough to tell a description column from
     a money column and short enough that a long sheet costs nothing. */
  if (cols.amount === null || cols.details === null) {
    const seen = {};
    const last = Math.min(rows.length - 1, headerRow + 25);
    for (let r = headerRow + 1; r <= last; r++) {
      const row = rows[r] || [];
      if (isTotalRow(row)) break;
      for (let c = from + 1; c <= to; c++) {
        const v = row[c];
        if (isBlank(v)) continue;
        seen[c] = seen[c] || { num: 0, str: 0 };
        if (toNum(v) !== null) seen[c].num++; else seen[c].str++;
      }
    }

    const numeric = Object.keys(seen).map(Number)
      .filter(c => seen[c].num > seen[c].str).sort((a, b) => a - b);
    const textual = Object.keys(seen).map(Number)
      .filter(c => seen[c].str >= seen[c].num).sort((a, b) => a - b);

    if (cols.amount === null && numeric.length) cols.amount = numeric[numeric.length - 1];
    if (cols.details === null && textual.length) {
      const before = textual.filter(c => cols.amount === null || c < cols.amount);
      cols.details = (before.length ? before : textual)[0];
    }
    /* Three money columns and no headers to say which is which: the
       sheet's own order is always quantity, price, amount. */
    if (cols.qty === null && cols.price === null && cols.amount !== null) {
      const before = numeric.filter(c => c < cols.amount);
      if (before.length >= 2) {
        cols.price = before[before.length - 1];
        cols.qty   = before[before.length - 2];
      }
    }
  }

  const claimed = new Set([cols.date, cols.details, cols.qty, cols.price, cols.amount]);
  for (let c = from + 1; c <= to; c++) if (!claimed.has(c)) cols.textCols.push(c);

  return cols;
}

/**
 * The category a block belongs to.
 *
 * The banner above it wins — FARM MWANZA's three blocks are only told
 * apart by the words sitting over them — and the sheet name is the
 * fallback for the sheets that carry one category and no banner.
 */
function bannerCategory(rows, headerRow, from, to, sheetName) {
  for (let r = headerRow - 1; r >= 0 && r >= headerRow - 4; r--) {
    const row = rows[r] || [];
    for (let c = from; c <= to; c++) {
      const v = text(row[c]);
      if (!v) continue;
      const cat = categoryFor(v);
      if (cat) return { category: cat, banner: v };
    }
  }
  const cat = categoryFor(sheetName);
  return cat ? { category: cat, banner: sheetName } : { category: null, banner: null };
}

/* ── reading one sheet ───────────────────────────────────── */

function parseSheet(ws, sheetName, issues) {
  const rows = sheetRows(ws);
  const width = rows.reduce((m, r) => Math.max(m, r.length), 0);

  /* Every row carrying DATE headers opens a set of blocks across the
     sheet. Looking for them everywhere rather than only near the top is
     what lets a sheet stack a second table under the first. */
  const headerRows = [];
  for (let r = 0; r < rows.length; r++) {
    const cols = [];
    for (let c = 0; c < width; c++) if (headerIs(rows[r][c], 'date')) cols.push(c);
    if (cols.length) headerRows.push({ row: r, cols });
  }
  if (!headerRows.length) return [];

  const blocks = [];
  for (const [i, h] of headerRows.entries()) {
    const endRow = i + 1 < headerRows.length ? headerRows[i + 1].row - 1 : rows.length - 1;
    for (const [j, from] of h.cols.entries()) {
      const to = j + 1 < h.cols.length ? h.cols[j + 1] - 1 : width - 1;
      blocks.push({ headerRow: h.row, endRow, from, to });
    }
  }

  const out = [];

  for (const b of blocks) {
    const { category, banner } = bannerCategory(rows, b.headerRow, b.from, b.to, sheetName);
    const cols = classifyColumns(rows, b.headerRow, b.from, b.to);
    const where = `${sheetName}!${A1(b.headerRow, b.from)}`;

    if (!category) {
      issues.warnings.push(
        `${where}: a table was found but nothing says which expense line it belongs to`
        + `${banner ? ` — the heading reads "${banner}"` : ''}. It was not imported.`
      );
      continue;
    }
    if (cols.amount === null) {
      issues.warnings.push(`${where}: no amount column could be found under "${banner}". Nothing was read from it.`);
      continue;
    }

    const entries = [];
    let carried = null;          // the date written above, still in force
    let sheetTotal = null;       // what the block's own TOTAL row claims
    let undated = 0;

    for (let r = b.headerRow + 1; r <= b.endRow; r++) {
      const row = rows[r] || [];
      if (isTotalRow(row.slice(b.from, b.to + 1))) {
        sheetTotal = toNum(row[cols.amount]);
        break;
      }

      const onThisRow = toDate(row[cols.date]);
      if (onThisRow) carried = onThisRow;

      const details = [cols.details, ...cols.textCols]
        .filter(c => c !== null)
        .map(c => text(row[c]))
        .filter(Boolean)
        .join(' · ');

      const qty    = cols.qty   !== null ? toNum(row[cols.qty])   : null;
      const price  = cols.price !== null ? toNum(row[cols.price]) : null;
      let   amount = toNum(row[cols.amount]);

      /* The sheets are printed with their rows already ruled and the
         AMOUNT cell holding =D*E, so an untouched row reads as zero
         rather than as nothing. A row with neither a description nor a
         figure is one of those, and is simply not an entry. */
      if (!amount && !details) continue;

      if (!amount && qty && price) amount = qty * price;
      if (!amount) {
        issues.warnings.push(
          `${sheetName}!${A1(r, cols.amount)}: "${details}" has no amount against it, so it was not imported.`
        );
        continue;
      }
      if (!details) {
        issues.warnings.push(
          `${sheetName}!${A1(r, cols.amount)}: ${money(amount).toLocaleString()} with nothing written against it — imported as "(no description)".`
        );
      }
      if (!carried) undated++;

      entries.push({
        date: carried,
        category: category.name,
        details: details || '(no description)',
        quantity: qty,
        unit_price: price,
        amount: money(amount),
        sheet: sheetName,
        cell: A1(r, cols.amount),
      });
    }

    if (undated) {
      issues.warnings.push(
        `${sheetName}: ${undated} row(s) above the first date have no day against them. `
        + 'They were dated to the first of the month.'
      );
    }

    const total = money(entries.reduce((a, e) => a + e.amount, 0));
    if (sheetTotal !== null && Math.abs(sheetTotal - total) > 1) {
      issues.warnings.push(
        `${sheetName} — ${category.name}: the sheet's own TOTAL says ${money(sheetTotal).toLocaleString()}, `
        + `the ${entries.length} rows under it add up to ${total.toLocaleString()}. `
        + 'The rows were imported; check the total on the sheet.'
      );
    }

    out.push({ sheet: sheetName, category: category.name, banner, entries, total, sheetTotal });
  }

  return out;
}

/* ── the payroll ─────────────────────────────────────────── */

/**
 * SALARY is the one sheet that is not a list of purchases: it is a
 * payroll, one row per employee, and what belongs on the month's
 * Salaries line is what each of them was actually paid.
 *
 * It is also the one sheet that is routinely left over from last month —
 * the workbook is copied forward and the payroll is rewritten when wages
 * are run, which can be after the book has been started. So the month it
 * names itself is checked against the month being imported, and a
 * payroll for a different month is skipped rather than quietly posted to
 * the wrong one.
 */
function parsePayroll(ws, sheetName, period, issues) {
  const rows = sheetRows(ws);
  const width = rows.reduce((m, r) => Math.max(m, r.length), 0);

  let nameCol = null, headerRow = null;
  for (let r = 0; r < Math.min(rows.length, 15) && nameCol === null; r++) {
    for (let c = 0; c < width; c++) {
      const n = norm(rows[r][c]);
      if (n === 'EMPLOYEESNAME' || n === 'EMPLOYEENAME' || n === 'NAMEOFEMPLOYEE') {
        nameCol = c; headerRow = r; break;
      }
    }
  }
  if (nameCol === null) {
    issues.warnings.push(`${sheetName}: no payroll could be recognised on this sheet, so no salaries were imported.`);
    return [];
  }

  /* GROSS SALARY is the wage, and the wage is what the month cost —
     which is also where the farm's own summary reads it from: the
     SALARIES line is =SALARY!G50, the foot of that column.

     TOTAL EARNINGS is the same wage with any advance already drawn
     taken off it, so it is what is handed over on payday rather than
     what was earned. Posting that would make a month look cheaper for
     having paid part of it early, and would leave an employee who drew
     his whole wage in advance costing nothing at all. Nothing is
     double-counted by reading gross, because the ADVANCES sheet is not
     imported — the advance is part of this wage, paid sooner.

     The two headings sit on different rows of the payroll's two-row
     header, so both are searched; TOTAL EARNINGS stands in only when a
     sheet has no gross column at all. */
  let payCol = null, payKind = null;
  for (const want of ['GROSSSALARY', 'TOTALEARNINGS']) {
    for (let r = headerRow; r <= headerRow + 1 && payCol === null; r++) {
      for (let c = 0; c < width; c++) {
        if (norm(rows[r]?.[c]) === want) { payCol = c; payKind = want; break; }
      }
    }
    if (payCol !== null) break;
  }
  if (payCol === null) {
    issues.warnings.push(
      `${sheetName}: the payroll has no "GROSS SALARY" column, so no salaries were imported.`
    );
    return [];
  }
  if (payKind === 'TOTALEARNINGS') {
    issues.warnings.push(
      `${sheetName}: this payroll has no "GROSS SALARY" column, so wages were read from `
      + '"TOTAL EARNINGS" — which is net of any advance already drawn, so the month may read light.'
    );
  }

  /* Which month this payroll is for, from the banner above it. */
  let payrollPeriod = null;
  for (let r = 0; r < headerRow; r++) {
    const line = (rows[r] || []).map(text).filter(Boolean).join(' ');
    const p = periodFromText(line);
    if (p?.monthNum) { payrollPeriod = p; break; }
  }
  if (payrollPeriod && (payrollPeriod.monthNum !== period.monthNum
      || (payrollPeriod.year && payrollPeriod.year !== period.year))) {
    issues.warnings.push(
      `${sheetName}: this payroll is headed ${monthLabel(payrollPeriod.monthNum, payrollPeriod.year || period.year)} `
      + `but the workbook is ${period.label}, so no salaries were imported. `
      + 'It is last month\'s payroll carried forward — rewrite it, or add the month\'s wages by hand.'
    );
    return [];
  }

  /* Paid at the end of the month worked, which is when the farm's own
     summary counts it. */
  const payday = new Date(Date.UTC(period.year, period.monthNum, 0)).toISOString().slice(0, 10);
  const entries = [];

  for (let r = headerRow + 1; r < rows.length; r++) {
    const row = rows[r] || [];
    if (isTotalRow(row)) break;

    const name = text(row[nameCol]);
    const paid = toNum(row[payCol]);
    if (!name || !paid || paid <= 0) continue;

    /* Whatever sits between the name and the first money column is the
       job — "DOCTOR", "FARM ASSISTANT" — and is worth keeping: a payroll
       line that reads only "PAUL" tells nobody anything a year later. */
    let role = '';
    for (let c = nameCol + 1; c < payCol; c++) {
      const v = text(row[c]);
      if (v && toNum(v) === null) { role = v; break; }
    }

    entries.push({
      date: payday,
      category: 'Salaries',
      details: role ? `${name} — ${role}` : name,
      quantity: null,
      unit_price: null,
      amount: money(paid),
      sheet: sheetName,
      cell: A1(r, payCol),
    });
  }

  /* A payroll that was read but posted nothing. Every other way out of
     this function says why; silence here is what let a header row read
     as a total row go unnoticed. */
  if (!entries.length) {
    issues.warnings.push(
      `${sheetName}: a payroll was found, but no employee on it has a wage against them, `
      + 'so no salaries were imported.'
    );
  }

  return entries;
}

/* ── the workbook's own summary, for checking against ────── */

/**
 * Read the SUMMARY grid's column for the month being imported.
 *
 * Not to import — the app works its own totals out of the entries — but
 * to say so when the two disagree. A detail sheet corrected without its
 * summary column being retyped is the single most common thing wrong
 * with a book kept this way, and the import is the moment to catch it.
 */
function readSummary(ws, period) {
  const rows = sheetRows(ws);
  const width = rows.reduce((m, r) => Math.max(m, r.length), 0);
  const wanted = MONTH_NAMES[period.monthNum - 1];

  for (let r = 0; r < Math.min(rows.length, 12); r++) {
    let monthCol = null, labelCol = null;
    for (let c = 0; c < width; c++) {
      const n = norm(rows[r][c]);
      if (n === wanted) monthCol = c;
      if (n === 'DETAILS' || n === 'PARTICULARS') labelCol = c;
    }
    if (monthCol === null) continue;
    if (labelCol === null) labelCol = Math.max(0, monthCol - 1);

    const totals = new Map();
    for (let rr = r + 1; rr < rows.length; rr++) {
      const row = rows[rr] || [];
      if (isTotalRow(row)) break;
      const cat = categoryFor(text(row[labelCol]));
      const v = toNum(row[monthCol]);
      if (cat && v !== null) totals.set(cat.name, money(v));
    }
    if (totals.size) return totals;
  }
  return null;
}

/* ── the whole workbook ──────────────────────────────────── */

/**
 * @param {Buffer} buffer  the uploaded .xlsx
 * @param {object} [hint]  { filename } — read only for the month's name,
 *                         and only if the sheets themselves cannot say.
 */
function parseExpensesWorkbook(buffer, hint = {}) {
  const issues = { errors: [], warnings: [] };
  let wb;
  try {
    wb = XLSX.read(buffer, { type: 'buffer', cellDates: true });
  } catch (err) {
    return { ok: false, errors: [`The file could not be opened as a spreadsheet: ${err.message}`], warnings: [] };
  }

  const blocks = [];
  const skipped = [];
  let summarySheet = null, payrollSheet = null;

  for (const name of wb.SheetNames) {
    const ws = wb.Sheets[name];
    const why = ignoredSheet(name);

    if (norm(name) === 'SUMMARY') { summarySheet = ws; skipped.push({ sheet: name, why }); continue; }
    if (why) { skipped.push({ sheet: name, why }); continue; }

    /* The payroll is read after the month is known — see parsePayroll. */
    const asCategory = categoryFor(name);
    if (asCategory?.name === 'Salaries') { payrollSheet = { ws, name }; continue; }

    const found = parseSheet(ws, name, issues);
    if (found.length) { blocks.push(...found); continue; }

    /* An empty sheet is how the farm leaves a line open for a month
       nothing was spent on, and is not worth a word. A sheet with rows
       on it that produced nothing is. */
    const filled = (ws['!ref'] || 'A1:A1') !== 'A1:A1'
      && sheetRows(ws).some(r => r.some(v => !isBlank(v)));
    if (filled) {
      skipped.push({ sheet: name, why: 'nothing on it could be read as a list of expenses' });
    }
  }

  /* Nothing here looks like an expenses workbook at all — most often the
     wrong file entirely. Saying that plainly beats the month-detection
     failure it would otherwise fall through to. */
  if (!blocks.length && !payrollSheet) {
    issues.errors.push(
      'No expenses could be recognised in this file. A month\'s workbook keeps a sheet per '
      + 'line — a DATE heading, what the money went on, and an amount against it — and none of '
      + `that was found. Sheets read: ${wb.SheetNames.join(', ') || 'none'}.`
    );
    return { ok: false, ...issues, skipped };
  }

  const entries = blocks.flatMap(b => b.entries);

  /* ── which month is this? ──
     The dates on the entries decide it, by weight of numbers, rather
     than the file name — a workbook is copied from last month's and
     renamed, and the dates inside are the part that gets rewritten. */
  const tally = new Map();
  for (const e of entries) {
    if (!e.date) continue;
    const key = e.date.slice(0, 7);
    tally.set(key, (tally.get(key) || 0) + 1);
  }

  let period = null;
  if (tally.size) {
    const [key] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0];
    const [year, month] = key.split('-').map(Number);
    period = { monthNum: month, year, label: monthLabel(month, year) };
  } else {
    const fromName = periodFromText(hint.filename || '');
    if (fromName?.monthNum && fromName?.year) {
      period = {
        monthNum: fromName.monthNum, year: fromName.year,
        label: monthLabel(fromName.monthNum, fromName.year),
      };
      issues.warnings.push(
        `No dated rows were found, so the month was taken from the file name (${period.label}).`
      );
    }
  }

  if (!period) {
    issues.errors.push(
      'Nothing in the workbook says which month it is for. The detail sheets carry no dated rows, '
      + 'and the file name does not name a month and year either.'
    );
    return { ok: false, ...issues, skipped };
  }

  /* Rows above the first date on a sheet, dated to the 1st now that the
     month is known. */
  const firstOfMonth = `${period.year}-${String(period.monthNum).padStart(2, '0')}-01`;
  for (const e of entries) if (!e.date) e.date = firstOfMonth;

  const strays = entries.filter(e => e.date.slice(0, 7) !== firstOfMonth.slice(0, 7));
  if (strays.length) {
    const dates = [...new Set(strays.map(e => e.date))].sort().slice(0, 6).join(', ');
    issues.warnings.push(
      `${strays.length} row(s) are dated outside ${period.label} (${dates}). `
      + 'They were imported with the dates written on them, but they will be filed under this month.'
    );
  }

  if (payrollSheet) {
    const wages = parsePayroll(payrollSheet.ws, payrollSheet.name, period, issues);
    if (wages.length) {
      entries.push(...wages);
      blocks.push({
        sheet: payrollSheet.name, category: 'Salaries', banner: payrollSheet.name, entries: wages,
        total: money(wages.reduce((a, e) => a + e.amount, 0)), sheetTotal: null,
      });
    } else {
      skipped.push({ sheet: payrollSheet.name, why: 'no wages on it could be posted to this month — see the warnings' });
    }
  }

  if (!entries.length) {
    issues.errors.push('No expense rows were found in the workbook. Nothing was imported.');
    return { ok: false, ...issues, skipped, period };
  }

  /* ── per category, and against the farm's own summary ── */
  const byCategory = new Map();
  for (const e of entries) {
    const row = byCategory.get(e.category) || { category: e.category, count: 0, total: 0 };
    row.count++; row.total = money(row.total + e.amount);
    byCategory.set(e.category, row);
  }

  const check = [];
  if (summarySheet) {
    const claimed = readSummary(summarySheet, period);
    if (claimed) {
      const names = new Set([...claimed.keys(), ...byCategory.keys()]);
      for (const name of names) {
        const workbook = claimed.has(name) ? claimed.get(name) : null;
        const parsed   = byCategory.get(name)?.total || 0;
        const diff     = money(parsed - (workbook || 0));
        check.push({ category: name, workbook, parsed, diff });
      }
      check.sort((a, b) => Math.abs(b.diff) - Math.abs(a.diff));

      for (const row of check) {
        if (Math.abs(row.diff) <= 1) continue;
        issues.warnings.push(
          row.workbook === null
            ? `${row.category}: ${row.parsed.toLocaleString()} was read from the detail sheets, but the SUMMARY sheet has no line for it.`
            : `${row.category}: the SUMMARY sheet says ${row.workbook.toLocaleString()} for ${period.label}, `
              + `the detail sheet adds up to ${row.parsed.toLocaleString()} — a difference of ${row.diff.toLocaleString()}. `
              + 'The detail rows were imported.'
        );
      }
    }
  }

  return {
    ok: true,
    period,
    entries,
    categories: [...byCategory.values()].sort((a, b) => b.total - a.total),
    total: money(entries.reduce((a, e) => a + e.amount, 0)),
    sheets: blocks.map(b => ({
      sheet: b.sheet, category: b.category, banner: b.banner,
      count: b.entries.length, total: b.total, sheet_total: b.sheetTotal,
    })),
    skipped,
    check,
    ...issues,
  };
}

module.exports = { parseExpensesWorkbook, MONTHS };
