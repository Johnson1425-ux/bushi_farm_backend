/* ══════════════════════════════════════════════════════════════
   THE SALES WORKBOOK, READ BACK

   Reads the farm's sales day book — "2026 SEPTEMBER SDB.xlsx" — and hands
   back one flat list: on this day, this unit sold this many shillings.

   "Unit" is the workbook's own word (it writes UNITY): each column of a
   SALES BY UNITY sheet is somewhere the milk went out through — the two
   shops, the sales people who carry it round, and the bulk buyers and
   outlets that take it by the crate.

   What a workbook holds, and what is read from it:

     • "<MONTH> SALES BY UNITY"   a row per day, a column per unit, a
                                  TOTAL row at the foot. This is the
                                  record, and every row of it is read.

     • "MONTHLY SALES BY UNITY"   a unit per row, a month per column —
                                  the year so far. For a month that has
                                  its own daily sheet it is only a check
                                  on that sheet. For the months before the
                                  daily sheets start (January to May in
                                  2026) it is all there is, so those
                                  months come in as one figure per unit.

     • The day books ("01-SEPTEMBER-2026") are the same day again, by
       product: under each shop and sales person, how many of each pack
       went out, at what price. They are the only place litres are
       written down, so they are read as `items` — what was sold, not a
       second record of how much was taken. Money totals still come from
       the SALES BY UNITY sheets, so nothing is counted twice.

     • The cash sheets are where the money went afterwards, and MR BUSH /
       MRS BUSH are the household's cash. Neither is a sale. Each sheet
       left out is named in `skipped` with the reason.

   Nothing is read from a fixed cell. Sheets are recognised by name, the
   header row by its DATE (or MONTHS) cell, the unit columns by running
   from there to TOTAL UNITS, and the rows by running to TOTAL.

   Problems are separated by severity, as in the expenses parser:
   `errors` mean nothing is imported, `warnings` are for the operator.
══════════════════════════════════════════════════════════════ */

const XLSX = require('xlsx');
const { norm, MONTHS, MONTH_NAMES, monthLabel } = require('./expenseCatalog');
const {
  sheetRows, isBlank, toNum, toDate, text, money, A1,
} = require('./expensesWorkbook');

/* ── the units ────────────────────────────────────────────────

   The same unit is spelt differently from sheet to sheet — VIVA on the
   summary, VIVA MARKET on the month, JEREMIA on sales and JEREMIAH on the
   cash book, " BUYOMBE (TSHS. 2000)" with its price in the heading and
   "KONA YA BUYOMBE" without. Two spellings of one unit would split its
   takings in half, so every heading is matched against this list first,
   on letters and digits alone, and filed under the name here.

   `kind` groups them the way the farm thinks of them:
     shop      — the farm's own counters
     seller    — sales people, who bank their takings day by day
     bulk      — buyers and outlets taking milk by the crate               */

const UNITS = [
  { name: 'Bushi Milk House M9', kind: 'shop',   aliases: ['BUSHMILKHOUSEM9', 'BUSHIMILKHOUSEM9', 'BUSHMILKHOUSE', 'BUSHIMILKHOUSE', 'M9', 'M9SHOP', 'CASHM9'] },
  { name: 'Bushi Milk Town',     kind: 'shop',   aliases: ['BUSHIMILKTOWN', 'BUSHMILKTOWN', 'TOWNSHOP', 'CASHTOWNSHOP'] },
  { name: 'Joseph',              kind: 'seller', aliases: ['JOSEPH', 'J0SEPH'] },
  { name: 'Jeremia',             kind: 'seller', aliases: ['JEREMIA', 'JEREMIAH'] },
  { name: 'Rashidi',             kind: 'seller', aliases: ['RASHIDI', 'RASHID'] },
  { name: 'Erick',               kind: 'seller', aliases: ['ERICK', 'ERIC'] },
  { name: 'Isamilo',             kind: 'bulk',   aliases: ['ISAMILO'] },
  { name: 'Omar',                kind: 'bulk',   aliases: ['OMAR', 'OMARI', 'OMARY'] },
  { name: 'Other bulk',          kind: 'bulk',   aliases: ['OTHERBULK'] },
  { name: 'Kona ya Buyombe',     kind: 'bulk',   aliases: ['BUYOMBE', 'KONAYABUYOMBE'] },
  { name: 'Mji Mwema',           kind: 'bulk',   aliases: ['MJIMWEMA'] },
  { name: 'Royal Mjini',         kind: 'bulk',   aliases: ['ROYALMJINI', 'ROYAL', 'RORALMJINI'] },
  { name: 'Mnadani',             kind: 'bulk',   aliases: ['MNADANI', 'MNADANINELL'] },
  { name: 'U-Turn',              kind: 'bulk',   aliases: ['UTURN'] },
  { name: 'Baraka',              kind: 'bulk',   aliases: ['BARAKA'] },
  { name: 'Sengerema',           kind: 'bulk',   aliases: ['SENGEREMA'] },
  { name: 'Protus SPM',          kind: 'bulk',   aliases: ['PROTUSSPM', 'PROTUS'] },
  { name: 'Viva Market',         kind: 'bulk',   aliases: ['VIVAMARKET', 'VIVA'] },
  { name: 'Nono',                kind: 'bulk',   aliases: ['NONO'] },
  { name: 'Mwaloni',             kind: 'bulk',   aliases: ['MWALONI'] },
  { name: 'Madum',               kind: 'bulk',   aliases: ['MADUM'] },
  { name: 'Kopo',                kind: 'bulk',   aliases: ['KOPO'] },
];

const BY_ALIAS = new Map();
for (const u of UNITS) for (const a of u.aliases) BY_ALIAS.set(a, u);

/** The running order of the grids: the workbook's own, shops first. */
const UNIT_ORDER = new Map(UNITS.map((u, i) => [u.name, i]));

/**
 * The unit a column heading names.
 *
 * Tried as written, then without anything in brackets — the price a
 * heading carries, "(TSHS. 2000)", changes when the price does and must
 * not make a new unit of the same buyer. A heading nobody has seen is
 * still read, under its own name, and flagged: dropping a column of
 * money because its buyer is new would be the worst thing to do with it.
 */
function unitFor(heading) {
  const raw = text(heading);
  const whole = norm(raw);
  const bare  = norm(raw.replace(/\([^)]*\)?/g, ' '));
  const known = BY_ALIAS.get(whole) || BY_ALIAS.get(bare);
  if (known) return { name: known.name, kind: known.kind, known: true };

  const cleaned = raw.replace(/\([^)]*\)?/g, ' ').replace(/\s+/g, ' ').trim() || raw;
  const name = cleaned.toLowerCase().replace(/(^|[\s-])\S/g, c => c.toUpperCase());
  return { name, kind: 'bulk', known: false };
}

/* ── sheets ──────────────────────────────────────────────── */

/** A month's daily sheet: "JUNE SALES BY UNITY", "SEPTEMBER SALES UNITY". */
const isDailySheet = (name) => {
  const n = norm(name);
  return n.includes('SALES') && n.includes('UNIT') && !n.includes('MONTHLY');
};

const isMonthlySheet = (name) => {
  const n = norm(name);
  return n.includes('MONTHLY') && n.includes('SALES') && n.includes('UNIT');
};

/** A day book: "01-SEPTEMBER-2026", "02-SEPTEMBER-2026  (7)". */
function dayBookDate(name) {
  const m = String(name).toUpperCase().match(/^\s*(\d{1,2})\W*([A-Z]+)\W*(\d{4})/);
  if (!m || !MONTHS[m[2]]) return null;
  const day = Number(m[1]);
  if (day < 1 || day > 31) return null;
  return `${m[3]}-${String(MONTHS[m[2]]).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
}

/** Why a sheet that is not a SALES BY UNITY sheet is left alone. */
function skipReason(name) {
  const n = norm(name);
  if (n.includes('CASH')) return 'where the money went after the sale — cash, bank and deposits, not sales';
  if (n.includes('BUSH')) return 'the household\'s own cash book, not sales';
  return 'not a SALES BY UNITY sheet';
}

/** The row with DATE (or, on the summary, MONTHS) in it, and where. */
function findHeader(rows, word) {
  const last = Math.min(rows.length, 30);
  for (let r = 0; r < last; r++) {
    const row = rows[r] || [];
    for (let c = 0; c < row.length; c++) {
      if (norm(row[c]) === word) return { row: r, col: c };
    }
  }
  return null;
}

const isTotalHeading = (v) => /^TOTAL/.test(norm(v));

/**
 * Formula cells with no value saved against them.
 *
 * The reader takes the value Excel saved with each formula — it does not
 * recalculate. A workbook written by something other than Excel can leave
 * those empty, and every formula would then read as a blank: the day
 * quietly short. Counted so the operator hears about it.
 */
function unsavedFormulas(ws) {
  let n = 0;
  for (const [addr, cell] of Object.entries(ws)) {
    if (addr[0] === '!') continue;
    if (cell && cell.f && (cell.v === undefined || cell.v === null)) n++;
  }
  return n;
}

/**
 * One month's SALES BY UNITY sheet → entries, the TOTAL row it claims,
 * and the month it is for.
 */
function parseDailySheet(ws, sheetName, issues) {
  const rows = sheetRows(ws);
  const head = findHeader(rows, 'DATE');
  if (!head) {
    issues.warnings.push(`${sheetName}: no DATE heading was found, so nothing on it was read.`);
    return null;
  }

  const header = rows[head.row];
  const cols = [];
  for (let c = head.col + 1; c < header.length; c++) {
    const h = header[c];
    if (isBlank(h)) continue;
    if (isTotalHeading(h)) break;
    const unit = unitFor(h);
    if (!unit.known) {
      issues.warnings.push(
        `${sheetName}: the column "${text(h)}" is not a unit the app knows. `
        + `It was read as "${unit.name}", grouped with the bulk buyers.`
      );
    }
    cols.push({ col: c, heading: text(h), ...unit });
  }

  const entries = [];
  const sheetTotals = new Map();
  let hasTotalRow = false;

  for (let r = head.row + 1; r < rows.length; r++) {
    const row = rows[r] || [];
    const label = row[head.col];
    if (isTotalHeading(label)) {
      hasTotalRow = true;
      for (const c of cols) {
        const v = toNum(row[c.col]);
        if (v !== null) sheetTotals.set(c.name, money((sheetTotals.get(c.name) || 0) + v));
      }
      break;
    }
    const date = label instanceof Date || typeof label === 'number' ? toDate(label) : null;
    if (!date) {
      const stray = cols.some(c => toNum(row[c.col]));
      if (stray) {
        issues.warnings.push(
          `${sheetName}!${A1(r, head.col)}: a row with figures on it but no date in the DATE column was left out.`
        );
      }
      continue;
    }

    for (const c of cols) {
      const v = toNum(row[c.col]);
      if (!v) continue;
      if (v < 0) {
        issues.warnings.push(
          `${sheetName}!${A1(r, c.col)}: ${c.name} is negative on ${date} (${v.toLocaleString()}). It was imported as written.`
        );
      }
      entries.push({
        date, unit: c.name, kind: c.kind, amount: money(v),
        whole_month: false, sheet: sheetName, cell: A1(r, c.col),
      });
    }
  }

  if (!entries.length) {
    return { sheet: sheetName, entries, month: null, units: cols.length };
  }

  /* The month by weight of dates, not from the tab: a sheet copied from
     last month and renamed keeps the old name until someone notices. */
  const tally = new Map();
  for (const e of entries) tally.set(e.date.slice(0, 7), (tally.get(e.date.slice(0, 7)) || 0) + 1);
  const [month] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0];

  const strays = [...new Set(entries.filter(e => e.date.slice(0, 7) !== month).map(e => e.date))];
  if (strays.length) {
    issues.warnings.push(
      `${sheetName}: most rows are in ${month} but ${strays.length} date(s) are not (${strays.slice(0, 5).join(', ')}). `
      + 'They were imported under the dates written on them.'
    );
  }

  /* The sheet's own TOTAL row, against what its days add up to. */
  const check = [];
  if (hasTotalRow) {
    const read = new Map();
    for (const e of entries) read.set(e.unit, money((read.get(e.unit) || 0) + e.amount));
    for (const name of new Set([...read.keys(), ...sheetTotals.keys()])) {
      const parsed = read.get(name) || 0;
      const claimed = sheetTotals.has(name) ? sheetTotals.get(name) : null;
      const diff = money(parsed - (claimed || 0));
      if (Math.abs(diff) > 1) {
        check.push({ sheet: sheetName, unit: name, workbook: claimed, parsed, diff });
        issues.warnings.push(
          `${sheetName}: the TOTAL row says ${(claimed || 0).toLocaleString()} for ${name}, `
          + `the days add up to ${parsed.toLocaleString()}. The days were imported.`
        );
      }
    }
  }

  return { sheet: sheetName, entries, month, units: cols.length, check };
}

/**
 * The year-so-far summary → a figure per unit per month.
 *
 * The year comes from its banner ("FOR THE YEAR 2026"), failing that from
 * the daily sheets beside it.
 */
function parseMonthlySheet(ws, sheetName, fallbackYear, issues) {
  const rows = sheetRows(ws);
  const head = findHeader(rows, 'MONTHS');
  if (!head) {
    issues.warnings.push(`${sheetName}: no MONTHS heading was found, so the year summary was not read.`);
    return null;
  }

  let year = null;
  for (let r = 0; r < head.row && !year; r++) {
    for (const v of rows[r] || []) {
      const m = String(v ?? '').match(/\b(20\d{2})\b/);
      if (m) { year = Number(m[1]); break; }
    }
  }
  year = year || fallbackYear;
  if (!year) {
    issues.warnings.push(`${sheetName}: the year could not be worked out, so the year summary was not read.`);
    return null;
  }

  const header = rows[head.row];
  const monthCols = [];
  for (let c = head.col + 1; c < header.length; c++) {
    const m = MONTHS[norm(header[c])];
    if (m) monthCols.push({ col: c, month: m });
  }

  const figures = [];
  for (let r = head.row + 1; r < rows.length; r++) {
    const row = rows[r] || [];
    const label = row[head.col];
    if (isBlank(label)) continue;
    if (isTotalHeading(label)) break;
    const unit = unitFor(label);
    for (const mc of monthCols) {
      const v = toNum(row[mc.col]);
      if (!v) continue;
      figures.push({
        month: `${year}-${String(mc.month).padStart(2, '0')}`,
        unit: unit.name, kind: unit.kind, known: unit.known, heading: text(label),
        amount: money(v), sheet: sheetName, cell: A1(r, mc.col),
      });
    }
  }
  return { sheet: sheetName, year, figures };
}

/* ── the day books ───────────────────────────────────────── */

/**
 * Litres in one pack, from the VOLUME column: "150ML", "CUPS 500mls",
 * "1L PLAINI", "10L". Loose milk is written LTRS, and its units are
 * litres already.
 */
function litresPerPack(volume) {
  const v = String(volume ?? '').toUpperCase();
  if (!v.trim()) return null;
  const m = v.match(/(\d+(?:\.\d+)?)\s*(ML|MLS|LTRS?|LITRES?|L)\b/);
  if (m) return m[2].startsWith('M') ? Number(m[1]) / 1000 : Number(m[1]);
  if (/\b(LTRS?|LITRES?)\b/.test(v)) return 1;
  return null;
}

/**
 * A row under a shop that is really another buyer's — "BULK SALE ISAMILO",
 * "BULK OMARY", "RORAL MJINI". The SALES BY UNITY sheet moves those to the
 * buyer's own column, and the litres follow them there so that a unit's
 * litres and its shillings describe the same sales. A plain "BULK FRESH"
 * names nobody and stays with the shop that sent it out.
 */
function buyerIn(product) {
  const words = String(product ?? '').toUpperCase().replace(/\([^)]*\)?/g, ' ')
    .split(/[^A-Z0-9]+/).filter(w => w && !['BULK', 'SALE', 'SALES', 'FRESH'].includes(w));
  if (!words.length) return null;
  return BY_ALIAS.get(words.join('')) || null;
}

/**
 * One day book → items: under each unit, how many of each pack, at what
 * price, and the litres that makes.
 *
 * The heading row names the units, the row beneath it repeats UNIT /
 * PRICE / AMOUNT for each. Blocks are found from that second row, and
 * each is named by the first heading over its three columns — on some
 * days a name sits one column off its block ("ERICK" on the 7th).
 */
function parseDayBook(ws, sheetName, date, issues) {
  const rows = sheetRows(ws);
  const head = findHeader(rows, 'PRODUCTS');
  if (!head) {
    issues.warnings.push(`${sheetName}: no PRODUCTS heading was found, so no litres were read from it.`);
    return null;
  }
  const header = rows[head.row] || [];
  const sub = rows[head.row + 1] || [];

  let volumeCol = null, totalCol = header.length, litresCol = null;
  for (let c = 0; c < header.length; c++) {
    const h = norm(header[c]);
    if (h === 'VOLUME') volumeCol = c;
    if (h.startsWith('TOTAL') && c > head.col && totalCol === header.length) totalCol = c;
  }
  for (let c = totalCol; c < sub.length; c++) if (norm(sub[c]) === 'LTRS') { litresCol = c; break; }

  const blocks = [];
  for (let c = head.col + 1; c < totalCol; c++) {
    if (!['UNIT', 'UNITY', 'UNITS'].includes(norm(sub[c]))) continue;
    const heading = [header[c], header[c + 1], header[c + 2]].find(v => !isBlank(v));
    if (!heading) continue;
    blocks.push({ col: c, heading: text(heading), ...unitFor(heading) });
  }

  const items = [];
  let product = '', volume = null, sheetLitres = 0;
  for (let r = head.row + 2; r < rows.length; r++) {
    const row = rows[r] || [];
    if (isTotalHeading(row[head.col - 1]) || isTotalHeading(row[head.col])) break;
    if (!isBlank(row[head.col])) product = text(row[head.col]);
    if (volumeCol !== null && !isBlank(row[volumeCol])) volume = text(row[volumeCol]);
    if (!product) continue;
    if (litresCol !== null) sheetLitres += toNum(row[litresCol]) || 0;

    const perPack = litresPerPack(volume);
    const pack = volume && norm(volume) !== 'LTRS' ? volume : 'Litres';
    for (const b of blocks) {
      const units = toNum(row[b.col]);
      if (!units) continue;
      const price = toNum(row[b.col + 1]);
      const written = toNum(row[b.col + 2]);
      const buyer = buyerIn(product);
      if (perPack === null) {
        issues.warnings.push(`${sheetName}!${A1(r, b.col)}: "${product} ${volume || ''}" has no pack size the app can read, so it counts no litres.`);
      }
      items.push({
        date,
        unit: buyer ? buyer.name : b.name,
        kind: buyer ? buyer.kind : b.kind,
        sold_by: b.name,
        product, pack,
        units,
        price,
        amount: money(written !== null ? written : units * (price || 0)),
        litres: perPack === null ? 0 : Math.round(units * perPack * 1000) / 1000,
        sheet: sheetName, cell: A1(r, b.col),
      });
    }
  }

  /* A column nobody knows is only worth a word if something was sold
     under it — the combined U-TURN&VIVA column sits empty most days. */
  for (const b of blocks) {
    if (!b.known && items.some(i => i.cell && i.sold_by === b.name)) {
      issues.warnings.push(`${sheetName}: the column "${b.heading}" is not a unit the app knows; its litres were filed under "${b.name}".`);
    }
  }

  const litres = Math.round(items.reduce((a, i) => a + i.litres, 0) * 1000) / 1000;
  return {
    sheet: sheetName, date, items, litres,
    sheet_litres: litresCol === null ? null : Math.round(sheetLitres * 1000) / 1000,
  };
}

const labelOf = (ym) => {
  const [y, m] = ym.split('-').map(Number);
  return monthLabel(m, y);
};

/**
 * Read a sales workbook.
 *
 * Returns { ok, entries, months: [{ month, label, detail, count, total }],
 * total, sheets, skipped, check, warnings } — or { ok: false, errors }.
 */
function parseSalesWorkbook(buffer) {
  const issues = { errors: [], warnings: [] };
  let wb;
  try {
    wb = XLSX.read(buffer, { type: 'buffer', cellDates: true });
  } catch (err) {
    return { ok: false, errors: [`The file could not be opened as a spreadsheet: ${err.message}`], warnings: [] };
  }

  const daily = [];
  const dayBooks = new Map();
  const skipped = [];
  let monthlySheet = null;
  let unsaved = 0;

  for (const name of wb.SheetNames) {
    const ws = wb.Sheets[name];
    if (isMonthlySheet(name)) { monthlySheet = { ws, name }; unsaved += unsavedFormulas(ws); continue; }
    const bookDate = dayBookDate(name);
    if (bookDate) {
      const book = parseDayBook(ws, name, bookDate, issues);
      if (!book) { skipped.push({ sheet: name, why: 'a day book with no PRODUCTS heading' }); continue; }
      if (!book.items.length) { skipped.push({ sheet: name, why: 'a day book with nothing sold on it — an empty copy' }); continue; }
      /* Two filled-in books for one day cannot both be right, and adding
         them would double the day's litres. The first is kept. */
      if (dayBooks.has(bookDate)) {
        issues.warnings.push(
          `"${name}" and "${dayBooks.get(bookDate).sheet}" are both day books for ${bookDate}. `
          + `Only "${dayBooks.get(bookDate).sheet}" was read.`
        );
        skipped.push({ sheet: name, why: `a second day book for ${bookDate}` });
        continue;
      }
      unsaved += unsavedFormulas(ws);
      dayBooks.set(bookDate, book);
      continue;
    }
    if (!isDailySheet(name)) { skipped.push({ sheet: name, why: skipReason(name) }); continue; }
    unsaved += unsavedFormulas(ws);
    const found = parseDailySheet(ws, name, issues);
    if (!found) { skipped.push({ sheet: name, why: 'no DATE heading on it' }); continue; }
    if (!found.entries.length) { skipped.push({ sheet: name, why: 'no sales written on it yet' }); continue; }
    daily.push(found);
  }

  if (unsaved) {
    issues.warnings.push(
      `${unsaved} formula cell(s) have no value saved with them, and were read as blank. `
      + 'Open the workbook in Excel, let it recalculate, save it and upload it again.'
    );
  }

  /* Two sheets for one month — usually last month's copied and not yet
     renamed. Both cannot be right, and adding them would double it. */
  const byMonth = new Map();
  for (const d of daily) {
    if (byMonth.has(d.month)) {
      issues.errors.push(
        `Two sheets are both for ${labelOf(d.month)}: "${byMonth.get(d.month).sheet}" and "${d.sheet}". `
        + 'Delete or fix one of them and upload again.'
      );
      continue;
    }
    byMonth.set(d.month, d);
  }

  const entries = [...byMonth.values()].flatMap(d => d.entries);
  const check = [...byMonth.values()].flatMap(d => d.check || []);

  /* ── the year summary ── */
  let summary = null;
  if (monthlySheet) {
    const years = [...byMonth.keys()].map(k => Number(k.slice(0, 4)));
    summary = parseMonthlySheet(monthlySheet.ws, monthlySheet.name, years[0] || null, issues);
  }

  const summaryOnly = new Map();
  if (summary) {
    const perMonth = new Map();
    for (const f of summary.figures) {
      if (!perMonth.has(f.month)) perMonth.set(f.month, []);
      perMonth.get(f.month).push(f);
    }

    for (const [month, figs] of perMonth) {
      const detail = byMonth.get(month);
      if (!detail) {
        /* No daily sheet for it: the summary is the only record. */
        for (const f of figs) {
          if (!f.known) {
            issues.warnings.push(
              `${f.sheet}: the row "${f.heading}" is not a unit the app knows. It was read as "${f.unit}".`
            );
          }
          entries.push({
            date: `${month}-01`, unit: f.unit, kind: f.kind, amount: f.amount,
            whole_month: true, sheet: f.sheet, cell: f.cell,
          });
        }
        summaryOnly.set(month, true);
        continue;
      }

      /* A daily sheet exists — the summary is only a check on it. */
      const read = new Map();
      for (const e of detail.entries) read.set(e.unit, money((read.get(e.unit) || 0) + e.amount));
      const claimed = new Map();
      for (const f of figs) claimed.set(f.unit, money((claimed.get(f.unit) || 0) + f.amount));
      for (const unit of new Set([...read.keys(), ...claimed.keys()])) {
        const parsed = read.get(unit) || 0;
        const said = claimed.has(unit) ? claimed.get(unit) : null;
        const diff = money(parsed - (said || 0));
        if (Math.abs(diff) <= 1) continue;
        check.push({ sheet: summary.sheet, month, unit, workbook: said, parsed, diff });
        issues.warnings.push(
          `${labelOf(month)}, ${unit}: the year summary says ${(said || 0).toLocaleString()}, `
          + `the ${detail.sheet} sheet adds up to ${parsed.toLocaleString()}. The daily figures were imported.`
        );
      }
    }
  }

  if (!issues.errors.length && !entries.length) {
    issues.errors.push(
      'No sales could be recognised in this file. The sales book keeps a sheet per month called '
      + '"<MONTH> SALES BY UNITY" — a DATE column, a column for each shop, sales person and bulk buyer, '
      + `and a TOTAL row — and none was found. Sheets in the file: ${wb.SheetNames.join(', ') || 'none'}.`
    );
  }
  if (issues.errors.length) return { ok: false, ...issues, skipped };

  /* ── per month ── */
  const months = new Map();
  for (const e of entries) {
    const key = e.date.slice(0, 7);
    const m = months.get(key) || {
      month: key, label: labelOf(key), detail: summaryOnly.has(key) ? 'month' : 'day',
      count: 0, total: 0,
    };
    m.count++; m.total = money(m.total + e.amount);
    months.set(key, m);
  }

  /* ── the day books, against the day they describe ──
     The SALES BY UNITY row for a day is the money; the day book is how
     it was made up. When the two disagree the operator should know,
     though the litres are still what the day book says was sold. */
  const items = [...dayBooks.values()].flatMap(b => b.items);

  /* The book's own LTRS column, where it disagrees with the packs. Said
     once for all the days: from the 2nd of September its formula adds
     up the PRICE columns, and a warning a day would bury the rest. */
  const off = [...dayBooks.values()].filter(b => b.sheet_litres !== null && Math.abs(b.sheet_litres - b.litres) > 0.5);
  if (off.length) {
    issues.warnings.push(
      `The day books' own LTRS total disagrees with the packs sold on ${off.length} day(s): `
      + off.map(b => `${b.date} (sheet ${b.sheet_litres.toLocaleString()}, packs ${b.litres.toLocaleString()})`).join('; ')
      + '. Litres were worked out from the packs. A total in the hundreds of thousands means the LTRS formula '
      + 'is adding up a PRICE column — usually after a column was inserted.'
    );
  }
  const books = [...dayBooks.values()].sort((a, b) => a.date.localeCompare(b.date)).map(b => {
    const booked = money(b.items.reduce((a, i) => a + i.amount, 0));
    const day = money(entries.filter(e => !e.whole_month && e.date === b.date).reduce((a, e) => a + e.amount, 0));
    if (day && Math.abs(booked - day) > 1) {
      issues.warnings.push(
        `${b.sheet}: the day book's amounts add up to ${booked.toLocaleString()}, the SALES BY UNITY sheet has `
        + `${day.toLocaleString()} for ${b.date}. Shillings come from SALES BY UNITY; the litres from the day book.`
      );
    }
    return { sheet: b.sheet, date: b.date, lines: b.items.length, litres: b.litres, amount: booked, day_total: day || null };
  });

  return {
    ok: true,
    entries,
    items,
    books,
    litres: Math.round(items.reduce((a, i) => a + i.litres, 0) * 1000) / 1000,
    months: [...months.values()].sort((a, b) => a.month.localeCompare(b.month)),
    total: money(entries.reduce((a, e) => a + e.amount, 0)),
    sheets: [
      ...[...byMonth.values()].map(d => ({
        sheet: d.sheet, kind: 'day', month: labelOf(d.month), units: d.units,
        count: d.entries.length, total: money(d.entries.reduce((a, e) => a + e.amount, 0)),
      })),
      ...(summary ? [{
        sheet: summary.sheet, kind: 'summary', month: `${summary.year} summary`,
        units: new Set(summary.figures.map(f => f.unit)).size,
        count: entries.filter(e => e.whole_month).length,
        total: money(entries.filter(e => e.whole_month).reduce((a, e) => a + e.amount, 0)),
      }] : []),
      ...books.map(b => ({
        sheet: b.sheet, kind: 'book', month: b.date, units: null, count: b.lines, total: b.amount,
      })),
    ],
    skipped,
    check,
    ...issues,
  };
}

module.exports = { parseSalesWorkbook, unitFor, UNITS, UNIT_ORDER, MONTH_NAMES };
