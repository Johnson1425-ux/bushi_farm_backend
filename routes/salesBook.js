const express = require('express');
const multer  = require('multer');
const { pool } = require('../db');
const { parseSalesWorkbook, UNIT_ORDER } = require('../lib/salesWorkbook');
const { monthLabel } = require('../lib/expenseCatalog');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* NOTE: mounted in server.js as
   `app.use('/api/sales-book', verifyToken, requireProduction, salesBookRouter)`.

   The sales day book, read in from the farm's workbook until the sales
   people record their sales in the app — see lib/initSalesBook.js for
   why it is a book of its own rather than till receipts.

   Every total here is worked out from the lines on the way past; nothing
   is stored twice. */

const num   = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const money = (v) => Math.round(num(v) * 100) / 100;
const litre = (v) => Math.round(num(v) * 100) / 100;

const KIND_ORDER = { shop: 0, seller: 1, bulk: 2 };

/** Shops, then sales people, then bulk buyers — the workbook's order within each. */
function byUnit(a, b) {
  return (KIND_ORDER[a.kind] - KIND_ORDER[b.kind])
    || ((UNIT_ORDER.has(a.unit) ? UNIT_ORDER.get(a.unit) : 999) - (UNIT_ORDER.has(b.unit) ? UNIT_ORDER.get(b.unit) : 999))
    || a.unit.localeCompare(b.unit);
}

/* ══════════════════════════════════
   THE UPLOADS
══════════════════════════════════ */

router.get('/imports', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.id, i.filename, i.sheets, i.uploaded_at, u.username AS uploaded_by,
             COUNT(e.id)::int                  AS entry_count,
             (SELECT COALESCE(SUM(t.litres), 0) FROM sales_book_items t WHERE t.import_id = i.id) AS litres,
             COALESCE(SUM(e.amount), 0)        AS total,
             TO_CHAR(MIN(e.entry_date), 'YYYY-MM') AS first_month,
             TO_CHAR(MAX(e.entry_date), 'YYYY-MM') AS last_month
      FROM sales_book_imports i
      LEFT JOIN sales_book_entries e ON e.import_id = i.id
      LEFT JOIN users u ON u.id = i.uploaded_by
      GROUP BY i.id, u.username
      ORDER BY i.uploaded_at DESC
    `);
    const label = (ym) => {
      if (!ym) return null;
      const [y, m] = ym.split('-').map(Number);
      return monthLabel(m, y);
    };
    res.json(rows.map(r => ({
      ...r, total: num(r.total), litres: num(r.litres),
      covers: r.first_month === r.last_month
        ? label(r.first_month)
        : `${label(r.first_month)} – ${label(r.last_month)}`,
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Read a sales workbook in.
 *
 * The book is one file that grows through the year, so an upload usually
 * repeats months already read. Each month it brings replaces that month,
 * whichever upload it came from before:
 *
 *   • a month with its own daily sheet replaces everything held for it;
 *   • a month known only from the year summary replaces an earlier
 *     summary figure, but never daily lines — the detail is kept.
 *
 * An earlier upload left with nothing in it is removed.
 */
router.post('/import', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const parsed = parseSalesWorkbook(req.file.buffer);
  if (!parsed.ok) {
    return res.status(422).json({
      error:    'The workbook could not be imported. Fix the issues below and upload it again.',
      issues:   parsed.errors,
      warnings: parsed.warnings,
      skipped:  parsed.skipped,
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const dayMonths   = parsed.months.filter(m => m.detail === 'day').map(m => m.month);
    const wholeMonths = parsed.months.filter(m => m.detail === 'month').map(m => m.month);

    /* Whatever an earlier upload read off the same daily sheets goes too,
       whichever month it was filed under. A sheet read wrongly once — a
       date that came in a day early and landed in the month before — is
       otherwise left behind, and would stop that month's summary figure
       from ever replacing it. */
    const daySheets = parsed.sheets.filter(s => s.kind === 'day').map(s => `${s.sheet}!`);
    const replaced = await client.query(
      `DELETE FROM sales_book_entries
       WHERE TO_CHAR(entry_date, 'YYYY-MM') = ANY($1::text[])
          OR (whole_month = FALSE AND EXISTS (
                SELECT 1 FROM UNNEST($2::text[]) p WHERE STARTS_WITH(source_ref, p)))
       RETURNING TO_CHAR(entry_date, 'YYYY-MM') AS month`, [dayMonths, daySheets]
    );

    /* Summary-only months that already have days behind them keep them. */
    const { rows: detailed } = await client.query(
      `SELECT DISTINCT TO_CHAR(entry_date, 'YYYY-MM') AS month FROM sales_book_entries
       WHERE whole_month = FALSE AND TO_CHAR(entry_date, 'YYYY-MM') = ANY($1::text[])`, [wholeMonths]
    );
    const keep = new Set(detailed.map(r => r.month));
    const summaryMonths = wholeMonths.filter(m => !keep.has(m));
    const replacedSummary = await client.query(
      `DELETE FROM sales_book_entries WHERE whole_month = TRUE AND TO_CHAR(entry_date, 'YYYY-MM') = ANY($1::text[])
       RETURNING TO_CHAR(entry_date, 'YYYY-MM') AS month`, [summaryMonths]
    );

    const entries = parsed.entries.filter(e => !keep.has(e.date.slice(0, 7)));

    const sheets = parsed.sheets.map(s => s.sheet).join(', ');
    const { rows: [imp] } = await client.query(
      `INSERT INTO sales_book_imports (filename, sheets, uploaded_by) VALUES ($1,$2,$3) RETURNING id`,
      [req.file.originalname, sheets, req.user.id]
    );

    /* One statement for the lot: a year's book is close to a thousand
       lines, and a round trip each would be most of the upload's time. */
    if (entries.length) {
      await client.query(
        `INSERT INTO sales_book_entries
           (import_id, entry_date, unit, unit_kind, amount, whole_month, source_ref)
         SELECT $1, d, u, k, a, w, r
         FROM UNNEST($2::date[], $3::text[], $4::text[], $5::numeric[], $6::boolean[], $7::text[])
              AS t(d, u, k, a, w, r)`,
        [imp.id,
         entries.map(e => e.date), entries.map(e => e.unit), entries.map(e => e.kind),
         entries.map(e => e.amount), entries.map(e => e.whole_month),
         entries.map(e => `${e.sheet}!${e.cell}`)]
      );
    }

    /* The day books' lines: a day's lines are replaced as a unit, as is
       anything an earlier upload read off a sheet of the same name. */
    const items = parsed.items;
    const bookDays = parsed.books.map(b => b.date);
    const bookSheets = parsed.books.map(b => `${b.sheet}!`);
    await client.query(
      `DELETE FROM sales_book_items
       WHERE entry_date = ANY($1::date[])
          OR EXISTS (SELECT 1 FROM UNNEST($2::text[]) p WHERE STARTS_WITH(source_ref, p))`,
      [bookDays, bookSheets]
    );
    if (items.length) {
      await client.query(
        `INSERT INTO sales_book_items
           (import_id, entry_date, unit, unit_kind, sold_by, product, pack, units, price, amount, litres, source_ref)
         SELECT $1, d, u, k, sb, p, pk, n, pr, a, l, r
         FROM UNNEST($2::date[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
                     $8::numeric[], $9::numeric[], $10::numeric[], $11::numeric[], $12::text[])
              AS t(d, u, k, sb, p, pk, n, pr, a, l, r)`,
        [imp.id,
         items.map(i => i.date), items.map(i => i.unit), items.map(i => i.kind), items.map(i => i.sold_by),
         items.map(i => i.product), items.map(i => i.pack), items.map(i => i.units), items.map(i => i.price),
         items.map(i => i.amount), items.map(i => i.litres), items.map(i => `${i.sheet}!${i.cell}`)]
      );
    }

    const emptied = await client.query(`
      DELETE FROM sales_book_imports i
      WHERE NOT EXISTS (SELECT 1 FROM sales_book_entries e WHERE e.import_id = i.id)
        AND NOT EXISTS (SELECT 1 FROM sales_book_items t WHERE t.import_id = i.id)
      RETURNING id
    `);

    /* Days the till already has receipts for. The two are shown side by
       side and never added together, but a day in both is worth knowing
       about: it is the day the sales people started using the app, or a
       day recorded twice. */
    const { rows: overlap } = await client.query(`
      SELECT TO_CHAR(d, 'YYYY-MM-DD') AS day FROM (
        SELECT DISTINCT entry_date AS d FROM sales_book_entries
        WHERE import_id = $1 AND whole_month = FALSE
      ) b
      WHERE EXISTS (SELECT 1 FROM pos_sales s WHERE s.sold_on = b.d AND s.status = 'completed')
      ORDER BY 1
    `, [imp.id]);

    await client.query('COMMIT');

    const warnings = [...parsed.warnings];
    if (keep.size) {
      warnings.push(
        `${[...keep].sort().join(', ')} already had day-by-day figures from an earlier upload, `
        + 'so this workbook\'s month totals for them were not used.'
      );
    }
    if (overlap.length) {
      warnings.push(
        `${overlap.length} day(s) in this workbook also have till receipts (${overlap.slice(0, 5).map(r => r.day).join(', ')}`
        + `${overlap.length > 5 ? ', …' : ''}). The Sales page keeps the two apart — check they are not the same sales twice.`
      );
    }

    const replacedMonths = [...new Set([...replaced.rows, ...replacedSummary.rows].map(r => r.month))].sort();

    res.status(201).json({
      success: true,
      import_id: emptied.rows.some(r => r.id === imp.id) ? null : imp.id,
      entries: entries.length,
      total: money(entries.reduce((a, e) => a + e.amount, 0)),
      litres: parsed.litres,
      books: parsed.books,
      months: parsed.months.map(m => ({ ...m, kept_earlier_detail: keep.has(m.month) })),
      replaced_months: replacedMonths,
      removed_imports: emptied.rows.filter(r => r.id !== imp.id).length,
      sheets: parsed.sheets,
      skipped: parsed.skipped,
      check: parsed.check,
      warnings,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

router.delete('/imports/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'DELETE FROM sales_book_imports WHERE id=$1 RETURNING filename', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'That upload no longer exists' });
    res.json({ ok: true, filename: rows[0].filename });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE UNITS — each shop, sales person and bulk buyer on its own,
   the way a category opens on the expenses page.
══════════════════════════════════ */

router.get('/units', async (req, res) => {
  const year = parseInt(req.query.year, 10) || new Date().getUTCFullYear();
  try {
    const { rows } = await pool.query(`
      SELECT unit, unit_kind AS kind,
             COALESCE(SUM(amount), 0)                                           AS total,
             COALESCE(SUM(amount) FILTER (WHERE EXTRACT(YEAR FROM entry_date) = $1), 0) AS year_total,
             COUNT(*) FILTER (WHERE NOT whole_month)::int                        AS days,
             COUNT(DISTINCT TO_CHAR(entry_date, 'YYYY-MM'))::int                 AS months,
             TO_CHAR(MIN(entry_date), 'YYYY-MM-DD')                              AS first_date,
             TO_CHAR(MAX(entry_date) FILTER (WHERE NOT whole_month), 'YYYY-MM-DD') AS last_day
      FROM sales_book_entries
      GROUP BY unit, unit_kind
    `, [year]);
    const { rows: lit } = await pool.query(`
      SELECT unit, SUM(litres) AS litres, COUNT(DISTINCT entry_date)::int AS litre_days
      FROM sales_book_items WHERE EXTRACT(YEAR FROM entry_date) = $1
      GROUP BY unit
    `, [year]);
    const litresOf = new Map(lit.map(r => [r.unit, r]));
    const units = rows.map(r => ({
      ...r, total: num(r.total), year_total: num(r.year_total),
      year_litres: litre(litresOf.get(r.unit)?.litres), litre_days: litresOf.get(r.unit)?.litre_days || 0,
    })).sort(byUnit);
    const yearTotal = money(units.reduce((a, u) => a + u.year_total, 0));
    res.json({ year, year_total: yearTotal, year_litres: litre(units.reduce((a, u) => a + u.year_litres, 0)), units });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * One unit, month by month, with the days behind each month.
 *
 * Every month of the year is listed, sold in or not: a sales person who
 * went quiet for two months is a reading, and a table that left those
 * months out would hide it.
 */
router.get('/units/:unit', async (req, res) => {
  const unit = req.params.unit;
  const year = parseInt(req.query.year, 10) || new Date().getUTCFullYear();
  try {
    const [entries, byYear, whole, lines] = await Promise.all([
      pool.query(`
        SELECT TO_CHAR(entry_date, 'YYYY-MM-DD') AS date, amount, whole_month, source_ref, unit_kind AS kind
        FROM sales_book_entries
        WHERE unit = $1 AND EXTRACT(YEAR FROM entry_date) = $2
        ORDER BY entry_date
      `, [unit, year]),
      pool.query(`
        SELECT EXTRACT(YEAR FROM entry_date)::int AS year, SUM(amount) AS total
        FROM sales_book_entries WHERE unit = $1
        GROUP BY year ORDER BY year DESC
      `, [unit]),
      /* Every unit together, month by month, for this unit's share. */
      pool.query(`
        SELECT EXTRACT(MONTH FROM entry_date)::int AS month, SUM(amount) AS total
        FROM sales_book_entries WHERE EXTRACT(YEAR FROM entry_date) = $1
        GROUP BY month
      `, [year]),
      /* The day books' lines, for the litres. */
      pool.query(`
        SELECT TO_CHAR(entry_date, 'YYYY-MM-DD') AS date, product, pack, units, price, amount, litres, sold_by
        FROM sales_book_items
        WHERE unit = $1 AND EXTRACT(YEAR FROM entry_date) = $2
        ORDER BY entry_date, id
      `, [unit, year]),
    ]);

    if (!byYear.rows.length) return res.status(404).json({ error: `Nothing in the sales book for ${unit}` });

    const allByMonth = Array(12).fill(0);
    for (const r of whole.rows) allByMonth[r.month - 1] = num(r.total);

    const months = Array.from({ length: 12 }, (_, i) => ({
      month: i + 1, total: 0, days: [], whole_month: false, share: 0,
    }));
    let kind = null;
    for (const e of entries.rows) {
      kind = e.kind;
      const m = months[Number(e.date.slice(5, 7)) - 1];
      const amount = num(e.amount);
      m.total = money(m.total + amount);
      if (e.whole_month) m.whole_month = true;
      else m.days.push({ date: e.date, amount, source_ref: e.source_ref });
    }
    /* Litres by day, and the products that made them. A day with money
       but no day book simply has no litres — it is not a day of zero. */
    const litresByDay = new Map();
    const products = new Map();
    for (const l of lines.rows) {
      const d = litresByDay.get(l.date) || { litres: 0, lines: [] };
      d.litres = litre(d.litres + num(l.litres));
      d.lines.push({
        product: l.product, pack: l.pack, units: num(l.units), price: l.price === null ? null : num(l.price),
        amount: num(l.amount), litres: num(l.litres), sold_by: l.sold_by,
      });
      litresByDay.set(l.date, d);

      const key = `${l.product}|${l.pack}`;
      const p = products.get(key) || { product: l.product, pack: l.pack, units: 0, litres: 0, amount: 0 };
      p.units = litre(p.units + num(l.units));
      p.litres = litre(p.litres + num(l.litres));
      p.amount = money(p.amount + num(l.amount));
      products.set(key, p);
    }
    for (const m of months) {
      m.litres = 0; m.litre_days = 0;
      for (const d of m.days) {
        const l = litresByDay.get(d.date);
        d.litres = l ? l.litres : null;
        d.lines = l ? l.lines : [];
        if (l) { m.litres = litre(m.litres + l.litres); m.litre_days++; }
      }
    }
    /* A day book for a day the money sheet has nothing on — the litres
       still belong to the month. */
    for (const [date, l] of litresByDay) {
      const m = months[Number(date.slice(5, 7)) - 1];
      if (m.days.some(d => d.date === date)) continue;
      m.days.push({ date, amount: 0, source_ref: null, litres: l.litres, lines: l.lines });
      m.days.sort((a, b) => a.date.localeCompare(b.date));
      m.litres = litre(m.litres + l.litres); m.litre_days++;
    }
    for (const m of months) {
      const all = allByMonth[m.month - 1];
      m.share = all ? Math.round((m.total / all) * 1000) / 10 : 0;
    }

    const sold = months.filter(m => m.total);
    const total = money(sold.reduce((a, m) => a + m.total, 0));
    /* The month still being written is left out of the average — seven
       days of September would drag it down. */
    const now = new Date();
    const openMonth = year === now.getUTCFullYear() ? now.getUTCMonth() + 1 : null;
    const finished = sold.filter(m => m.month !== openMonth);
    const days = sold.flatMap(m => m.days);
    const bestDay = days.reduce((a, d) => (d.amount > (a?.amount || 0) ? d : a), null);
    const yearAll = allByMonth.reduce((a, b) => a + b, 0);

    res.json({
      unit, kind: kind || (await pool.query(
        'SELECT unit_kind FROM sales_book_entries WHERE unit = $1 LIMIT 1', [unit]
      )).rows[0]?.unit_kind,
      year, months, total,
      share: yearAll ? Math.round((total / yearAll) * 1000) / 10 : 0,
      /* Over the months it actually sold in — dividing by twelve in
         September would make every unit look half what it is. */
      monthly_average: finished.length ? money(finished.reduce((a, m) => a + m.total, 0) / finished.length) : 0,
      best_month: sold.length ? sold.reduce((a, m) => (m.total > a.total ? m : a)).month : null,
      days_recorded: days.length,
      litres: litre(months.reduce((a, m) => a + m.litres, 0)),
      litre_days: litresByDay.size,
      litres_per_day: litresByDay.size ? litre(months.reduce((a, m) => a + m.litres, 0) / litresByDay.size) : 0,
      products: [...products.values()].sort((a, b) => b.litres - a.litres),
      daily_average: days.length ? money(days.reduce((a, d) => a + d.amount, 0) / days.length) : 0,
      best_day: bestDay,
      years: byYear.rows.map(r => ({ year: r.year, total: num(r.total) })),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE YEAR — a unit per row, a month per column,
   the way MONTHLY SALES BY UNITY is laid out.
══════════════════════════════════ */

router.get('/years', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT EXTRACT(YEAR FROM entry_date)::int AS year
      FROM sales_book_entries ORDER BY year DESC
    `);
    res.json(rows.map(r => r.year));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/year', async (req, res) => {
  const year = parseInt(req.query.year, 10) || new Date().getUTCFullYear();
  try {
    const [book, till] = await Promise.all([
      pool.query(`
        SELECT unit, unit_kind AS kind, EXTRACT(MONTH FROM entry_date)::int AS month,
               SUM(amount) AS amount, BOOL_AND(whole_month) AS whole_month
        FROM sales_book_entries
        WHERE EXTRACT(YEAR FROM entry_date) = $1
        GROUP BY unit, unit_kind, month
      `, [year]),
      pool.query(`
        SELECT EXTRACT(MONTH FROM sold_on)::int AS month, SUM(total) AS amount
        FROM pos_sales
        WHERE status = 'completed' AND EXTRACT(YEAR FROM sold_on) = $1
        GROUP BY month
      `, [year]),
    ]);

    const units = new Map();
    const months = Array(12).fill(0);
    const detail = Array(12).fill(null);
    for (const r of book.rows) {
      const key = r.unit;
      const u = units.get(key) || { unit: r.unit, kind: r.kind, by_month: Array(12).fill(0), total: 0 };
      u.by_month[r.month - 1] = money(num(r.amount));
      u.total = money(u.total + num(r.amount));
      units.set(key, u);
      months[r.month - 1] = money(months[r.month - 1] + num(r.amount));
      /* A month is "day" if any of it came in by the day. */
      detail[r.month - 1] = detail[r.month - 1] === 'day' || !r.whole_month ? 'day' : 'month';
    }

    const lit = await pool.query(`
      SELECT unit, EXTRACT(MONTH FROM entry_date)::int AS month, SUM(litres) AS litres
      FROM sales_book_items WHERE EXTRACT(YEAR FROM entry_date) = $1
      GROUP BY unit, month
    `, [year]);
    const litresByMonth = Array(12).fill(0);
    for (const r of lit.rows) {
      litresByMonth[r.month - 1] = litre(litresByMonth[r.month - 1] + num(r.litres));
      const u = units.get(r.unit);
      if (u) {
        u.litres_by_month = u.litres_by_month || Array(12).fill(0);
        u.litres_by_month[r.month - 1] = litre(num(r.litres));
      }
    }

    const tillMonths = Array(12).fill(0);
    for (const r of till.rows) tillMonths[r.month - 1] = money(num(r.amount));

    res.json({
      year,
      units: [...units.values()].sort(byUnit),
      months,
      detail,
      total: money(months.reduce((a, b) => a + b, 0)),
      till: tillMonths,
      litres: litresByMonth,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE MONTH — a day per row, a unit per column,
   the way a month's SALES BY UNITY sheet is laid out.
══════════════════════════════════ */

router.get('/month', async (req, res) => {
  const now   = new Date();
  const year  = parseInt(req.query.year, 10)  || now.getUTCFullYear();
  const month = parseInt(req.query.month, 10) || (now.getUTCMonth() + 1);
  if (month < 1 || month > 12) return res.status(400).json({ error: 'month must be 1–12' });
  const from = `${year}-${String(month).padStart(2, '0')}-01`;
  const to   = new Date(Date.UTC(year, month, 0)).toISOString().slice(0, 10);

  try {
    const [book, till, lit] = await Promise.all([
      pool.query(`
        SELECT TO_CHAR(entry_date, 'YYYY-MM-DD') AS day, unit, unit_kind AS kind,
               amount, whole_month, source_ref
        FROM sales_book_entries
        WHERE entry_date BETWEEN $1 AND $2
        ORDER BY entry_date
      `, [from, to]),
      pool.query(`
        SELECT TO_CHAR(sold_on, 'YYYY-MM-DD') AS day, SUM(total) AS amount
        FROM pos_sales
        WHERE status = 'completed' AND sold_on BETWEEN $1 AND $2
        GROUP BY sold_on
      `, [from, to]),
      pool.query(`
        SELECT TO_CHAR(entry_date, 'YYYY-MM-DD') AS day, unit, unit_kind AS kind, SUM(litres) AS litres
        FROM sales_book_items
        WHERE entry_date BETWEEN $1 AND $2
        GROUP BY entry_date, unit, unit_kind
      `, [from, to]),
    ]);

    /* Litres, laid out the same way as the money: a day per row, a unit
       per column. Only the days with a day book have any. */
    const litreUnits = new Map();
    const litreDays = new Map();
    for (const r of lit.rows) {
      const l = num(r.litres);
      const u = litreUnits.get(r.unit) || { unit: r.unit, kind: r.kind, total: 0 };
      u.total = litre(u.total + l);
      litreUnits.set(r.unit, u);
      const d = litreDays.get(r.day) || { day: r.day, by_unit: {}, total: 0 };
      d.by_unit[r.unit] = litre((d.by_unit[r.unit] || 0) + l);
      d.total = litre(d.total + l);
      litreDays.set(r.day, d);
    }

    const wholeMonth = book.rows.length > 0 && book.rows.every(r => r.whole_month);

    const units = new Map();
    const days = new Map();
    for (const r of book.rows) {
      const amount = num(r.amount);
      const u = units.get(r.unit) || { unit: r.unit, kind: r.kind, total: 0 };
      u.total = money(u.total + amount);
      units.set(r.unit, u);

      const d = days.get(r.day) || { day: r.day, by_unit: {}, total: 0 };
      d.by_unit[r.unit] = money((d.by_unit[r.unit] || 0) + amount);
      d.total = money(d.total + amount);
      days.set(r.day, d);
    }

    const tillByDay = Object.fromEntries(till.rows.map(r => [r.day, money(num(r.amount))]));

    res.json({
      year, month, label: monthLabel(month, year),
      whole_month: wholeMonth,
      units: [...units.values()].sort(byUnit),
      days: wholeMonth ? [] : [...days.values()],
      total: money([...units.values()].reduce((a, u) => a + u.total, 0)),
      till: tillByDay,
      till_total: money(Object.values(tillByDay).reduce((a, b) => a + b, 0)),
      litres: {
        units: [...litreUnits.values()].sort(byUnit),
        days: [...litreDays.values()].sort((a, b) => a.day.localeCompare(b.day)),
        total: litre([...litreUnits.values()].reduce((a, u) => a + u.total, 0)),
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   ONE DAY — what each unit took out, product by product,
   the way that day's day book is laid out.
══════════════════════════════════ */

router.get('/day', async (req, res) => {
  const date = String(req.query.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
  try {
    const [items, money_] = await Promise.all([
      pool.query(`
        SELECT unit, unit_kind AS kind, sold_by, product, pack, units, price, amount, litres, source_ref
        FROM sales_book_items WHERE entry_date = $1 ORDER BY id
      `, [date]),
      pool.query(`
        SELECT unit, unit_kind AS kind, amount FROM sales_book_entries
        WHERE entry_date = $1 AND whole_month = FALSE
      `, [date]),
    ]);

    const units = new Map();
    const get = (unit, kind) => {
      if (!units.has(unit)) units.set(unit, { unit, kind, amount: 0, litres: 0, booked: 0, lines: [] });
      return units.get(unit);
    };
    for (const r of money_.rows) get(r.unit, r.kind).amount = money(get(r.unit, r.kind).amount + num(r.amount));
    for (const r of items.rows) {
      const u = get(r.unit, r.kind);
      u.litres = litre(u.litres + num(r.litres));
      u.booked = money(u.booked + num(r.amount));
      u.lines.push({
        product: r.product, pack: r.pack, units: num(r.units),
        price: r.price === null ? null : num(r.price), amount: num(r.amount), litres: num(r.litres),
        sold_by: r.sold_by, source_ref: r.source_ref,
      });
    }

    const list = [...units.values()].sort(byUnit);
    res.json({
      date,
      has_day_book: items.rows.length > 0,
      units: list,
      amount: money(list.reduce((a, u) => a + u.amount, 0)),
      litres: litre(list.reduce((a, u) => a + u.litres, 0)),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
