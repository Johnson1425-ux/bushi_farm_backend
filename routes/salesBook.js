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
      ...r, total: num(r.total),
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

    const replaced = await client.query(
      `DELETE FROM sales_book_entries WHERE TO_CHAR(entry_date, 'YYYY-MM') = ANY($1::text[])
       RETURNING TO_CHAR(entry_date, 'YYYY-MM') AS month`, [dayMonths]
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

    const emptied = await client.query(`
      DELETE FROM sales_book_imports i
      WHERE NOT EXISTS (SELECT 1 FROM sales_book_entries e WHERE e.import_id = i.id)
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

    const tillMonths = Array(12).fill(0);
    for (const r of till.rows) tillMonths[r.month - 1] = money(num(r.amount));

    res.json({
      year,
      units: [...units.values()].sort(byUnit),
      months,
      detail,
      total: money(months.reduce((a, b) => a + b, 0)),
      till: tillMonths,
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
    const [book, till] = await Promise.all([
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
    ]);

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
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
