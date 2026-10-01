const express = require('express');
const multer  = require('multer');
const { pool } = require('../db');
const { parseUnitsSoldWorkbook } = require('../lib/unitsSoldWorkbook');
const { monthLabel } = require('../lib/expenseCatalog');
const { UNIT_ORDER } = require('../lib/salesWorkbook');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* NOTE: mounted in server.js as
   `app.use('/api/units-sold', verifyToken, requireProduction, unitsSoldRouter)`.

   Litres and units sold, from the farm's UNIT SOLD workbook — see
   lib/unitsSoldWorkbook.js for what it holds and lib/initSalesBook.js for
   why it sits beside the sales book rather than inside it. Every total
   is worked out from the lines on the way past. */

const num   = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const litre = (v) => Math.round(num(v) * 100) / 100;

/* Outlets in the order the sheet lists them: the shops first, then the
   buyers the sales book knows, then the rest by name. */
function byOutlet(a, b) {
  const rank = (o) => (o.unit && UNIT_ORDER.has(o.unit) ? UNIT_ORDER.get(o.unit) : 500);
  return rank(a) - rank(b) || a.item.localeCompare(b.item);
}

/* Products in the sheet's order; packs smallest first. */
const PRODUCT_ORDER = ['Vanilla', 'Strawberry', 'Kerf milk', 'Mtindi bonge'];
function byProduct(a, b) {
  const ra = PRODUCT_ORDER.indexOf(a.item), rb = PRODUCT_ORDER.indexOf(b.item);
  return ((ra < 0 ? 99 : ra) - (rb < 0 ? 99 : rb)) || a.item.localeCompare(b.item)
    || (num(a.litres_per_pack) - num(b.litres_per_pack)) || String(a.pack).localeCompare(String(b.pack));
}

/* ══════════════════════════════════
   THE UPLOADS
══════════════════════════════════ */

router.get('/imports', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.id, i.filename, i.sheets, i.uploaded_at, u.username AS uploaded_by,
             COUNT(l.id)::int                       AS line_count,
             COALESCE(SUM(l.litres), 0)             AS litres,
             TO_CHAR(MIN(l.entry_date), 'YYYY-MM')  AS first_month,
             TO_CHAR(MAX(l.entry_date), 'YYYY-MM')  AS last_month
      FROM units_sold_imports i
      LEFT JOIN units_sold_lines l ON l.import_id = i.id
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
      ...r, litres: litre(r.litres),
      covers: r.first_month === r.last_month ? label(r.first_month) : `${label(r.first_month)} – ${label(r.last_month)}`,
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Read a UNIT SOLD workbook in.
 *
 * Like the sales book, the workbook grows through the year, so each
 * month it carries replaces whatever was held for that month — from any
 * earlier upload — and an upload left with nothing is removed.
 */
async function importUnitsSold(req, res) {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const parsed = parseUnitsSoldWorkbook(req.file.buffer, { filename: req.file.originalname });
  if (!parsed.ok) {
    return res.status(422).json({
      error: 'The workbook could not be imported. Fix the issues below and upload it again.',
      issues: parsed.errors, warnings: parsed.warnings, skipped: parsed.skipped,
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const months = parsed.months.map(m => m.month);
    const replaced = await client.query(
      `DELETE FROM units_sold_lines WHERE TO_CHAR(entry_date, 'YYYY-MM') = ANY($1::text[])
       RETURNING TO_CHAR(entry_date, 'YYYY-MM') AS month`, [months]
    );

    const { rows: [imp] } = await client.query(
      `INSERT INTO units_sold_imports (filename, sheets, uploaded_by) VALUES ($1,$2,$3) RETURNING id`,
      [req.file.originalname, parsed.months.map(m => m.sheet).join(', '), req.user.id]
    );

    const L = parsed.lines;
    await client.query(
      `INSERT INTO units_sold_lines
         (import_id, entry_date, section, item, pack, unit, litres, units, litres_per_pack, source_ref)
       SELECT $1, d, s, i, p, u, l, n, pp, r
       FROM UNNEST($2::date[], $3::text[], $4::text[], $5::text[], $6::text[],
                   $7::numeric[], $8::numeric[], $9::numeric[], $10::text[])
            AS t(d, s, i, p, u, l, n, pp, r)`,
      [imp.id,
       L.map(l => l.date), L.map(l => l.section), L.map(l => l.item), L.map(l => l.pack), L.map(l => l.unit),
       L.map(l => l.litres), L.map(l => l.units), L.map(l => l.litres_per_pack), L.map(l => `${l.sheet}!${l.cell}`)]
    );

    const emptied = await client.query(`
      DELETE FROM units_sold_imports i
      WHERE NOT EXISTS (SELECT 1 FROM units_sold_lines l WHERE l.import_id = i.id)
      RETURNING id
    `);

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      import_id: imp.id,
      year: parsed.year,
      lines: L.length,
      litres: parsed.litres,
      months: parsed.months,
      replaced_months: [...new Set(replaced.rows.map(r => r.month))].sort(),
      removed_imports: emptied.rows.length,
      skipped: parsed.skipped,
      warnings: parsed.warnings,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
}
router.post('/import', upload.single('file'), importUnitsSold);

router.delete('/imports/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('DELETE FROM units_sold_imports WHERE id=$1 RETURNING filename', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'That upload no longer exists' });
    res.json({ ok: true, filename: rows[0].filename });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE YEAR — a row per outlet and per pack, a column per month,
   the way the workbook's MONTHLY sheet is laid out.
══════════════════════════════════ */

router.get('/years', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT DISTINCT EXTRACT(YEAR FROM entry_date)::int AS year FROM units_sold_lines ORDER BY year DESC'
    );
    res.json(rows.map(r => r.year));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/year', async (req, res) => {
  const year = parseInt(req.query.year, 10) || new Date().getUTCFullYear();
  try {
    const { rows } = await pool.query(`
      SELECT section, item, pack, unit, MAX(litres_per_pack) AS litres_per_pack,
             EXTRACT(MONTH FROM entry_date)::int AS month,
             SUM(litres) AS litres, SUM(units) AS units
      FROM units_sold_lines WHERE EXTRACT(YEAR FROM entry_date) = $1
      GROUP BY section, item, pack, unit, month
    `, [year]);

    const rowsBy = new Map();
    const totals = { fresh: Array(12).fill(0), processed: Array(12).fill(0) };
    for (const r of rows) {
      const key = `${r.section}|${r.item}|${r.pack || ''}`;
      const row = rowsBy.get(key) || {
        section: r.section, item: r.item, pack: r.pack, unit: r.unit,
        litres_per_pack: r.litres_per_pack === null ? null : num(r.litres_per_pack),
        litres: Array(12).fill(0), units: Array(12).fill(null), total_litres: 0, total_units: null,
      };
      row.litres[r.month - 1] = litre(r.litres);
      if (r.units !== null) {
        row.units[r.month - 1] = litre(r.units);
        row.total_units = litre((row.total_units || 0) + num(r.units));
      }
      row.total_litres = litre(row.total_litres + num(r.litres));
      rowsBy.set(key, row);
      totals[r.section][r.month - 1] = litre(totals[r.section][r.month - 1] + num(r.litres));
    }

    const all = [...rowsBy.values()];
    const all12 = totals.fresh.map((f, i) => litre(f + totals.processed[i]));
    res.json({
      year,
      fresh: all.filter(r => r.section === 'fresh').sort(byOutlet),
      processed: all.filter(r => r.section === 'processed').sort(byProduct),
      totals: { ...totals, all: all12 },
      total: litre(all12.reduce((a, b) => a + b, 0)),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE MONTH — a day per row: litres to each outlet, litres of each
   product, and what each pack came to over the month.
══════════════════════════════════ */

router.get('/month', async (req, res) => {
  const now   = new Date();
  const year  = parseInt(req.query.year, 10)  || now.getUTCFullYear();
  const month = parseInt(req.query.month, 10) || (now.getUTCMonth() + 1);
  if (month < 1 || month > 12) return res.status(400).json({ error: 'month must be 1–12' });
  const from = `${year}-${String(month).padStart(2, '0')}-01`;
  const to   = new Date(Date.UTC(year, month, 0)).toISOString().slice(0, 10);

  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(entry_date, 'YYYY-MM-DD') AS day, section, item, pack, unit,
             litres, units, litres_per_pack
      FROM units_sold_lines WHERE entry_date BETWEEN $1 AND $2
      ORDER BY entry_date
    `, [from, to]);

    const outlets = new Map(), products = new Map(), packs = new Map(), days = new Map();
    for (const r of rows) {
      const l = num(r.litres);
      const d = days.get(r.day) || { day: r.day, fresh: {}, processed: {}, fresh_total: 0, processed_total: 0, total: 0 };
      if (r.section === 'fresh') {
        const o = outlets.get(r.item) || { item: r.item, unit: r.unit, litres: 0 };
        o.litres = litre(o.litres + l); outlets.set(r.item, o);
        d.fresh[r.item] = litre((d.fresh[r.item] || 0) + l);
        d.fresh_total = litre(d.fresh_total + l);
      } else {
        const p = products.get(r.item) || { item: r.item, litres: 0 };
        p.litres = litre(p.litres + l); products.set(r.item, p);
        const key = `${r.item}|${r.pack}`;
        const k = packs.get(key) || {
          item: r.item, pack: r.pack, litres_per_pack: r.litres_per_pack === null ? null : num(r.litres_per_pack),
          litres: 0, units: null, days: 0,
        };
        k.litres = litre(k.litres + l); k.days++;
        if (r.units !== null) k.units = litre((k.units || 0) + num(r.units));
        packs.set(key, k);
        d.processed[r.item] = litre((d.processed[r.item] || 0) + l);
        d.processed_total = litre(d.processed_total + l);
      }
      d.total = litre(d.total + l);
      days.set(r.day, d);
    }

    const list = [...days.values()];
    const sum = (k) => litre(list.reduce((a, d) => a + d[k], 0));
    res.json({
      year, month, label: monthLabel(month, year),
      outlets: [...outlets.values()].sort(byOutlet),
      products: [...products.values()].sort(byProduct),
      packs: [...packs.values()].sort(byProduct),
      days: list,
      fresh: sum('fresh_total'), processed: sum('processed_total'), total: sum('total'),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   ONE DAY
══════════════════════════════════ */

router.get('/day', async (req, res) => {
  const date = String(req.query.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
  try {
    const { rows } = await pool.query(`
      SELECT section, item, pack, unit, litres, units, litres_per_pack, source_ref
      FROM units_sold_lines WHERE entry_date = $1 ORDER BY id
    `, [date]);
    const shape = (r) => ({
      item: r.item, pack: r.pack, unit: r.unit, litres: num(r.litres),
      units: r.units === null ? null : num(r.units),
      litres_per_pack: r.litres_per_pack === null ? null : num(r.litres_per_pack),
      source_ref: r.source_ref,
    });
    const fresh = rows.filter(r => r.section === 'fresh').map(shape).sort(byOutlet);
    const processed = rows.filter(r => r.section === 'processed').map(shape).sort(byProduct);
    const sum = (a) => litre(a.reduce((t, l) => t + l.litres, 0));
    res.json({ date, fresh, processed, fresh_total: sum(fresh), processed_total: sum(processed), total: sum([...fresh, ...processed]) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
/* The Workbooks tab has one upload for both workbooks; routes/salesBook.js
   tells them apart and hands a UNIT SOLD workbook on to this. */
module.exports.importUnitsSold = importUnitsSold;
