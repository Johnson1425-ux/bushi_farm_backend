const express = require('express');
const multer  = require('multer');
const { pool } = require('../db');
const { parseExpensesWorkbook } = require('../lib/expensesWorkbook');
const { monthLabel } = require('../lib/expenseCatalog');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* NOTE: mounted in server.js as
   `app.use('/api/expenses', verifyToken, requireProduction, expensesRouter)`.

   What the farm spends is management's book — the same territory as the
   sales reports, and read by the same two roles. An attendant runs one
   counter and has no business in the household's line or the payroll.

   Every total this file returns is worked out from the entries on the
   way past. Nothing is stored twice, so there is no figure here that can
   disagree with the rows beneath it — which is the one thing the
   workbook could not promise. */

const num   = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const money = (v) => Math.round(num(v) * 100) / 100;

/** A month, as the caller asked for it or as today happens to be. */
function resolveMonth(query) {
  const now   = new Date();
  const year  = parseInt(query.year, 10)  || now.getUTCFullYear();
  const month = parseInt(query.month, 10) || (now.getUTCMonth() + 1);
  if (month < 1 || month > 12) return null;
  const from = `${year}-${String(month).padStart(2, '0')}-01`;
  const to   = new Date(Date.UTC(year, month, 0)).toISOString().slice(0, 10);
  return { year, month, from, to, label: monthLabel(month, year) };
}

const SELECT_ENTRY = `
  SELECT e.id, TO_CHAR(e.entry_date,'YYYY-MM-DD') AS entry_date,
         e.category_id, c.name AS category, e.details, e.quantity, e.unit_price,
         e.amount, e.source, e.source_ref, e.import_id, e.notes,
         u.username AS created_by, e.created_at
  FROM expenses e
  JOIN expense_categories c ON c.id = e.category_id
  LEFT JOIN users u ON u.id = e.created_by
`;

const shape = (r) => ({
  ...r,
  amount: num(r.amount),
  quantity:   r.quantity   === null ? null : num(r.quantity),
  unit_price: r.unit_price === null ? null : num(r.unit_price),
});

/* ══════════════════════════════════
   THE CATEGORIES

   The dozen lines the summary is built from. Fixed rather than typed,
   because two spellings of one heading split a line in half and take
   money out of the month without anybody noticing.
══════════════════════════════════ */

router.get('/categories', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.sort_order, c.active, c.notes,
             COUNT(e.id)::int AS entry_count,
             COALESCE(SUM(e.amount), 0) AS total
      FROM expense_categories c
      LEFT JOIN expenses e ON e.category_id = c.id
      GROUP BY c.id
      ORDER BY c.sort_order, c.name
    `);
    res.json(rows.map(r => ({ ...r, total: num(r.total) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/categories', async (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'A category needs a name' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO expense_categories (name, sort_order, notes)
       VALUES ($1, COALESCE($2, 500), $3) RETURNING *`,
      [name, req.body.sort_order ? parseInt(req.body.sort_order, 10) : null,
       req.body.notes?.trim() || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That category already exists' });
    res.status(500).json({ error: err.message });
  }
});

/* A category is never deleted while anything is filed under it — the
   entries are the record and they have to keep their heading. Closing
   one takes it off the forms and leaves the history alone. */
router.patch('/categories/:id', async (req, res) => {
  const { name, sort_order, active, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE expense_categories SET
         name       = COALESCE($1, name),
         sort_order = COALESCE($2, sort_order),
         active     = COALESCE($3, active),
         notes      = COALESCE($4, notes)
       WHERE id = $5 RETURNING *`,
      [name?.trim() || null,
       sort_order != null ? parseInt(sort_order, 10) : null,
       typeof active === 'boolean' ? active : null,
       notes?.trim() || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Category not found' });
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That category already exists' });
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   THE SUMMARY SHEET

   Category down the side, month across the top, cumulative on the end —
   the grid the farm reads its year on, except that here every cell is a
   SUM over the entries rather than a formula pointing at another sheet.

   That distinction is not academic. In the September 2026 workbook the
   summary's formulas slipped a row from BMH downwards, so the lorry's
   column showed the shops' spending and the shops' showed nothing. The
   month's grand total was right, because the same figures were all
   present, which is exactly why nobody caught it.
══════════════════════════════════ */

router.get('/summary', async (req, res) => {
  const year = parseInt(req.query.year, 10) || new Date().getUTCFullYear();
  try {
    const [grid, years] = await Promise.all([
      pool.query(`
        SELECT c.id, c.name, c.sort_order, c.active,
               EXTRACT(MONTH FROM e.entry_date)::int AS month,
               COALESCE(SUM(e.amount), 0) AS total,
               COUNT(e.id)::int AS entry_count
        FROM expense_categories c
        LEFT JOIN expenses e
          ON e.category_id = c.id AND EXTRACT(YEAR FROM e.entry_date) = $1
        GROUP BY c.id, month
        ORDER BY c.sort_order, c.name
      `, [year]),
      pool.query(`
        SELECT EXTRACT(YEAR FROM entry_date)::int AS year,
               COALESCE(SUM(amount), 0) AS total
        FROM expenses GROUP BY year ORDER BY year
      `),
    ]);

    /* One row per category, twelve cells across. Built here rather than
       pivoted in SQL so a category with nothing against it still comes
       back as a row of zeroes — the paper sheet shows every line whether
       it was spent on or not, and a line that quietly vanishes in a
       thin month is a line nobody thinks to fill in. */
    const byId = new Map();
    for (const r of grid.rows) {
      if (!byId.has(r.id)) {
        byId.set(r.id, {
          id: r.id, name: r.name, sort_order: r.sort_order, active: r.active,
          months: Array(12).fill(0), total: 0, entry_count: 0,
        });
      }
      if (!r.month) continue;
      const row = byId.get(r.id);
      row.months[r.month - 1] = money(r.total);
      row.total = money(row.total + num(r.total));
      row.entry_count += r.entry_count;
    }

    const categories = [...byId.values()]
      .filter(c => c.active || c.total > 0);

    const months = Array.from({ length: 12 }, (_, i) =>
      money(categories.reduce((a, c) => a + c.months[i], 0)));

    res.json({
      year,
      categories,
      months,
      total: money(months.reduce((a, m) => a + m, 0)),
      years: years.rows.map(r => ({ year: r.year, total: num(r.total) })),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE YEAR SHEET

   The same thing one level up: every category against every year the
   farm has entries for, which is how a cost that has been creeping for
   three years becomes visible.
══════════════════════════════════ */

router.get('/years', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.sort_order,
             EXTRACT(YEAR FROM e.entry_date)::int AS year,
             COALESCE(SUM(e.amount), 0) AS total
      FROM expense_categories c
      JOIN expenses e ON e.category_id = c.id
      GROUP BY c.id, year
      ORDER BY c.sort_order, c.name
    `);

    const years = [...new Set(rows.map(r => r.year))].sort();
    const byId  = new Map();
    for (const r of rows) {
      if (!byId.has(r.id)) byId.set(r.id, { id: r.id, name: r.name, by_year: {}, total: 0 });
      const row = byId.get(r.id);
      row.by_year[r.year] = money(r.total);
      row.total = money(row.total + num(r.total));
    }

    const categories = [...byId.values()];
    const totals = Object.fromEntries(years.map(y =>
      [y, money(categories.reduce((a, c) => a + (c.by_year[y] || 0), 0))]));

    res.json({ years, categories, totals });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE WORKBOOKS

   One row per month read in, so an import can be undone as a unit and a
   month re-read without doubling it.
══════════════════════════════════ */

router.get('/imports', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.id, i.label, i.month_num, i.year, i.filename, i.sheets,
             i.entry_count, i.total, i.uploaded_at, u.username AS uploaded_by
      FROM expense_imports i
      LEFT JOIN users u ON u.id = i.uploaded_by
      ORDER BY i.year DESC, i.month_num DESC
    `);
    res.json(rows.map(r => ({ ...r, total: num(r.total) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Read a month's workbook in.
 *
 * The month is replaced wholesale, the way the processing unit replaces
 * one: a second upload of September is a correction of September, not a
 * second September. ON DELETE CASCADE clears the entries the previous
 * import brought with it.
 *
 * Entries typed into the app survive that, because they carry no
 * import_id — someone who keyed a payment the workbook has not caught up
 * with does not lose it when the workbook arrives.
 */
router.post('/import', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const parsed = parseExpensesWorkbook(req.file.buffer, { filename: req.file.originalname });

  if (!parsed.ok) {
    return res.status(422).json({
      error:    'The workbook could not be imported. Fix the issues below and re-upload.',
      issues:   parsed.errors,
      warnings: parsed.warnings,
      skipped:  parsed.skipped,
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: cats } = await client.query('SELECT id, name FROM expense_categories');
    const byName = new Map(cats.map(c => [c.name.trim().toLowerCase(), c.id]));

    /* A category the catalogue knows but the table has not seen yet —
       a database seeded before the heading existed. Open it rather than
       drop the money that belongs on it. */
    for (const name of new Set(parsed.entries.map(e => e.category))) {
      if (byName.has(name.trim().toLowerCase())) continue;
      const { rows } = await client.query(
        `INSERT INTO expense_categories (name, sort_order) VALUES ($1, 500)
         ON CONFLICT (LOWER(BTRIM(name))) DO UPDATE SET name = expense_categories.name
         RETURNING id`, [name]
      );
      byName.set(name.trim().toLowerCase(), rows[0].id);
    }

    const { period } = parsed;
    const replaced = await client.query(
      'DELETE FROM expense_imports WHERE year=$1 AND month_num=$2 RETURNING id',
      [period.year, period.monthNum]
    );

    const sheets = [...new Set(parsed.sheets.filter(s => s.count).map(s => s.sheet))].join(', ');
    const { rows: importRow } = await client.query(
      `INSERT INTO expense_imports
         (label, month_num, year, filename, sheets, entry_count, total, uploaded_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [period.label, period.monthNum, period.year, req.file.originalname,
       sheets, parsed.entries.length, parsed.total, req.user.id]
    );
    const importId = importRow[0].id;

    for (const e of parsed.entries) {
      await client.query(
        `INSERT INTO expenses
           (entry_date, category_id, details, quantity, unit_price, amount,
            source, import_id, source_ref, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,'import',$7,$8,$9)`,
        [e.date, byName.get(e.category.trim().toLowerCase()), e.details,
         e.quantity, e.unit_price, e.amount, importId,
         e.sheet ? `${e.sheet}!${e.cell}` : null, req.user.id]
      );
    }

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      import_id: importId,
      period,
      replaced: replaced.rowCount > 0,
      entries: parsed.entries.length,
      total: parsed.total,
      categories: parsed.categories,
      sheets: parsed.sheets,
      skipped: parsed.skipped,
      /* What the workbook's own summary claims for this month, beside
         what its detail sheets actually add up to. */
      check: parsed.check,
      warnings: parsed.warnings,
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
      'DELETE FROM expense_imports WHERE id=$1 RETURNING label', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'That import no longer exists' });
    res.json({ ok: true, label: rows[0].label });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   THE MONTH ITSELF

   Every line spent, and what each category came to. This is the detail
   sheet — the part that is actually kept — and the two grids above are
   nothing but this, grouped.
══════════════════════════════════ */

router.get('/', async (req, res) => {
  const period = resolveMonth(req.query);
  if (!period) return res.status(400).json({ error: 'month must be between 1 and 12' });

  const params = [period.from, period.to];
  const where  = ['e.entry_date BETWEEN $1 AND $2'];
  if (req.query.category_id) {
    params.push(parseInt(req.query.category_id, 10));
    where.push(`e.category_id = $${params.length}`);
  }
  if (req.query.q) {
    params.push(`%${req.query.q}%`);
    where.push(`e.details ILIKE $${params.length}`);
  }

  try {
    const [entries, totals, imported] = await Promise.all([
      pool.query(`${SELECT_ENTRY} WHERE ${where.join(' AND ')}
                  ORDER BY e.entry_date, c.sort_order, e.id`, params),
      pool.query(`
        SELECT c.id, c.name, c.sort_order, c.active, c.notes,
               COALESCE(SUM(e.amount), 0) AS total,
               COUNT(e.id)::int           AS entry_count
        FROM expense_categories c
        LEFT JOIN expenses e
          ON e.category_id = c.id AND e.entry_date BETWEEN $1 AND $2
        GROUP BY c.id ORDER BY c.sort_order, c.name
      `, [period.from, period.to]),
      pool.query(`
        SELECT i.id, i.label, i.filename, i.uploaded_at, i.entry_count, i.total,
               u.username AS uploaded_by
        FROM expense_imports i LEFT JOIN users u ON u.id = i.uploaded_by
        WHERE i.year=$1 AND i.month_num=$2
      `, [period.year, period.month]),
    ]);

    const categories = totals.rows
      .map(r => ({ ...r, total: num(r.total) }))
      .filter(c => c.active || c.entry_count > 0);

    const rows = entries.rows.map(shape);

    res.json({
      period,
      entries: rows,
      categories,
      total: money(categories.reduce((a, c) => a + c.total, 0)),
      /* Typed in against read in, because the difference matters when a
         month looks light: nobody has uploaded the workbook yet. */
      counts: {
        entries:  rows.length,
        manual:   rows.filter(e => e.source === 'manual').length,
        imported: rows.filter(e => e.source === 'import').length,
      },
      import: imported.rows[0] ? { ...imported.rows[0], total: num(imported.rows[0].total) } : null,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── one line, typed in ──────────────────────────────────────
   The counterpart to the workbook: something paid for today, recorded
   before the month's sheet catches up with it. */
router.post('/', async (req, res) => {
  const { entry_date, category_id, category, details, quantity, unit_price, notes } = req.body;

  const date = String(entry_date || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'A date is required' });
  if (!String(details || '').trim())     return res.status(400).json({ error: 'Say what the money went on' });

  const qty   = quantity   === '' || quantity   == null ? null : num(quantity);
  const price = unit_price === '' || unit_price == null ? null : num(unit_price);

  /* Quantity times price, when the two are given and the total is not —
     the arithmetic the sheet's AMOUNT column does. */
  let amount = req.body.amount === '' || req.body.amount == null ? null : money(req.body.amount);
  if (!amount && qty && price) amount = money(qty * price);
  if (!amount) return res.status(400).json({ error: 'An amount is required, or a quantity and a price to work it out from' });

  try {
    let categoryId = parseInt(category_id, 10);
    if (!Number.isFinite(categoryId)) {
      const { rows } = await pool.query(
        'SELECT id FROM expense_categories WHERE LOWER(BTRIM(name)) = LOWER(BTRIM($1))',
        [String(category || '')]
      );
      if (!rows.length) return res.status(400).json({ error: 'Choose which line this belongs on' });
      categoryId = rows[0].id;
    }

    const { rows } = await pool.query(
      `INSERT INTO expenses
         (entry_date, category_id, details, quantity, unit_price, amount, source, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,'manual',$7,$8) RETURNING id`,
      [date, categoryId, String(details).trim(), qty, price, amount,
       notes?.trim() || null, req.user.id]
    );

    const { rows: full } = await pool.query(`${SELECT_ENTRY} WHERE e.id = $1`, [rows[0].id]);
    res.status(201).json(shape(full[0]));
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'That category no longer exists' });
    res.status(500).json({ error: err.message });
  }
});

/* An imported line is not edited here.

   It is a copy of a row in a workbook that is still the farm's own
   record, and correcting the copy would leave the two saying different
   things until the next upload silently threw the correction away. Fix
   the sheet and upload the month again — that is what replacing a month
   is for. */
const IMPORTED = 'That line came from a workbook. Correct it in the sheet and upload the month '
               + 'again, or delete the import first — an edit here would be lost on the next upload.';

router.patch('/:id', async (req, res) => {
  const { entry_date, category_id, details, quantity, unit_price, amount, notes } = req.body;
  try {
    const { rows: existing } = await pool.query('SELECT source FROM expenses WHERE id=$1', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'That entry no longer exists' });
    if (existing[0].source === 'import') return res.status(409).json({ error: IMPORTED });

    const { rows } = await pool.query(
      `UPDATE expenses SET
         entry_date  = COALESCE($1, entry_date),
         category_id = COALESCE($2, category_id),
         details     = COALESCE($3, details),
         quantity    = $4,
         unit_price  = $5,
         amount      = COALESCE($6, amount),
         notes       = COALESCE($7, notes)
       WHERE id = $8 RETURNING id`,
      [entry_date ? String(entry_date).slice(0, 10) : null,
       category_id ? parseInt(category_id, 10) : null,
       details?.trim() || null,
       quantity   === '' || quantity   == null ? null : num(quantity),
       unit_price === '' || unit_price == null ? null : num(unit_price),
       amount == null || amount === '' ? null : money(amount),
       notes?.trim() || null, req.params.id]
    );

    const { rows: full } = await pool.query(`${SELECT_ENTRY} WHERE e.id = $1`, [rows[0].id]);
    res.json(shape(full[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `DELETE FROM expenses WHERE id=$1 AND source='manual' RETURNING id`, [req.params.id]
    );
    if (!rows.length) {
      const { rows: found } = await pool.query('SELECT source FROM expenses WHERE id=$1', [req.params.id]);
      if (!found.length) return res.status(404).json({ error: 'That entry no longer exists' });
      return res.status(409).json({ error: IMPORTED });
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
