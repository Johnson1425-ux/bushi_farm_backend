const express = require('express');
const multer  = require('multer');
const XLSX    = require('xlsx');
const { pool } = require('../db');
const { parseDate } = require('../lib/parsers');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// NOTE: mounted in server.js as `app.use('/api/sales', verifyToken, requireProduction, salesRouter)`.

router.get('/', async (req, res) => {
  const { month, from, to } = req.query;
  const conditions = [], params = [];
  if (month) { params.push(month); conditions.push(`TO_CHAR(date,'YYYY-MM') = $${params.length}`); }
  if (from)  { params.push(from);  conditions.push(`date >= $${params.length}`); }
  if (to)    { params.push(to);    conditions.push(`date <= $${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(
      `SELECT id, TO_CHAR(date,'YYYY-MM-DD') AS date, litres_sold, price_per_litre,
              ROUND((litres_sold * price_per_litre)::numeric, 2) AS total, notes
       FROM sales ${where} ORDER BY date DESC`, params
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/', async (req, res) => {
  const { date, litres_sold, price_per_litre, notes } = req.body;
  if (!date || !litres_sold || !price_per_litre) return res.status(400).json({ error: 'date, litres_sold and price_per_litre required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO sales(date, litres_sold, price_per_litre, notes) VALUES($1,$2,$3,$4) RETURNING *`,
      [date, litres_sold, price_per_litre, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM sales WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/summary', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date,'YYYY-MM') AS month,
             COUNT(*)::int AS record_count,
             ROUND(SUM(litres_sold)::numeric,2) AS total_litres,
             ROUND(AVG(litres_sold)::numeric,2) AS avg_litres_per_day,
             ROUND(SUM(litres_sold * price_per_litre)::numeric,2) AS total_revenue
      FROM sales GROUP BY month ORDER BY month DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/import', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb    = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows  = XLSX.utils.sheet_to_json(sheet);
    let imported = 0; const errors = [];
    for (const row of rows) {
      try {
        const date   = parseDate(row['date'] || row['Date'] || row['DATE']);
        const litres = parseFloat(row['litres_sold'] || row['Litres'] || row['LITRES'] || 0);
        const price  = parseFloat(row['price_per_litre'] || row['Price'] || row['PRICE'] || 0);
        if (!date || !litres || !price) { errors.push(`Skipped row: missing data`); continue; }
        await pool.query(
          `INSERT INTO sales(date,litres_sold,price_per_litre,notes) VALUES($1,$2,$3,$4)
           ON CONFLICT(date) DO UPDATE SET litres_sold=EXCLUDED.litres_sold, price_per_litre=EXCLUDED.price_per_litre`,
          [date, litres, price, row['notes'] || null]
        );
        imported++;
      } catch (e) { errors.push(e.message); }
    }
    res.json({ imported, errors });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
