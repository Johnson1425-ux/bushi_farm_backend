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

// NOTE: mounted in server.js as `app.use('/api/inventory', verifyToken, requireProduction, inventoryRouter)`.

router.get('/items', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.*,
        COALESCE(SUM(CASE WHEN l.type='in'  THEN l.quantity ELSE 0 END),0) AS total_in,
        COALESCE(SUM(CASE WHEN l.type='out' THEN l.quantity ELSE 0 END),0) AS total_out,
        COALESCE(SUM(CASE WHEN l.type='in'  THEN l.quantity ELSE -l.quantity END),0) AS current_stock
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      GROUP BY i.id ORDER BY i.name
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/items', async (req, res) => {
  const { name, unit = 'pcs', notes } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_items(name,unit,notes) VALUES($1,$2,$3) RETURNING *`,
      [name.trim(), unit, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.patch('/items/:id', async (req, res) => {
  const { name, unit, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE inventory_items SET name=$1, unit=$2, notes=$3 WHERE id=$4 RETURNING *`,
      [name, unit, notes || null, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/items/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM inventory_items WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/logs', async (req, res) => {
  const { item_id, from, to } = req.query;
  const conditions = [], params = [];
  if (item_id) { params.push(item_id); conditions.push(`l.item_id = $${params.length}`); }
  if (from)    { params.push(from);    conditions.push(`l.date >= $${params.length}`); }
  if (to)      { params.push(to);      conditions.push(`l.date <= $${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(
      `SELECT l.*, i.name AS item_name, i.unit FROM inventory_logs l
       JOIN inventory_items i ON i.id = l.item_id
       ${where} ORDER BY l.date DESC, l.id DESC`, params
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/logs', async (req, res) => {
  const { item_id, type, quantity, date, notes } = req.body;
  if (!item_id || !type || !quantity || !date) return res.status(400).json({ error: 'item_id, type, quantity, date required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_logs(item_id,type,quantity,date,notes) VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [item_id, type, quantity, date, notes || null]
    );
    res.status(201).json(rows[0]);
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
        const name = String(row['item'] || row['Item'] || row['ITEM'] || row['name'] || '').trim();
        const type = String(row['type'] || row['Type'] || row['TYPE'] || 'in').toLowerCase();
        const qty  = parseFloat(row['quantity'] || row['Quantity'] || row['QTY'] || 0);
        const date = parseDate(row['date'] || row['Date'] || row['DATE']);
        if (!name || !qty || !date) { errors.push(`Skipped row: missing data`); continue; }
        const unit = String(row['unit'] || row['Unit'] || 'pcs');
        const cowRes = await pool.query(
          `INSERT INTO inventory_items(name,unit) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET unit=EXCLUDED.unit RETURNING id`,
          [name, unit]
        );
        await pool.query(
          `INSERT INTO inventory_logs(item_id,type,quantity,date,notes) VALUES($1,$2,$3,$4,$5)`,
          [cowRes.rows[0].id, type, qty, date, row['notes'] || null]
        );
        imported++;
      } catch (e) { errors.push(e.message); }
    }
    res.json({ imported, errors });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
