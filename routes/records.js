const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// NOTE: mounted in server.js as
// `app.use('/api/records', verifyToken, requireRoleForWrites('admin','manager'), recordsRouter)`
// — every signed-in role can read, only admin/manager can write.

router.get('/', async (req, res) => {
  const { cow_id, date_from, date_to, limit = 500, offset = 0 } = req.query;
  const conditions = [], params = [];
  if (cow_id)    { params.push(cow_id);    conditions.push(`r.cow_id = $${params.length}`); }
  if (date_from) { params.push(date_from); conditions.push(`r.date >= $${params.length}`); }
  if (date_to)   { params.push(date_to);   conditions.push(`r.date <= $${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(limit, offset);
  try {
    const { rows } = await pool.query(`
      SELECT r.id, c.name AS cow, TO_CHAR(r.date,'YYYY-MM-DD') AS date, r.litres, r.notes
      FROM milk_records r JOIN cows c ON c.id = r.cow_id
      ${where}
      ORDER BY r.date DESC, c.name
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `, params);
    const countRes = await pool.query(`SELECT COUNT(*) FROM milk_records r ${where}`, params.slice(0, -2));
    res.json({ records: rows, total: parseInt(countRes.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/', async (req, res) => {
  const { cow_id, date, litres } = req.body;
  if (!cow_id || !date || litres === undefined) return res.status(400).json({ error: 'cow_id, date and litres are required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO milk_records(cow_id, date, litres)
       VALUES($1, $2, $3)
       ON CONFLICT (cow_id, date) DO UPDATE SET litres = EXCLUDED.litres
       RETURNING *`,
      [cow_id, date, parseFloat(litres)]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Managers own the production record, so they may correct it as well as add
   to it. The requireRoleForWrites gate at mount already limits this to
   admin and manager. */
router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM milk_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
