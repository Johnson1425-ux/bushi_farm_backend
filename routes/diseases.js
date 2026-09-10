const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// NOTE: mounted in server.js as `app.use('/api/diseases', verifyToken, requireHealth, diseasesRouter)`.

router.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.id, d.name, d.description, TO_CHAR(d.date,'YYYY-MM-DD') AS date, d.notes,
        COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', c.id, 'name', c.name)) FILTER (WHERE c.id IS NOT NULL), '[]') AS affected_cows,
        COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', t.id, 'medicine', t.medicine_name, 'dosage', t.dosage, 'date', TO_CHAR(t.date,'YYYY-MM-DD'), 'notes', t.notes)) FILTER (WHERE t.id IS NOT NULL), '[]'::json) AS treatments,
        COUNT(DISTINCT t.id)::int AS treatment_count
      FROM diseases d
      LEFT JOIN disease_cows dc ON dc.disease_id = d.id
      LEFT JOIN cows c ON c.id = dc.cow_id
      LEFT JOIN treatments t ON t.disease_id = d.id
      GROUP BY d.id ORDER BY d.date DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/', async (req, res) => {
  const { name, description, date, notes, cow_ids = [] } = req.body;
  if (!name || !date) return res.status(400).json({ error: 'name and date required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'INSERT INTO diseases(name, description, date, notes) VALUES($1,$2,$3,$4) RETURNING *',
      [name.trim(), description || null, date, notes || null]
    );
    const disease = rows[0];
    for (const cow_id of cow_ids) {
      await client.query('INSERT INTO disease_cows(disease_id, cow_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [disease.id, cow_id]);
    }
    await client.query('COMMIT');
    res.status(201).json(disease);
  } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); }
  finally { client.release(); }
});

router.patch('/:id', async (req, res) => {
  const { name, description, date, notes, cow_ids } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'UPDATE diseases SET name=COALESCE($1,name), description=COALESCE($2,description), date=COALESCE($3,date), notes=COALESCE($4,notes) WHERE id=$5 RETURNING *',
      [name || null, description || null, date || null, notes || null, req.params.id]
    );
    if (cow_ids) {
      await client.query('DELETE FROM disease_cows WHERE disease_id=$1', [req.params.id]);
      for (const cow_id of cow_ids) {
        await client.query('INSERT INTO disease_cows(disease_id, cow_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.params.id, cow_id]);
      }
    }
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); }
  finally { client.release(); }
});

router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM diseases WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Treatments for a single disease. The disease list already embeds them, but
   the Health page's treatment modal fetches them on their own. */
router.get('/:id/treatments', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, disease_id, medicine_name, dosage, TO_CHAR(treatments.date,'YYYY-MM-DD') AS date, notes FROM treatments WHERE disease_id=$1 ORDER BY treatments.date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/:id/treatments', async (req, res) => {
  const { medicine_name, dosage, date, notes } = req.body;
  if (!medicine_name || !date) return res.status(400).json({ error: 'medicine_name and date required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO treatments(disease_id, medicine_name, dosage, date, notes) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.params.id, medicine_name.trim(), dosage || null, date, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
