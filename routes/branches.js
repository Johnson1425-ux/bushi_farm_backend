const express = require('express');
const { pool } = require('../db');
const { requireProduction } = require('../auth');

const router = express.Router();

/* NOTE: mounted in server.js as
   `app.use('/api/branches', verifyToken, requireBranchAccess, branchesRouter)`.

   Reads are open to attendants because a till has to name the branch it is
   selling from. Writes are managers' work, gated per route below — an
   attendant renaming or deactivating their own branch is not a thing the
   job requires. */

/* List branches, each with a live count of what it holds.

   An attendant gets one row: their own. Filtering here rather than letting
   them read the list and ignore the rest matters because the row carries
   stock figures. */
router.get('/', async (req, res) => {
  const attendant = req.user.role === 'attendant';
  if (attendant && !req.user.branch_id) return res.json([]);

  const params = [];
  let where = '';
  if (attendant)                { params.push(req.user.branch_id); where = 'WHERE b.id = $1'; }
  else if (req.query.active === 'true') { where = 'WHERE b.active'; }

  try {
    const { rows } = await pool.query(`
      SELECT b.id, b.name, b.code, b.location, b.phone, b.active, b.created_at,
             COALESCE(s.units, 0)   AS stock_units,
             COALESCE(s.litres, 0)  AS stock_litres,
             COALESCE(u.attendants, 0) AS attendants
      FROM branches b
      LEFT JOIN (
        SELECT branch_id, SUM(units) AS units, SUM(litres) AS litres
        FROM stock_movements WHERE location_kind = 'branch' GROUP BY branch_id
      ) s ON s.branch_id = b.id
      LEFT JOIN (
        SELECT branch_id, COUNT(*)::int AS attendants
        FROM users WHERE branch_id IS NOT NULL GROUP BY branch_id
      ) u ON u.branch_id = b.id
      ${where}
      ORDER BY b.active DESC, b.name
    `, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/', requireProduction, async (req, res) => {
  const { name, code, location, phone } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO branches (name, code, location, phone)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [String(name).trim(), code?.trim() || null, location?.trim() || null, phone?.trim() || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A branch with that name or code already exists' });
    res.status(500).json({ error: err.message });
  }
});

router.patch('/:id', requireProduction, async (req, res) => {
  const { name, code, location, phone, active } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE branches SET
         name     = COALESCE($1, name),
         code     = COALESCE($2, code),
         location = COALESCE($3, location),
         phone    = COALESCE($4, phone),
         active   = COALESCE($5, active)
       WHERE id = $6 RETURNING *`,
      [name?.trim() || null, code?.trim() || null, location?.trim() || null,
       phone?.trim() || null, typeof active === 'boolean' ? active : null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Branch not found' });
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A branch with that name or code already exists' });
    res.status(500).json({ error: err.message });
  }
});

/* Closing a branch deactivates it; there is no delete.

   Its issue notes are the record of stock that really did leave the
   processing store, and its movements are what a past month's figures were
   built from. Deleting the branch would take both with it, so a branch that
   has ever held stock is retired instead — off the till, off the issue form,
   still in the history. */
router.delete('/:id', requireProduction, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'UPDATE branches SET active = FALSE WHERE id = $1 RETURNING id, name, active',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Branch not found' });
    res.json({ ok: true, branch: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
