const express = require('express');
const bcrypt  = require('bcrypt');
const { pool } = require('../db');
const { ROLES } = require('../auth');

const router = express.Router();

// NOTE: verifyToken + requireAdmin are applied once, at the mount point in
// server.js (`app.use('/api/users', verifyToken, requireAdmin, usersRouter)`).

router.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.username, u.role, u.branch_id, b.name AS branch_name, u.created_at
      FROM users u LEFT JOIN branches b ON b.id = u.branch_id
      ORDER BY u.created_at
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * The branch to store against a role.
 *
 * An attendant without a branch can do nothing at all — every route they can
 * reach is scoped to one — so the account is refused at creation rather than
 * being handed over broken. Every other role is pinned to no branch, even if
 * one was sent: a manager oversees all of them, and a stray branch_id on a
 * manager would read as a restriction that nothing actually enforces.
 */
function branchForRole(role, branchId) {
  if (role !== 'attendant') return { branch_id: null };
  const id = parseInt(branchId, 10);
  if (!Number.isFinite(id)) {
    return { error: 'An attendant account must be assigned to a branch' };
  }
  return { branch_id: id };
}

router.post('/', async (req, res) => {
  /* Default to the most limited role, and validate against ROLES so this list
     cannot drift from the database constraint the way it did with 'viewer'. */
  const { username, password, role = 'veteran', branch_id } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: `Role must be one of: ${ROLES.join(', ')}` });
  }
  const branch = branchForRole(role, branch_id);
  if (branch.error) return res.status(400).json({ error: branch.error });

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users(username, password_hash, role, branch_id) VALUES($1,$2,$3,$4)
       RETURNING id, username, role, branch_id, created_at`,
      [username.trim(), hash, role, branch.branch_id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    if (err.code === '23503') return res.status(400).json({ error: 'That branch does not exist' });
    res.status(500).json({ error: err.message });
  }
});

/* Change a role, or move an attendant to another branch.

   An admin cannot demote themselves: the last admin doing so by accident
   would leave nobody able to put it back. */
router.patch('/:id', async (req, res) => {
  const { role, branch_id } = req.body;
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: `Role must be one of: ${ROLES.join(', ')}` });
  }
  if (parseInt(req.params.id, 10) === req.user.id && role !== 'admin') {
    return res.status(400).json({ error: 'Cannot change your own role' });
  }
  const branch = branchForRole(role, branch_id);
  if (branch.error) return res.status(400).json({ error: branch.error });

  try {
    const { rows } = await pool.query(
      `UPDATE users SET role=$1, branch_id=$2 WHERE id=$3
       RETURNING id, username, role, branch_id, created_at`,
      [role, branch.branch_id, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'That branch does not exist' });
    res.status(500).json({ error: err.message });
  }
});

router.patch('/:id/password', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/:id', async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
