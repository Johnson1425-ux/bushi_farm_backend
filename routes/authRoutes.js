const express = require('express');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const { pool } = require('../db');
const {
  verifyToken, SECRET,
  loginRateLimit, recordLoginFailure, clearLoginFailures,
} = require('../auth');

const router = express.Router();

router.post('/login', loginRateLimit, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username.trim()]);
    const user = rows[0];
    if (!user) { recordLoginFailure(req); return res.status(401).json({ error: 'Invalid credentials' }); }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) { recordLoginFailure(req); return res.status(401).json({ error: 'Invalid credentials' }); }
    clearLoginFailures(req);
    /* branch_id rides on the token so every branch-scoped route can settle
       "which branch is this?" without a lookup — and, more to the point,
       without trusting a branch id the client sent. Reassigning an attendant
       therefore takes effect at their next sign-in, which is the right
       trade for a shift-long session that must not silently change till. */
    const claims = {
      id: user.id, username: user.username, role: user.role,
      branch_id: user.branch_id ?? null,
    };
    const token = jwt.sign(claims, SECRET, { expiresIn: '7d' });
    res.json({ token, user: await withBranchName(claims) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/me', verifyToken, async (req, res) => {
  try {
    res.json({ user: await withBranchName(req.user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* The branch name is for the sidebar to show, not for any decision — those
   are all made from branch_id. A token naming a branch that has since been
   deleted simply comes back without a name rather than failing sign-in. */
async function withBranchName(user) {
  if (!user.branch_id) return { ...user, branch_name: null };
  const { rows } = await pool.query('SELECT name FROM branches WHERE id=$1', [user.branch_id]);
  return { ...user, branch_name: rows[0]?.name ?? null };
}

module.exports = router;
