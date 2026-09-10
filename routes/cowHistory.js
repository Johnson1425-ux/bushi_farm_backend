const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// NOTE: mounted in server.js as `app.use('/api/cow-history', verifyToken, requireHealth, cowHistoryRouter)`.
// This is the route the UI actually calls; routes/cows.js also exposes a
// cow-scoped variant (DELETE /api/cows/:id/history/:hid) for callers that
// scope by cow.

router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_history WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
