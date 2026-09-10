const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// NOTE: mounted in server.js as `app.use('/api/treatments', verifyToken, requireHealth, treatmentsRouter)`.

router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM treatments WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
