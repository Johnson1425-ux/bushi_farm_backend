const express = require('express');
const { pool } = require('../db');

const router = express.Router();

/* ══════════════════════════════════════════════════════════════
   BULK MILK, BEFORE THE TILLS  —  read only

   Mounted in server.js as
   `app.use('/api/sales', verifyToken, requireProduction, salesRouter)`.

   This table is the hand-kept record of raw milk sold by the litre, from
   before branches had a till. It is history and nothing more.

   Milk sold loose is now an ordinary product measured in litres — see
   lib/initStock.js — so it goes out on an issue note, sells at a branch
   with a customer and a payment method against it, lands in that day's
   cash-up and appears in the reports. None of which this table can do:
   it knows a date, a quantity and a price, and nothing about where the
   milk went or whether the money arrived.

   Keeping a second way to record a sale would split the farm's revenue
   across two places that never reconcile, so the writes are gone. The
   rows themselves are not: they are last year's figures, and the AI
   reports still surface them for periods that have them.

   When these have been carried across — or judged not worth carrying —
   the table and this file can go together.
══════════════════════════════════════════════════════════════ */

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

/* Every write returns the same answer, and says where the sale belongs
   instead — a 404 would suggest the endpoint had simply moved. */
const closed = (req, res) => res.status(410).json({
  error: 'Bulk milk is sold at a branch till now, which records who bought it, '
       + 'how they paid, and puts it in the day\'s cash. This record is read-only history.',
});

router.post('/', closed);
router.post('/import', closed);
router.delete('/:id', closed);

module.exports = router;
