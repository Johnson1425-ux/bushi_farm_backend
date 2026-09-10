const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// NOTE: mounted in server.js as `app.use('/api/analytics', verifyToken, analyticsRouter)`.

router.get('/summary', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      /* Head count is the herd you have today; historical milk records
         remain included in the overall analytics. */

      SELECT
        COALESCE(
          COUNT(DISTINCT c.id) FILTER (WHERE c.status = 'active')::int,
          0
        ) AS total_cows,

        COALESCE(
          COUNT(DISTINCT c.id) FILTER (WHERE c.status <> 'active')::int,
          0
        ) AS archived_cows,

        COALESCE(COUNT(r.id)::int, 0) AS total_records,

        /* Total litres recorded yesterday */
        COALESCE(
          ROUND(
            SUM(r.litres) FILTER (
              WHERE r.date = CURRENT_DATE - 1
            )::numeric,
            1
          ),
          0
        ) AS total_litres,

        COALESCE(
          ROUND(AVG(r.litres)::numeric, 2),
          0
        ) AS overall_avg,

        COALESCE(
          COUNT(DISTINCT r.date)::int,
          0
        ) AS days_tracked,

        TO_CHAR(MIN(r.date), 'YYYY-MM-DD') AS first_date,

        TO_CHAR(MAX(r.date), 'YYYY-MM-DD') AS last_date

      FROM cows c
      LEFT JOIN milk_records r
        ON r.cow_id = c.id
    `);

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

router.get('/trend', async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date,'YYYY-MM-DD') AS date, ROUND(AVG(litres)::numeric,2) AS avg_litres,
             ROUND(SUM(litres)::numeric,2) AS total_litres, COUNT(*)::int AS cow_count
      FROM milk_records WHERE date >= CURRENT_DATE - $1::int
      GROUP BY date ORDER BY date
    `, [days]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Whole-farm production, one row per calendar month.

   Deliberately not filtered by cow status: this is history, and a cow that
   has since died or been sold still produced the milk credited to the month
   she produced it in. Filtering archived animals out here would make last
   year's totals change every time an animal leaves the herd.

   `days_recorded` counts days that actually have readings rather than days
   in the month, so avg_per_day is not dragged down by days nobody milked —
   a half-entered month reads as a half-entered month, not a bad one. */
router.get('/monthly', async (req, res) => {
  const cowId = parseInt(req.query.cow_id, 10);
  const args = [];
  let where = '';
  if (Number.isInteger(cowId)) { args.push(cowId); where = 'WHERE cow_id = $1'; }

  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date, 'YYYY-MM')                AS month,
             ROUND(SUM(litres)::numeric, 1)          AS total_litres,
             COUNT(*)::int                           AS records,
             COUNT(DISTINCT cow_id)::int             AS cows_milked,
             COUNT(DISTINCT date)::int               AS days_recorded,
             ROUND(AVG(litres)::numeric, 2)          AS avg_per_record,
             ROUND((SUM(litres) / NULLIF(COUNT(DISTINCT date), 0))::numeric, 1) AS avg_per_day,
             ROUND(MAX(litres)::numeric, 1)          AS best_single_record
      FROM milk_records
      ${where}
      GROUP BY 1
      ORDER BY 1 DESC
    `, args);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Which cows made up one month's total. The obvious next question after
   seeing a month move, so it is one request away rather than a page away. */
router.get('/monthly/:month', async (req, res) => {
  const month = String(req.params.month || '');
  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: 'month must be formatted YYYY-MM' });
  }
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.tag, c.status,
             ROUND(SUM(r.litres)::numeric, 1)  AS total_litres,
             ROUND(AVG(r.litres)::numeric, 2)  AS avg_litres,
             COUNT(r.id)::int                  AS days_recorded
      FROM milk_records r
      JOIN cows c ON c.id = r.cow_id
      WHERE TO_CHAR(r.date, 'YYYY-MM') = $1
      GROUP BY c.id
      ORDER BY total_litres DESC
    `, [month]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/compare', async (req, res) => {
  const ids = (req.query.ids || '').split(',').map(Number).filter(Boolean);
  if (!ids.length) return res.status(400).json({ error: 'ids required' });
  try {
    const { rows: stats } = await pool.query(`
      SELECT c.id, c.name, ROUND(AVG(r.litres)::numeric,2) AS avg_litres,
             ROUND(SUM(r.litres)::numeric,2) AS total_litres, ROUND(MAX(r.litres)::numeric,2) AS max_litres,
             ROUND(MIN(r.litres)::numeric,2) AS min_litres, ROUND(STDDEV(r.litres)::numeric,2) AS stddev_litres,
             COUNT(r.id)::int AS record_count
      FROM cows c JOIN milk_records r ON r.cow_id = c.id
      WHERE c.id = ANY($1) GROUP BY c.id
    `, [ids]);
    const { rows: daily } = await pool.query(`
      SELECT c.name AS cow, TO_CHAR(r.date,'YYYY-MM-DD') AS date, r.litres
      FROM milk_records r JOIN cows c ON c.id = r.cow_id
      WHERE r.cow_id = ANY($1) ORDER BY r.date
    `, [ids]);
    res.json({ stats, daily });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/dates', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT DISTINCT TO_CHAR(date,'YYYY-MM-DD') AS date FROM milk_records ORDER BY date DESC`);
    res.json(rows.map(r => r.date));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
