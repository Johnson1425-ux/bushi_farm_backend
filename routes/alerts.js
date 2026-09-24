const express = require('express');
const { pool } = require('../db');
const { balance, stockState } = require('../lib/inventoryLedger');

const router = express.Router();

// NOTE: mounted in server.js as `app.use('/api/alerts', verifyToken, alertsRouter)`.
// Two implementations exist here, same as they did in server.js: GET / (used
// by useAlerts.js on the frontend) and GET /daily (a slightly different
// production-drop/low-stock variant). Left as-is rather than merged, so
// behavior does not shift as part of this refactor.

/**
 * Store lines that are out, or down to the level the store reorders at.
 *
 * Written once and used by both handlers below. It had lived only in
 * /daily — which nothing on the frontend calls — so the one alert the
 * store keeper could actually act on was the one nobody ever saw. It is
 * on GET / as well now, which is what useAlerts.js polls.
 *
 * An item with no reorder level set can only be "out": a level of zero
 * means nobody has said what low looks like for that line, and warning on
 * every row from the day it was added is how an alert list gets ignored.
 */
async function storeStockAlerts() {
  const { rows } = await pool.query(`
    SELECT i.name, i.unit, i.reorder_level,
           ${balance('l')} AS current_stock
    FROM inventory_items i
    LEFT JOIN inventory_logs l ON l.item_id = i.id
    WHERE i.status = 'active'
    GROUP BY i.id, i.name, i.unit, i.reorder_level
    HAVING ${balance('l')} <= 0
        OR (i.reorder_level > 0 AND ${balance('l')} <= i.reorder_level)
    ORDER BY ${balance('l')} ASC
  `);

  return rows.map((r) => {
    const qty   = Number(r.current_stock) || 0;
    const level = Number(r.reorder_level) || 0;
    const state = stockState(qty, level);
    return {
      type: 'low_stock',
      severity: state === 'out' ? 'high' : 'medium',
      message: state === 'out'
        ? `${r.name} is out of stock`
        : `${r.name} is down to ${qty} ${r.unit} — at or below its reorder level of ${level}`,
      item: r.name,
    };
  });
}

router.get('/', async (req, res) => {
  try {
    const alerts = [];

    // 1. Production drop — cows whose latest record is 25% below their own average
    const { rows: prodDrops } = await pool.query(`
      WITH latest AS (
        SELECT DISTINCT ON (cow_id) cow_id, litres, date
        FROM milk_records ORDER BY cow_id, date DESC
      ),
      averages AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric, 2) AS avg_litres
        FROM milk_records GROUP BY cow_id
      )
      SELECT c.name, l.litres AS latest_litres, a.avg_litres,
        ROUND(((a.avg_litres - l.litres) / NULLIF(a.avg_litres,0) * 100)::numeric, 1) AS drop_pct,
        TO_CHAR(l.date,'YYYY-MM-DD') AS date
      FROM latest l
      JOIN averages a ON a.cow_id = l.cow_id
      JOIN cows c ON c.id = l.cow_id
      WHERE c.status = 'active' AND l.litres < a.avg_litres * 0.75
      ORDER BY drop_pct DESC
    `);
    for (const r of prodDrops) {
      alerts.push({
        type: 'production_drop',
        severity: r.drop_pct >= 50 ? 'high' : 'medium',
        message: `${r.name} production dropped ${r.drop_pct}% (${r.latest_litres}L vs avg ${r.avg_litres}L)`,
        cow: r.name, date: r.date,
      });
    }

    // 2. Upcoming births — pregnancies due within 14 days
    const { rows: births } = await pool.query(`
      SELECT c.name AS cow_name, TO_CHAR(p.expected_due_date,'YYYY-MM-DD') AS due_date,
        (p.expected_due_date - CURRENT_DATE)::int AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE c.status = 'active'
        AND p.status = 'active' AND p.expected_due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 14
      ORDER BY p.expected_due_date ASC
    `);
    for (const b of births) {
      alerts.push({
        type: 'upcoming_birth',
        severity: b.days_remaining <= 3 ? 'high' : 'medium',
        message: `${b.cow_name} is due to give birth in ${b.days_remaining} day(s) (${b.due_date})`,
        cow: b.cow_name, date: b.due_date,
      });
    }

    // 3. Overdue births — past due date and still active
    const { rows: overdue } = await pool.query(`
      SELECT c.name AS cow_name, TO_CHAR(p.expected_due_date,'YYYY-MM-DD') AS due_date,
        (CURRENT_DATE - p.expected_due_date)::int AS days_overdue
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE c.status = 'active'
        AND p.status = 'active' AND p.expected_due_date < CURRENT_DATE
    `);
    for (const o of overdue) {
      alerts.push({
        type: 'overdue_birth',
        severity: 'high',
        message: `${o.cow_name} is ${o.days_overdue} day(s) overdue! Expected: ${o.due_date}`,
        cow: o.cow_name, date: o.due_date,
      });
    }

    // 4. Store stock that is out, or due an order.
    alerts.push(...await storeStockAlerts());

    res.json(alerts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/daily', async (req, res) => {
  try {
    const alerts = [];

    // 1. Production drop — cows whose today/recent avg is 20%+ below their overall avg
    const { rows: prodRows } = await pool.query(`
      WITH overall AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric,2) AS avg_all
        FROM milk_records GROUP BY cow_id
      ),
      recent AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric,2) AS avg_recent
        FROM milk_records
        WHERE date >= CURRENT_DATE - 7
        GROUP BY cow_id
      )
      SELECT c.name, o.avg_all, r.avg_recent,
             ROUND(((o.avg_all - r.avg_recent) / NULLIF(o.avg_all,0) * 100)::numeric,1) AS drop_pct
      FROM overall o
      JOIN recent r ON r.cow_id = o.cow_id
      JOIN cows c ON c.id = o.cow_id
      WHERE c.status = 'active' AND r.avg_recent < o.avg_all * 0.80
      ORDER BY drop_pct DESC
    `);
    for (const r of prodRows) {
      alerts.push({
        type: 'production_drop',
        severity: r.drop_pct >= 40 ? 'high' : 'medium',
        message: `${r.name}'s production dropped ${r.drop_pct}% (${r.avg_recent}L vs avg ${r.avg_all}L)`,
        cow: r.name,
      });
    }

    // 2. Upcoming births — pregnancies due within 14 days
    const { rows: birthRows } = await pool.query(`
      SELECT c.name AS cow_name, p.expected_due_date,
             (p.expected_due_date - CURRENT_DATE)::int AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE c.status = 'active'
        AND p.status = 'active'
        AND p.expected_due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 14
      ORDER BY p.expected_due_date ASC
    `);
    for (const r of birthRows) {
      alerts.push({
        type: 'upcoming_birth',
        severity: r.days_remaining <= 3 ? 'high' : 'medium',
        message: r.days_remaining === 0
          ? `${r.cow_name} is due to give birth today!`
          : `${r.cow_name} is due to give birth in ${r.days_remaining} day(s)`,
        cow: r.cow_name,
      });
    }

    // 3. Store stock that is out, or due an order.
    alerts.push(...await storeStockAlerts());

    res.json(alerts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
