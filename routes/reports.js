const express = require('express');
const { pool } = require('../db');

const router = express.Router();

/* ══════════════════════════════════════════════════════════════
   REPORTS

   Mounted in server.js as
   `app.use('/api/reports', verifyToken, requireProduction, reportsRouter)`.

   These follow the shape of the farm's own Sales Day Book, because that
   is the shape the people reading them already think in:

     sales-by-branch   a row per period, a column per branch. The
                       workbook calls it SALES BY UNITY, and it is the
                       one view that answers "which outlet is carrying
                       this month".
     cash-book         a row per day: sales, what went out on credit,
                       expenses, money collected against old debts, and
                       what the drawer should therefore have held. The
                       workbook's CASH BALANCE sheet.
     products          what sold, split by the two price lists, so
                       counter trade and agent trade can be told apart.
     debtors           who owes what, and how long it has been owed —
                       the day book's debtor table, aged.

   Everything is built from receipts and cash-ups. Nothing here stores a
   figure of its own, so a report can never disagree with the day it
   describes.

   Voided receipts are excluded throughout: money that was never taken.
══════════════════════════════════════════════════════════════ */

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

/* day / week / month, as a date_trunc unit. Anything else is a typo, and
   silently falling back to days would hide it in a report nobody checks. */
const GROUPS = { day: 'day', week: 'week', month: 'month' };

function groupUnit(value) {
  return GROUPS[String(value || 'day').toLowerCase()] || null;
}

/** from/to with sane defaults: the current month. */
function period(req) {
  const now = new Date();
  const first = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  return {
    from: req.query.from || first.toISOString().slice(0, 10),
    to:   req.query.to   || now.toISOString().slice(0, 10),
  };
}

/* ── income per branch, per period ───────────────────────────
   Returned as a matrix — the periods down the side, the branches across
   the top — rather than as a flat list the client would have to pivot.
   The pivot is where a total goes wrong, and it should go wrong in one
   place that can be tested. */
router.get('/sales-by-branch', async (req, res) => {
  const { from, to } = period(req);
  const unit = groupUnit(req.query.group);
  if (!unit) return res.status(400).json({ error: 'group must be day, week or month' });

  try {
    const [cells, branches] = await Promise.all([
      pool.query(`
        SELECT TO_CHAR(DATE_TRUNC($3, s.sold_on), 'YYYY-MM-DD') AS period,
               s.branch_id,
               ROUND(SUM(s.total)::numeric, 2)   AS revenue,
               COUNT(*)::int                      AS receipts,
               ROUND(COALESCE(SUM(s.total) FILTER (WHERE s.payment_method = 'credit'), 0)::numeric, 2) AS credit
        FROM pos_sales s
        WHERE s.status = 'completed' AND s.sold_on BETWEEN $1 AND $2
        GROUP BY 1, s.branch_id
        ORDER BY 1
      `, [from, to, unit]),
      pool.query('SELECT id, name, code, active FROM branches ORDER BY active DESC, name'),
    ]);

    /* Only branches that actually traded get a column. A report twelve
       columns wide, nine of them empty, is harder to read than the same
       report without them. */
    const traded = new Set(cells.rows.map(r => r.branch_id));
    const columns = branches.rows.filter(b => traded.has(b.id));

    const byPeriod = new Map();
    for (const r of cells.rows) {
      if (!byPeriod.has(r.period)) byPeriod.set(r.period, { period: r.period, cells: {}, total: 0, receipts: 0 });
      const row = byPeriod.get(r.period);
      row.cells[r.branch_id] = { revenue: num(r.revenue), receipts: r.receipts, credit: num(r.credit) };
      row.total    += num(r.revenue);
      row.receipts += r.receipts;
    }

    const rows = [...byPeriod.values()].map(r => ({ ...r, total: Math.round(r.total * 100) / 100 }));

    const branchTotals = {};
    for (const b of columns) {
      branchTotals[b.id] = Math.round(
        rows.reduce((a, r) => a + (r.cells[b.id]?.revenue || 0), 0) * 100
      ) / 100;
    }

    res.json({
      from, to, group: unit,
      branches: columns,
      rows,
      branch_totals: branchTotals,
      grand_total: Math.round(rows.reduce((a, r) => a + r.total, 0) * 100) / 100,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── the cash book ───────────────────────────────────────────
   A row per trading day, following the farm's own columns. The takings
   come from receipts; the expenses, debtor receipts, prepaids and the
   counted cash come from that day's cash-up, where one was done.

   `expected_cash` is the arithmetic the paper book does in its head:
   sales, less what went out on credit, less what was paid out of the
   drawer, plus what was collected against old debts and taken in
   advance. `variance` is the only figure worth arguing about. */
router.get('/cash-book', async (req, res) => {
  const { from, to } = period(req);
  const branchId = req.query.branch_id ? parseInt(req.query.branch_id, 10) : null;

  const params = [from, to];
  let branchFilter = '';
  if (branchId) { params.push(branchId); branchFilter = `AND branch_id = $3`; }

  try {
    const { rows } = await pool.query(`
      WITH days AS (
        SELECT DISTINCT sold_on AS day FROM pos_sales
          WHERE status = 'completed' AND sold_on BETWEEN $1 AND $2 ${branchFilter}
        UNION
        SELECT DISTINCT business_day FROM pos_cash_ups
          WHERE business_day BETWEEN $1 AND $2 ${branchFilter}
        UNION
        SELECT DISTINCT entry_date FROM customer_entries
          WHERE kind = 'payment' AND entry_date BETWEEN $1 AND $2 ${branchFilter}
      ),
      takings AS (
        SELECT sold_on AS day,
               SUM(total)                                                  AS sales,
               SUM(total) FILTER (WHERE payment_method = 'cash')            AS cash_sales,
               SUM(total) FILTER (WHERE payment_method = 'mobile')          AS mobile_sales,
               SUM(total) FILTER (WHERE payment_method = 'card')            AS card_sales,
               SUM(total) FILTER (WHERE payment_method = 'credit')          AS credit_sales,
               SUM(discount)                                                AS discounts,
               COUNT(*)::int                                                AS receipts
        FROM pos_sales
        WHERE status = 'completed' AND sold_on BETWEEN $1 AND $2 ${branchFilter}
        GROUP BY sold_on
      ),
      ups AS (
        SELECT c.business_day AS day,
               SUM(c.prepaids)        AS prepaids,
               SUM(c.counted_cash)    AS counted_cash,
               SUM(c.mobile_counted)  AS mobile_counted,
               SUM(c.bank_deposit)    AS bank_deposit,
               SUM(c.float_retained)  AS float_retained,
               COALESCE(SUM(e.total), 0) AS expenses,
               BOOL_AND(c.status = 'closed') AS all_closed,
               COUNT(*)::int          AS cash_ups
        FROM pos_cash_ups c
        LEFT JOIN (
          SELECT cash_up_id, SUM(amount) AS total
          FROM pos_cash_up_expenses GROUP BY cash_up_id
        ) e ON e.cash_up_id = c.id
        WHERE c.business_day BETWEEN $1 AND $2 ${branchFilter}
        GROUP BY c.business_day
      ),
      /* Named "collected" rather than "receipts", which in this query
         already means the number of sales rung up that day. */
      collected AS (
        SELECT entry_date AS day, SUM(-amount) AS debtor_receipts
        FROM customer_entries
        WHERE kind = 'payment' AND entry_date BETWEEN $1 AND $2 ${branchFilter}
        GROUP BY entry_date
      )
      SELECT TO_CHAR(d.day, 'YYYY-MM-DD') AS day,
             COALESCE(t.sales, 0)         AS sales,
             COALESCE(t.cash_sales, 0)    AS cash_sales,
             COALESCE(t.mobile_sales, 0)  AS mobile_sales,
             COALESCE(t.card_sales, 0)    AS card_sales,
             COALESCE(t.credit_sales, 0)  AS credit_sales,
             COALESCE(t.discounts, 0)     AS discounts,
             COALESCE(t.receipts, 0)      AS receipts,
             COALESCE(u.expenses, 0)        AS expenses,
             COALESCE(p.debtor_receipts, 0) AS debtor_receipts,
             COALESCE(u.prepaids, 0)        AS prepaids,
             COALESCE(u.counted_cash, 0)    AS counted_cash,
             COALESCE(u.mobile_counted, 0)  AS mobile_counted,
             COALESCE(u.bank_deposit, 0)    AS bank_deposit,
             COALESCE(u.float_retained, 0)  AS float_retained,
             COALESCE(u.cash_ups, 0)        AS cash_ups,
             COALESCE(u.all_closed, FALSE)  AS closed
      FROM days d
      LEFT JOIN takings   t ON t.day = d.day
      LEFT JOIN ups       u ON u.day = d.day
      LEFT JOIN collected p ON p.day = d.day
      ORDER BY d.day
    `, params);

    const days = rows.map(r => {
      const expected = num(r.cash_sales) + num(r.debtor_receipts) + num(r.prepaids) - num(r.expenses);
      const round = (v) => Math.round(v * 100) / 100;
      return {
        day: r.day,
        sales: num(r.sales), cash_sales: num(r.cash_sales),
        mobile_sales: num(r.mobile_sales), card_sales: num(r.card_sales),
        credit_sales: num(r.credit_sales), discounts: num(r.discounts),
        receipts: r.receipts,
        expenses: num(r.expenses),
        debtor_receipts: num(r.debtor_receipts), prepaids: num(r.prepaids),
        counted_cash: num(r.counted_cash), mobile_counted: num(r.mobile_counted),
        bank_deposit: num(r.bank_deposit), float_retained: num(r.float_retained),
        expected_cash: round(expected),
        /* A day with no cash-up has nothing to compare, and reporting its
           variance as minus the whole day's takings would be nonsense. */
        variance: r.cash_ups > 0 ? round(num(r.counted_cash) - expected) : null,
        cash_ups: r.cash_ups,
        closed: r.closed,
      };
    });

    const sum = (key) => Math.round(days.reduce((a, d) => a + num(d[key]), 0) * 100) / 100;
    res.json({
      from, to, branch_id: branchId,
      days,
      totals: {
        sales: sum('sales'), cash_sales: sum('cash_sales'),
        mobile_sales: sum('mobile_sales'), card_sales: sum('card_sales'),
        credit_sales: sum('credit_sales'), discounts: sum('discounts'),
        expenses: sum('expenses'), debtor_receipts: sum('debtor_receipts'),
        prepaids: sum('prepaids'), counted_cash: sum('counted_cash'),
        bank_deposit: sum('bank_deposit'),
        expected_cash: sum('expected_cash'),
        receipts: days.reduce((a, d) => a + d.receipts, 0),
        /* Only over days that were actually counted, so an uncounted day
           cannot drag the total towards zero and hide a real gap. */
        variance: Math.round(
          days.filter(d => d.variance !== null).reduce((a, d) => a + d.variance, 0) * 100
        ) / 100,
        days_uncounted: days.filter(d => d.cash_ups === 0).length,
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── what sold, and on which price list ──────────────────────
   Retail and wholesale are reported side by side rather than added
   together: the same pack at 1,000 over the counter and 800 to an agent
   is two different trades, and a single revenue figure hides which one
   the month actually was. */
router.get('/products', async (req, res) => {
  const { from, to } = period(req);
  const params = [from, to];
  let branchFilter = '';
  if (req.query.branch_id) {
    params.push(parseInt(req.query.branch_id, 10));
    branchFilter = `AND s.branch_id = $3`;
  }

  try {
    const { rows } = await pool.query(`
      SELECT p.id AS product_id, p.product, p.size, p.sort_order,
             SUM(i.units)                                                     AS units,
             ROUND(SUM(i.litres)::numeric, 1)                                 AS litres,
             ROUND(SUM(i.line_total)::numeric, 2)                             AS revenue,
             COALESCE(SUM(i.units) FILTER (WHERE i.price_tier = 'retail'), 0)      AS retail_units,
             ROUND(COALESCE(SUM(i.line_total) FILTER (WHERE i.price_tier = 'retail'), 0)::numeric, 2)    AS retail_revenue,
             COALESCE(SUM(i.units) FILTER (WHERE i.price_tier = 'wholesale'), 0)   AS wholesale_units,
             ROUND(COALESCE(SUM(i.line_total) FILTER (WHERE i.price_tier = 'wholesale'), 0)::numeric, 2) AS wholesale_revenue
      FROM pos_sales s
      JOIN pos_sale_items i ON i.sale_id = s.id
      JOIN products p ON p.id = i.product_id
      WHERE s.status = 'completed' AND s.sold_on BETWEEN $1 AND $2 ${branchFilter}
      GROUP BY p.id, p.product, p.size, p.sort_order
      ORDER BY p.sort_order, p.product, p.size
    `, params);

    const products = rows.map(r => ({
      ...r,
      units: num(r.units), litres: num(r.litres), revenue: num(r.revenue),
      retail_units: num(r.retail_units), retail_revenue: num(r.retail_revenue),
      wholesale_units: num(r.wholesale_units), wholesale_revenue: num(r.wholesale_revenue),
    }));

    const sum = (key) => Math.round(products.reduce((a, p) => a + p[key], 0) * 100) / 100;
    res.json({
      from, to,
      products,
      totals: {
        units: sum('units'), litres: sum('litres'), revenue: sum('revenue'),
        retail_units: sum('retail_units'), retail_revenue: sum('retail_revenue'),
        wholesale_units: sum('wholesale_units'), wholesale_revenue: sum('wholesale_revenue'),
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── who owes what ───────────────────────────────────────────
   The day book's debtor table with an age against each balance. The paper
   version carries a balance and nothing else, so a debt from March reads
   exactly like one from last week; the ages here are the whole point of
   putting it on a screen.

   Accounts in credit are reported separately rather than netted off. A
   customer who has overpaid is owed milk, and subtracting them from what
   is owed to the farm would make both figures wrong. */
router.get('/debtors', async (req, res) => {
  const asOf = req.query.as_of || new Date().toISOString().slice(0, 10);

  try {
    const { rows } = await pool.query(`
      WITH ledger AS (
        SELECT d.id, d.name, d.phone, d.active, d.branch_id,
               d.opening_balance + COALESCE(SUM(e.amount) FILTER (WHERE e.entry_date <= $1), 0) AS balance,
               MAX(e.entry_date) FILTER (WHERE e.kind = 'payment') AS last_payment,
               MAX(e.entry_date) FILTER (WHERE e.kind = 'charge')  AS last_charge,
               COALESCE(SUM(e.amount)  FILTER (WHERE e.kind = 'charge'  AND e.entry_date <= $1), 0) AS charged,
               COALESCE(SUM(-e.amount) FILTER (WHERE e.kind = 'payment' AND e.entry_date <= $1), 0) AS paid
        FROM customers d
        LEFT JOIN customer_entries e ON e.customer_id = d.id
        GROUP BY d.id
      )
      SELECT l.*, b.name AS branch_name,
             CASE WHEN l.last_payment IS NULL AND l.last_charge IS NULL THEN NULL
                  ELSE ($1::date - GREATEST(
                    COALESCE(l.last_payment, '1900-01-01'::date),
                    COALESCE(l.last_charge,  '1900-01-01'::date)))::int
             END AS days_since_activity
      FROM ledger l LEFT JOIN branches b ON b.id = l.branch_id
      ORDER BY l.balance DESC, l.name
    `, [asOf]);

    const debtors = rows.map(r => ({
      ...r,
      balance: num(r.balance), charged: num(r.charged), paid: num(r.paid),
    }));

    const owing  = debtors.filter(d => d.balance >  0.005);
    const credit = debtors.filter(d => d.balance < -0.005);

    /* Aged by time since the account last moved, not since each charge was
       raised. A running account is paid down as a whole rather than
       invoice by invoice, so per-charge ageing would describe a way of
       trading the farm does not do. */
    const bucket = (d) => {
      const days = d.days_since_activity;
      if (days === null) return 'no activity';
      if (days <= 30) return '0-30 days';
      if (days <= 60) return '31-60 days';
      if (days <= 90) return '61-90 days';
      return 'over 90 days';
    };
    const ageing = {};
    for (const d of owing) {
      const key = bucket(d);
      if (!ageing[key]) ageing[key] = { bucket: key, count: 0, amount: 0 };
      ageing[key].count += 1;
      ageing[key].amount = Math.round((ageing[key].amount + d.balance) * 100) / 100;
    }

    const sum = (list) => Math.round(list.reduce((a, d) => a + d.balance, 0) * 100) / 100;
    res.json({
      as_of: asOf,
      debtors: debtors.map(d => ({ ...d, age_bucket: bucket(d) })),
      ageing: ['0-30 days', '31-60 days', '61-90 days', 'over 90 days', 'no activity']
        .map(k => ageing[k]).filter(Boolean),
      totals: {
        accounts: debtors.length,
        owing_count: owing.length,
        owed: sum(owing),
        in_credit: sum(credit),
        in_credit_count: credit.length,
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
