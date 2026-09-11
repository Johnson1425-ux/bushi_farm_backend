const express = require('express');
const { pool } = require('../db');
const { requireProduction, assertBranchAllowed } = require('../auth');

const router = express.Router();

/* NOTE: mounted in server.js as
   `app.use('/api/customers', verifyToken, requireBranchAccess, customersRouter)`.

   An attendant needs the list to ring up any sale, and takes payments
   over the counter, so reads and payments are open to them. Writing off a
   balance, or setting the figure a customer arrived owing, is a manager's
   job and gated per route. */

const num   = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const money = (v) => Math.round(num(v) * 100) / 100;

/**
 * Find an account by name, or open one.
 *
 * The till sends a name rather than an id when the attendant types a new
 * customer, so this is the path most accounts are created by. Matching is
 * on the normalised name — the same rule as the unique index — because
 * two accounts for one customer split their trade in half.
 */
async function findOrCreateCustomer(client, name, { branchId, userId } = {}) {
  const clean = String(name || '').trim();
  if (!clean) return null;

  const { rows: found } = await client.query(
    'SELECT id, name FROM customers WHERE LOWER(BTRIM(name)) = LOWER(BTRIM($1))', [clean]
  );
  if (found.length) return found[0];

  const { rows } = await client.query(
    `INSERT INTO customers (name, branch_id, created_by) VALUES ($1,$2,$3)
     RETURNING id, name`,
    [clean, branchId || null, userId || null]
  );
  return rows[0];
}

/** Balance = opening + charges − payments, as one SUM over the entries. */
const BALANCE_SQL = `
  c.opening_balance + COALESCE((
    SELECT SUM(e.amount) FROM customer_entries e WHERE e.customer_id = c.id
  ), 0)
`;

/* What a customer is worth, and what they still owe.

   Spend counts every completed sale rung up against the account, cash or
   credit alike — they bought it either way. Voided receipts are excluded:
   money that was never taken. */
const SPEND_SQL = `
  LEFT JOIN LATERAL (
    SELECT COALESCE(SUM(s.total), 0)  AS total_spent,
           COUNT(*)::int              AS purchases,
           MAX(s.sold_on)             AS last_purchase
    FROM pos_sales s
    WHERE s.customer_id = c.id AND s.status = 'completed'
  ) spend ON TRUE
`;

/* ── the book ────────────────────────────────────────────────
   Every account, with what they have spent and what they owe. Customers
   in credit come back too: someone who has overpaid is owed milk, and
   leaving them out of the list is how that gets forgotten.

   ?owing=true narrows it to the debtors — which is not a separate list,
   just this one filtered on a balance above zero. */
router.get('/', async (req, res) => {
  const conditions = [], params = [];
  if (req.query.active === 'true') conditions.push('c.active');
  if (req.query.q) {
    params.push(`%${req.query.q}%`);
    conditions.push(`c.name ILIKE $${params.length}`);
  }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.phone, c.branch_id, b.name AS branch_name,
             c.opening_balance, c.active, c.notes, c.created_at,
             ${BALANCE_SQL} AS balance,
             spend.total_spent, spend.purchases, spend.last_purchase,
             (SELECT MAX(e.entry_date) FROM customer_entries e WHERE e.customer_id = c.id) AS last_activity
      FROM customers c
      LEFT JOIN branches b ON b.id = c.branch_id
      ${SPEND_SQL}
      ${where}
      ORDER BY ${BALANCE_SQL} DESC, spend.total_spent DESC, c.name
    `, params);

    const customers = rows.map(r => ({
      ...r,
      opening_balance: num(r.opening_balance),
      balance: num(r.balance),
      total_spent: num(r.total_spent),
    }));

    const owing  = customers.filter(c => c.balance >  0.005);
    const credit = customers.filter(c => c.balance < -0.005);

    res.json({
      customers,
      /* The debtors, named rather than left for the client to re-derive —
         two places deciding what counts as owing is two places to get it
         wrong. */
      debtors: owing,
      totals: {
        count:           customers.length,
        owing_count:     owing.length,
        owed:            money(owing.reduce((a, c) => a + c.balance, 0)),
        in_credit:       money(credit.reduce((a, c) => a + c.balance, 0)),
        in_credit_count: credit.length,
        net:             money(customers.reduce((a, c) => a + c.balance, 0)),
        lifetime_spend:  money(customers.reduce((a, c) => a + c.total_spent, 0)),
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── one account ─────────────────────────────────────────────
   The ledger with a balance carried down each line, the way the paper
   book reads — you can put a finger on any row and see what was owed at
   that moment — and the purchases beside it, which is the half a debtors
   book never had. */
router.get('/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.phone, c.branch_id, b.name AS branch_name,
             c.opening_balance, c.active, c.notes, c.created_at,
             ${BALANCE_SQL} AS balance,
             spend.total_spent, spend.purchases, spend.last_purchase
      FROM customers c LEFT JOIN branches b ON b.id = c.branch_id
      ${SPEND_SQL}
      WHERE c.id = $1
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Customer not found' });

    const [entries, purchases] = await Promise.all([
      pool.query(`
        SELECT e.id, TO_CHAR(e.entry_date,'YYYY-MM-DD') AS entry_date, e.kind, e.amount,
               e.branch_id, b.name AS branch_name, e.ref_kind, e.ref_id, e.description,
               u.username AS created_by, e.created_at, s.receipt_no
        FROM customer_entries e
        LEFT JOIN branches b ON b.id = e.branch_id
        LEFT JOIN users u ON u.id = e.created_by
        LEFT JOIN pos_sales s ON e.ref_kind = 'pos_sale' AND s.id = e.ref_id
        WHERE e.customer_id = $1
        ORDER BY e.entry_date, e.id
      `, [req.params.id]),
      pool.query(`
        SELECT s.id, s.receipt_no, TO_CHAR(s.sold_on,'YYYY-MM-DD') AS sold_on,
               s.total, s.payment_method, s.price_tier, s.status,
               b.name AS branch_name
        FROM pos_sales s JOIN branches b ON b.id = s.branch_id
        WHERE s.customer_id = $1
        ORDER BY s.sold_on DESC, s.id DESC
        LIMIT 100
      `, [req.params.id]),
    ]);

    let running = num(rows[0].opening_balance);
    const statement = entries.rows.map(e => {
      running += num(e.amount);
      return { ...e, amount: num(e.amount), balance: money(running) };
    });

    res.json({
      ...rows[0],
      opening_balance: num(rows[0].opening_balance),
      balance: num(rows[0].balance),
      total_spent: num(rows[0].total_spent),
      entries: statement,
      purchases: purchases.rows.map(p => ({ ...p, total: num(p.total) })),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Open an account. The opening balance is what they arrived owing, and is
   a manager's figure — it is not something that happened at a till. */
router.post('/', async (req, res) => {
  const { name, phone, branch_id, opening_balance, notes } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name required' });

  const opening = money(opening_balance);
  if (opening !== 0 && req.user.role === 'attendant') {
    return res.status(403).json({ error: 'Only a manager can set an opening balance' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO customers (name, phone, branch_id, opening_balance, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [String(name).trim(), phone?.trim() || null, branch_id || null,
       opening, notes?.trim() || null, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A customer with that name already exists' });
    res.status(500).json({ error: err.message });
  }
});

router.patch('/:id', requireProduction, async (req, res) => {
  const { name, phone, branch_id, opening_balance, active, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE customers SET
         name            = COALESCE($1, name),
         phone           = COALESCE($2, phone),
         branch_id       = COALESCE($3, branch_id),
         opening_balance = COALESCE($4, opening_balance),
         active          = COALESCE($5, active),
         notes           = COALESCE($6, notes)
       WHERE id = $7 RETURNING *`,
      [name?.trim() || null, phone?.trim() || null, branch_id || null,
       opening_balance != null ? money(opening_balance) : null,
       typeof active === 'boolean' ? active : null,
       notes?.trim() || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Customer not found' });
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A customer with that name already exists' });
    res.status(500).json({ error: err.message });
  }
});

/* ── take a payment ──────────────────────────────────────────
   The counterpart to a credit sale, and the figure the cash-up reads back
   as the day's receipts. It carries the branch that took the money, so a
   payment made at one shop against a debt run up at another lands in the
   right till.

   A payment larger than the balance is allowed and leaves the account in
   credit — that is a customer paying for milk they have not collected
   yet, which the paper book keeps in a separate prepaids table. */
router.post('/:id/payments', async (req, res) => {
  const amount = money(req.body.amount);
  if (!(amount > 0)) return res.status(400).json({ error: 'A payment must be more than zero' });

  const branchId = req.user.role === 'attendant' ? req.user.branch_id
    : (req.body.branch_id ? parseInt(req.body.branch_id, 10) : null);
  if (branchId) {
    const denied = assertBranchAllowed(req, branchId);
    if (denied) return res.status(403).json({ error: denied });
  }

  const date = req.body.date || new Date().toISOString().slice(0, 10);

  try {
    const { rows: exists } = await pool.query('SELECT id FROM customers WHERE id=$1', [req.params.id]);
    if (!exists.length) return res.status(404).json({ error: 'Customer not found' });

    const { rows } = await pool.query(
      `INSERT INTO customer_entries
         (customer_id, entry_date, kind, amount, branch_id, ref_kind, description, created_by)
       VALUES ($1,$2,'payment',$3,$4,'manual',$5,$6) RETURNING *`,
      [req.params.id, date, -amount, branchId,
       req.body.description?.trim() || 'Payment received', req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── charge something that did not go through the till ───────
   The paper book's DELIVERY column: goods handed over on account without
   a receipt being rung up. */
router.post('/:id/charges', requireProduction, async (req, res) => {
  const amount = money(req.body.amount);
  if (!(amount > 0)) return res.status(400).json({ error: 'A charge must be more than zero' });
  const description = String(req.body.description || '').trim();
  if (!description) return res.status(400).json({ error: 'A charge needs a description' });

  const date = req.body.date || new Date().toISOString().slice(0, 10);
  try {
    const { rows } = await pool.query(
      `INSERT INTO customer_entries
         (customer_id, entry_date, kind, amount, branch_id, ref_kind, description, created_by)
       VALUES ($1,$2,'charge',$3,$4,'manual',$5,$6) RETURNING *`,
      [req.params.id, date, amount, req.body.branch_id || null, description, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Write off, or correct a balance. Signed, and a reason is required —
   an adjustment nobody explained is indistinguishable from a mistake. */
router.post('/:id/adjustments', requireProduction, async (req, res) => {
  const amount = money(req.body.amount);
  if (!amount) return res.status(400).json({ error: 'An adjustment must be a non-zero amount' });
  const description = String(req.body.description || '').trim();
  if (!description) return res.status(400).json({ error: 'An adjustment needs a reason' });

  const date = req.body.date || new Date().toISOString().slice(0, 10);
  try {
    const { rows } = await pool.query(
      `INSERT INTO customer_entries
         (customer_id, entry_date, kind, amount, ref_kind, description, created_by)
       VALUES ($1,$2,'adjustment',$3,'manual',$4,$5) RETURNING *`,
      [req.params.id, date, amount, description, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* An entry is never edited. A payment keyed wrong is corrected by an
   adjustment that says so, because a statement a customer has already
   seen must not silently become a different one. Only an entry posted by
   mistake can be removed, and only by a manager. */
router.delete('/entries/:entryId', requireProduction, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `DELETE FROM customer_entries WHERE id=$1 AND ref_kind = 'manual' RETURNING id`,
      [req.params.entryId]
    );
    if (!rows.length) {
      return res.status(409).json({
        error: 'That entry came from a sale and cannot be deleted. Void the receipt instead.',
      });
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = { router, findOrCreateCustomer };
