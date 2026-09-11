const express = require('express');
const { pool } = require('../db');
const { requireProduction, assertBranchAllowed } = require('../auth');
const { onHand, postMovements } = require('../lib/stockLedger');
const { findOrCreateCustomer } = require('./customers');

const router = express.Router();

/* ══════════════════════════════════════════════════════════════
   THE TILL

   Mounted in server.js as
   `app.use('/api/pos', verifyToken, requireBranchAccess, posRouter)`.

   Every route here acts on one branch. Which branch is settled by
   resolveBranch() below, from the token for an attendant and from the
   request for anyone senior — never from the request for an attendant,
   or a till could be pointed at another shop's stock by editing a URL.
══════════════════════════════════════════════════════════════ */

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const money = (v) => Math.round(num(v) * 100) / 100;
const TIERS = ['retail', 'wholesale'];

/** The list price for a tier, falling back to retail when wholesale is unset. */
function tierPrice(product, tier) {
  const wholesale = num(product.wholesale_price);
  if (tier === 'wholesale' && wholesale > 0) return wholesale;
  return num(product.retail_price);
}

/**
 * The branch this request may act on, or an error to send back.
 *
 * An attendant gets theirs and nothing else. A manager must name one:
 * defaulting them to "the first branch" would let a mis-click ring up a
 * sale against a shop they were only looking at.
 */
function resolveBranch(req, requested) {
  if (req.user.role === 'attendant') {
    if (!req.user.branch_id) {
      return { error: 'This account is not assigned to a branch yet. Ask an admin to set one.' };
    }
    return { branchId: req.user.branch_id };
  }
  const id = parseInt(requested, 10);
  if (!Number.isFinite(id)) return { error: 'branch_id is required' };
  return { branchId: id };
}

/**
 * The branch filter for a listing.
 *
 * A named branch is checked against what this account may see, so an
 * attendant asking for someone else's branch is refused rather than quietly
 * handed their own — a UI bug then shows up as an error instead of as the
 * wrong figures under the right heading.
 *
 * With no branch named, an attendant is scoped to theirs and anyone senior
 * sees every branch.
 */
function listScope(req, requested) {
  if (requested != null && String(requested).trim() !== '') {
    const denied = assertBranchAllowed(req, requested);
    if (denied) return { error: denied, status: 403 };
    return { branchId: parseInt(requested, 10) };
  }
  if (req.user.role === 'attendant') {
    if (!req.user.branch_id) {
      return { error: 'This account is not assigned to a branch yet. Ask an admin to set one.', status: 400 };
    }
    return { branchId: req.user.branch_id };
  }
  return { branchId: null };   // every branch
}

/* ── what this branch can sell right now ─────────────────────
   Stock and price in one call: a till that fetched them separately could
   show a price against a line that had just run out. */
router.get('/catalogue', async (req, res) => {
  const scope = resolveBranch(req, req.query.branch_id);
  if (scope.error) return res.status(400).json({ error: scope.error });
  const denied = assertBranchAllowed(req, scope.branchId);
  if (denied) return res.status(403).json({ error: denied });

  try {
    const rows = await onHand(pool, { locationKind: 'branch', branchId: scope.branchId });
    res.json(rows.filter(r => r.active || r.units !== 0));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/** Header + lines for one receipt. */
async function loadSale(client, id) {
  const { rows } = await client.query(`
    SELECT s.id, s.receipt_no, s.branch_id, b.name AS branch_name,
           TO_CHAR(s.sold_on,'YYYY-MM-DD') AS sold_on, s.sold_at,
           s.customer_name, s.customer_id, d.name AS customer_account,
           s.payment_method, s.price_tier,
           s.subtotal, s.discount, s.total,
           s.status, s.void_reason, s.voided_at, s.notes,
           c.username AS cashier, v.username AS voided_by
    FROM pos_sales s
    JOIN branches b ON b.id = s.branch_id
    LEFT JOIN customers d ON d.id = s.customer_id
    LEFT JOIN users c ON c.id = s.cashier_id
    LEFT JOIN users v ON v.id = s.voided_by
    WHERE s.id = $1
  `, [id]);
  if (!rows.length) return null;

  const { rows: items } = await client.query(`
    SELECT i.id, i.product_id, p.product, p.size, i.units, i.unit_price,
           i.line_total, i.litres, i.price_tier
    FROM pos_sale_items i JOIN products p ON p.id = i.product_id
    WHERE i.sale_id = $1 ORDER BY p.sort_order, p.product, p.size
  `, [id]);

  return { ...rows[0], items };
}

/* ── ring up a sale ──────────────────────────────────────────
   The whole thing lands in one transaction: the receipt, its lines, and
   the movements that take the packs off the shelf. A receipt without its
   movements would be takings with no stock behind them.

   Selling more than the branch holds is refused, per product. The ledger
   is what every other screen believes, so letting a till drive a balance
   negative would quietly make all of them wrong — and where the shelf
   really does hold more than the system thinks, the fix is a manager's
   stock adjustment, which leaves a note saying so. */
router.post('/sales', async (req, res) => {
  const { branch_id, sold_on, items, customer_name, customer_id,
          payment_method = 'cash', price_tier = 'retail', discount, notes } = req.body;

  const scope = resolveBranch(req, branch_id);
  if (scope.error) return res.status(400).json({ error: scope.error });
  const denied = assertBranchAllowed(req, scope.branchId);
  if (denied) return res.status(403).json({ error: denied });

  /* A line may name its own tier — one crate at agent prices alongside a
     couple of packs over the counter is an ordinary sale here. Anything
     that does not becomes the sale's tier. */
  const lines = (items || [])
    .map(i => ({
      product_id: parseInt(i.product_id, 10),
      units: num(i.units),
      unit_price: i.unit_price,
      price_tier: TIERS.includes(i.price_tier) ? i.price_tier : null,
    }))
    .filter(i => Number.isFinite(i.product_id) && i.units > 0);
  if (!lines.length) return res.status(400).json({ error: 'Add at least one item to the sale' });

  if (!['cash', 'mobile', 'card', 'credit'].includes(payment_method)) {
    return res.status(400).json({ error: 'Unknown payment method' });
  }
  if (!TIERS.includes(price_tier)) {
    return res.status(400).json({ error: 'Price tier must be retail or wholesale' });
  }
  /* Credit is a debt, and a debt with nobody attached to it is how a book
     ends up with a receipts column nobody can reconcile. */
  if (payment_method === 'credit' && !customer_id && !String(customer_name || '').trim()) {
    return res.status(400).json({ error: 'A credit sale needs the customer it is owed by' });
  }

  const day = sold_on || new Date().toISOString().slice(0, 10);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    /* Lock the product rows so two tills cannot both pass the stock check
       on the same last crate. The lock is on the product rather than the
       branch's balance, which briefly serialises a product across branches
       too — at a handful of shops that costs nothing, and it is the simple
       thing that is certainly correct. */
    const productIds = lines.map(l => l.product_id);
    const { rows: stockRows } = await client.query(`
      SELECT p.id, p.product, p.size, p.retail_price, p.wholesale_price,
             p.litres_per_pack, p.active,
             COALESCE((
               SELECT SUM(m.units) FROM stock_movements m
               WHERE m.product_id = p.id AND m.location_kind = 'branch'
                 AND m.branch_id = $2
             ), 0) AS on_hand
      FROM products p WHERE p.id = ANY($1)
      ORDER BY p.id
      FOR UPDATE OF p
    `, [productIds, scope.branchId]);

    const byId = new Map(stockRows.map(r => [r.id, r]));
    const short = [], unknown = [];

    for (const line of lines) {
      const p = byId.get(line.product_id);
      if (!p) { unknown.push(line.product_id); continue; }
      if (line.units > Number(p.on_hand)) {
        short.push({
          product: p.product, size: p.size,
          wanted: line.units, on_hand: Number(p.on_hand),
        });
      }
    }
    if (unknown.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Unknown product id ${unknown[0]}` });
    }
    if (short.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'This branch does not hold enough stock for the sale',
        shortfalls: short,
      });
    }

    /* The price is normally the catalogue's, from whichever list this line
       is being sold on. An override is allowed — haggling happens — but it
       is recorded on the line, never written back to the product.

       A product with no wholesale price falls back to retail rather than
       to zero: an unset price is the farm not having got round to it, and
       giving the pack away is never the safer reading. */
    let subtotal = 0;
    const priced = lines.map(line => {
      const p = byId.get(line.product_id);
      const tier = line.price_tier || price_tier;
      const unitPrice = line.unit_price != null && num(line.unit_price) >= 0
        ? money(line.unit_price) : money(tierPrice(p, tier));
      const lineTotal = money(unitPrice * line.units);
      subtotal += lineTotal;
      return { ...line, tier, unitPrice, lineTotal, perPack: Number(p.litres_per_pack) };
    });
    subtotal = money(subtotal);

    const disc = Math.min(Math.max(money(discount), 0), subtotal);
    const total = money(subtotal - disc);

    /* The account is resolved before the receipt is written so the whole
       thing — sale, lines, movements and any debt — lands together or not
       at all. A charge without its receipt is a balance nobody can explain.

       Any sale may name its customer, not only a credit one: that is what
       makes an account worth having for someone who always pays cash,
       since otherwise the farm knows what it sold and not who to. */
    let customer = null;
    if (customer_id || String(customer_name || '').trim()) {
      customer = customer_id
        ? (await client.query('SELECT id, name FROM customers WHERE id=$1', [customer_id])).rows[0]
        : await findOrCreateCustomer(client, customer_name, {
            branchId: scope.branchId, userId: req.user.id,
          });
      if (!customer) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'That customer account was not found' });
      }
    }

    const { rows: created } = await client.query(`
      INSERT INTO pos_sales
        (receipt_no, branch_id, sold_on, cashier_id, customer_name, customer_id,
         payment_method, price_tier, subtotal, discount, total, notes)
      VALUES (
        'RC-' || TO_CHAR($2::date, 'YYYY') || '-' ||
          LPAD(NEXTVAL('pos_receipt_no_seq')::text, 5, '0'),
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
      ) RETURNING id
    `, [scope.branchId, day, req.user.id,
        customer?.name || customer_name?.trim() || null, customer?.id || null,
        payment_method, price_tier, subtotal, disc, total, notes?.trim() || null]);
    const saleId = created[0].id;

    for (const l of priced) {
      await client.query(`
        INSERT INTO pos_sale_items
          (sale_id, product_id, units, unit_price, line_total, litres, price_tier)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
      `, [saleId, l.product_id, l.units, l.unitPrice, l.lineTotal,
          l.units * l.perPack, l.tier]);
    }

    await postMovements(client, priced.map(l => ({
      locationKind: 'branch', branchId: scope.branchId, productId: l.product_id,
      reason: 'sold',
      units:  -l.units,
      litres: -l.units * l.perPack,
      occurredOn: day,
      refKind: 'pos_sale', refId: saleId,
      createdBy: req.user.id,
    })));

    /* Only a credit sale puts anything on the ledger. A cash sale names the
       customer so their trade is recorded, but nothing is owed, and posting
       a charge and a payment that cancel out would fill the statement with
       noise. */
    if (customer && payment_method === 'credit' && total > 0) {
      await client.query(`
        INSERT INTO customer_entries
          (customer_id, entry_date, kind, amount, branch_id, ref_kind, ref_id, description, created_by)
        VALUES ($1,$2,'charge',$3,$4,'pos_sale',$5,$6,$7)
      `, [customer.id, day, total, scope.branchId, saleId, 'Sold on credit', req.user.id]);
    }

    const sale = await loadSale(client, saleId);
    await client.query('COMMIT');
    res.status(201).json(sale);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* ── receipts ────────────────────────────────────────────── */
router.get('/sales', async (req, res) => {
  const { from, to, status, payment_method, price_tier, product_id } = req.query;
  const conditions = [], params = [];

  const scope = listScope(req, req.query.branch_id);
  if (scope.error) return res.status(scope.status).json({ error: scope.error });
  if (scope.branchId) {
    params.push(scope.branchId); conditions.push(`s.branch_id = $${params.length}`);
  }
  if (from)   { params.push(from);   conditions.push(`s.sold_on >= $${params.length}`); }
  if (to)     { params.push(to);     conditions.push(`s.sold_on <= $${params.length}`); }
  if (status) { params.push(status); conditions.push(`s.status = $${params.length}`); }
  if (payment_method) { params.push(payment_method); conditions.push(`s.payment_method = $${params.length}`); }
  if (price_tier)     { params.push(price_tier);     conditions.push(`s.price_tier = $${params.length}`); }
  /* Filtering by product keeps whole receipts rather than trimming them to
     the matching line: a receipt is the unit a person reads, and one showing
     a total that excluded half its items would be worse than useless. */
  if (product_id) {
    params.push(product_id);
    conditions.push(`EXISTS (SELECT 1 FROM pos_sale_items i
                             WHERE i.sale_id = s.id AND i.product_id = $${params.length})`);
  }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);

  try {
    const { rows } = await pool.query(`
      SELECT s.id, s.receipt_no, s.branch_id, b.name AS branch_name,
             TO_CHAR(s.sold_on,'YYYY-MM-DD') AS sold_on, s.sold_at,
             s.customer_name, s.payment_method, s.price_tier,
             s.subtotal, s.discount, s.total,
             s.status, c.username AS cashier,
             COALESCE(agg.units, 0)  AS units,
             COALESCE(agg.litres, 0) AS litres,
             COALESCE(agg.lines, 0)  AS lines
      FROM pos_sales s
      JOIN branches b ON b.id = s.branch_id
      LEFT JOIN users c ON c.id = s.cashier_id
      LEFT JOIN (
        SELECT sale_id, COUNT(*)::int AS lines, SUM(units) AS units, SUM(litres) AS litres
        FROM pos_sale_items GROUP BY sale_id
      ) agg ON agg.sale_id = s.id
      ${where}
      ORDER BY s.sold_on DESC, s.id DESC
      LIMIT ${limit}
    `, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/sales/:id', async (req, res) => {
  try {
    const sale = await loadSale(pool, req.params.id);
    if (!sale) return res.status(404).json({ error: 'Receipt not found' });
    const denied = assertBranchAllowed(req, sale.branch_id);
    if (denied) return res.status(403).json({ error: denied });
    res.json(sale);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── void a sale ─────────────────────────────────────────────
   The receipt stays; reversing movements put the packs back. Nothing is
   deleted, because the day's takings and the day's stock have to keep
   explaining each other even when the till was wrong.

   An attendant may only void their own branch's sale from the same
   trading day — the mis-key they just made. Anything older is a
   manager's call, because by then the day has been counted. */
router.post('/sales/:id/void', async (req, res) => {
  const reason = String(req.body?.reason || '').trim();
  if (!reason) return res.status(400).json({ error: 'A void needs a reason' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: locked } = await client.query(`
      SELECT id, branch_id, status, customer_id, total, receipt_no,
             TO_CHAR(sold_on,'YYYY-MM-DD') AS sold_on,
             sold_on = CURRENT_DATE AS is_today
      FROM pos_sales WHERE id = $1 FOR UPDATE
    `, [req.params.id]);
    if (!locked.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Receipt not found' });
    }
    const sale = locked[0];

    const denied = assertBranchAllowed(req, sale.branch_id);
    if (denied) { await client.query('ROLLBACK'); return res.status(403).json({ error: denied }); }

    if (req.user.role === 'attendant' && !sale.is_today) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: 'Only a manager can void a sale from an earlier day',
      });
    }
    if (sale.status === 'voided') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This receipt is already voided' });
    }

    const { rows: items } = await client.query(`
      SELECT i.product_id, i.units, i.litres FROM pos_sale_items i WHERE i.sale_id = $1
    `, [req.params.id]);

    /* Dated to the sale's own trading day, so voiding tomorrow does not
       move stock between two days' figures. */
    await postMovements(client, items.map(i => ({
      locationKind: 'branch', branchId: sale.branch_id, productId: i.product_id,
      reason: 'returned',
      units: Number(i.units), litres: Number(i.litres),
      occurredOn: sale.sold_on,
      refKind: 'pos_sale', refId: Number(req.params.id),
      notes: `Sale voided — ${reason}`,
      createdBy: req.user.id,
    })));

    /* A voided credit sale is a debt that never was. The charge is
       reversed rather than deleted: a statement the customer has already
       seen must not silently become a different one, so both the charge
       and its cancellation stay on the account.

       Keyed off the charge this sale actually posted, not off the sale
       naming a customer. Every sale may name one now — a cash sale does
       so to record whose trade it was — and reversing on that alone would
       credit a customer money they were never charged, leaving the farm
       believing it owed them milk. */
    const { rows: charged } = await client.query(
      `SELECT COALESCE(SUM(amount), 0) AS amount FROM customer_entries
       WHERE ref_kind = 'pos_sale' AND ref_id = $1 AND kind = 'charge'`,
      [sale.id]
    );
    if (sale.customer_id && num(charged[0].amount) > 0) {
      await client.query(`
        INSERT INTO customer_entries
          (customer_id, entry_date, kind, amount, branch_id, ref_kind, ref_id, description, created_by)
        VALUES ($1,$2,'adjustment',$3,$4,'pos_sale',$5,$6,$7)
      `, [sale.customer_id, sale.sold_on, -num(charged[0].amount), sale.branch_id, sale.id,
          `Receipt ${sale.receipt_no} voided — ${reason}`, req.user.id]);
    }

    await client.query(`
      UPDATE pos_sales SET status='voided', voided_by=$1, voided_at=NOW(), void_reason=$2
      WHERE id=$3
    `, [req.user.id, reason, req.params.id]);

    const updated = await loadSale(client, req.params.id);
    await client.query('COMMIT');
    res.json(updated);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* ══════════════════════════════════════════════════════════════
   CASH-UP

   The attendant's end of the day. Everything already recorded elsewhere
   is read back rather than typed: sales, cash, mobile, card and credit
   from the receipts, and money collected against old debts from the
   debtors' ledger. The farm's paper book totals its debtor receipts
   column into the cash summary by hand; here the same figure is only ever
   held in one place, so the two cannot disagree.

   What a person still supplies is what nothing else records — cash paid
   out of the drawer, money taken in advance from someone with no account,
   and what was actually counted at closing.

     expected = cash sales + debtor receipts + prepaids - expenses
     variance = counted - expected

   Credit sales never enter it: no money changed hands. Mobile and card
   are shown but not expected in the drawer, because they are not in it.
══════════════════════════════════════════════════════════════ */

/**
 * Money collected against old debts at this branch on this day.
 *
 * Read from the debtors' ledger rather than entered, so a payment taken
 * at the counter reaches the day's cash without being keyed twice. A
 * payment recorded without a branch — a manager settling an account from
 * the office — belongs to no till and is deliberately not counted here;
 * it still shows on the customer's statement and in the reports.
 */
async function dayCustomerReceipts(client, branchId, day) {
  const { rows } = await client.query(`
    SELECT ROUND(COALESCE(SUM(-amount), 0)::numeric, 2) AS received
    FROM customer_entries
    WHERE kind = 'payment' AND branch_id = $1 AND entry_date = $2
  `, [branchId, day]);
  return num(rows[0].received);
}

/** The day's takings, split the way a cash-up needs them. */
async function daySales(client, branchId, day) {
  const { rows } = await client.query(`
    SELECT
      ROUND(COALESCE(SUM(total), 0)::numeric, 2)                                          AS sales,
      ROUND(COALESCE(SUM(total) FILTER (WHERE payment_method = 'cash'), 0)::numeric, 2)   AS cash_sales,
      ROUND(COALESCE(SUM(total) FILTER (WHERE payment_method = 'mobile'), 0)::numeric, 2) AS mobile_sales,
      ROUND(COALESCE(SUM(total) FILTER (WHERE payment_method = 'card'), 0)::numeric, 2)   AS card_sales,
      ROUND(COALESCE(SUM(total) FILTER (WHERE payment_method = 'credit'), 0)::numeric, 2) AS credit_sales,
      ROUND(COALESCE(SUM(discount), 0)::numeric, 2)                                       AS discounts,
      COUNT(*)::int                                                                        AS receipts
    FROM pos_sales
    WHERE branch_id = $1 AND sold_on = $2 AND status = 'completed'
  `, [branchId, day]);
  const r = rows[0];
  return {
    sales: num(r.sales), cash_sales: num(r.cash_sales),
    mobile_sales: num(r.mobile_sales), card_sales: num(r.card_sales),
    credit_sales: num(r.credit_sales), discounts: num(r.discounts),
    receipts: r.receipts,
  };
}

/**
 * A branch's cash-up for one day, whether or not one has been started.
 *
 * A day nobody has touched still comes back — with the takings filled in
 * and the entered figures at zero — so the attendant opens a form that is
 * already most of the way done rather than a blank one.
 */
async function loadCashUp(client, branchId, day) {
  const { rows } = await client.query(`
    SELECT c.*, TO_CHAR(c.business_day,'YYYY-MM-DD') AS business_day,
           b.name AS branch_name,
           cb.username AS closed_by_name, cr.username AS created_by_name
    FROM pos_cash_ups c
    JOIN branches b ON b.id = c.branch_id
    LEFT JOIN users cb ON cb.id = c.closed_by
    LEFT JOIN users cr ON cr.id = c.created_by
    WHERE c.branch_id = $1 AND c.business_day = $2
  `, [branchId, day]);

  const takings = await daySales(client, branchId, day);
  const record = rows[0] || null;

  let expenses = [];
  if (record) {
    const e = await client.query(
      'SELECT id, description, amount FROM pos_cash_up_expenses WHERE cash_up_id = $1 ORDER BY id',
      [record.id]
    );
    expenses = e.rows.map(x => ({ ...x, amount: num(x.amount) }));
  }

  const expenseTotal = expenses.reduce((a, x) => a + x.amount, 0);
  const debtorReceipts = await dayCustomerReceipts(client, branchId, day);

  const entered = {
    prepaids:        num(record?.prepaids),
    counted_cash:    num(record?.counted_cash),
    mobile_counted:  num(record?.mobile_counted),
    bank_deposit:    num(record?.bank_deposit),
    float_retained:  num(record?.float_retained),
  };

  const expected = money(
    takings.cash_sales + debtorReceipts + entered.prepaids - expenseTotal
  );

  return {
    branch_id: branchId,
    branch_name: record?.branch_name || null,
    business_day: day,
    status: record?.status || 'open',
    exists: !!record,
    id: record?.id || null,
    notes: record?.notes || null,
    closed_by: record?.closed_by_name || null,
    closed_at: record?.closed_at || null,
    takings,
    expenses,
    expense_total: money(expenseTotal),
    debtor_receipts: debtorReceipts,
    debtor_payments: await dayCustomerPayments(client, branchId, day),
    ...entered,
    expected_cash: expected,
    variance: money(entered.counted_cash - expected),
  };
}

/* The payments behind the total, so the attendant can check the figure
   against the money in front of them rather than taking it on trust. */
async function dayCustomerPayments(client, branchId, day) {
  const { rows } = await client.query(`
    SELECT e.id, d.id AS customer_id, d.name, -e.amount AS amount, e.description
    FROM customer_entries e JOIN customers d ON d.id = e.customer_id
    WHERE e.kind = 'payment' AND e.branch_id = $1 AND e.entry_date = $2
    ORDER BY e.id
  `, [branchId, day]);
  return rows.map(r => ({ ...r, amount: num(r.amount) }));
}

/* GET the cash-up for a day — defaults to today at the caller's branch. */
router.get('/cash-up', async (req, res) => {
  const scope = resolveBranch(req, req.query.branch_id);
  if (scope.error) return res.status(400).json({ error: scope.error });
  const denied = assertBranchAllowed(req, scope.branchId);
  if (denied) return res.status(403).json({ error: denied });

  const day = req.query.date || new Date().toISOString().slice(0, 10);
  try {
    res.json(await loadCashUp(pool, scope.branchId, day));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Save or close it.

   Saving is repeatable while the day is open — an attendant records an
   expense when it happens rather than trying to remember it all at
   closing. Closing is the signature, and a closed day is not editable by
   the attendant who closed it: reopening is a manager's call, so that the
   count someone signed for cannot quietly become a different one. */
router.post('/cash-up', async (req, res) => {
  const scope = resolveBranch(req, req.body.branch_id);
  if (scope.error) return res.status(400).json({ error: scope.error });
  const denied = assertBranchAllowed(req, scope.branchId);
  if (denied) return res.status(403).json({ error: denied });

  const day = req.body.date || new Date().toISOString().slice(0, 10);
  const close = req.body.close === true;

  const expenses = (req.body.expenses || [])
    .map(e => ({ description: String(e.description || '').trim(), amount: money(e.amount) }))
    .filter(e => e.amount > 0);
  if (expenses.some(e => !e.description)) {
    return res.status(400).json({ error: 'Every expense needs a description' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: existing } = await client.query(
      'SELECT id, status FROM pos_cash_ups WHERE branch_id=$1 AND business_day=$2 FOR UPDATE',
      [scope.branchId, day]
    );

    if (existing[0]?.status === 'closed' && req.user.role === 'attendant') {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'This day is already closed. A manager can reopen it if the count was wrong.',
      });
    }

    /* debtor_receipts is deliberately absent: it comes from the debtors'
       ledger. Accepting it here would let the day's cash disagree with the
       statements the customers are holding. */
    const fields = [
      scope.branchId, day,
      money(req.body.prepaids),
      money(req.body.counted_cash), money(req.body.mobile_counted),
      money(req.body.bank_deposit), money(req.body.float_retained),
      req.body.notes?.trim() || null,
      req.user.id,
    ];

    const { rows: saved } = await client.query(`
      INSERT INTO pos_cash_ups
        (branch_id, business_day, prepaids, counted_cash,
         mobile_counted, bank_deposit, float_retained, notes, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (branch_id, business_day) DO UPDATE SET
        prepaids        = EXCLUDED.prepaids,
        counted_cash    = EXCLUDED.counted_cash,
        mobile_counted  = EXCLUDED.mobile_counted,
        bank_deposit    = EXCLUDED.bank_deposit,
        float_retained  = EXCLUDED.float_retained,
        notes           = EXCLUDED.notes,
        updated_at      = NOW()
      RETURNING id
    `, fields);
    const cashUpId = saved[0].id;

    /* The expense list is replaced wholesale rather than merged: the form
       sends the day's list as it now stands, and a line the attendant
       deleted has to actually go. */
    await client.query('DELETE FROM pos_cash_up_expenses WHERE cash_up_id = $1', [cashUpId]);
    for (const e of expenses) {
      await client.query(
        'INSERT INTO pos_cash_up_expenses (cash_up_id, description, amount) VALUES ($1,$2,$3)',
        [cashUpId, e.description, e.amount]
      );
    }

    if (close) {
      await client.query(
        `UPDATE pos_cash_ups SET status='closed', closed_by=$1, closed_at=NOW() WHERE id=$2`,
        [req.user.id, cashUpId]
      );
    }

    const result = await loadCashUp(client, scope.branchId, day);
    await client.query('COMMIT');
    res.status(201).json(result);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* Reopen a closed day. A manager's call, and it says who reopened it by
   clearing the signature rather than keeping a stale one. */
router.post('/cash-up/:id/reopen', requireProduction, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE pos_cash_ups SET status='open', closed_by=NULL, closed_at=NULL, updated_at=NOW()
       WHERE id=$1 AND status='closed'
       RETURNING branch_id, TO_CHAR(business_day,'YYYY-MM-DD') AS business_day`,
      [req.params.id]
    );
    if (!rows.length) return res.status(409).json({ error: 'That day is not closed' });
    res.json(await loadCashUp(pool, rows[0].branch_id, rows[0].business_day));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── takings ─────────────────────────────────────────────────
   Voided receipts are excluded from every figure here. They are money
   that was never taken, and leaving them in would overstate a day the
   attendant already knows was corrected. */
router.get('/summary', async (req, res) => {
  const { from, to, payment_method, price_tier, product_id } = req.query;
  const conditions = [`s.status = 'completed'`], params = [];

  const scope = listScope(req, req.query.branch_id);
  if (scope.error) return res.status(scope.status).json({ error: scope.error });
  if (scope.branchId) {
    params.push(scope.branchId); conditions.push(`s.branch_id = $${params.length}`);
  }
  if (from) { params.push(from); conditions.push(`s.sold_on >= $${params.length}`); }
  if (to)   { params.push(to);   conditions.push(`s.sold_on <= $${params.length}`); }
  if (payment_method) { params.push(payment_method); conditions.push(`s.payment_method = $${params.length}`); }
  if (price_tier)     { params.push(price_tier);     conditions.push(`s.price_tier = $${params.length}`); }
  if (product_id) {
    params.push(product_id);
    conditions.push(`EXISTS (SELECT 1 FROM pos_sale_items i
                             WHERE i.sale_id = s.id AND i.product_id = $${params.length})`);
  }
  const where = 'WHERE ' + conditions.join(' AND ');

  try {
    const [byMonth, byBranch, byPayment, byProduct, totals] = await Promise.all([
      pool.query(`
        SELECT TO_CHAR(s.sold_on,'YYYY-MM') AS month,
               COUNT(*)::int AS receipts,
               ROUND(SUM(s.total)::numeric, 2) AS revenue,
               ROUND(SUM(s.discount)::numeric, 2) AS discount
        FROM pos_sales s ${where}
        GROUP BY month ORDER BY month DESC
      `, params),
      pool.query(`
        SELECT b.id AS branch_id, b.name AS branch_name,
               COUNT(*)::int AS receipts,
               ROUND(SUM(s.total)::numeric, 2) AS revenue
        FROM pos_sales s JOIN branches b ON b.id = s.branch_id ${where}
        GROUP BY b.id, b.name ORDER BY revenue DESC NULLS LAST
      `, params),
      pool.query(`
        SELECT s.payment_method, s.price_tier,
               COUNT(*)::int AS receipts,
               ROUND(SUM(s.total)::numeric, 2) AS revenue
        FROM pos_sales s ${where}
        GROUP BY s.payment_method, s.price_tier
        ORDER BY revenue DESC NULLS LAST
      `, params),
      pool.query(`
        SELECT p.product, p.size,
               SUM(i.units)  AS units,
               ROUND(SUM(i.litres)::numeric, 1) AS litres,
               ROUND(SUM(i.line_total)::numeric, 2) AS revenue
        FROM pos_sales s
        JOIN pos_sale_items i ON i.sale_id = s.id
        JOIN products p ON p.id = i.product_id
        ${where}
        GROUP BY p.id, p.product, p.size, p.sort_order
        ORDER BY revenue DESC NULLS LAST
      `, params),
      /* One CTE naming the selected receipts, so the money columns and the
         litres column are read from the same set without the join that
         would multiply each receipt total by its line count. */
      pool.query(`
        WITH selected AS (SELECT s.id, s.total, s.discount FROM pos_sales s ${where})
        SELECT COUNT(*)::int AS receipts,
               ROUND(COALESCE(SUM(total), 0)::numeric, 2)    AS revenue,
               ROUND(COALESCE(SUM(discount), 0)::numeric, 2) AS discount,
               ROUND(COALESCE(AVG(total), 0)::numeric, 2)    AS avg_receipt,
               ROUND(COALESCE((
                 SELECT SUM(i.litres) FROM pos_sale_items i
                 WHERE i.sale_id IN (SELECT id FROM selected)
               ), 0)::numeric, 1) AS litres
        FROM selected
      `, params),
    ]);

    res.json({
      by_month:   byMonth.rows,
      by_branch:  byBranch.rows,
      by_payment: byPayment.rows,
      by_product: byProduct.rows,
      totals:     totals.rows[0],
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* One branch's trading day, for the attendant closing the till. */
router.get('/day', async (req, res) => {
  const scope = resolveBranch(req, req.query.branch_id);
  if (scope.error) return res.status(400).json({ error: scope.error });
  const denied = assertBranchAllowed(req, scope.branchId);
  if (denied) return res.status(403).json({ error: denied });

  const day = req.query.date || new Date().toISOString().slice(0, 10);
  try {
    const { rows } = await pool.query(`
      SELECT COUNT(*) FILTER (WHERE status='completed')::int AS receipts,
             COUNT(*) FILTER (WHERE status='voided')::int    AS voided,
             ROUND(COALESCE(SUM(total) FILTER (WHERE status='completed'), 0)::numeric, 2) AS revenue,
             ROUND(COALESCE(SUM(total) FILTER (WHERE status='completed' AND payment_method='cash'), 0)::numeric, 2)   AS cash,
             ROUND(COALESCE(SUM(total) FILTER (WHERE status='completed' AND payment_method='mobile'), 0)::numeric, 2) AS mobile,
             ROUND(COALESCE(SUM(total) FILTER (WHERE status='completed' AND payment_method='card'), 0)::numeric, 2)   AS card,
             ROUND(COALESCE(SUM(total) FILTER (WHERE status='completed' AND payment_method='credit'), 0)::numeric, 2) AS credit
      FROM pos_sales WHERE branch_id = $1 AND sold_on = $2
    `, [scope.branchId, day]);
    res.json({ date: day, branch_id: scope.branchId, ...rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
