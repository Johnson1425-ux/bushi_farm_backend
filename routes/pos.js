const express = require('express');
const { pool } = require('../db');
const { assertBranchAllowed } = require('../auth');
const { onHand, postMovements } = require('../lib/stockLedger');

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
           s.customer_name, s.payment_method, s.subtotal, s.discount, s.total,
           s.status, s.void_reason, s.voided_at, s.notes,
           c.username AS cashier, v.username AS voided_by
    FROM pos_sales s
    JOIN branches b ON b.id = s.branch_id
    LEFT JOIN users c ON c.id = s.cashier_id
    LEFT JOIN users v ON v.id = s.voided_by
    WHERE s.id = $1
  `, [id]);
  if (!rows.length) return null;

  const { rows: items } = await client.query(`
    SELECT i.id, i.product_id, p.product, p.size, i.units, i.unit_price,
           i.line_total, i.litres
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
  const { branch_id, sold_on, items, customer_name, payment_method = 'cash', discount, notes } = req.body;

  const scope = resolveBranch(req, branch_id);
  if (scope.error) return res.status(400).json({ error: scope.error });
  const denied = assertBranchAllowed(req, scope.branchId);
  if (denied) return res.status(403).json({ error: denied });

  const lines = (items || [])
    .map(i => ({ product_id: parseInt(i.product_id, 10), units: num(i.units), unit_price: i.unit_price }))
    .filter(i => Number.isFinite(i.product_id) && i.units > 0);
  if (!lines.length) return res.status(400).json({ error: 'Add at least one item to the sale' });

  if (!['cash', 'mobile', 'card', 'credit'].includes(payment_method)) {
    return res.status(400).json({ error: 'Unknown payment method' });
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
      SELECT p.id, p.product, p.size, p.unit_price, p.litres_per_pack, p.active,
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

    /* The price is normally the catalogue's. An override is allowed —
       haggling happens — but it is recorded on the line, never written
       back to the product. */
    let subtotal = 0;
    const priced = lines.map(line => {
      const p = byId.get(line.product_id);
      const unitPrice = line.unit_price != null && num(line.unit_price) >= 0
        ? money(line.unit_price) : money(p.unit_price);
      const lineTotal = money(unitPrice * line.units);
      subtotal += lineTotal;
      return { ...line, unitPrice, lineTotal, perPack: Number(p.litres_per_pack) };
    });
    subtotal = money(subtotal);

    const disc = Math.min(Math.max(money(discount), 0), subtotal);
    const total = money(subtotal - disc);

    const { rows: created } = await client.query(`
      INSERT INTO pos_sales
        (receipt_no, branch_id, sold_on, cashier_id, customer_name,
         payment_method, subtotal, discount, total, notes)
      VALUES (
        'RC-' || TO_CHAR($2::date, 'YYYY') || '-' ||
          LPAD(NEXTVAL('pos_receipt_no_seq')::text, 5, '0'),
        $1, $2, $3, $4, $5, $6, $7, $8, $9
      ) RETURNING id
    `, [scope.branchId, day, req.user.id, customer_name?.trim() || null,
        payment_method, subtotal, disc, total, notes?.trim() || null]);
    const saleId = created[0].id;

    for (const l of priced) {
      await client.query(`
        INSERT INTO pos_sale_items (sale_id, product_id, units, unit_price, line_total, litres)
        VALUES ($1,$2,$3,$4,$5,$6)
      `, [saleId, l.product_id, l.units, l.unitPrice, l.lineTotal, l.units * l.perPack]);
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
  const { from, to, status, payment_method } = req.query;
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

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);

  try {
    const { rows } = await pool.query(`
      SELECT s.id, s.receipt_no, s.branch_id, b.name AS branch_name,
             TO_CHAR(s.sold_on,'YYYY-MM-DD') AS sold_on, s.sold_at,
             s.customer_name, s.payment_method, s.subtotal, s.discount, s.total,
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
      SELECT id, branch_id, status, TO_CHAR(sold_on,'YYYY-MM-DD') AS sold_on,
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

/* ── takings ─────────────────────────────────────────────────
   Voided receipts are excluded from every figure here. They are money
   that was never taken, and leaving them in would overstate a day the
   attendant already knows was corrected. */
router.get('/summary', async (req, res) => {
  const { from, to } = req.query;
  const conditions = [`s.status = 'completed'`], params = [];

  const scope = listScope(req, req.query.branch_id);
  if (scope.error) return res.status(scope.status).json({ error: scope.error });
  if (scope.branchId) {
    params.push(scope.branchId); conditions.push(`s.branch_id = $${params.length}`);
  }
  if (from) { params.push(from); conditions.push(`s.sold_on >= $${params.length}`); }
  if (to)   { params.push(to);   conditions.push(`s.sold_on <= $${params.length}`); }
  const where = 'WHERE ' + conditions.join(' AND ');

  try {
    const [byMonth, byBranch, byProduct, totals] = await Promise.all([
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
