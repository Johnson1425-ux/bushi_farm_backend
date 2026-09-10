const express = require('express');
const { pool } = require('../db');
const { requireProduction, assertBranchAllowed } = require('../auth');
const { onHand, postMovements, inTransit } = require('../lib/stockLedger');
const { productKeyMap, findProduct } = require('../lib/products');

const router = express.Router();

/* NOTE: mounted in server.js as
   `app.use('/api/stock', verifyToken, requireBranchAccess, stockRouter)`.

   Reads are branch-scoped per route: an attendant asking for a branch that
   is not theirs is refused rather than quietly redirected, so a misconfigured
   till says so instead of showing someone else's figures. */

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

/* ── on-hand ─────────────────────────────────────────────────
   ?location=processing            the packing store
   ?location=branch&branch_id=3    one branch's shelves               */
router.get('/on-hand', async (req, res) => {
  const locationKind = req.query.location === 'branch' ? 'branch' : 'processing';
  const branchId = locationKind === 'branch' ? parseInt(req.query.branch_id, 10) : null;

  if (locationKind === 'branch' && !Number.isFinite(branchId)) {
    return res.status(400).json({ error: 'branch_id is required when location=branch' });
  }
  if (locationKind === 'branch') {
    const denied = assertBranchAllowed(req, branchId);
    if (denied) return res.status(403).json({ error: denied });
  } else if (req.user.role === 'attendant') {
    return res.status(403).json({ error: 'This account can only see its own branch' });
  }

  try {
    const rows = await onHand(pool, { locationKind, branchId });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Everything the issuing page needs in one call: what the store holds, what
   each branch holds, and what is on the road between them. Three round trips
   from the browser would render the three panels at three different moments,
   which on a page whose whole job is a balance looks like a bug. */
router.get('/overview', requireProduction, async (req, res) => {
  try {
    const [processing, branchRows, transit] = await Promise.all([
      onHand(pool, { locationKind: 'processing' }),
      pool.query(`
        SELECT b.id, b.name, b.code, b.active,
               COALESCE(SUM(m.units), 0)  AS units,
               COALESCE(SUM(m.litres), 0) AS litres
        FROM branches b
        LEFT JOIN stock_movements m
          ON m.branch_id = b.id AND m.location_kind = 'branch'
        GROUP BY b.id ORDER BY b.active DESC, b.name
      `),
      inTransit(pool),
    ]);

    res.json({
      processing,
      branches: branchRows.rows.map(b => ({ ...b, units: num(b.units), litres: num(b.litres) })),
      in_transit: transit,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── movement history ────────────────────────────────────────
   The audit trail behind any balance on screen. */
router.get('/movements', async (req, res) => {
  const { location, branch_id, product_id, from, to } = req.query;
  const conditions = [], params = [];

  if (location === 'branch' || location === 'processing') {
    params.push(location); conditions.push(`m.location_kind = $${params.length}`);
  }
  if (branch_id) {
    const denied = assertBranchAllowed(req, branch_id);
    if (denied) return res.status(403).json({ error: denied });
    params.push(branch_id); conditions.push(`m.branch_id = $${params.length}`);
  } else if (req.user.role === 'attendant') {
    if (!req.user.branch_id) return res.json([]);
    params.push(req.user.branch_id); conditions.push(`m.branch_id = $${params.length}`);
  }
  if (product_id) { params.push(product_id); conditions.push(`m.product_id = $${params.length}`); }
  if (from)       { params.push(from);       conditions.push(`m.occurred_on >= $${params.length}`); }
  if (to)         { params.push(to);         conditions.push(`m.occurred_on <= $${params.length}`); }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);

  try {
    const { rows } = await pool.query(`
      SELECT m.id, m.location_kind, m.branch_id, b.name AS branch_name,
             m.product_id, p.product, p.size, m.reason, m.units, m.litres,
             TO_CHAR(m.occurred_on,'YYYY-MM-DD') AS occurred_on,
             m.ref_kind, m.ref_id, m.notes, m.created_at,
             usr.username AS created_by
      FROM stock_movements m
      JOIN products p ON p.id = m.product_id
      LEFT JOIN branches b ON b.id = m.branch_id
      LEFT JOIN users usr ON usr.id = m.created_by
      ${where}
      ORDER BY m.occurred_on DESC, m.id DESC
      LIMIT ${limit}
    `, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── record a day's packing ──────────────────────────────────
   The live replacement for the workbook's PACKED and DAMAGE blocks. One
   post covers a whole day: every line with a figure against it becomes a
   movement, and lines left blank are simply absent rather than stored as
   zero, so the ledger stays a record of things that happened.

   Damaged packs are a negative movement in the processing store, not a
   separate loss column — they were made, then written off, and the balance
   has to show both halves of that. */
router.post('/production', requireProduction, async (req, res) => {
  const { date, entries, notes } = req.body;
  if (!date) return res.status(400).json({ error: 'date required' });
  if (!Array.isArray(entries) || !entries.length) {
    return res.status(400).json({ error: 'entries required' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: products } = await client.query('SELECT id, litres_per_pack FROM products');
    const byId = new Map(products.map(p => [p.id, Number(p.litres_per_pack)]));

    const movements = [];
    for (const e of entries) {
      const productId = parseInt(e.product_id, 10);
      const perPack = byId.get(productId);
      if (perPack === undefined) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Unknown product id ${e.product_id}` });
      }
      const packed  = num(e.packed_units);
      const damaged = num(e.damaged_units);
      if (packed < 0 || damaged < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Packed and damaged figures cannot be negative' });
      }
      const base = {
        locationKind: 'processing', branchId: null, productId,
        occurredOn: date, refKind: 'production', notes: notes || null,
        createdBy: req.user.id,
      };
      if (packed)  movements.push({ ...base, reason: 'packed',  units:  packed,  litres:  packed  * perPack });
      if (damaged) movements.push({ ...base, reason: 'damaged', units: -damaged, litres: -damaged * perPack });
    }

    if (!movements.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Nothing to record — every line was blank' });
    }

    await postMovements(client, movements);
    await client.query('COMMIT');
    res.status(201).json({ ok: true, movements: movements.length });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* ── correct a balance by hand ───────────────────────────────
   A stock count that disagrees with the ledger is settled by writing the
   difference down, never by editing history. `units` is signed and a reason
   is required: an adjustment nobody explained is indistinguishable from a
   mistake. */
router.post('/adjustment', requireProduction, async (req, res) => {
  const { product_id, location = 'processing', branch_id, units, date, notes } = req.body;
  if (!product_id || !date) return res.status(400).json({ error: 'product_id and date required' });
  if (!num(units))          return res.status(400).json({ error: 'units must be a non-zero number' });
  if (!notes || !String(notes).trim()) {
    return res.status(400).json({ error: 'An adjustment needs a reason' });
  }
  const locationKind = location === 'branch' ? 'branch' : 'processing';
  if (locationKind === 'branch' && !branch_id) {
    return res.status(400).json({ error: 'branch_id required for a branch adjustment' });
  }

  try {
    const { rows } = await pool.query('SELECT litres_per_pack FROM products WHERE id=$1', [product_id]);
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });

    await postMovements(pool, [{
      locationKind,
      branchId: locationKind === 'branch' ? branch_id : null,
      productId: product_id,
      reason: 'adjustment',
      units: num(units),
      litres: num(units) * Number(rows[0].litres_per_pack),
      occurredOn: date,
      refKind: 'manual',
      notes: String(notes).trim(),
      createdBy: req.user.id,
    }]);
    res.status(201).json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── bootstrap the ledger from a workbook ────────────────────
   The ledger starts empty, and stock that was already on the racks the day
   it went live did not arrive through it. This posts the closing balance of
   one uploaded month as opening movements, dated the last day of that month,
   so day one of live issuing starts from a real figure instead of zero.

   It is a one-time bootstrap and refuses to run twice: opening movements
   already present mean this has been done, and repeating it would double
   the starting stock. */
router.post('/opening', requireProduction, async (req, res) => {
  const { upload_id } = req.body;
  if (!upload_id) return res.status(400).json({ error: 'upload_id required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: existing } = await client.query(
      `SELECT 1 FROM stock_movements WHERE reason = 'opening' LIMIT 1`
    );
    if (existing.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Opening balances have already been set. Correct the figures with a stock adjustment instead.',
      });
    }

    const { rows: uploads } = await client.query(
      'SELECT id, label, month_num, year FROM processing_uploads WHERE id = $1', [upload_id]
    );
    if (!uploads.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Upload not found' });
    }
    const up = uploads[0];

    /* Dated the last day of the month the figures close on. Without a month
       and year on the row — the case for anything imported before those
       columns existed — today is the honest fallback. */
    const asOf = up.year && up.month_num
      ? new Date(Date.UTC(up.year, up.month_num, 0)).toISOString().slice(0, 10)
      : new Date().toISOString().slice(0, 10);

    const { rows: stock } = await client.query(
      'SELECT product, size, units FROM processing_stock WHERE upload_id = $1', [upload_id]
    );
    const map = await productKeyMap(client);

    const movements = [], unmatched = [];
    for (const s of stock) {
      const units = num(s.units);
      if (!units) continue;
      const p = findProduct(map, s.product, s.size);
      if (!p) { unmatched.push(`${s.product} ${s.size}`); continue; }
      movements.push({
        locationKind: 'processing', branchId: null, productId: p.id,
        reason: 'opening', units, litres: units * Number(p.litres_per_pack),
        occurredOn: asOf, refKind: 'processing_upload', refId: up.id,
        notes: `Opening balance carried in from ${up.label}`,
        createdBy: req.user.id,
      });
    }

    await postMovements(client, movements);
    await client.query('COMMIT');

    res.status(201).json({
      ok: true, from: up.label, as_of: asOf,
      products: movements.length,
      units: movements.reduce((a, m) => a + m.units, 0),
      /* A product on the sheet with no catalogue row is reported rather than
         dropped in silence — it is stock the ledger will never account for. */
      unmatched,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

module.exports = router;
