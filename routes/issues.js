const express = require('express');
const { pool } = require('../db');
const { requireProduction, assertBranchAllowed } = require('../auth');
const { postMovements } = require('../lib/stockLedger');

const router = express.Router();

/* ══════════════════════════════════════════════════════════════
   ISSUE NOTES

   Mounted in server.js as
   `app.use('/api/issues', verifyToken, requireBranchAccess, issuesRouter)`.

   An issue note replaces the workbook's single "issued" figure with a
   document that says where the stock went. Its life is:

     draft       being typed up; nothing has moved
     dispatched  gone from the processing store, not yet on a branch shelf
     received    the branch has counted it in
     cancelled   called off; anything already dispatched is put back

   The two-step dispatch/receive is what makes a shortfall visible. If
   issuing simply moved stock from one balance to the other, a crate that
   never arrived would show as branch stock that nobody can find, and the
   discrepancy would surface weeks later as an unexplained shrinkage.

   Who does what: managers and admins raise and dispatch notes, because
   they are the ones with the store. Confirming receipt is the branch's
   side of the paperwork, so an attendant may do that for their own branch
   and nothing else.
══════════════════════════════════════════════════════════════ */

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

/** Header + lines for one note, or null. */
async function loadIssue(client, id) {
  const { rows } = await client.query(`
    SELECT si.id, si.issue_no, si.branch_id, b.name AS branch_name, b.code AS branch_code,
           TO_CHAR(si.issue_date,'YYYY-MM-DD') AS issue_date, si.status, si.notes,
           si.dispatched_at, si.received_at, si.created_at,
           iu.username AS issued_by, ru.username AS received_by
    FROM stock_issues si
    JOIN branches b ON b.id = si.branch_id
    LEFT JOIN users iu ON iu.id = si.issued_by
    LEFT JOIN users ru ON ru.id = si.received_by
    WHERE si.id = $1
  `, [id]);
  if (!rows.length) return null;

  const { rows: items } = await client.query(`
    SELECT it.id, it.product_id, p.product, p.size, p.litres_per_pack,
           it.units, it.litres, it.received_units
    FROM stock_issue_items it
    JOIN products p ON p.id = it.product_id
    WHERE it.issue_id = $1
    ORDER BY p.sort_order, p.product, p.size
  `, [id]);

  return { ...rows[0], items };
}

/* ── list ─────────────────────────────────────────────────── */
router.get('/', async (req, res) => {
  const { branch_id, status, from, to } = req.query;
  const conditions = [], params = [];

  if (branch_id) {
    const denied = assertBranchAllowed(req, branch_id);
    if (denied) return res.status(403).json({ error: denied });
    params.push(branch_id); conditions.push(`si.branch_id = $${params.length}`);
  } else if (req.user.role === 'attendant') {
    if (!req.user.branch_id) return res.json([]);
    params.push(req.user.branch_id); conditions.push(`si.branch_id = $${params.length}`);
  }
  if (status) { params.push(status); conditions.push(`si.status = $${params.length}`); }
  if (from)   { params.push(from);   conditions.push(`si.issue_date >= $${params.length}`); }
  if (to)     { params.push(to);     conditions.push(`si.issue_date <= $${params.length}`); }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const { rows } = await pool.query(`
      SELECT si.id, si.issue_no, si.branch_id, b.name AS branch_name,
             TO_CHAR(si.issue_date,'YYYY-MM-DD') AS issue_date,
             si.status, si.notes, si.created_at, si.received_at,
             iu.username AS issued_by, ru.username AS received_by,
             COALESCE(agg.lines, 0)  AS lines,
             COALESCE(agg.units, 0)  AS units,
             COALESCE(agg.litres, 0) AS litres
      FROM stock_issues si
      JOIN branches b ON b.id = si.branch_id
      LEFT JOIN users iu ON iu.id = si.issued_by
      LEFT JOIN users ru ON ru.id = si.received_by
      LEFT JOIN (
        SELECT issue_id, COUNT(*)::int AS lines, SUM(units) AS units, SUM(litres) AS litres
        FROM stock_issue_items GROUP BY issue_id
      ) agg ON agg.issue_id = si.id
      ${where}
      ORDER BY si.issue_date DESC, si.id DESC
      LIMIT 200
    `, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.get('/:id', async (req, res) => {
  try {
    const issue = await loadIssue(pool, req.params.id);
    if (!issue) return res.status(404).json({ error: 'Issue note not found' });
    const denied = assertBranchAllowed(req, issue.branch_id);
    if (denied) return res.status(403).json({ error: denied });
    res.json(issue);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── raise a note ─────────────────────────────────────────────
   `dispatch: true` raises and sends it in one go, which is the normal case
   at the loading bay. Saving a draft first is for a note being prepared
   ahead of the van arriving. */
router.post('/', requireProduction, async (req, res) => {
  const { branch_id, issue_date, items, notes, dispatch } = req.body;
  if (!branch_id)  return res.status(400).json({ error: 'branch_id required' });
  if (!issue_date) return res.status(400).json({ error: 'issue_date required' });

  const lines = (items || [])
    .map(i => ({ product_id: parseInt(i.product_id, 10), units: num(i.units) }))
    .filter(i => Number.isFinite(i.product_id) && i.units > 0);
  if (!lines.length) return res.status(400).json({ error: 'Add at least one product with a quantity' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: branches } = await client.query(
      'SELECT id, active FROM branches WHERE id = $1', [branch_id]
    );
    if (!branches.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Branch not found' });
    }
    if (!branches[0].active) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'That branch is closed — stock cannot be issued to it' });
    }

    const { rows: created } = await client.query(`
      INSERT INTO stock_issues (issue_no, branch_id, issue_date, issued_by, notes)
      VALUES (
        'ISS-' || TO_CHAR($2::date, 'YYYY') || '-' ||
          LPAD(NEXTVAL('stock_issue_no_seq')::text, 4, '0'),
        $1, $2, $3, $4
      )
      RETURNING id
    `, [branch_id, issue_date, req.user.id, notes?.trim() || null]);
    const issueId = created[0].id;

    const { rows: products } = await client.query('SELECT id, litres_per_pack FROM products');
    const perPack = new Map(products.map(p => [p.id, Number(p.litres_per_pack)]));

    for (const line of lines) {
      if (!perPack.has(line.product_id)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Unknown product id ${line.product_id}` });
      }
      /* Two lines for the same product are one line for twice the quantity —
         the unique constraint would otherwise reject the whole note over
         what is really just a double entry on the form. */
      await client.query(`
        INSERT INTO stock_issue_items (issue_id, product_id, units, litres)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (issue_id, product_id) DO UPDATE
          SET units  = stock_issue_items.units  + EXCLUDED.units,
              litres = stock_issue_items.litres + EXCLUDED.litres
      `, [issueId, line.product_id, line.units, line.units * perPack.get(line.product_id)]);
    }

    if (dispatch) {
      const failed = await dispatchIssue(client, issueId, req.user.id);
      if (failed) {
        await client.query('ROLLBACK');
        return res.status(409).json(failed);
      }
    }

    const issue = await loadIssue(client, issueId);
    await client.query('COMMIT');
    res.status(201).json(issue);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/**
 * Move a draft to dispatched, taking its stock out of the processing store.
 *
 * Returns null on success, or an error body describing what could not be
 * covered. The caller owns the transaction: the movements and the status
 * change have to land together or a retry would issue the same crate twice.
 */
async function dispatchIssue(client, issueId, userId) {
  const { rows: locked } = await client.query(
    `SELECT id, status, branch_id, TO_CHAR(issue_date,'YYYY-MM-DD') AS issue_date
     FROM stock_issues WHERE id = $1 FOR UPDATE`, [issueId]
  );
  if (!locked.length) return { error: 'Issue note not found' };
  const issue = locked[0];
  if (issue.status !== 'draft') {
    return { error: `This note is already ${issue.status} and cannot be dispatched again` };
  }

  /* What the store holds against what this note asks for, in one query, so
     the check cannot be read from a balance that moved between lines. */
  const { rows: check } = await client.query(`
    SELECT it.product_id, p.product, p.size, p.litres_per_pack,
           it.units AS wanted,
           COALESCE((
             SELECT SUM(m.units) FROM stock_movements m
             WHERE m.product_id = it.product_id AND m.location_kind = 'processing'
           ), 0) AS on_hand
    FROM stock_issue_items it
    JOIN products p ON p.id = it.product_id
    WHERE it.issue_id = $1
    ORDER BY p.sort_order
  `, [issueId]);

  const short = check
    .filter(r => Number(r.wanted) > Number(r.on_hand))
    .map(r => ({
      product: r.product, size: r.size,
      wanted: Number(r.wanted), on_hand: Number(r.on_hand),
    }));

  if (short.length) {
    return {
      error: 'The processing store does not hold enough for this note',
      shortfalls: short,
    };
  }

  await postMovements(client, check.map(r => ({
    locationKind: 'processing', branchId: null, productId: r.product_id,
    reason: 'issue_out',
    units:  -Number(r.wanted),
    litres: -Number(r.wanted) * Number(r.litres_per_pack),
    occurredOn: issue.issue_date,
    refKind: 'stock_issue', refId: issueId,
    createdBy: userId,
  })));

  await client.query(
    `UPDATE stock_issues SET status='dispatched', dispatched_at=NOW() WHERE id=$1`, [issueId]
  );
  return null;
}

router.post('/:id/dispatch', requireProduction, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const failed = await dispatchIssue(client, req.params.id, req.user.id);
    if (failed) {
      await client.query('ROLLBACK');
      return res.status(failed.error === 'Issue note not found' ? 404 : 409).json(failed);
    }
    const issue = await loadIssue(client, req.params.id);
    await client.query('COMMIT');
    res.json(issue);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* ── the branch counts it in ─────────────────────────────────
   `received` may carry a per-line count that differs from what was sent.
   The branch is credited with what actually arrived, and the difference
   stays on the note as a shortfall for someone to explain — it is not
   quietly written back to the store, because the stock is not there.

   Sending nothing means "all of it arrived", which is the common case and
   should not require re-typing the whole note. */
router.post('/:id/receive', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: locked } = await client.query(
      `SELECT id, status, branch_id, TO_CHAR(issue_date,'YYYY-MM-DD') AS issue_date
       FROM stock_issues WHERE id = $1 FOR UPDATE`, [req.params.id]
    );
    if (!locked.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Issue note not found' });
    }
    const issue = locked[0];

    const denied = assertBranchAllowed(req, issue.branch_id);
    if (denied) { await client.query('ROLLBACK'); return res.status(403).json({ error: denied }); }

    if (issue.status !== 'dispatched') {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: issue.status === 'received'
          ? 'This note has already been received'
          : `A ${issue.status} note cannot be received`,
      });
    }

    const counted = new Map(
      (req.body?.received || [])
        .map(r => [parseInt(r.product_id, 10), num(r.units)])
        .filter(([id, units]) => Number.isFinite(id) && units >= 0)
    );

    const { rows: items } = await client.query(`
      SELECT it.product_id, it.units, p.litres_per_pack, p.product, p.size
      FROM stock_issue_items it JOIN products p ON p.id = it.product_id
      WHERE it.issue_id = $1
    `, [req.params.id]);

    const movements = [], shortfalls = [];
    for (const it of items) {
      const sent = Number(it.units);
      const got  = counted.has(it.product_id) ? counted.get(it.product_id) : sent;
      if (got > sent) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          error: `More ${it.product} ${it.size} was counted in than was sent (${got} against ${sent})`,
        });
      }
      await client.query(
        'UPDATE stock_issue_items SET received_units = $1 WHERE issue_id = $2 AND product_id = $3',
        [got, req.params.id, it.product_id]
      );
      if (got < sent) shortfalls.push({ product: it.product, size: it.size, sent, received: got });
      if (got > 0) {
        movements.push({
          locationKind: 'branch', branchId: issue.branch_id, productId: it.product_id,
          reason: 'issue_in',
          units: got, litres: got * Number(it.litres_per_pack),
          occurredOn: req.body?.date || issue.issue_date,
          refKind: 'stock_issue', refId: Number(req.params.id),
          createdBy: req.user.id,
        });
      }
    }

    await postMovements(client, movements);
    await client.query(
      `UPDATE stock_issues SET status='received', received_by=$1, received_at=NOW() WHERE id=$2`,
      [req.user.id, req.params.id]
    );

    const updated = await loadIssue(client, req.params.id);
    await client.query('COMMIT');
    res.json({ ...updated, shortfalls });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* ── call it off ─────────────────────────────────────────────
   A draft simply stops existing as a live note. A dispatched one has
   already moved stock, so cancelling posts the opposite movement rather
   than deleting the original: the crate went out and came back, and both
   trips belong in the record. A received note is not cancellable — that
   stock is on a shelf, and putting it back is a return, not an undo. */
router.post('/:id/cancel', requireProduction, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: locked } = await client.query(
      `SELECT id, status, TO_CHAR(issue_date,'YYYY-MM-DD') AS issue_date
       FROM stock_issues WHERE id = $1 FOR UPDATE`, [req.params.id]
    );
    if (!locked.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Issue note not found' });
    }
    const issue = locked[0];

    if (issue.status === 'received') {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'This note was received. Record a return from the branch instead of cancelling it.',
      });
    }
    if (issue.status === 'cancelled') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This note is already cancelled' });
    }

    if (issue.status === 'dispatched') {
      const { rows: items } = await client.query(`
        SELECT it.product_id, it.units, p.litres_per_pack
        FROM stock_issue_items it JOIN products p ON p.id = it.product_id
        WHERE it.issue_id = $1
      `, [req.params.id]);

      await postMovements(client, items.map(it => ({
        locationKind: 'processing', branchId: null, productId: it.product_id,
        reason: 'returned',
        units: Number(it.units),
        litres: Number(it.units) * Number(it.litres_per_pack),
        /* Dated to the note's own issue date, not today. A month's issued
           total is read back from these movements, so a return dated into
           the next month would leave a phantom issue in one month and an
           unexplained return in the next. Cancelling means the stock never
           really left: both halves belong on the day it was raised. */
        occurredOn: issue.issue_date,
        refKind: 'stock_issue', refId: Number(req.params.id),
        notes: 'Dispatch cancelled — stock returned to the processing store',
        createdBy: req.user.id,
      })));
    }

    await client.query(`UPDATE stock_issues SET status='cancelled' WHERE id=$1`, [req.params.id]);
    const updated = await loadIssue(client, req.params.id);
    await client.query('COMMIT');
    res.json(updated);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* A draft never moved stock, so it can be deleted outright. Anything past
   draft has movements pointing at it and is cancelled, not removed. */
router.delete('/:id', requireProduction, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `DELETE FROM stock_issues WHERE id=$1 AND status='draft' RETURNING id`, [req.params.id]
    );
    if (!rows.length) {
      return res.status(409).json({ error: 'Only a draft can be deleted. Cancel the note instead.' });
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
