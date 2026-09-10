const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   THE STOCK LEDGER

   One table answers "what is on hand": stock_movements, summed. Nothing
   caches a balance, because a cached balance is a second answer that can
   disagree with the first — and when it does, neither can be trusted.

   Every function here takes a `client` so callers can run inside the
   transaction that is also writing the document the movements belong to.
   A dispatch that posted its movements but failed to mark the issue note
   dispatched would take stock out of the store twice on the retry.
══════════════════════════════════════════════════════════════ */

/**
 * On-hand units per product at one location.
 *
 * Every active product comes back, including the ones sitting at zero — a
 * stock sheet with rows silently missing is how a shortage goes unnoticed.
 * Products that are inactive but still holding stock are included too, so
 * retiring a line cannot hide what is left of it.
 */
async function onHand(client, { locationKind = 'processing', branchId = null } = {}) {
  const params = [locationKind];
  let branchFilter = 'AND m.branch_id IS NULL';
  if (locationKind === 'branch') {
    params.push(branchId);
    branchFilter = 'AND m.branch_id = $2';
  }

  const { rows } = await client.query(`
    SELECT p.id AS product_id, p.product, p.size, p.litres_per_pack,
           p.unit_price, p.active, p.sort_order,
           COALESCE(SUM(m.units), 0)  AS units,
           COALESCE(SUM(m.litres), 0) AS litres
    FROM products p
    LEFT JOIN stock_movements m
      ON m.product_id = p.id AND m.location_kind = $1 ${branchFilter}
    GROUP BY p.id
    HAVING p.active OR COALESCE(SUM(m.units), 0) <> 0
    ORDER BY p.sort_order, p.product, p.size
  `, params);

  return rows.map(r => ({
    ...r,
    units:  Number(r.units),
    litres: Number(r.litres),
    litres_per_pack: Number(r.litres_per_pack),
    unit_price: Number(r.unit_price),
  }));
}

/** On-hand units for one product at one location, as a plain number. */
async function onHandFor(client, productId, { locationKind = 'processing', branchId = null } = {}) {
  const { rows } = await client.query(`
    SELECT COALESCE(SUM(units), 0) AS units FROM stock_movements
    WHERE product_id = $1 AND location_kind = $2
      AND (($2 = 'branch' AND branch_id = $3) OR ($2 = 'processing' AND branch_id IS NULL))
  `, [productId, locationKind, branchId]);
  return Number(rows[0].units);
}

/**
 * Write movements.
 *
 * `units` is signed by the caller: positive into the location, negative out
 * of it. Litres follow the same sign, worked out from the pack size rather
 * than passed in, so the two columns cannot describe different quantities.
 */
async function postMovements(client, movements) {
  for (const m of movements) {
    await client.query(`
      INSERT INTO stock_movements
        (location_kind, branch_id, product_id, reason, units, litres,
         occurred_on, ref_kind, ref_id, notes, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    `, [
      m.locationKind, m.branchId ?? null, m.productId, m.reason,
      m.units, m.litres ?? 0, m.occurredOn,
      m.refKind ?? null, m.refId ?? null, m.notes ?? null, m.createdBy ?? null,
    ]);
  }
}

/**
 * Stock that has left the processing store but no branch has confirmed.
 *
 * It belongs to neither balance while it is on the road, so it is reported
 * on its own rather than folded into one of them.
 */
async function inTransit(client = pool, branchId = null) {
  const params = [];
  let filter = '';
  if (branchId) { params.push(branchId); filter = 'AND si.branch_id = $1'; }

  const { rows } = await client.query(`
    SELECT p.id AS product_id, p.product, p.size,
           SUM(it.units) AS units
    FROM stock_issues si
    JOIN stock_issue_items it ON it.issue_id = si.id
    JOIN products p ON p.id = it.product_id
    WHERE si.status = 'dispatched' ${filter}
    GROUP BY p.id
    ORDER BY p.sort_order
  `, params);

  return rows.map(r => ({ ...r, units: Number(r.units) }));
}

module.exports = { onHand, onHandFor, postMovements, inTransit };
