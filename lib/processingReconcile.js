const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   RECONCILING A MONTH

   The workbook and the app each own half of a month's figures, and the
   split is not arbitrary — it follows who knows the answer:

     from the sheet    opening balance, milk received, packs made,
                       packs written off before they left the store
     from the ledger   packs issued, because they went to a named branch
                       on a named day and only the app was told which

   The sheet's own ISSUED block is no longer read at all. It recorded a
   single figure with no destination, and keeping it would mean a month
   had two answers to "how much went out" with nothing to say which was
   right.

   So closing stock cannot be computed at upload time any more: issuing
   carries on after the workbook is filed. It is worked out here, on
   every read, from the sheet's stored components and the ledger as it
   stands now.
══════════════════════════════════════════════════════════════ */

/** First and last day of an upload's month, or null if it is not dated. */
function monthRange(upload) {
  if (!upload?.month_num || !upload?.year) return null;
  return {
    from: new Date(Date.UTC(upload.year, upload.month_num - 1, 1)).toISOString().slice(0, 10),
    to:   new Date(Date.UTC(upload.year, upload.month_num, 0)).toISOString().slice(0, 10),
  };
}

/**
 * Packs issued out of the processing store during a month, by day.
 *
 * Returns rows shaped like the daily tables it replaces — day, product,
 * size, units, litres — so everything downstream reads issuing the same
 * way it always did.
 *
 * A cancelled dispatch nets itself out: the movements it posts are dated to
 * the original issue date, so the month shows stock leaving and coming
 * straight back rather than a phantom issue in one month and a return in
 * the next.
 */
async function ledgerIssuedDaily(client, upload) {
  const range = monthRange(upload);
  if (!range) return [];

  const { rows } = await client.query(`
    SELECT EXTRACT(DAY FROM m.occurred_on)::int AS day,
           p.product, p.size,
           SUM(-m.units)  AS units,
           SUM(-m.litres) AS litres
    FROM stock_movements m
    JOIN products p ON p.id = m.product_id
    WHERE m.location_kind = 'processing'
      AND m.reason IN ('issue_out', 'returned')
      AND m.occurred_on BETWEEN $1 AND $2
    GROUP BY 1, p.product, p.size, p.sort_order
    HAVING SUM(-m.units) <> 0
    ORDER BY 1, p.sort_order
  `, [range.from, range.to]);

  return rows.map(r => ({ ...r, units: Number(r.units), litres: Number(r.litres) }));
}

/**
 * Stock rows with issuing folded in.
 *
 * `stockRows` are the sheet's own components as stored at upload time:
 * opening, packed and damaged. `units` on those rows is what the sheet
 * accounts for — opening + packed − damaged — and is deliberately NOT the
 * closing balance, because the sheet has nothing to say about issuing.
 *
 * Closing is that figure less what the ledger issued, and a line that
 * closes below zero is flagged: more was issued or written off than was
 * ever made, which is a counting error rather than negative stock.
 */
function applyIssued(stockRows, issuedDaily, { litresFor } = {}) {
  const key = (product, size) => `${product}|${size}`;
  const issuedBy = new Map();
  for (const r of issuedDaily) {
    const k = key(r.product, r.size);
    issuedBy.set(k, (issuedBy.get(k) || 0) + r.units);
  }

  const rows = stockRows.map(s => {
    const available = Number(s.units);
    const issued    = issuedBy.get(key(s.product, s.size)) || 0;
    const closing   = available - issued;
    const perPack   = Number(s.litres) && available ? Number(s.litres) / available : null;
    return {
      ...s,
      issued_units: issued,
      units:  closing,
      litres: perPack != null ? Math.round(closing * perPack * 1000) / 1000
            : litresFor ? litresFor(s.size, closing) : Number(s.litres),
    };
  });

  /* A product issued this month that the sheet never mentioned still has to
     appear, or the month silently under-reports what left the store. */
  const known = new Set(stockRows.map(s => key(s.product, s.size)));
  for (const [k, issued] of issuedBy) {
    if (known.has(k)) continue;
    const [product, size] = k.split('|');
    rows.push({
      product, size,
      opening_units: 0, packed_units: 0, damaged_units: 0,
      issued_units: issued,
      units: -issued,
      litres: litresFor ? litresFor(size, -issued) : 0,
    });
  }

  return rows;
}

/** Everything a month's reconciliation needs, in one call. */
async function reconcileUpload(upload, stockRows, opts = {}) {
  const client = opts.client || pool;
  const issued = await ledgerIssuedDaily(client, upload);
  return { issued, stock: applyIssued(stockRows, issued, opts) };
}

module.exports = { monthRange, ledgerIssuedDaily, applyIssued, reconcileUpload };
