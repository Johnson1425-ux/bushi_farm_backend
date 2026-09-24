const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   RECONCILING A MONTH

   The workbook and the app each own half of a month's figures, and the
   split is not arbitrary — it follows who knows the answer:

     from the sheet    opening balance, milk received, packs made,
                       packs written off before they left the store
     from the ledger   packs issued, because they went to a named branch
                       on a named day and only the app was told which

   Issuing is the half that changed hands. It used to be a column on the
   sheet — one figure with no destination on it — and is now an issue note
   naming the branch that took the stock.

   The sheet decides which of the two a month uses. While its ISSUED
   column is still being filled in, that column is the month's answer;
   the month the farm stops filling it in, the app's issue notes become
   the answer instead.

   It reads backwards until you see what the alternative does. Stock has
   to reach a branch before a till can sell it, so issue notes get raised
   as soon as the shops go live — long before anyone stops writing issuing
   down on the sheet. Letting the ledger win on sight would take a month
   still being kept by hand and show a fraction of what really went out,
   and the changeover would happen as a side effect of setting up a shop
   rather than when the farm decided it should.

   Handing the decision to the sheet makes the switch deliberate: upload a
   month with the column left empty, and that month is the app's from then
   on. Nothing else has to change.

   The two are never added together. A month that has both is the farm in
   transition, and the figure not in use is reported alongside rather than
   folded in, so a disagreement is visible instead of silently doubling
   the total.

   So closing stock cannot be computed at upload time: issuing carries on
   after the workbook is filed. It is worked out here, on every read.
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

/**
 * The sheet's own ISSUED figures for an upload, shaped like the ledger's.
 *
 * Rows with nothing in them are left out, so an ISSUED block that exists
 * but was never filled counts as no answer — which is what lets a month be
 * handed to the app by uploading it with the column empty, without anyone
 * having to delete the block from the workbook.
 */
async function workbookIssuedDaily(client, uploadId) {
  const { rows } = await client.query(`
    SELECT day, product, size, units, litres
    FROM processing_issued WHERE upload_id = $1 AND units <> 0
    ORDER BY day, product, size
  `, [uploadId]);
  return rows.map(r => ({ ...r, units: Number(r.units), litres: Number(r.litres) }));
}

/**
 * A month's issuing, from whichever record has it.
 *
 * Every reader goes through here — the processing page, the AI context,
 * the alert signals — so none of them can end up with a different idea of
 * where a month's figures come from.
 */
async function issuedForUpload(client, upload) {
  const sheet  = await workbookIssuedDaily(client, upload.id);
  const ledger = sheet.length ? [] : await ledgerIssuedDaily(client, upload);
  const useLedger = sheet.length === 0;
  return { issued: useLedger ? ledger : sheet, useLedger, ledger, sheet };
}

/**
 * Everything a month's reconciliation needs, in one call.
 *
 * `issued_source` says which record the figures came from, because a
 * screen showing an issued total is useless if the reader cannot tell
 * whether it is what the app dispatched or what someone typed on the
 * sheet.
 */
async function reconcileUpload(upload, stockRows, opts = {}) {
  const client = opts.client || pool;

  /* Both records are read here, unlike issuedForUpload which stops as soon
     as the ledger answers: this is the one caller that reports on the
     comparison, so it needs the figure it is not using. */
  const [ledger, sheet] = await Promise.all([
    ledgerIssuedDaily(client, upload),
    workbookIssuedDaily(client, upload.id),
  ]);
  const total = (rows) => Math.round(rows.reduce((a, r) => a + r.units, 0) * 1000) / 1000;

  const useLedger = sheet.length === 0;
  const issued = useLedger ? ledger : sheet;

  return {
    issued,
    stock: applyIssued(stockRows, issued, opts),
    issued_source: sheet.length ? 'workbook' : ledger.length ? 'ledger' : 'none',
    ledger_units:   total(ledger),
    workbook_units: total(sheet),
    /* Both records have something for this month — the farm is issuing on
       the sheet and moving stock to branches in the app at the same time.
       The sheet is in use; the ledger's total is reported so the gap can
       be looked at rather than guessed at. */
    both_present: sheet.length > 0 && ledger.length > 0,
  };
}

module.exports = {
  monthRange, ledgerIssuedDaily, workbookIssuedDaily, issuedForUpload,
  applyIssued, reconcileUpload,
};
