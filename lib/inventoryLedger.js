/* ══════════════════════════════════════════════════════════════
   THE INVENTORY LEDGER

   Everything the production and processing unit consumes but does not
   sell — packaging bottles, caps, labels, crates, cultures, CIP chemicals,
   machine spares, PPE — lives here.

   The rule is the same one the finished-goods ledger (lib/stockLedger.js)
   already follows: `inventory_logs` summed IS the balance. Nothing caches
   it. A cached balance is a second answer that can disagree with the
   first, and when it does neither can be trusted — which is exactly what
   the unused `inventory_items.current_stock` column was, sitting at zero
   on every row while the page showed something else entirely.

   What changed beyond that: stock used to have only two things it could
   do — come IN or go OUT. So a crate of bottles broken in the packing hall
   was filed as "out", indistinguishable from bottles that actually left
   with product, and the one number the store most needs to watch — how
   much is being lost rather than used — could not be recovered from the
   records at all.

   Five movements say what really happened:

     in      received from a supplier                              (+)
     return  unused stock handed back to the store from the floor  (+)
     out     issued to production                                  (−)
     damage  broken, spoiled or expired — written off              (−)
     adjust  a stock count correcting the book to the shelf        (±)

   `adjust` is the only signed one: its quantity carries the direction
   because a count can go either way, and it is written by posting a stock
   count rather than typed by hand, so the variance always has a document
   behind it.
══════════════════════════════════════════════════════════════ */

/** Every movement type, in the order a stock card reads. */
const TYPES = ['in', 'return', 'out', 'damage', 'adjust'];

/** Movements that reduce what is on the shelf. */
const OUTWARD = ['out', 'damage'];

/**
 * One movement's effect on the balance, as SQL.
 *
 * Written once and used by every query that sums the ledger — here, the
 * alerts route and the AI context — because three hand-rolled copies of
 * this CASE is how "out" and "damage" end up counted differently in two
 * places. `alias` is the table alias the logs are joined under.
 */
const signedQty = (alias = 'l') =>
  `CASE WHEN ${alias}.type IN ('out','damage') THEN -${alias}.quantity ELSE ${alias}.quantity END`;

/** Sum of one movement type over a set of rows, as SQL. */
const totalOf = (type, alias = 'l') =>
  `COALESCE(SUM(CASE WHEN ${alias}.type = '${type}' THEN ${alias}.quantity ELSE 0 END), 0)`;

/** The running balance over a set of rows, as SQL. */
const balance = (alias = 'l') => `COALESCE(SUM(${signedQty(alias)}), 0)`;

/**
 * The stock-card columns every listing and report shares.
 *
 * Received, returned, issued, damaged, adjusted and the balance they
 * produce — so a row always adds up in front of whoever is reading it,
 * and "where did the other forty bottles go" is answered by the row
 * itself rather than by opening the movement log.
 */
const CARD_COLUMNS = (alias = 'l') => `
  ${totalOf('in', alias)}     AS total_in,
  ${totalOf('return', alias)} AS total_returned,
  ${totalOf('out', alias)}    AS total_out,
  ${totalOf('damage', alias)} AS total_damaged,
  COALESCE(SUM(CASE WHEN ${alias}.type = 'adjust' THEN ${alias}.quantity ELSE 0 END), 0) AS total_adjusted,
  ${balance(alias)} AS current_stock
`;

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

/**
 * What one item has on hand right now, as a plain number.
 *
 * Takes a `client` so a caller can read the balance inside the same
 * transaction that is about to write against it. Issuing out 200 bottles
 * from a shelf holding 150 used to succeed and leave the balance at −50;
 * the check that stops it has to see the same rows the insert will join.
 */
async function onHandFor(client, itemId) {
  const { rows } = await client.query(
    `SELECT ${balance('l')} AS qty FROM inventory_logs l WHERE l.item_id = $1`,
    [itemId]
  );
  return num(rows[0]?.qty);
}

/**
 * Would this movement take the item below zero?
 *
 * Returns an explaining message, or null when the movement is fine. Stock
 * that cannot go negative is the whole point of keeping the book: a
 * negative balance is not a shortage, it is a record that stopped being
 * true at some earlier point nobody can now identify.
 */
function shortfallMessage({ type, quantity, onHand, name, unit }) {
  if (!OUTWARD.includes(type)) return null;
  const qty = num(quantity);
  if (qty <= onHand) return null;
  return `${name} has only ${onHand} ${unit} on hand — cannot take out ${qty}. `
       + 'Record the delivery that brought it in first, or post a stock count if the book is wrong.';
}

/**
 * Where an item stands against its reorder level.
 *
 *   out    nothing left
 *   low    at or below the level the store reorders at
 *   ok     enough
 *
 * An item with no reorder level set is never "low" — it would cry wolf on
 * every row from the day it was added, and an alert nobody can act on is
 * an alert everybody learns to ignore.
 */
function stockState(currentStock, reorderLevel) {
  const qty   = num(currentStock);
  const level = num(reorderLevel);
  if (qty <= 0) return 'out';
  if (level > 0 && qty <= level) return 'low';
  return 'ok';
}

module.exports = {
  TYPES, OUTWARD,
  signedQty, totalOf, balance, CARD_COLUMNS,
  onHandFor, shortfallMessage, stockState, num,
};
