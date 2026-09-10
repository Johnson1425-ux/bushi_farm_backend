const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   POINT OF SALE

   A branch sells the stock it was issued. The till writes two things: a
   receipt, and the movements that take the packs off the shelf — the same
   ledger everything else reads, so a branch's stock figure is never a
   separate number that has to be kept in step with its sales.

   Two decisions are baked into the shape here:

   Prices are copied onto the line, not referenced. products.unit_price is
   what the till offers today; a receipt has to keep saying what was
   actually charged when someone reprints it next year, and a price rise
   must not quietly restate last month's takings.

   A sale is never deleted. Cash was taken and packs left the shelf, and
   both facts survive the mistake that a void corrects — the sale is
   marked voided and reversing movements put the stock back, so the day's
   takings and the day's stock still explain each other.
══════════════════════════════════════════════════════════════ */

async function initPosTables() {
  await pool.query(`
    /* Receipt numbers come from a sequence: two tills ringing up at the
       same moment must not both decide they are number 40. */
    CREATE SEQUENCE IF NOT EXISTS pos_receipt_no_seq;

    CREATE TABLE IF NOT EXISTS pos_sales (
      id             SERIAL PRIMARY KEY,
      receipt_no     TEXT NOT NULL UNIQUE,
      branch_id      INTEGER NOT NULL REFERENCES branches(id) ON DELETE RESTRICT,
      /* The trading day, kept apart from the timestamp. A till reconciled
         at closing time needs "which day's takings is this", and a sale
         rung up at 00:10 belongs to the day the attendant says it does. */
      sold_on        DATE NOT NULL,
      sold_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      cashier_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
      customer_name  TEXT,
      payment_method TEXT NOT NULL DEFAULT 'cash'
                       CHECK (payment_method IN ('cash','mobile','card','credit')),
      subtotal       NUMERIC NOT NULL DEFAULT 0,
      discount       NUMERIC NOT NULL DEFAULT 0,
      total          NUMERIC NOT NULL DEFAULT 0,
      status         TEXT NOT NULL DEFAULT 'completed'
                       CHECK (status IN ('completed','voided')),
      voided_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
      voided_at      TIMESTAMPTZ,
      void_reason    TEXT,
      notes          TEXT,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_pos_sales_branch ON pos_sales(branch_id, sold_on);
    CREATE INDEX IF NOT EXISTS idx_pos_sales_day    ON pos_sales(sold_on);

    /* unit_price and line_total are the price charged, frozen at the sale.
       litres is carried so a day's takings can be read in litres as well as
       shillings without re-deriving it from the pack size every time. */
    CREATE TABLE IF NOT EXISTS pos_sale_items (
      id         SERIAL PRIMARY KEY,
      sale_id    INTEGER NOT NULL REFERENCES pos_sales(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      units      NUMERIC NOT NULL CHECK (units > 0),
      unit_price NUMERIC NOT NULL,
      line_total NUMERIC NOT NULL,
      litres     NUMERIC NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_pos_sale_items_sale ON pos_sale_items(sale_id);
  `);
}

module.exports = { initPosTables };
