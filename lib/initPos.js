const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   POINT OF SALE

   A branch sells the stock it was issued. The till writes two things: a
   receipt, and the movements that take the packs off the shelf — the same
   ledger everything else reads, so a branch's stock figure is never a
   separate number that has to be kept in step with its sales.

   Two decisions are baked into the shape here:

   Prices are copied onto the line, not referenced. The products table
   holds what the till offers today; a receipt has to keep saying what was
   actually charged when someone reprints it next year, and a price rise
   must not quietly restate last month's takings.

   Which of the two price lists was used is recorded alongside, on the
   line rather than only on the sale. The charged price alone cannot say
   it: 2,000 is the retail price of one pack and the wholesale price of
   another, so without the tier a month's trade cannot be split into
   counter sales and agent sales at all.

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
      /* The list the attendant was working from. Individual lines may
         differ — hence the column on the items too — so this is what the
         sale was rung up as, not a promise about every line. */
      price_tier     TEXT NOT NULL DEFAULT 'retail'
                       CHECK (price_tier IN ('retail','wholesale')),
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
      litres     NUMERIC NOT NULL DEFAULT 0,
      price_tier TEXT NOT NULL DEFAULT 'retail'
                   CHECK (price_tier IN ('retail','wholesale'))
    );
    CREATE INDEX IF NOT EXISTS idx_pos_sale_items_sale ON pos_sale_items(sale_id);

    /* Receipts written before the two price lists existed were all over
       the counter, so retail is the honest default and the columns can be
       added without restating them. */
    ALTER TABLE pos_sales
      ADD COLUMN IF NOT EXISTS price_tier TEXT NOT NULL DEFAULT 'retail';
    ALTER TABLE pos_sale_items
      ADD COLUMN IF NOT EXISTS price_tier TEXT NOT NULL DEFAULT 'retail';

    /* ── the day's cash-up ──────────────────────────────────────

       One per branch per trading day. The figures the till already knows
       are not stored here — they are read back from the receipts, so a
       cash-up can never disagree with the sales behind it. What is stored
       is only what a person has to tell the system: money that came in
       without a sale, money that went out of the drawer, and what was
       actually counted at closing.

       The reconciliation, following the farm's own cash book:

         expected = cash sales + debtor receipts + prepaids - expenses
         variance = counted - expected

       Credit sales never enter it: no money changed hands. Mobile money
       and card are counted separately because they are not in the drawer,
       and a bank deposit is recorded so the day says where the cash went
       as well as how much there was. */
    CREATE TABLE IF NOT EXISTS pos_cash_ups (
      id              SERIAL PRIMARY KEY,
      branch_id       INTEGER NOT NULL REFERENCES branches(id) ON DELETE RESTRICT,
      business_day    DATE NOT NULL,
      status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
      /* Money in that no receipt accounts for. */
      debtor_receipts NUMERIC NOT NULL DEFAULT 0,
      prepaids        NUMERIC NOT NULL DEFAULT 0,
      /* What was actually counted and where it went. */
      counted_cash    NUMERIC NOT NULL DEFAULT 0,
      mobile_counted  NUMERIC NOT NULL DEFAULT 0,
      bank_deposit    NUMERIC NOT NULL DEFAULT 0,
      float_retained  NUMERIC NOT NULL DEFAULT 0,
      notes           TEXT,
      closed_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
      closed_at       TIMESTAMPTZ,
      created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW(),
      /* One per branch per day, enforced rather than assumed: two
         cash-ups for one day would each be reconciled against the whole
         day's sales and both would look wrong. */
      UNIQUE (branch_id, business_day)
    );
    CREATE INDEX IF NOT EXISTS idx_cash_ups_day ON pos_cash_ups(business_day);

    /* Expenses paid out of the drawer, itemised. A single total would
       reconcile just as well and tell nobody what the money went on. */
    CREATE TABLE IF NOT EXISTS pos_cash_up_expenses (
      id          SERIAL PRIMARY KEY,
      cash_up_id  INTEGER NOT NULL REFERENCES pos_cash_ups(id) ON DELETE CASCADE,
      description TEXT NOT NULL,
      amount      NUMERIC NOT NULL CHECK (amount > 0)
    );
    CREATE INDEX IF NOT EXISTS idx_cash_up_expenses ON pos_cash_up_expenses(cash_up_id);
  `);
}

module.exports = { initPosTables };
