const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   DEBTORS

   The farm's day book carries a debtor table beside the cash summary,
   and the two tie exactly: the debtors' charges for the day add up to
   the summary's CREDIT SALES line, and their payments add up to its
   RECEIPT line. That is not a coincidence to be reproduced by typing the
   same figure into two places — it is the reason the ledger exists.

   So a credit sale posts a charge here automatically, a payment is
   recorded against a named account, and the cash-up reads both totals
   back. Neither figure can be entered twice, so neither can disagree.

   One running balance per account, following the paper:

     balance = opening + charges - payments

   A balance below zero is not an error: it is a customer in credit, who
   has paid for milk not yet collected. The paper book keeps a separate
   prepaids table for that; one signed ledger says the same thing without
   two places to look.
══════════════════════════════════════════════════════════════ */

async function initDebtorTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS debtors (
      id              SERIAL PRIMARY KEY,
      name            TEXT NOT NULL,
      phone           TEXT,
      /* The branch that usually serves them. Not a restriction — a
         customer known at one shop can pay at another, and the payment
         belongs to whichever till took it. */
      branch_id       INTEGER REFERENCES branches(id) ON DELETE SET NULL,
      /* What was owed before the app started keeping the book. Kept apart
         from the entries so an opening figure carried over from paper is
         never mistaken for something that happened here. */
      opening_balance NUMERIC NOT NULL DEFAULT 0,
      active          BOOLEAN NOT NULL DEFAULT TRUE,
      notes           TEXT,
      created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    /* Names are matched case- and space-insensitively so that ISAMILO,
       Isamilo and " isamilo " are one account. A till that quietly opened
       a second account for the same customer would split their balance in
       half and neither half would be chased. */
    CREATE UNIQUE INDEX IF NOT EXISTS idx_debtors_name
      ON debtors (LOWER(BTRIM(name)));

    /* Signed, like the stock ledger: positive is owed to the farm,
       negative is money received. A balance is one SUM, and there is no
       stored total that can drift from the entries beneath it. */
    CREATE TABLE IF NOT EXISTS debtor_entries (
      id          SERIAL PRIMARY KEY,
      debtor_id   INTEGER NOT NULL REFERENCES debtors(id) ON DELETE CASCADE,
      entry_date  DATE NOT NULL,
      kind        TEXT NOT NULL CHECK (kind IN ('charge','payment','adjustment')),
      amount      NUMERIC NOT NULL,
      branch_id   INTEGER REFERENCES branches(id) ON DELETE SET NULL,
      ref_kind    TEXT,
      ref_id      INTEGER,
      description TEXT,
      created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_debtor_entries_debtor ON debtor_entries(debtor_id, entry_date);
    CREATE INDEX IF NOT EXISTS idx_debtor_entries_date   ON debtor_entries(entry_date);
    CREATE INDEX IF NOT EXISTS idx_debtor_entries_ref    ON debtor_entries(ref_kind, ref_id);

    /* A credit sale names the account it is owed by. Without it the sale
       would be a debt with nobody attached, which is how a paper book
       ends up with a receipts column nobody can reconcile. */
    ALTER TABLE pos_sales
      ADD COLUMN IF NOT EXISTS debtor_id INTEGER REFERENCES debtors(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS idx_pos_sales_debtor ON pos_sales(debtor_id);
  `);
}

module.exports = { initDebtorTables };
