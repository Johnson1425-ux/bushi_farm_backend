const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   CUSTOMERS, AND THE ONES WHO OWE

   Every named buyer gets an account, whether they pay cash or not. A
   debtor is not a different kind of record — it is a customer whose
   balance happens to be above zero today, and who stops being one the
   moment they settle up. Two tables would have meant deciding at the
   till which sort of person was standing there, and moving them across
   when that turned out to be wrong.

   So the table is customers, and "debtors" is a view of it. What a
   customer's account carries is their whole trade with the farm: what
   they have spent across every shop, and what is still outstanding.

   The farm's day book keeps a debtor table beside the cash summary, and
   the two tie exactly: the day's charges add up to CREDIT SALES, the
   day's payments add up to RECEIPT. That is not a coincidence to be
   reproduced by typing the same figure into two places — it is the
   reason the ledger exists. A credit sale posts its charge here
   automatically, a payment is recorded against the account, and the
   cash-up reads both totals back.

   One running balance per account, following the paper:

     balance = opening + charges - payments

   A balance below zero is not an error: it is a customer in credit, who
   has paid for milk not yet collected. The paper book keeps a separate
   prepaids table for that; one signed ledger says the same thing without
   two places to look.
══════════════════════════════════════════════════════════════ */

async function initCustomerTables() {
  await pool.query(`
    /* These started life as "debtors", back when an account was only
       opened for someone who owed money. Now every named buyer has one
       and owing is a state rather than a category, so the tables are
       renamed to say what they hold. Guarded both ways so it runs once
       and never on a database that was created after the change. */
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.tables
                 WHERE table_name = 'debtors')
         AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                         WHERE table_name = 'customers')
      THEN
        ALTER TABLE debtors RENAME TO customers;
      END IF;

      IF EXISTS (SELECT 1 FROM information_schema.tables
                 WHERE table_name = 'debtor_entries')
         AND NOT EXISTS (SELECT 1 FROM information_schema.tables
                         WHERE table_name = 'customer_entries')
      THEN
        ALTER TABLE debtor_entries RENAME TO customer_entries;
      END IF;

      IF EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name = 'customer_entries' AND column_name = 'debtor_id')
      THEN
        ALTER TABLE customer_entries RENAME COLUMN debtor_id TO customer_id;
      END IF;

      IF EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name = 'pos_sales' AND column_name = 'debtor_id')
         AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                         WHERE table_name = 'pos_sales' AND column_name = 'customer_id')
      THEN
        ALTER TABLE pos_sales RENAME COLUMN debtor_id TO customer_id;
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS customers (
      id              SERIAL PRIMARY KEY,
      name            TEXT NOT NULL,
      phone           TEXT,
      /* The branch that usually serves them. Not a restriction — a
         customer known at one shop can buy or pay at another, and the
         sale belongs to whichever till took it. */
      branch_id       INTEGER REFERENCES branches(id) ON DELETE SET NULL,
      /* What was owed before the app started keeping the book. Kept
         apart from the entries so an opening figure carried over from
         paper is never mistaken for something that happened here. */
      opening_balance NUMERIC NOT NULL DEFAULT 0,
      active          BOOLEAN NOT NULL DEFAULT TRUE,
      notes           TEXT,
      created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    /* Names are matched case- and space-insensitively so that ISAMILO,
       Isamilo and " isamilo " are one account. A till that quietly
       opened a second for the same customer would split their trade in
       half — and if they owed money, neither half would be chased. */
    CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_name
      ON customers (LOWER(BTRIM(name)));

    /* Signed, like the stock ledger: positive is owed to the farm,
       negative is money received. A balance is one SUM, and there is no
       stored total that can drift from the entries beneath it. */
    CREATE TABLE IF NOT EXISTS customer_entries (
      id          SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
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
    CREATE INDEX IF NOT EXISTS idx_customer_entries_customer ON customer_entries(customer_id, entry_date);
    CREATE INDEX IF NOT EXISTS idx_customer_entries_date     ON customer_entries(entry_date);
    CREATE INDEX IF NOT EXISTS idx_customer_entries_ref      ON customer_entries(ref_kind, ref_id);

    /* Any sale may name its customer, not only a credit one. That is
       what makes an account worth opening for someone who always pays
       cash: without it the farm knows what it sold and not who to. A
       credit sale additionally posts a charge, because then there is
       also a debt, and a debt with nobody attached to it is how a book
       ends up with a receipts column nobody can reconcile. */
    ALTER TABLE pos_sales
      ADD COLUMN IF NOT EXISTS customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS idx_pos_sales_customer ON pos_sales(customer_id);
  `);
}

module.exports = { initCustomerTables };
