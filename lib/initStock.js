const { pool } = require('../db');
const { PRODUCT_ROWS, litresFor } = require('../processingCatalog');

/* ══════════════════════════════════════════════════════════════
   BRANCH DISTRIBUTION SCHEMA

   The monthly workbook records what the processing unit made and one
   unified "issued" figure — a number with no destination attached. That
   is enough to reconcile a month after the fact, and useless for running
   a branch: it cannot say what any branch holds today, so nothing can be
   sold against it.

   These tables move stock from a monthly snapshot to a running balance:

     branches           where stock can live besides the processing store
     products           the catalogue, given database identity so issue
                        lines and (later) till receipts can reference a row
                        rather than re-matching two free-text strings
     stock_movements    every pack that moves, signed, one row per event
     stock_issues       an issue note: the paperwork that goes with a
       + _items         dispatch, and what the branch confirms receiving

   stock_movements is the single source of truth for on-hand stock. Units
   are signed — positive into a location, negative out of it — so a
   balance is one SUM and never needs a stored total that can drift from
   the events beneath it. `reason` says why the stock moved; `ref_kind`
   and `ref_id` point back at the document that caused it.
══════════════════════════════════════════════════════════════ */

async function initStockTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS branches (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL UNIQUE,
      code       TEXT UNIQUE,
      location   TEXT,
      phone      TEXT,
      active     BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    /* One row per product/pack size the unit sells.

       litres_per_pack is copied from the catalogue rather than looked up
       at read time: a pack size that is later redefined must not silently
       restate litres on issue notes that were already signed for.

       Two selling prices, because the farm has always had two. The shops
       sell a 150ML vanilla at 1,000 over the counter; the agents who take
       a crate at a time pay 800 for the same pack. They are separate
       columns rather than one price and a discount, because the discount
       would have to be re-derived on every line and would say nothing
       about which trade it was.

       Both are defaults the till reads. A price agreed for one sale
       belongs on that sale, not on the product. */
    CREATE TABLE IF NOT EXISTS products (
      id              SERIAL PRIMARY KEY,
      product         TEXT NOT NULL,
      size            TEXT NOT NULL,
      litres_per_pack NUMERIC NOT NULL DEFAULT 0,
      retail_price    NUMERIC NOT NULL DEFAULT 0,
      wholesale_price NUMERIC NOT NULL DEFAULT 0,
      active          BOOLEAN NOT NULL DEFAULT TRUE,
      sort_order      INTEGER NOT NULL DEFAULT 0,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (product, size)
    );

    /* Databases created before wholesale existed carry a single
       unit_price. It was the over-the-counter price, so it becomes the
       retail one; wholesale starts unset and the farm fills it in. */
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name = 'products' AND column_name = 'unit_price')
         AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                         WHERE table_name = 'products' AND column_name = 'retail_price')
      THEN
        ALTER TABLE products RENAME COLUMN unit_price TO retail_price;
      END IF;
    END $$;
    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS retail_price    NUMERIC NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS wholesale_price NUMERIC NOT NULL DEFAULT 0;

    /* How a line is measured.

       'pack' is a sealed unit — a 1L bottle, a 500ml cup — and quantities
       are whole numbers. 'litre' is milk sold loose from the churn, where
       217.5 is an ordinary quantity and litres_per_pack is 1, so a "unit"
       in the ledger simply is a litre.

       Bulk milk being an ordinary product rather than a parallel system
       is the whole point: it is issued to a branch, sold at the till,
       counted in the cash-up and reported beside everything else, with no
       second set of rules to keep in step. */
    ALTER TABLE products
      ADD COLUMN IF NOT EXISTS sold_by TEXT NOT NULL DEFAULT 'pack';
    ALTER TABLE products DROP CONSTRAINT IF EXISTS products_sold_by_check;
    UPDATE products SET sold_by = 'pack' WHERE sold_by NOT IN ('pack','litre');
    ALTER TABLE products ADD CONSTRAINT products_sold_by_check
      CHECK (sold_by IN ('pack','litre'));

    CREATE TABLE IF NOT EXISTS stock_movements (
      id            SERIAL PRIMARY KEY,
      location_kind TEXT NOT NULL CHECK (location_kind IN ('processing','branch')),
      branch_id     INTEGER REFERENCES branches(id) ON DELETE CASCADE,
      product_id    INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      reason        TEXT NOT NULL CHECK (reason IN
                      ('opening','packed','damaged','issue_out','issue_in',
                       'returned','sold','adjustment')),
      units         NUMERIC NOT NULL,
      litres        NUMERIC NOT NULL DEFAULT 0,
      occurred_on   DATE NOT NULL,
      ref_kind      TEXT,
      ref_id        INTEGER,
      notes         TEXT,
      created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      /* A branch movement names its branch; a processing-store movement
         cannot, or the same row would count in two places. */
      CONSTRAINT stock_movements_location CHECK (
        (location_kind = 'branch'     AND branch_id IS NOT NULL) OR
        (location_kind = 'processing' AND branch_id IS NULL)
      )
    );
    CREATE INDEX IF NOT EXISTS idx_stock_mv_location
      ON stock_movements(location_kind, branch_id, product_id);
    CREATE INDEX IF NOT EXISTS idx_stock_mv_date ON stock_movements(occurred_on);
    CREATE INDEX IF NOT EXISTS idx_stock_mv_ref  ON stock_movements(ref_kind, ref_id);

    /* Issue numbers come from a sequence rather than a count of existing
       rows: two dispatches raised in the same second must not both work out
       that they are number 15. */
    CREATE SEQUENCE IF NOT EXISTS stock_issue_no_seq;

    /* An issue note is dispatched by the processing unit and confirmed by
       the branch, so the two sides are recorded separately. Between the
       two the stock is in transit: out of the store, not yet on a shelf,
       and visible as neither side's balance — which is the point. */
    CREATE TABLE IF NOT EXISTS stock_issues (
      id          SERIAL PRIMARY KEY,
      issue_no    TEXT NOT NULL UNIQUE,
      branch_id   INTEGER NOT NULL REFERENCES branches(id) ON DELETE RESTRICT,
      issue_date  DATE NOT NULL,
      status      TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft','dispatched','received','cancelled')),
      issued_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
      dispatched_at TIMESTAMPTZ,
      received_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      received_at TIMESTAMPTZ,
      notes       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_stock_issues_branch ON stock_issues(branch_id);
    CREATE INDEX IF NOT EXISTS idx_stock_issues_date   ON stock_issues(issue_date);

    /* received_units is null until the branch confirms. It is stored even
       when it equals units, so "confirmed identical" and "not yet counted"
       stay distinguishable. */
    CREATE TABLE IF NOT EXISTS stock_issue_items (
      id             SERIAL PRIMARY KEY,
      issue_id       INTEGER NOT NULL REFERENCES stock_issues(id) ON DELETE CASCADE,
      product_id     INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
      units          NUMERIC NOT NULL CHECK (units > 0),
      litres         NUMERIC NOT NULL DEFAULT 0,
      received_units NUMERIC,
      UNIQUE (issue_id, product_id)
    );
    CREATE INDEX IF NOT EXISTS idx_stock_issue_items_issue ON stock_issue_items(issue_id);

    /* An attendant works one branch. The column is on users rather than a
       join table because the till needs exactly one answer to "which
       branch is this sale from" and a second row would make that
       ambiguous. Managers and admins leave it null. */
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS branch_id INTEGER REFERENCES branches(id) ON DELETE SET NULL;
  `);

  await seedProducts();
}

/* Bring the catalogue into the database.

   processingCatalog.js stays the definition of what the unit makes — it is
   what the parser and the template generator read. This copies it into a
   table so that issue lines can hold a foreign key instead of a pair of
   strings, and adds nothing of its own.

   Existing rows are left alone apart from their sort order: prices are set
   by the farm, and re-running the seed must never reset one. */
async function seedProducts() {
  for (const [i, row] of PRODUCT_ROWS.entries()) {
    await pool.query(
      `INSERT INTO products (product, size, litres_per_pack, sort_order)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (product, size) DO UPDATE SET sort_order = EXCLUDED.sort_order`,
      [row.product, row.size, litresFor(row.size, 1), i]
    );
  }
}

module.exports = { initStockTables, seedProducts };
