const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   THE SALES BOOK

   What the farm sold before the sales people ring it up in the app: the
   sales day book, read in from its workbook (see salesWorkbook.js).

   It is kept apart from the till on purpose. A till receipt knows its
   branch, its products, its customer and how it was paid, and it moved
   stock when it was rung up. A line of the sales book knows a day, a
   unit and an amount. Making receipts out of these would invent the
   rest, and move stock that has already moved — so they stay a book of
   their own, and the Sales page shows the two side by side.

   One line per unit per day. The months before the daily sheets start
   exist only as a figure per unit for the whole month: those lines are
   dated to the 1st and marked `whole_month`, so nothing reads them as
   the takings of one day.

   Every line belongs to the upload it came from, and a month is replaced
   as a unit: the workbook is kept as one growing file, so September's
   copy carries June again, and uploading it must not count June twice.
══════════════════════════════════════════════════════════════ */

async function initSalesBookTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sales_book_imports (
      id          SERIAL PRIMARY KEY,
      filename    TEXT,
      sheets      TEXT,
      uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      uploaded_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sales_book_entries (
      id          SERIAL PRIMARY KEY,
      import_id   INTEGER NOT NULL REFERENCES sales_book_imports(id) ON DELETE CASCADE,
      entry_date  DATE NOT NULL,
      unit        TEXT NOT NULL,
      unit_kind   TEXT NOT NULL DEFAULT 'bulk' CHECK (unit_kind IN ('shop', 'seller', 'bulk')),
      amount      NUMERIC NOT NULL,
      whole_month BOOLEAN NOT NULL DEFAULT FALSE,
      /* "JUNE SALES BY UNITY!C7" — so a figure somebody queries can be
         traced to the cell it came out of. */
      source_ref  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sales_book_date   ON sales_book_entries(entry_date);
    CREATE INDEX IF NOT EXISTS idx_sales_book_import ON sales_book_entries(import_id);

    /* Litres were briefly read from the day books into this table. They
       come from the UNIT SOLD workbook now (below), and nothing in it
       was ever more than a copy of a sheet that can be uploaded again. */
    DROP TABLE IF EXISTS sales_book_items;

    /* ── UNITS SOLD ──
       The farm's UNIT SOLD workbook: on each day, how many litres of
       fresh milk went to each outlet, and how many of each processed
       pack were sold in all. Kept beside the sales book, not in it — it
       is litres, not shillings, and processed milk is the farm's total
       for the day rather than anyone's sales.

       unit links an outlet to the same buyer in the sales book where
       there is one, so M9's litres and M9's takings can be read
       together. units is worked out from the pack size on the way in;
       the litres are what the sheet says. */
    CREATE TABLE IF NOT EXISTS units_sold_imports (
      id          SERIAL PRIMARY KEY,
      filename    TEXT,
      sheets      TEXT,
      uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      uploaded_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS units_sold_lines (
      id              SERIAL PRIMARY KEY,
      import_id       INTEGER NOT NULL REFERENCES units_sold_imports(id) ON DELETE CASCADE,
      entry_date      DATE NOT NULL,
      section         TEXT NOT NULL CHECK (section IN ('fresh', 'processed')),
      item            TEXT NOT NULL,
      pack            TEXT,
      unit            TEXT,
      litres          NUMERIC NOT NULL,
      units           NUMERIC,
      litres_per_pack NUMERIC,
      source_ref      TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_units_sold_date   ON units_sold_lines(entry_date);
    CREATE INDEX IF NOT EXISTS idx_units_sold_unit   ON units_sold_lines(unit, entry_date);
    CREATE INDEX IF NOT EXISTS idx_units_sold_import ON units_sold_lines(import_id);
  `);
}

module.exports = { initSalesBookTables };
