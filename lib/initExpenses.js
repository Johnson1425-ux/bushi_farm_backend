const { pool } = require('../db');
const { CATEGORIES } = require('./expenseCatalog');

/* ══════════════════════════════════════════════════════════════
   WHAT THE FARM SPENDS

   The expenses workbook is three sheets of arithmetic sitting on top of
   one list. Underneath the SUMMARY grid and the YEAR comparison there is
   nothing but lines — a date, what it was for, how many, at what price,
   how much — filed under a dozen headings.

   So that list is the table, and everything above it is a query. A
   month's total for a category is a SUM; the summary grid is that SUM
   grouped by month; the year sheet is the same grouped by year. None of
   them is stored, because a stored total is a number that can disagree
   with the rows it came from — and in a book kept by hand that is
   exactly what goes wrong: the detail sheet is corrected and the summary
   column is not.

   Two things are stored beside the entry itself:

     • the category, from a fixed list (see expenseCatalog.js), because
       free text would split a line in two spellings and take money out
       of the month without anyone noticing;

     • where the entry came from — typed into the app, or read out of a
       month's workbook. An import can then be undone as a unit, and
       re-importing a month cannot double it.
══════════════════════════════════════════════════════════════ */

async function initExpenseTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS expense_categories (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL,
      /* The summary's own order. The grid reads top to bottom the way
         the paper does, rather than alphabetically. */
      sort_order INTEGER NOT NULL DEFAULT 100,
      active     BOOLEAN NOT NULL DEFAULT TRUE,
      notes      TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    /* Same rule as customers: one line per heading, whatever the case or
       spacing it was typed in. */
    CREATE UNIQUE INDEX IF NOT EXISTS idx_expense_categories_name
      ON expense_categories (LOWER(BTRIM(name)));

    /* One row per workbook read in, so a month can be replaced or undone
       as a unit. The label is how the farm names the month — "SEPTEMBER
       2026" — and it is unique, because importing the same month twice
       must replace it rather than add it again. */
    CREATE TABLE IF NOT EXISTS expense_imports (
      id          SERIAL PRIMARY KEY,
      label       TEXT NOT NULL,
      month_num   INTEGER NOT NULL CHECK (month_num BETWEEN 1 AND 12),
      year        INTEGER NOT NULL,
      filename    TEXT,
      sheets      TEXT,
      entry_count INTEGER NOT NULL DEFAULT 0,
      total       NUMERIC NOT NULL DEFAULT 0,
      uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      uploaded_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_expense_imports_month
      ON expense_imports (year, month_num);

    /* The line itself.

       quantity and unit_price are what the sheet calls UNITY and PRICE —
       kept because "6,580 kg of machicha at 80.84" says something that
       "531,927" does not. amount is stored rather than multiplied on
       read: a hand-kept sheet sometimes rounds it, or fills it in with
       no quantity at all, and the figure the farm wrote down is the one
       that has to add up to the month.

       An entry typed into the app has no import_id. One read out of a
       workbook carries it, and goes when that import goes. */
    CREATE TABLE IF NOT EXISTS expenses (
      id          SERIAL PRIMARY KEY,
      entry_date  DATE NOT NULL,
      category_id INTEGER NOT NULL REFERENCES expense_categories(id) ON DELETE RESTRICT,
      details     TEXT NOT NULL,
      quantity    NUMERIC,
      unit_price  NUMERIC,
      amount      NUMERIC NOT NULL,
      source      TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'import')),
      import_id   INTEGER REFERENCES expense_imports(id) ON DELETE CASCADE,
      /* Where in the workbook it was read from — "BMH!G56" — so a figure
         somebody queries can be traced back to the cell it came out of
         rather than argued about. Empty for anything typed into the app,
         which already carries who typed it and when. */
      source_ref  TEXT,
      notes       TEXT,
      created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_expenses_date     ON expenses(entry_date);
    CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category_id, entry_date);
    CREATE INDEX IF NOT EXISTS idx_expenses_import   ON expenses(import_id);
  `);

  await seedCategories();
}

/**
 * Put the workbook's own headings in the table.
 *
 * Runs on every boot and inserts only what is missing, so a category
 * renamed or deactivated by an admin stays that way — this seeds an
 * empty table, it does not push the catalogue back over the farm's own
 * edits. The sort order is refreshed either way, since that is the
 * summary's running order rather than anybody's preference.
 */
async function seedCategories() {
  for (const [i, cat] of CATEGORIES.entries()) {
    await pool.query(
      `INSERT INTO expense_categories (name, sort_order, notes)
       VALUES ($1, $2, $3)
       ON CONFLICT (LOWER(BTRIM(name))) DO UPDATE SET sort_order = EXCLUDED.sort_order`,
      [cat.name, (i + 1) * 10, cat.note || null]
    );
  }
}

module.exports = { initExpenseTables };
