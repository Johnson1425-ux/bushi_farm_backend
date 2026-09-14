const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME     || 'milktrack',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || '',
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS cows (
        id         SERIAL PRIMARY KEY,
        name       VARCHAR(100) NOT NULL UNIQUE,
        tag        VARCHAR(50),
        breed      VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS milk_records (
        id         SERIAL PRIMARY KEY,
        cow_id     INTEGER NOT NULL REFERENCES cows(id) ON DELETE CASCADE,
        date       DATE NOT NULL,
        litres     NUMERIC(6,2) NOT NULL CHECK (litres > 0),
        notes      TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(cow_id, date)
      );

      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        username      VARCHAR(50) NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role          VARCHAR(10) NOT NULL DEFAULT 'veteran' CHECK (role IN ('admin', 'manager', 'veteran')),
        created_at    TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_milk_records_cow_id ON milk_records(cow_id);
      CREATE INDEX IF NOT EXISTS idx_milk_records_date   ON milk_records(date);

      CREATE TABLE IF NOT EXISTS inventory_items (
        id            SERIAL PRIMARY KEY,
        name          TEXT NOT NULL UNIQUE,
        unit          TEXT NOT NULL DEFAULT 'pcs',
        current_stock NUMERIC NOT NULL DEFAULT 0,
        notes         TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS inventory_logs (
        id         SERIAL PRIMARY KEY,
        item_id    INTEGER NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
        type       TEXT NOT NULL CHECK(type IN ('in','out')),
        quantity   NUMERIC NOT NULL,
        date       DATE NOT NULL,
        notes      TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_inv_logs_item ON inventory_logs(item_id);
      CREATE INDEX IF NOT EXISTS idx_inv_logs_date ON inventory_logs(date);

      /* A stock take: the shelf counted against the book.

         Kept as a document rather than as a handful of loose corrections,
         because a variance only means anything next to the count that
         produced it. A count is typed up as a draft, and posting it writes
         one 'adjust' movement per line that disagrees — so every correction
         to the book is traceable to the day somebody stood in the store and
         counted. */
      CREATE TABLE IF NOT EXISTS inventory_counts (
        id         SERIAL PRIMARY KEY,
        ref        TEXT NOT NULL UNIQUE,
        count_date DATE NOT NULL,
        status     TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','posted','cancelled')),
        notes      TEXT,
        counted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        posted_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
        posted_at  TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_inv_counts_date ON inventory_counts(count_date);

      /* book_qty is filled in at posting, never before: it is what the
         ledger said at the moment the correction was made, and re-deriving
         it later from a ledger the count itself has since changed would
         give a different — and wrong — answer every time it is read. */
      CREATE TABLE IF NOT EXISTS inventory_count_lines (
        id          SERIAL PRIMARY KEY,
        count_id    INTEGER NOT NULL REFERENCES inventory_counts(id) ON DELETE CASCADE,
        item_id     INTEGER NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
        counted_qty NUMERIC NOT NULL DEFAULT 0,
        book_qty    NUMERIC,
        notes       TEXT,
        UNIQUE (count_id, item_id)
      );
      CREATE INDEX IF NOT EXISTS idx_inv_count_lines_count ON inventory_count_lines(count_id);
      
      CREATE TABLE IF NOT EXISTS sales (
        id              SERIAL PRIMARY KEY,
        date            DATE NOT NULL,
        litres_sold     NUMERIC NOT NULL,
        price_per_litre NUMERIC NOT NULL DEFAULT 0,
        notes           TEXT,
        created_at      TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(date);

      CREATE TABLE IF NOT EXISTS processing_uploads (
        id          SERIAL PRIMARY KEY,
        label       TEXT NOT NULL,
        uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        uploaded_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS processing_milk_received (
        id               SERIAL PRIMARY KEY,
        upload_id        INTEGER NOT NULL REFERENCES processing_uploads(id) ON DELETE CASCADE,
        day              INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31),
        farm_litres      NUMERIC NOT NULL DEFAULT 0,
        purchased_litres NUMERIC NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_proc_received_upload ON processing_milk_received(upload_id);

      CREATE TABLE IF NOT EXISTS processing_packed (
        id        SERIAL PRIMARY KEY,
        upload_id INTEGER NOT NULL REFERENCES processing_uploads(id) ON DELETE CASCADE,
        day       INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31),
        product   TEXT NOT NULL,
        size      TEXT NOT NULL,
        units     NUMERIC NOT NULL DEFAULT 0,
        litres    NUMERIC NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_proc_packed_upload ON processing_packed(upload_id);

      CREATE TABLE IF NOT EXISTS processing_issued (
        id        SERIAL PRIMARY KEY,
        upload_id INTEGER NOT NULL REFERENCES processing_uploads(id) ON DELETE CASCADE,
        day       INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31),
        product   TEXT NOT NULL,
        size      TEXT NOT NULL,
        units     NUMERIC NOT NULL DEFAULT 0,
        litres    NUMERIC NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_proc_issued_upload ON processing_issued(upload_id);

      CREATE TABLE IF NOT EXISTS processing_damaged (
        id        SERIAL PRIMARY KEY,
        upload_id INTEGER NOT NULL REFERENCES processing_uploads(id) ON DELETE CASCADE,
        day       INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31),
        product   TEXT NOT NULL,
        size      TEXT NOT NULL,
        units     NUMERIC NOT NULL DEFAULT 0,
        litres    NUMERIC NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_proc_damaged_upload ON processing_damaged(upload_id);

      CREATE TABLE IF NOT EXISTS processing_stock (
        id        SERIAL PRIMARY KEY,
        upload_id INTEGER NOT NULL REFERENCES processing_uploads(id) ON DELETE CASCADE,
        product   TEXT NOT NULL,
        size      TEXT NOT NULL,
        units     NUMERIC NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_proc_stock_upload ON processing_stock(upload_id);
    `);

    /* ── Migrations ──────────────────────────────────────────────────
       CREATE TABLE IF NOT EXISTS does nothing to a table that already
       exists, so any schema change made after a database was first created
       has to be applied explicitly here. Keep every statement idempotent so
       this block is safe to run on every boot.

       Each step runs on its own. Passing several statements to one query()
       puts them in an implicit transaction, so one failure rolls back the
       whole batch — and because the steps used to run in sequence with no
       error handling, a failure in an early one meant every later migration
       was skipped entirely. That is how a single out-of-range users.role
       value left processing_uploads without the columns the upload route
       needs, reported to the operator as nothing more than
       'column "month_num" does not exist' at upload time.

       A step that fails now leaves the rest to apply, and says so loudly. */
    const migrations = [
      /* Roles are admin / manager / veteran / attendant. Databases created
         before 'manager' and 'veteran' existed kept a two-value constraint
         that rejected them, and 'viewer' has since been retired.

         'attendant' arrived with branch distribution: it runs one branch's
         stock and till and nothing else. It must be listed here before any
         such account can be created — and, just as importantly, before this
         very migration demotes one, since it runs on every boot.

         Anything outside the current four is moved to 'veteran' rather than
         only 'viewer' — a database carrying some other historical value would
         otherwise fail the CHECK below, and narrowing an unknown role to a
         limited one is the safe direction to be wrong in. */
      ['users.role constraint', `
        ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
        UPDATE users SET role = 'veteran'
          WHERE role IS NULL OR role NOT IN ('admin', 'manager', 'veteran', 'attendant');
        ALTER TABLE users ADD CONSTRAINT users_role_check
          CHECK (role IN ('admin', 'manager', 'veteran', 'attendant'));
        ALTER TABLE users ALTER COLUMN role SET DEFAULT 'veteran';
      `],

      /* Processing unit: figures the original tables had nowhere to put.

         The farm's own workbook carries a stock balance forward from one
         month to the next, splits milk received across three sources rather
         than two, and records raw milk spoiled before packing separately
         from packs written off after it. Without these columns an upload
         silently lost all of that, and closing stock could only ever be
         guessed at. */
      ['processing_uploads columns', `
        ALTER TABLE processing_uploads
          ADD COLUMN IF NOT EXISTS opening_fresh_litres NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS fresh_damage_litres  NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS month_num            INTEGER,
          ADD COLUMN IF NOT EXISTS year                 INTEGER,
          ADD COLUMN IF NOT EXISTS source               TEXT;
      `],

      ['processing_milk_received columns', `
        ALTER TABLE processing_milk_received
          ADD COLUMN IF NOT EXISTS mwabulugu_litres NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS damaged_litres   NUMERIC NOT NULL DEFAULT 0;
      `],

      /* processing_stock.units is the CLOSING balance. The movements that
         produce it are stored alongside so the figure can be explained
         without re-reading the daily tables. */
      ['processing_stock columns', `
        ALTER TABLE processing_stock
          ADD COLUMN IF NOT EXISTS opening_units NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS packed_units  NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS issued_units  NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS damaged_units NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS litres        NUMERIC NOT NULL DEFAULT 0;
      `],

      /* An animal leaves the herd without leaving the records.

         Deleting a cow row cascades through milk_records, cow_health_records,
         pregnancies, disease_cows and cow_history, so a death used to erase
         every trace of her — including the milk she really did produce, which
         quietly changed last year's farm totals. Archiving takes her out of
         the active herd and leaves all of that intact.

         `status` doubles as the reason she left, so there is no second column
         that can disagree with it. */
      ['cows archive status', `
        ALTER TABLE cows
          ADD COLUMN IF NOT EXISTS status        TEXT NOT NULL DEFAULT 'active',
          ADD COLUMN IF NOT EXISTS archived_at   DATE,
          ADD COLUMN IF NOT EXISTS archived_note TEXT,
          ADD COLUMN IF NOT EXISTS archived_by   INTEGER REFERENCES users(id) ON DELETE SET NULL;

        ALTER TABLE cows DROP CONSTRAINT IF EXISTS cows_status_check;
        UPDATE cows SET status = 'active'
          WHERE status IS NULL OR status NOT IN ('active', 'dead', 'sold', 'culled');
        ALTER TABLE cows ADD CONSTRAINT cows_status_check
          CHECK (status IN ('active', 'dead', 'sold', 'culled'));

        CREATE INDEX IF NOT EXISTS idx_cows_status ON cows(status);
      `],

      /* Inventory: an item the store can actually run.

         The original two columns — name and unit — could say what a thing
         was called and nothing about how to keep it. No reorder level, so
         the only warning anyone got was "out of stock", which arrives on
         the morning packing has already stopped. No unit cost, so the
         value sitting in the store was unknowable. No category, so the
         packaging bottles were listed in amongst the spanners.

         `status` retires an item without deleting it. Deleting cascades
         through inventory_logs and takes every movement ever filed against
         it with it, which silently rewrites last year's consumption for a
         line the store merely stopped carrying. */
      ['inventory_items columns', `
        ALTER TABLE inventory_items
          ADD COLUMN IF NOT EXISTS code          TEXT,
          ADD COLUMN IF NOT EXISTS category      TEXT NOT NULL DEFAULT 'general',
          ADD COLUMN IF NOT EXISTS reorder_level NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS reorder_qty   NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS unit_cost     NUMERIC NOT NULL DEFAULT 0,
          ADD COLUMN IF NOT EXISTS supplier      TEXT,
          ADD COLUMN IF NOT EXISTS location      TEXT,
          ADD COLUMN IF NOT EXISTS status        TEXT NOT NULL DEFAULT 'active',
          ADD COLUMN IF NOT EXISTS archived_at   TIMESTAMPTZ,
          ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ DEFAULT NOW();

        ALTER TABLE inventory_items DROP CONSTRAINT IF EXISTS inventory_items_status_check;
        UPDATE inventory_items SET status = 'active'
          WHERE status IS NULL OR status NOT IN ('active', 'archived');
        ALTER TABLE inventory_items ADD CONSTRAINT inventory_items_status_check
          CHECK (status IN ('active', 'archived'));

        ALTER TABLE inventory_items DROP CONSTRAINT IF EXISTS inventory_items_category_check;
        UPDATE inventory_items SET category = 'general'
          WHERE category IS NULL OR category NOT IN
            ('packaging','ingredient','chemical','spare','tool','ppe','general');
        ALTER TABLE inventory_items ADD CONSTRAINT inventory_items_category_check
          CHECK (category IN ('packaging','ingredient','chemical','spare','tool','ppe','general'));

        CREATE UNIQUE INDEX IF NOT EXISTS idx_inv_items_code
          ON inventory_items(LOWER(code)) WHERE code IS NOT NULL AND code <> '';
        CREATE INDEX IF NOT EXISTS idx_inv_items_status ON inventory_items(status);
      `],

      /* The balance is the ledger summed, and only the ledger.

         `current_stock` was declared on day one, never written to, and left
         at zero on every row — while /inventory/items quietly returned a
         second column of the same name computed from the logs. Two answers
         to one question, one of them always wrong, distinguishable only by
         which query you happened to read. Dropping it leaves one. */
      ['inventory_items drop cached balance', `
        ALTER TABLE inventory_items DROP COLUMN IF EXISTS current_stock;
      `],

      /* A movement that says what actually happened.

         'damage' and 'return' are the two the store was missing. Breakages
         used to be filed as 'out' — so bottles smashed in the packing hall
         and bottles that left holding yoghurt were the same row, and the
         damage rate, which is the number that tells you a crate is being
         stacked wrong, could not be recovered from the records at all.
         'adjust' carries a signed quantity because a stock count corrects
         in both directions; it is the one type allowed to be negative.

         created_by answers "who took the bottles", which the old logs had
         no column for. */
      ['inventory_logs columns', `
        ALTER TABLE inventory_logs
          ADD COLUMN IF NOT EXISTS unit_cost  NUMERIC,
          ADD COLUMN IF NOT EXISTS reference  TEXT,
          ADD COLUMN IF NOT EXISTS party      TEXT,
          ADD COLUMN IF NOT EXISTS created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          ADD COLUMN IF NOT EXISTS count_id   INTEGER REFERENCES inventory_counts(id) ON DELETE SET NULL;

        ALTER TABLE inventory_logs DROP CONSTRAINT IF EXISTS inventory_logs_type_check;
        ALTER TABLE inventory_logs ADD CONSTRAINT inventory_logs_type_check
          CHECK (type IN ('in','out','damage','return','adjust'));

        ALTER TABLE inventory_logs DROP CONSTRAINT IF EXISTS inventory_logs_quantity_check;
        ALTER TABLE inventory_logs ADD CONSTRAINT inventory_logs_quantity_check
          CHECK (quantity <> 0 AND (quantity > 0 OR type = 'adjust'));

        CREATE INDEX IF NOT EXISTS idx_inv_logs_type  ON inventory_logs(type);
        CREATE INDEX IF NOT EXISTS idx_inv_logs_count ON inventory_logs(count_id);
      `],

      /* One upload per month, enforced rather than assumed: the upload route
         replaces a month by label, and a duplicate row would leave the old
         figures visible beside the new ones. Older rows are de-duplicated
         first, keeping the most recent, or the index cannot be built.

         This one is deliberately last: it is the only step that can fail on
         data rather than on schema, and nothing else depends on it. */
      ['unique month index', `
        DELETE FROM processing_uploads a
          USING processing_uploads b
          WHERE a.label = b.label AND a.id < b.id;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_proc_uploads_label
          ON processing_uploads(label);
      `],
    ];

    const failures = [];
    for (const [name, sql] of migrations) {
      try {
        await client.query(sql);
      } catch (err) {
        failures.push({ name, message: err.message });
        console.error(`✗ Migration "${name}" failed: ${err.message}`);
      }
    }
    if (failures.length) {
      console.error(
        `✗ ${failures.length} of ${migrations.length} migrations did not apply. `
        + 'The API is running against an incomplete schema and some routes will fail.'
      );
    }

    /* Seed a default admin if no users exist yet */
    const { rows } = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(rows[0].count) === 0) {
      const bcrypt = require('bcrypt');
      const hash   = await bcrypt.hash('admin123', 10);
      await client.query(
        `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')`,
        ['admin', hash]
      );
      console.log('✓ Default admin created  →  username: admin  password: admin123');
      console.log('  ⚠  Change this password immediately via the Users page!');
    }

    console.log('✓ Database schema ready');
  } finally {
    client.release();
  }
}

/* ── startup gate ────────────────────────────────────────────────
   initDB() used to be fired and forgotten at module load. Requests were
   served immediately, so anything arriving during a cold start could reach
   a table whose migration had not run yet and fail on a missing column —
   and on a serverless host, where the process can be frozen once a response
   is sent, a migration interrupted that way may never finish at all.

   `ready()` runs the initialisation exactly once per process and hands back
   the same promise to every caller, so a request can wait for it instead of
   racing it. A failure is not cached as permanent: the next call retries,
   since the usual cause is the database still coming up. */
let _ready = null;

function ready(...tasks) {
  if (!_ready) {
    _ready = (async () => {
      await initDB();
      for (const task of tasks) await task();
    })().catch((err) => {
      _ready = null;
      throw err;
    });
  }
  return _ready;
}

module.exports = { pool, initDB, ready };
