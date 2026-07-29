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
       this block is safe to run on every boot. */

    /* Roles are admin / manager / veteran. Two corrections are folded in here:
       databases created before 'manager' and 'veteran' existed kept a
       two-value constraint that rejected them, and 'viewer' has since been
       retired. Any surviving viewer is moved to 'veteran', the most limited
       remaining role, so the constraint below cannot fail on existing rows. */
    await client.query(`
      ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
      UPDATE users SET role = 'veteran' WHERE role = 'viewer';
      ALTER TABLE users ADD CONSTRAINT users_role_check
        CHECK (role IN ('admin', 'manager', 'veteran'));
      ALTER TABLE users ALTER COLUMN role SET DEFAULT 'veteran';
    `);

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

module.exports = { pool, initDB };
