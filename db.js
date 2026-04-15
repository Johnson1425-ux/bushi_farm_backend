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
        role          VARCHAR(10) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
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
