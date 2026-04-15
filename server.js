require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const multer   = require('multer');
const XLSX     = require('xlsx');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const { pool, initDB }           = require('./db');
const { verifyToken, requireAdmin, SECRET } = require('./auth');

const app    = express();
const upload = multer({ storage: multer.memoryStorage() });

const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'https://bushi-farm.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

/* ══════════════════════════════════
   AUTH ROUTES  (public)
══════════════════════════════════ */
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username.trim()]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', verifyToken, (req, res) => {
  res.json({ user: req.user });
});

/* ══════════════════════════════════
   USER MANAGEMENT  (admin only)
══════════════════════════════════ */
app.get('/api/users', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, role, created_at FROM users ORDER BY created_at'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', verifyToken, requireAdmin, async (req, res) => {
  const { username, password, role = 'viewer' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!['admin', 'viewer'].includes(role)) return res.status(400).json({ error: 'role must be admin or viewer' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users(username, password_hash, role) VALUES($1,$2,$3) RETURNING id, username, role, created_at',
      [username.trim(), hash, role]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/users/:id/password', verifyToken, requireAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', verifyToken, requireAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   HELPER — normalise column names
══════════════════════════════════ */
function findKey(sample, candidates) {
  const keys = Object.keys(sample);
  for (const c of candidates) {
    const k = keys.find(k => k.toLowerCase().replace(/[\s_\-]/g,'').includes(c));
    if (k) return k;
  }
  return null;
}

function parseDate(val) {
  if (!val) return null;
  if (val instanceof Date) return val.toISOString().slice(0,10);
  const s = String(val).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const parts = s.split(/[\/\-\.]/);
  if (parts.length === 3) {
    const [a,b,c] = parts.map(Number);
    if (c > 1000) return `${c}-${String(b).padStart(2,'0')}-${String(a).padStart(2,'0')}`;
    return new Date(s).toISOString().slice(0,10);
  }
  const d = new Date(s);
  return isNaN(d) ? null : d.toISOString().slice(0,10);
}

/* ══════════════════════════════════
   COWS  (all authenticated)
══════════════════════════════════ */
app.get('/api/cows', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id, c.name, c.tag, c.breed, c.created_at,
        COUNT(r.id)::int                      AS record_count,
        ROUND(AVG(r.litres)::numeric, 2)      AS avg_litres,
        ROUND(SUM(r.litres)::numeric, 2)      AS total_litres,
        ROUND(MAX(r.litres)::numeric, 2)      AS max_litres,
        ROUND(MIN(r.litres)::numeric, 2)      AS min_litres,
        ROUND(STDDEV(r.litres)::numeric, 2)   AS stddev_litres,
        MIN(r.date)                            AS first_date,
        MAX(r.date)                            AS last_date
      FROM cows c
      LEFT JOIN milk_records r ON r.cow_id = c.id
      GROUP BY c.id
      ORDER BY avg_litres DESC NULLS LAST
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cows', verifyToken, requireAdmin, async (req, res) => {
  const { name, tag, breed } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO cows(name,tag,breed) VALUES($1,$2,$3) ON CONFLICT(name) DO UPDATE SET tag=EXCLUDED.tag, breed=EXCLUDED.breed RETURNING *',
      [name.trim(), tag||null, breed||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/cows/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM cows WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   MILK RECORDS
══════════════════════════════════ */
app.get('/api/records', verifyToken, async (req, res) => {
  const { cow_id, date_from, date_to, limit=500, offset=0 } = req.query;
  const conditions = [], params = [];
  if (cow_id)    { params.push(cow_id);    conditions.push(`r.cow_id = $${params.length}`); }
  if (date_from) { params.push(date_from); conditions.push(`r.date >= $${params.length}`); }
  if (date_to)   { params.push(date_to);   conditions.push(`r.date <= $${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(limit, offset);
  try {
    const { rows } = await pool.query(`
      SELECT r.id, c.name AS cow, TO_CHAR(r.date,'YYYY-MM-DD') AS date, r.litres, r.notes
      FROM milk_records r JOIN cows c ON c.id = r.cow_id
      ${where}
      ORDER BY r.date DESC, c.name
      LIMIT $${params.length-1} OFFSET $${params.length}
    `, params);
    const countRes = await pool.query(`SELECT COUNT(*) FROM milk_records r ${where}`, params.slice(0,-2));
    res.json({ records: rows, total: parseInt(countRes.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/records', verifyToken, requireAdmin, async (req, res) => {
  const { cow_name, date, litres, notes } = req.body;
  if (!cow_name || !date || !litres) return res.status(400).json({ error: 'cow_name, date and litres required' });
  try {
    const cowRes = await pool.query(
      'INSERT INTO cows(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id',
      [cow_name.trim()]
    );
    const { rows } = await pool.query(
      `INSERT INTO milk_records(cow_id,date,litres,notes) VALUES($1,$2,$3,$4)
       ON CONFLICT(cow_id,date) DO UPDATE SET litres=EXCLUDED.litres, notes=EXCLUDED.notes RETURNING *`,
      [cowRes.rows[0].id, date, litres, notes||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/records/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM milk_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   BULK IMPORT  (admin only)
══════════════════════════════════ */
app.post('/api/import', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb   = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows  = XLSX.utils.sheet_to_json(sheet, { header: 1 });
    if (!rows.length) return res.status(400).json({ error: 'Empty file' });

    const headerIndex = rows.findIndex(r => r.some(cell => String(cell).toUpperCase().includes('COW')));
    if (headerIndex === -1) return res.status(400).json({ error: 'Invalid format: "COW" column not found' });

    const header      = rows[headerIndex];
    const cowColIndex = header.findIndex(c => String(c).toUpperCase().includes('COW'));
    const dayColumns  = [];
    header.forEach((col, idx) => {
      const day = parseInt(col);
      if (!isNaN(day) && day >= 1 && day <= 31) dayColumns.push({ day, idx });
    });
    if (!dayColumns.length) return res.status(400).json({ error: 'No day columns (1–31) found' });

    let year = new Date().getFullYear(), month = new Date().getMonth() + 1;
    const name = req.file.originalname.toLowerCase();
    const months = { january:1,february:2,march:3,april:4,may:5,june:6,july:7,august:8,september:9,october:10,november:11,december:12 };
    for (const m in months) { if (name.includes(m)) { month = months[m]; break; } }
    const yearMatch = name.match(/20\d{2}/);
    if (yearMatch) year = parseInt(yearMatch[0]);

    const client = await pool.connect();
    let added = 0, skipped = 0;
    try {
      await client.query('BEGIN');
      for (const row of rows.slice(headerIndex + 1)) {
        const cowName = String(row[cowColIndex] || '').trim();
        if (!cowName) continue;
        const cowRes = await client.query(
          `INSERT INTO cows(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
          [cowName]
        );
        const cow_id = cowRes.rows[0].id;
        for (const d of dayColumns) {
          let value = row[d.idx];
          if (typeof value === 'string') value = value.replace(',', '.');
          const litres = parseFloat(value);
          if (isNaN(litres) || litres <= 0) { skipped++; continue; }
          const date = `${year}-${String(month).padStart(2,'0')}-${String(d.day).padStart(2,'0')}`;
          await client.query(
            `INSERT INTO milk_records(cow_id,date,litres) VALUES($1,$2,$3) ON CONFLICT(cow_id,date) DO UPDATE SET litres=EXCLUDED.litres`,
            [cow_id, date, litres]
          );
          added++;
        }
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ success: true, added, skipped, detected_month: month, detected_year: year });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   ANALYTICS  (all authenticated)
══════════════════════════════════ */
app.get('/api/analytics/summary', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(COUNT(DISTINCT c.id)::int,0)        AS total_cows,
        COALESCE(COUNT(r.id)::int,0)                 AS total_records,
        COALESCE(ROUND(SUM(r.litres)::numeric,1),0)  AS total_litres,
        COALESCE(ROUND(AVG(r.litres)::numeric,2),0)  AS overall_avg,
        COALESCE(COUNT(DISTINCT r.date)::int,0)      AS days_tracked,
        TO_CHAR(MIN(r.date),'YYYY-MM-DD')            AS first_date,
        TO_CHAR(MAX(r.date),'YYYY-MM-DD')            AS last_date
      FROM cows c LEFT JOIN milk_records r ON r.cow_id = c.id
    `);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/trend', verifyToken, async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date,'YYYY-MM-DD') AS date, ROUND(AVG(litres)::numeric,2) AS avg_litres,
             ROUND(SUM(litres)::numeric,2) AS total_litres, COUNT(*)::int AS cow_count
      FROM milk_records WHERE date >= CURRENT_DATE - $1::int
      GROUP BY date ORDER BY date
    `, [days]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/compare', verifyToken, async (req, res) => {
  const ids = (req.query.ids||'').split(',').map(Number).filter(Boolean);
  if (!ids.length) return res.status(400).json({ error: 'ids required' });
  try {
    const { rows: stats } = await pool.query(`
      SELECT c.id, c.name, ROUND(AVG(r.litres)::numeric,2) AS avg_litres,
             ROUND(SUM(r.litres)::numeric,2) AS total_litres, ROUND(MAX(r.litres)::numeric,2) AS max_litres,
             ROUND(MIN(r.litres)::numeric,2) AS min_litres, ROUND(STDDEV(r.litres)::numeric,2) AS stddev_litres,
             COUNT(r.id)::int AS record_count
      FROM cows c JOIN milk_records r ON r.cow_id = c.id
      WHERE c.id = ANY($1) GROUP BY c.id
    `, [ids]);
    const { rows: daily } = await pool.query(`
      SELECT c.name AS cow, TO_CHAR(r.date,'YYYY-MM-DD') AS date, r.litres
      FROM milk_records r JOIN cows c ON c.id = r.cow_id
      WHERE r.cow_id = ANY($1) ORDER BY r.date
    `, [ids]);
    res.json({ stats, daily });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/dates', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT DISTINCT TO_CHAR(date,'YYYY-MM-DD') AS date FROM milk_records ORDER BY date DESC`);
    res.json(rows.map(r => r.date));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   PUBLIC STATS  (no auth required)
══════════════════════════════════ */
app.get('/api/public/stats', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COALESCE(COUNT(DISTINCT c.id)::int, 0)       AS total_cows,
        COALESCE(COUNT(r.id)::int, 0)                AS total_records,
        COALESCE(ROUND(SUM(r.litres)::numeric, 1), 0) AS total_litres,
        COALESCE(ROUND(AVG(r.litres)::numeric, 2), 0) AS overall_avg,
        COALESCE(COUNT(DISTINCT r.date)::int, 0)     AS days_tracked
      FROM cows c LEFT JOIN milk_records r ON r.cow_id = c.id
    `);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/* ══════════════════════════════════
   INVENTORY ITEMS
══════════════════════════════════ */
 
// GET /api/inventory/items
app.get('/api/inventory/items', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        i.*,
        COALESCE(SUM(CASE WHEN l.type='in'  THEN l.quantity ELSE 0 END), 0) AS total_in,
        COALESCE(SUM(CASE WHEN l.type='out' THEN l.quantity ELSE 0 END), 0) AS total_out
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      GROUP BY i.id
      ORDER BY i.name
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// POST /api/inventory/items
app.post('/api/inventory/items', verifyToken, requireAdmin, async (req, res) => {
  const { name, unit = 'pcs', current_stock = 0, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_items (name, unit, current_stock, notes)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [name.trim(), unit, current_stock, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Item already exists' });
    res.status(500).json({ error: err.message });
  }
});
 
// PATCH /api/inventory/items/:id
app.patch('/api/inventory/items/:id', verifyToken, requireAdmin, async (req, res) => {
  const { name, unit, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE inventory_items
       SET name  = COALESCE($1, name),
           unit  = COALESCE($2, unit),
           notes = COALESCE($3, notes)
       WHERE id=$4 RETURNING *`,
      [name || null, unit || null, notes || null, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// DELETE /api/inventory/items/:id
app.delete('/api/inventory/items/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM inventory_items WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
/* ══════════════════════════════════
   INVENTORY LOGS
══════════════════════════════════ */
 
// GET /api/inventory/logs?item_id=&from=&to=
app.get('/api/inventory/logs', verifyToken, async (req, res) => {
  const { item_id, from, to } = req.query;
  const conditions = [], params = [];
  if (item_id) { params.push(item_id); conditions.push(`l.item_id=$${params.length}`); }
  if (from)    { params.push(from);    conditions.push(`l.date>=$${params.length}`); }
  if (to)      { params.push(to);      conditions.push(`l.date<=$${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(`
      SELECT l.*, i.name AS item_name, i.unit,
             TO_CHAR(l.date,'YYYY-MM-DD') AS date
      FROM inventory_logs l
      JOIN inventory_items i ON i.id = l.item_id
      ${where}
      ORDER BY l.date DESC, l.id DESC
    `, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// POST /api/inventory/logs
app.post('/api/inventory/logs', verifyToken, requireAdmin, async (req, res) => {
  const { item_id, type, quantity, date, notes } = req.body;
  if (!item_id || !type || !quantity || !date)
    return res.status(400).json({ error: 'item_id, type, quantity, date required' });
  if (!['in','out'].includes(type))
    return res.status(400).json({ error: "type must be 'in' or 'out'" });
 
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO inventory_logs (item_id, type, quantity, date, notes)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [item_id, type, quantity, date, notes || null]
    );
    const delta = type === 'in' ? quantity : -quantity;
    await client.query(
      `UPDATE inventory_items SET current_stock = current_stock + $1 WHERE id=$2`,
      [delta, item_id]
    );
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});
 
/* ══════════════════════════════════
   INVENTORY — EXCEL IMPORT
   Columns: ITEM | TYPE | QUANTITY | DATE | NOTES
══════════════════════════════════ */
app.post('/api/inventory/import', verifyToken, requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb   = XLSX.read(req.file.buffer, { type: 'buffer', cellDates: true });
    const ws   = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws, { defval: '' });
    if (!rows.length) return res.status(400).json({ error: 'Empty file' });
 
    const client = await pool.connect();
    let imported = 0;
    const errors = [];
    try {
      await client.query('BEGIN');
      for (const [i, row] of rows.entries()) {
        const rowNum   = i + 2;
        const itemName = String(row['ITEM'] ?? row['item'] ?? row['Item'] ?? '').trim();
        const type     = String(row['TYPE'] ?? row['type'] ?? row['Type'] ?? '').trim().toLowerCase();
        const qty      = parseFloat(String(row['QUANTITY'] ?? row['quantity'] ?? row['Quantity'] ?? 0).replace(',','.'));
        const dateRaw  = row['DATE'] ?? row['date'] ?? row['Date'] ?? '';
        const notes    = String(row['NOTES'] ?? row['notes'] ?? row['Notes'] ?? '').trim() || null;
 
        if (!itemName || !type || !qty || !dateRaw) {
          errors.push(`Row ${rowNum}: missing required field (ITEM, TYPE, QUANTITY, DATE)`);
          continue;
        }
        if (!['in','out'].includes(type)) {
          errors.push(`Row ${rowNum}: TYPE must be 'in' or 'out', got '${type}'`);
          continue;
        }
        const date = parseDate(dateRaw);
        if (!date) { errors.push(`Row ${rowNum}: invalid DATE '${dateRaw}'`); continue; }
 
        // Find or create item
        const itemRes = await client.query(
          `INSERT INTO inventory_items (name) VALUES ($1)
           ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
          [itemName]
        );
        const item_id = itemRes.rows[0].id;
 
        await client.query(
          `INSERT INTO inventory_logs (item_id, type, quantity, date, notes)
           VALUES ($1,$2,$3,$4,$5)`,
          [item_id, type, qty, date, notes]
        );
        const delta = type === 'in' ? qty : -qty;
        await client.query(
          `UPDATE inventory_items SET current_stock = current_stock + $1 WHERE id=$2`,
          [delta, item_id]
        );
        imported++;
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ success: true, imported, errors });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
/* ══════════════════════════════════
   INVENTORY — EXCEL EXPORT
══════════════════════════════════ */
app.get('/api/inventory/export', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(l.date,'YYYY-MM-DD') AS "DATE",
             i.name AS "ITEM", i.unit AS "UNIT",
             l.type AS "TYPE", l.quantity AS "QUANTITY", l.notes AS "NOTES"
      FROM inventory_logs l JOIN inventory_items i ON i.id=l.item_id
      ORDER BY l.date DESC
    `);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), 'Inventory Logs');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename="inventory_logs.xlsx"');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
/* ══════════════════════════════════
   SALES
══════════════════════════════════ */
 
// GET /api/sales?from=&to=&month=YYYY-MM
app.get('/api/sales', verifyToken, async (req, res) => {
  const { from, to, month } = req.query;
  const conditions = [], params = [];
  if (month) {
    params.push(month);
    conditions.push(`TO_CHAR(date,'YYYY-MM')=$${params.length}`);
  } else {
    if (from) { params.push(from); conditions.push(`date>=$${params.length}`); }
    if (to)   { params.push(to);   conditions.push(`date<=$${params.length}`); }
  }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(`
      SELECT id,
             TO_CHAR(date,'YYYY-MM-DD') AS date,
             litres_sold, price_per_litre,
             ROUND((litres_sold * price_per_litre)::numeric, 2) AS total,
             notes, created_at
      FROM sales ${where}
      ORDER BY date DESC
    `, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// POST /api/sales
app.post('/api/sales', verifyToken, requireAdmin, async (req, res) => {
  const { date, litres_sold, price_per_litre, notes } = req.body;
  if (!date || !litres_sold || !price_per_litre)
    return res.status(400).json({ error: 'date, litres_sold, price_per_litre required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO sales (date, litres_sold, price_per_litre, notes)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT DO NOTHING RETURNING *`,
      [date, litres_sold, price_per_litre, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// DELETE /api/sales/:id
app.delete('/api/sales/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM sales WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
// GET /api/sales/summary  — totals grouped by month
app.get('/api/sales/summary', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        TO_CHAR(date,'YYYY-MM') AS month,
        COUNT(*)::int AS record_count,
        ROUND(SUM(litres_sold)::numeric, 2) AS total_litres,
        ROUND(SUM(litres_sold * price_per_litre)::numeric, 2) AS total_revenue,
        ROUND(AVG(litres_sold)::numeric, 2) AS avg_litres_per_day
      FROM sales
      GROUP BY TO_CHAR(date,'YYYY-MM')
      ORDER BY month DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
/* ══════════════════════════════════
   SALES — EXCEL IMPORT
   Same monthly grid format as milk records
   Columns: DATE | LITRES | PRICE_PER_LITRE | NOTES
   OR monthly grid: rows=days (1-31), cols per month
══════════════════════════════════ */
app.post('/api/sales/import', verifyToken, requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb   = XLSX.read(req.file.buffer, { type: 'buffer', cellDates: true });
    const ws   = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws, { defval: '' });
    if (!rows.length) return res.status(400).json({ error: 'Empty file' });
 
    const sample = rows[0];
    const hasDateCol = findKey(sample, ['date']);
 
    // ── Format A: DATE | LITRES | PRICE_PER_LITRE | NOTES ──
    if (hasDateCol) {
      const client = await pool.connect();
      let imported = 0;
      const errors = [];
      try {
        await client.query('BEGIN');
        for (const [i, row] of rows.entries()) {
          const rowNum = i + 2;
          const dateRaw = row[findKey(row, ['date'])] ?? '';
          const litres  = parseFloat(String(row[findKey(row, ['litre','liter','qty','litres'])] ?? 0).replace(',','.'));
          const price   = parseFloat(String(row[findKey(row, ['price','ppl','rate'])] ?? 0).replace(',','.'));
          const notes   = String(row[findKey(row, ['notes','note','remarks'])] ?? '').trim() || null;
 
          const date = parseDate(dateRaw);
          if (!date || isNaN(litres) || litres <= 0 || isNaN(price) || price <= 0) {
            errors.push(`Row ${rowNum}: invalid or missing values`);
            continue;
          }
          await client.query(
            `INSERT INTO sales (date, litres_sold, price_per_litre, notes)
             VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
            [date, litres, price, notes]
          );
          imported++;
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
      return res.json({ success: true, imported, errors });
    }
 
    // ── Format B: monthly grid (day columns 1-31) ──
    // Uses same detection logic as /api/import for milk
    const headerRow = rows[0];
    const dayColumns = [];
    Object.keys(headerRow).forEach(col => {
      const day = parseInt(col);
      if (!isNaN(day) && day >= 1 && day <= 31) dayColumns.push({ day, col });
    });
    if (!dayColumns.length)
      return res.status(400).json({ error: 'Could not detect format. Use DATE|LITRES|PRICE_PER_LITRE or monthly grid.' });
 
    const priceKey  = findKey(sample, ['price','ppl','rate']);
    const globalPrice = priceKey ? parseFloat(String(sample[priceKey]).replace(',','.')) : 0;
 
    let year = new Date().getFullYear(), month = new Date().getMonth() + 1;
    const name = req.file.originalname.toLowerCase();
    const monthMap = {january:1,february:2,march:3,april:4,may:5,june:6,july:7,august:8,september:9,october:10,november:11,december:12};
    for (const m in monthMap) { if (name.includes(m)) { month = monthMap[m]; break; } }
    const yearMatch = name.match(/20\d{2}/);
    if (yearMatch) year = parseInt(yearMatch[0]);
 
    const client = await pool.connect();
    let imported = 0;
    const errors = [];
    try {
      await client.query('BEGIN');
      for (const row of rows) {
        const rowPrice = findKey(row, ['price','ppl','rate'])
          ? parseFloat(String(row[findKey(row, ['price','ppl','rate'])]).replace(',','.'))
          : globalPrice;
        if (!rowPrice || isNaN(rowPrice)) { errors.push('Missing price_per_litre'); continue; }
 
        for (const { day, col } of dayColumns) {
          let val = row[col];
          if (typeof val === 'string') val = val.replace(',','.');
          const litres = parseFloat(val);
          if (isNaN(litres) || litres <= 0) continue;
          const date = `${year}-${String(month).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
          await client.query(
            `INSERT INTO sales (date, litres_sold, price_per_litre)
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
            [date, litres, rowPrice]
          );
          imported++;
        }
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ success: true, imported, errors, detected_month: month, detected_year: year });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
/* ══════════════════════════════════
   SALES — EXCEL EXPORT
══════════════════════════════════ */
app.get('/api/sales/export', verifyToken, async (req, res) => {
  const { month } = req.query;
  const conditions = [], params = [];
  if (month) { params.push(month); conditions.push(`TO_CHAR(date,'YYYY-MM')=$${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date,'YYYY-MM-DD') AS "DATE",
             litres_sold AS "LITRES_SOLD",
             price_per_litre AS "PRICE_PER_LITRE",
             ROUND((litres_sold * price_per_litre)::numeric,2) AS "TOTAL",
             notes AS "NOTES"
      FROM sales ${where}
      ORDER BY date DESC
    `, params);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), 'Sales');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename="sales.xlsx"');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   START (Updated for Vercel)
══════════════════════════════════ */

// 1. Initialize the DB immediately (top level)
initDB().catch(err => console.error('DB Init Error:', err.message));

// 2. EXPORT the app (Mandatory for Vercel)
module.exports = app;

// 3. ONLY listen if running locally
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`✓ MilkTrack API running on http://localhost:${PORT}`);
  });
}