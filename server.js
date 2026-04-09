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

app.use(cors());
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
   START
══════════════════════════════════ */
const PORT = process.env.PORT || 3001;
initDB().then(() => {
  app.listen(PORT, () => console.log(`✓ MilkTrack API running on http://localhost:${PORT}`));
}).catch(err => {
  console.error('Failed to connect to database:', err.message);
  process.exit(1);
});