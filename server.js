require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const multer   = require('multer');
const XLSX     = require('xlsx');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const mammoth   = require('mammoth');
const { pool, initDB }           = require('./db');
const { verifyToken, requireAdmin, SECRET } = require('./auth');

const app    = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());

app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'https://bushi-farm.vercel.app'],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.options('*', cors());

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


app.post('/api/records', verifyToken, async (req, res) => {
  const { cow_id, date, litres } = req.body;
  if (!cow_id || !date || litres === undefined) return res.status(400).json({ error: 'cow_id, date and litres are required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO milk_records(cow_id, date, litres)
       VALUES($1, $2, $3)
       ON CONFLICT (cow_id, date) DO UPDATE SET litres = EXCLUDED.litres
       RETURNING *`,
      [cow_id, date, parseFloat(litres)]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    const months = { 
      january:1, jan:1,
      february:2, feb:2,
      march:3, mar:3,
      april:4, apr:4,
      may:5,
      june:6, jun:6,
      july:7, jul:7,
      august:8, aug:8,
      september:9, sep:9,
      october:10, oct:10,
      november:11, nov:11,
      december:12, dec:12
    };
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
   DISEASES & TREATMENTS
══════════════════════════════════ */
app.get('/api/diseases', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.id, d.name, d.description, TO_CHAR(d.date,'YYYY-MM-DD') AS date, d.notes,
        COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', c.id, 'name', c.name)) FILTER (WHERE c.id IS NOT NULL), '[]') AS affected_cows,
        COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', t.id, 'medicine', t.medicine_name, 'dosage', t.dosage, 'date', TO_CHAR(t.date,'YYYY-MM-DD'), 'notes', t.notes)) FILTER (WHERE t.id IS NOT NULL), '[]'::json) AS treatments
      FROM diseases d
      LEFT JOIN disease_cows dc ON dc.disease_id = d.id
      LEFT JOIN cows c ON c.id = dc.cow_id
      LEFT JOIN treatments t ON t.disease_id = d.id
      GROUP BY d.id ORDER BY d.date DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/diseases', verifyToken, requireAdmin, async (req, res) => {
  const { name, description, date, notes, cow_ids = [] } = req.body;
  if (!name || !date) return res.status(400).json({ error: 'name and date required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'INSERT INTO diseases(name, description, date, notes) VALUES($1,$2,$3,$4) RETURNING *',
      [name.trim(), description||null, date, notes||null]
    );
    const disease = rows[0];
    for (const cow_id of cow_ids) {
      await client.query('INSERT INTO disease_cows(disease_id, cow_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [disease.id, cow_id]);
    }
    await client.query('COMMIT');
    res.status(201).json(disease);
  } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); }
  finally { client.release(); }
});

app.patch('/api/diseases/:id', verifyToken, requireAdmin, async (req, res) => {
  const { name, description, date, notes, cow_ids } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'UPDATE diseases SET name=COALESCE($1,name), description=COALESCE($2,description), date=COALESCE($3,date), notes=COALESCE($4,notes) WHERE id=$5 RETURNING *',
      [name||null, description||null, date||null, notes||null, req.params.id]
    );
    if (cow_ids) {
      await client.query('DELETE FROM disease_cows WHERE disease_id=$1', [req.params.id]);
      for (const cow_id of cow_ids) {
        await client.query('INSERT INTO disease_cows(disease_id, cow_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.params.id, cow_id]);
      }
    }
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); }
  finally { client.release(); }
});

app.delete('/api/diseases/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM diseases WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/diseases/:id/treatments', verifyToken, requireAdmin, async (req, res) => {
  const { medicine_name, dosage, date, notes } = req.body;
  if (!medicine_name || !date) return res.status(400).json({ error: 'medicine_name and date required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO treatments(disease_id, medicine_name, dosage, date, notes) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.params.id, medicine_name.trim(), dosage||null, date, notes||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/treatments/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM treatments WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   COW HISTORY
══════════════════════════════════ */
app.get('/api/cows/:id/history', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, event_type, TO_CHAR(date,'YYYY-MM-DD') AS date, source, notes
       FROM cow_history WHERE cow_id=$1 ORDER BY date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/cows/:id/history', verifyToken, requireAdmin, async (req, res) => {
  const { event_type, date, source, notes } = req.body;
  if (!event_type || !date) return res.status(400).json({ error: 'event_type and date required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO cow_history(cow_id, event_type, date, source, notes) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.params.id, event_type, date, source||null, notes||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/cow-history/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_history WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   PREGNANCIES
══════════════════════════════════ */
app.get('/api/pregnancies', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.cow_id, c.name AS cow_name,
        TO_CHAR(p.conception_date,'YYYY-MM-DD')    AS conception_date,
        TO_CHAR(p.expected_due_date,'YYYY-MM-DD')  AS expected_due_date,
        TO_CHAR(p.actual_birth_date,'YYYY-MM-DD')  AS actual_birth_date,
        p.status, p.notes,
        (p.expected_due_date - CURRENT_DATE)::int  AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      ORDER BY p.expected_due_date ASC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pregnancies', verifyToken, requireAdmin, async (req, res) => {
  const { cow_id, conception_date, expected_due_date, notes } = req.body;
  if (!cow_id || !conception_date || !expected_due_date) return res.status(400).json({ error: 'cow_id, conception_date and expected_due_date required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO pregnancies(cow_id, conception_date, expected_due_date, notes, status)
       VALUES($1,$2,$3,$4,'active') RETURNING *`,
      [cow_id, conception_date, expected_due_date, notes||null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/pregnancies/:id', verifyToken, requireAdmin, async (req, res) => {
  const { status, actual_birth_date, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE pregnancies SET
        status = COALESCE($1, status),
        actual_birth_date = COALESCE($2, actual_birth_date),
        notes = COALESCE($3, notes)
       WHERE id=$4 RETURNING *`,
      [status||null, actual_birth_date||null, notes||null, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/pregnancies/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM pregnancies WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   DAILY ALERTS
══════════════════════════════════ */
app.get('/api/alerts', verifyToken, async (req, res) => {
  try {
    const alerts = [];

    // 1. Production drop — cows whose latest record is 25% below their own average
    const { rows: prodDrops } = await pool.query(`
      WITH latest AS (
        SELECT DISTINCT ON (cow_id) cow_id, litres, date
        FROM milk_records ORDER BY cow_id, date DESC
      ),
      averages AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric, 2) AS avg_litres
        FROM milk_records GROUP BY cow_id
      )
      SELECT c.name, l.litres AS latest_litres, a.avg_litres,
        ROUND(((a.avg_litres - l.litres) / NULLIF(a.avg_litres,0) * 100)::numeric, 1) AS drop_pct,
        TO_CHAR(l.date,'YYYY-MM-DD') AS date
      FROM latest l
      JOIN averages a ON a.cow_id = l.cow_id
      JOIN cows c ON c.id = l.cow_id
      WHERE l.litres < a.avg_litres * 0.75
      ORDER BY drop_pct DESC
    `);
    for (const r of prodDrops) {
      alerts.push({
        type: 'production_drop',
        severity: r.drop_pct >= 50 ? 'high' : 'medium',
        message: `${r.name} production dropped ${r.drop_pct}% (${r.latest_litres}L vs avg ${r.avg_litres}L)`,
        cow: r.name, date: r.date,
      });
    }

    // 2. Upcoming births — pregnancies due within 14 days
    const { rows: births } = await pool.query(`
      SELECT c.name AS cow_name, TO_CHAR(p.expected_due_date,'YYYY-MM-DD') AS due_date,
        (p.expected_due_date - CURRENT_DATE)::int AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE p.status = 'active' AND p.expected_due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 14
      ORDER BY p.expected_due_date ASC
    `);
    for (const b of births) {
      alerts.push({
        type: 'upcoming_birth',
        severity: b.days_remaining <= 3 ? 'high' : 'medium',
        message: `${b.cow_name} is due to give birth in ${b.days_remaining} day(s) (${b.due_date})`,
        cow: b.cow_name, date: b.due_date,
      });
    }

    // 3. Overdue births — past due date and still active
    const { rows: overdue } = await pool.query(`
      SELECT c.name AS cow_name, TO_CHAR(p.expected_due_date,'YYYY-MM-DD') AS due_date,
        (CURRENT_DATE - p.expected_due_date)::int AS days_overdue
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE p.status = 'active' AND p.expected_due_date < CURRENT_DATE
    `);
    for (const o of overdue) {
      alerts.push({
        type: 'overdue_birth',
        severity: 'high',
        message: `${o.cow_name} is ${o.days_overdue} day(s) overdue! Expected: ${o.due_date}`,
        cow: o.cow_name, date: o.due_date,
      });
    }

    res.json(alerts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   PREGNANCY IMPORT FROM EXCEL
══════════════════════════════════ */
app.post('/api/pregnancies/import', verifyToken, requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const XLSX = require('xlsx');
    const wb   = XLSX.read(req.file.buffer, { type: 'buffer', cellDates: true });

    // Find the pregnant sheet (flexible name match)
    const sheetName = wb.SheetNames.find(n =>
      n.toUpperCase().includes('PREGNANT') || n.toUpperCase().includes('WAJAWAZITO')
    );
    if (!sheetName) return res.status(400).json({ error: 'No pregnancy sheet found. Expected sheet named "PREGNANT OF COW" or similar.' });

    const sheet = wb.Sheets[sheetName];
    const rows  = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: null, raw: false });

    // Find header row: look for row containing DATE and NAME OF COW
    const headerIdx = rows.findIndex(r =>
      r.some(c => String(c||'').toUpperCase().includes('DATE')) &&
      r.some(c => String(c||'').toUpperCase().includes('NAME'))
    );
    if (headerIdx === -1) return res.status(400).json({ error: 'Could not find header row with DATE and NAME OF COW.' });

    const header   = rows[headerIdx];
    const dateCol  = header.findIndex(c => String(c||'').toUpperCase().trim() === 'DATE');
    const nameCol  = header.findIndex(c => String(c||'').toUpperCase().includes('NAME'));
    const breedCol = header.findIndex(c => String(c||'').toUpperCase().includes('AINA') || String(c||'').toUpperCase().includes('MBEGU'));
    const doctorCol= header.findIndex(c => String(c||'').toUpperCase().includes('MPANDISHAJI') || String(c||'').toUpperCase().includes('DOCTOR'));

    const GESTATION_DAYS = 283;
    const results = { imported: 0, skipped: 0, errors: [] };
    const client  = await pool.connect();

    try {
      await client.query('BEGIN');

      for (const row of rows.slice(headerIdx + 1)) {
        // Skip empty rows
        if (!row || row.every(c => !c)) continue;

        const rawDate = row[dateCol];
        const rawName = row[nameCol];
        if (!rawDate || !rawName) { results.skipped++; continue; }

        const cowName = String(rawName).trim().toUpperCase();
        if (!cowName) { results.skipped++; continue; }

        // Parse date — could be string "2025-12-07" or Excel serial
        let conceptionDate;
        try {
          const d = new Date(rawDate);
          if (isNaN(d.getTime())) throw new Error('invalid date');
          conceptionDate = d.toISOString().slice(0, 10);
        } catch {
          results.errors.push(`Row skipped — invalid date for ${cowName}: ${rawDate}`);
          results.skipped++;
          continue;
        }

        const due = new Date(conceptionDate);
        due.setDate(due.getDate() + GESTATION_DAYS);
        const expectedDueDate = due.toISOString().slice(0, 10);

        const semenBatch = breedCol >= 0 ? String(row[breedCol] || '').trim().slice(0, 200) : null;
        const doctor     = doctorCol >= 0 ? String(row[doctorCol] || '').trim() : null;
        const notes      = [semenBatch, doctor ? 'Inseminated by: ' + doctor : null].filter(Boolean).join(' | ') || null;

        // Find or create cow
        const cowRes = await client.query(
          'INSERT INTO cows(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id',
          [cowName]
        );
        const cow_id = cowRes.rows[0].id;

        // Check for existing active pregnancy for this cow
        const existing = await client.query(
          "SELECT id FROM pregnancies WHERE cow_id=$1 AND status='active'",
          [cow_id]
        );

        if (existing.rows.length > 0) {
          // Update existing
          await client.query(
            'UPDATE pregnancies SET conception_date=$1, expected_due_date=$2, notes=$3 WHERE id=$4',
            [conceptionDate, expectedDueDate, notes, existing.rows[0].id]
          );
        } else {
          // Insert new
          await client.query(
            "INSERT INTO pregnancies(cow_id, conception_date, expected_due_date, notes, status) VALUES($1,$2,$3,$4,'active')",
            [cow_id, conceptionDate, expectedDueDate, notes]
          );
        }
        results.imported++;
      }

      await client.query('COMMIT');
      res.json({ success: true, ...results, sheet: sheetName });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   DB INIT — new tables
══════════════════════════════════ */
async function initNewTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS diseases (
      id          SERIAL PRIMARY KEY,
      name        TEXT NOT NULL,
      description TEXT,
      date        DATE NOT NULL,
      notes       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS disease_cows (
      disease_id INT REFERENCES diseases(id) ON DELETE CASCADE,
      cow_id     INT REFERENCES cows(id) ON DELETE CASCADE,
      PRIMARY KEY (disease_id, cow_id)
    );
    CREATE TABLE IF NOT EXISTS treatments (
      id            SERIAL PRIMARY KEY,
      disease_id    INT REFERENCES diseases(id) ON DELETE CASCADE,
      medicine_name TEXT NOT NULL,
      dosage        TEXT,
      date          DATE NOT NULL,
      notes         TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS cow_history (
      id         SERIAL PRIMARY KEY,
      cow_id     INT REFERENCES cows(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      date       DATE NOT NULL,
      source     TEXT,
      notes      TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pregnancies (
      id                SERIAL PRIMARY KEY,
      cow_id            INT REFERENCES cows(id) ON DELETE CASCADE,
      conception_date   DATE NOT NULL,
      expected_due_date DATE NOT NULL,
      actual_birth_date DATE,
      status            TEXT DEFAULT 'active',
      notes             TEXT,
      created_at        TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}
initNewTables().catch(err => console.error('initNewTables error:', err.message));

/* ══════════════════════════════════
   SALES
══════════════════════════════════ */
app.get('/api/sales', verifyToken, async (req, res) => {
  const { month, from, to } = req.query;
  const conditions = [], params = [];
  if (month)  { params.push(month);  conditions.push(`TO_CHAR(date,'YYYY-MM') = $${params.length}`); }
  if (from)   { params.push(from);   conditions.push(`date >= $${params.length}`); }
  if (to)     { params.push(to);     conditions.push(`date <= $${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(
      `SELECT id, TO_CHAR(date,'YYYY-MM-DD') AS date, litres_sold, price_per_litre,
              ROUND((litres_sold * price_per_litre)::numeric, 2) AS total, notes
       FROM sales ${where} ORDER BY date DESC`, params
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/sales', verifyToken, async (req, res) => {
  const { date, litres_sold, price_per_litre, notes } = req.body;
  if (!date || !litres_sold || !price_per_litre) return res.status(400).json({ error: 'date, litres_sold and price_per_litre required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO sales(date, litres_sold, price_per_litre, notes) VALUES($1,$2,$3,$4) RETURNING *`,
      [date, litres_sold, price_per_litre, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/sales/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM sales WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/sales/summary', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date,'YYYY-MM') AS month,
             COUNT(*)::int AS record_count,
             ROUND(SUM(litres_sold)::numeric,2) AS total_litres,
             ROUND(AVG(litres_sold)::numeric,2) AS avg_litres_per_day,
             ROUND(SUM(litres_sold * price_per_litre)::numeric,2) AS total_revenue
      FROM sales GROUP BY month ORDER BY month DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/sales/import', verifyToken, requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb    = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows  = XLSX.utils.sheet_to_json(sheet);
    let imported = 0; const errors = [];
    for (const row of rows) {
      try {
        const date  = parseDate(row['date'] || row['Date'] || row['DATE']);
        const litres = parseFloat(row['litres_sold'] || row['Litres'] || row['LITRES'] || 0);
        const price  = parseFloat(row['price_per_litre'] || row['Price'] || row['PRICE'] || 0);
        if (!date || !litres || !price) { errors.push(`Skipped row: missing data`); continue; }
        await pool.query(
          `INSERT INTO sales(date,litres_sold,price_per_litre,notes) VALUES($1,$2,$3,$4)
           ON CONFLICT(date) DO UPDATE SET litres_sold=EXCLUDED.litres_sold, price_per_litre=EXCLUDED.price_per_litre`,
          [date, litres, price, row['notes'] || null]
        );
        imported++;
      } catch (e) { errors.push(e.message); }
    }
    res.json({ imported, errors });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   INVENTORY
══════════════════════════════════ */
app.get('/api/inventory/items', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.*,
        COALESCE(SUM(CASE WHEN l.type='in'  THEN l.quantity ELSE 0 END),0) AS total_in,
        COALESCE(SUM(CASE WHEN l.type='out' THEN l.quantity ELSE 0 END),0) AS total_out,
        COALESCE(SUM(CASE WHEN l.type='in'  THEN l.quantity ELSE -l.quantity END),0) AS current_stock
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      GROUP BY i.id ORDER BY i.name
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory/items', verifyToken, requireAdmin, async (req, res) => {
  const { name, unit = 'pcs', notes } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_items(name,unit,notes) VALUES($1,$2,$3) RETURNING *`,
      [name.trim(), unit, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/inventory/items/:id', verifyToken, requireAdmin, async (req, res) => {
  const { name, unit, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE inventory_items SET name=$1, unit=$2, notes=$3 WHERE id=$4 RETURNING *`,
      [name, unit, notes || null, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/inventory/items/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM inventory_items WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/inventory/logs', verifyToken, async (req, res) => {
  const { item_id, from, to } = req.query;
  const conditions = [], params = [];
  if (item_id) { params.push(item_id); conditions.push(`l.item_id = $${params.length}`); }
  if (from)    { params.push(from);    conditions.push(`l.date >= $${params.length}`); }
  if (to)      { params.push(to);      conditions.push(`l.date <= $${params.length}`); }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  try {
    const { rows } = await pool.query(
      `SELECT l.*, i.name AS item_name, i.unit FROM inventory_logs l
       JOIN inventory_items i ON i.id = l.item_id
       ${where} ORDER BY l.date DESC, l.id DESC`, params
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory/logs', verifyToken, async (req, res) => {
  const { item_id, type, quantity, date, notes } = req.body;
  if (!item_id || !type || !quantity || !date) return res.status(400).json({ error: 'item_id, type, quantity, date required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_logs(item_id,type,quantity,date,notes) VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [item_id, type, quantity, date, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory/import', verifyToken, requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb    = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    const rows  = XLSX.utils.sheet_to_json(sheet);
    let imported = 0; const errors = [];
    for (const row of rows) {
      try {
        const name = String(row['item'] || row['Item'] || row['ITEM'] || row['name'] || '').trim();
        const type = String(row['type'] || row['Type'] || row['TYPE'] || 'in').toLowerCase();
        const qty  = parseFloat(row['quantity'] || row['Quantity'] || row['QTY'] || 0);
        const date = parseDate(row['date'] || row['Date'] || row['DATE']);
        if (!name || !qty || !date) { errors.push(`Skipped row: missing data`); continue; }
        const unit = String(row['unit'] || row['Unit'] || 'pcs');
        const cowRes = await pool.query(
          `INSERT INTO inventory_items(name,unit) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET unit=EXCLUDED.unit RETURNING id`,
          [name, unit]
        );
        await pool.query(
          `INSERT INTO inventory_logs(item_id,type,quantity,date,notes) VALUES($1,$2,$3,$4,$5)`,
          [cowRes.rows[0].id, type, qty, date, row['notes'] || null]
        );
        imported++;
      } catch (e) { errors.push(e.message); }
    }
    res.json({ imported, errors });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   DISEASES & TREATMENTS
══════════════════════════════════ */
app.get('/api/diseases', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.*,
        TO_CHAR(d.date,'YYYY-MM-DD') AS date,
        ARRAY_AGG(DISTINCT dc.cow_id) FILTER (WHERE dc.cow_id IS NOT NULL) AS affected_cow_ids,
        ARRAY_AGG(DISTINCT c.name)    FILTER (WHERE c.name IS NOT NULL)    AS affected_cow_names,
        COUNT(DISTINCT t.id)::int AS treatment_count
      FROM diseases d
      LEFT JOIN disease_cows dc ON dc.disease_id = d.id
      LEFT JOIN cows c ON c.id = dc.cow_id
      LEFT JOIN treatments t ON t.disease_id = d.id
      GROUP BY d.id ORDER BY d.date DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/diseases', verifyToken, async (req, res) => {
  const { name, description, date, cow_ids = [] } = req.body;
  if (!name || !date) return res.status(400).json({ error: 'name and date required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO diseases(name, description, date) VALUES($1,$2,$3) RETURNING *`,
      [name.trim(), description || null, date]
    );
    const disease = rows[0];
    for (const cow_id of cow_ids) {
      await client.query(`INSERT INTO disease_cows(disease_id, cow_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, [disease.id, cow_id]);
    }
    await client.query('COMMIT');
    res.status(201).json(disease);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

app.patch('/api/diseases/:id', verifyToken, async (req, res) => {
  const { name, description, date, cow_ids = [] } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE diseases SET name=$1, description=$2, date=$3 WHERE id=$4 RETURNING *`,
      [name, description || null, date, req.params.id]
    );
    await client.query(`DELETE FROM disease_cows WHERE disease_id=$1`, [req.params.id]);
    for (const cow_id of cow_ids) {
      await client.query(`INSERT INTO disease_cows(disease_id, cow_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, [req.params.id, cow_id]);
    }
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

app.delete('/api/diseases/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM diseases WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/diseases/:id/treatments', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, disease_id, medicine_name, dosage, TO_CHAR(treatments.date,'YYYY-MM-DD') AS date, notes FROM treatments WHERE disease_id=$1 ORDER BY treatments.date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/diseases/:id/treatments', verifyToken, async (req, res) => {
  const { medicine_name, dosage, date, notes } = req.body;
  if (!medicine_name || !date) return res.status(400).json({ error: 'medicine_name and date required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO treatments(disease_id,medicine_name,dosage,date,notes) VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [req.params.id, medicine_name.trim(), dosage || null, date, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/treatments/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM treatments WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   COW HISTORY
══════════════════════════════════ */
app.get('/api/cows/:id/history', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT *, TO_CHAR(date,'YYYY-MM-DD') AS date FROM cow_history WHERE cow_id=$1 ORDER BY date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/cows/:id/history', verifyToken, async (req, res) => {
  const { event_type, date, source, notes } = req.body;
  if (!event_type || !date) return res.status(400).json({ error: 'event_type and date required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO cow_history(cow_id,event_type,date,source,notes) VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [req.params.id, event_type, date, source || null, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/cows/:id/history/:hid', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_history WHERE id=$1 AND cow_id=$2', [req.params.hid, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   PREGNANCIES
══════════════════════════════════ */
app.get('/api/pregnancies', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.*, c.name AS cow_name, c.tag AS cow_tag,
        TO_CHAR(p.conception_date,'YYYY-MM-DD')   AS conception_date,
        TO_CHAR(p.expected_due_date,'YYYY-MM-DD') AS expected_due_date,
        TO_CHAR(p.actual_birth_date,'YYYY-MM-DD') AS actual_birth_date,
        (p.expected_due_date - CURRENT_DATE)::int AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      ORDER BY p.expected_due_date ASC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pregnancies', verifyToken, async (req, res) => {
  const { cow_id, conception_date, notes } = req.body;
  if (!cow_id || !conception_date) return res.status(400).json({ error: 'cow_id and conception_date required' });
  // Expected due date = conception + 283 days (average gestation for cattle)
  try {
    const { rows } = await pool.query(
      `INSERT INTO pregnancies(cow_id, conception_date, expected_due_date, notes)
       VALUES($1,$2,$2::date + INTERVAL '283 days',$3) RETURNING *`,
      [cow_id, conception_date, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/pregnancies/:id', verifyToken, async (req, res) => {
  const { status, actual_birth_date, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE pregnancies SET status=$1, actual_birth_date=$2, notes=$3 WHERE id=$4 RETURNING *`,
      [status, actual_birth_date || null, notes || null, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/pregnancies/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM pregnancies WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   DAILY ALERTS
══════════════════════════════════ */
app.get('/api/alerts/daily', verifyToken, async (req, res) => {
  try {
    const alerts = [];

    // 1. Production drop — cows whose today/recent avg is 20%+ below their overall avg
    const { rows: prodRows } = await pool.query(`
      WITH overall AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric,2) AS avg_all
        FROM milk_records GROUP BY cow_id
      ),
      recent AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric,2) AS avg_recent
        FROM milk_records
        WHERE date >= CURRENT_DATE - 7
        GROUP BY cow_id
      )
      SELECT c.name, o.avg_all, r.avg_recent,
             ROUND(((o.avg_all - r.avg_recent) / NULLIF(o.avg_all,0) * 100)::numeric,1) AS drop_pct
      FROM overall o
      JOIN recent r ON r.cow_id = o.cow_id
      JOIN cows c ON c.id = o.cow_id
      WHERE r.avg_recent < o.avg_all * 0.80
      ORDER BY drop_pct DESC
    `);
    for (const r of prodRows) {
      alerts.push({
        type: 'production_drop',
        severity: r.drop_pct >= 40 ? 'high' : 'medium',
        message: `${r.name}'s production dropped ${r.drop_pct}% (${r.avg_recent}L vs avg ${r.avg_all}L)`,
        cow: r.name,
      });
    }

    // 2. Upcoming births — pregnancies due within 14 days
    const { rows: birthRows } = await pool.query(`
      SELECT c.name AS cow_name, p.expected_due_date,
             (p.expected_due_date - CURRENT_DATE)::int AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE p.status = 'active'
        AND p.expected_due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 14
      ORDER BY p.expected_due_date ASC
    `);
    for (const r of birthRows) {
      alerts.push({
        type: 'upcoming_birth',
        severity: r.days_remaining <= 3 ? 'high' : 'medium',
        message: r.days_remaining === 0
          ? `${r.cow_name} is due to give birth today!`
          : `${r.cow_name} is due to give birth in ${r.days_remaining} day(s)`,
        cow: r.cow_name,
      });
    }

    // 3. Low inventory — items with stock <= 0
    const { rows: stockRows } = await pool.query(`
      SELECT i.name,
        COALESCE(SUM(CASE WHEN l.type='in' THEN l.quantity ELSE -l.quantity END),0) AS current_stock
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      GROUP BY i.id, i.name
      HAVING COALESCE(SUM(CASE WHEN l.type='in' THEN l.quantity ELSE -l.quantity END),0) <= 0
    `);
    for (const r of stockRows) {
      alerts.push({
        type: 'low_stock',
        severity: 'medium',
        message: `${r.name} is out of stock`,
        item: r.name,
      });
    }

    res.json(alerts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

function parseProcessingSheet(sheet) {
  const rows = XLSX.utils.sheet_to_json(sheet, {
    header: 1,
    defval: null,
    blankrows: false,
  });
 
  // ── helpers ──────────────────────────────────────────────
  const cellText = (v) => (v == null ? '' : String(v).trim().toUpperCase());
 
  // Find all column indices whose header is a day number (1–31)
  function getDayColumns(headerRow) {
    const cols = [];
    headerRow.forEach((cell, idx) => {
      const n = parseInt(cell);
      if (!isNaN(n) && n >= 1 && n <= 31) cols.push({ day: n, idx });
    });
    return cols;
  }
 
  // Find the TOTAL column index
  function getTotalColIdx(headerRow) {
    for (let i = 0; i < headerRow.length; i++) {
      if (cellText(headerRow[i]) === 'TOTAL') return i;
    }
    return -1;
  }

  // Detect section changes — only trigger on dedicated header rows where
  // cols 0-2 are all null (real data rows always have product/size in col 1 or 2).
  // This prevents summary total rows mid-section from flipping the section state.
  function sectionOf(row) {
    const text = row.map(cellText).join(' ');
    // Order matters: check most specific first
    if (text.includes('PROCESSING MILK STOCK') || text.includes('PROCESSED MILK STOCK')) return 'stock';
    if (text.includes('ISSUED')) return 'issued';
    if (text.includes('PROCESSED MILK LITRES') || text.includes('PROCESSING MILK LITRES')) return 'litres';
    if (text.includes('PROCESSED MILK PACKED') || text.includes('PROCESSED MILK  PACKED')) return 'packed';
    if (text.includes('MILK RESEIVED') || text.includes('MILK RECEIVED')) return 'received';
    return null;
  }
 
  // Known products & their canonical names
  const PRODUCTS = {
    'VANILLA':     'Vanilla',
    'STRAWBERRY':  'Strawberry',
    'MTINDI BONGE':'Mtindi Bonge',
    'MTINDI':      'Mtindi Bonge',
  };
  function detectProduct(row) {
    for (const key of Object.keys(PRODUCTS)) {
      if (row.map(cellText).some(t => t.includes(key))) return PRODUCTS[key];
    }
    return null;
  }
 
  // ── state machine ────────────────────────────────────────
  let section = null;
  let dayCols = [];
  let totalColIdx = -1;
  let currentProduct = null;
  const received = {};   // { day: { farm, purchased } }
  const packed   = [];   // [{ day, product, size, units }]
  const litres   = [];   // [{ day, product, size, litres }]
  const issued   = [];   // [{ day, product, size, units }]
  const stock    = [];   // [{ product, size, units }]
 
  // Detect label (month/year) from the sheet name or first rows
  let label = 'Uploaded';
 
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (!row || row.every(c => c == null)) continue;

    // ── detect label from header rows ──
    const joined = row.map(cellText).join(' ');
    const monthMatch = joined.match(/(JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER)\s+\d{4}/);
    if (monthMatch && label === 'Uploaded') label = monthMatch[0].replace(/\s+/g, ' ');

    // ── isSummaryTotalRow guard ──
    // Rows that have numeric values at day column positions AND contain section keywords
    // are summary/total rows — do NOT flip section for them
    const isSummaryTotalRow = dayCols.length > 0 && dayCols.some(d => {
      const v = row[d.idx];
      return v != null && !isNaN(parseFloat(v)) && parseFloat(v) > 0;
    });

    // ── detect section change (only on non-summary rows) ──
    if (!isSummaryTotalRow) {
      const newSection = sectionOf(row);
      if (newSection) { section = newSection; currentProduct = null; continue; }
    }

    // ── detect DATE header row (contains 1 2 3 ... 30) ──
    const potentialDays = getDayColumns(row);
    if (potentialDays.length >= 5) {
      dayCols = potentialDays;
      totalColIdx = getTotalColIdx(row);
      continue;
    }

    if (!section || !dayCols.length) continue;

    // ── detect product name ──
    const prod = detectProduct(row);
    if (prod) currentProduct = prod;

    // ── detect size ──
    let size = null;
    for (let c = 0; c < Math.min(row.length, 5); c++) {
      const t = cellText(row[c]);
      if (!t) continue;
      if (Object.keys(PRODUCTS).some(k => t.includes(k))) continue;
      if (['FARM','PURCHASED','GRAND TOTAL','PROCESSED MILK LITRES',
           'PROCESSED MILK PACKED','PROCESSING MILK LITRES','ISSUED'].some(x => t.includes(x))) continue;
      if (/^\d+(\.\d+)?(ML|L)$/i.test(t) || t.includes('CHUPA') || t.includes('CUP') || t.includes('PACT') || /\d+ML/i.test(t)) {
        size = t; break;
      }
    }
 
    // ── RECEIVED section ──
    if (section === 'received') {
      const label2 = cellText(row[1]) || cellText(row[0]);
      if (label2 === 'FARM' || label2.includes('FARM')) {
        for (const d of dayCols) {
          const v = parseFloat(row[d.idx]);
          if (!isNaN(v) && v > 0) {
            if (!received[d.day]) received[d.day] = { farm: 0, purchased: 0 };
            received[d.day].farm = v;
          }
        }
      }
      if (label2 === 'PURCHASED' || label2.includes('PURCH')) {
        for (const d of dayCols) {
          const v = parseFloat(row[d.idx]);
          if (!isNaN(v) && v > 0) {
            if (!received[d.day]) received[d.day] = { farm: 0, purchased: 0 };
            received[d.day].purchased = v;
          }
        }
      }
    }
 
    // ── PACKED section ──
    if (section === 'packed' && currentProduct && size && size !== 'FARM' && size !== 'GRAND TOTAL') {
      for (const d of dayCols) {
        const v = parseInt(row[d.idx]);
        if (!isNaN(v) && v > 0) {
          packed.push({ day: d.day, product: currentProduct, size, units: v });
        }
      }
    }
 
    // ── LITRES section ──
    if (section === 'litres' && currentProduct && size && size !== 'FARM' && size !== 'GRAND TOTAL') {
      for (const d of dayCols) {
        const v = parseFloat(row[d.idx]);
        if (!isNaN(v) && v > 0) {
          litres.push({ day: d.day, product: currentProduct, size, litres: v });
        }
      }
    }
 
    // ── ISSUED section ──
    if (section === 'issued' && currentProduct && size && size !== 'FARM' && size !== 'GRAND TOTAL') {
      for (const d of dayCols) {
        const v = parseInt(row[d.idx]);
        if (!isNaN(v) && v > 0) {
          issued.push({ day: d.day, product: currentProduct, size, units: v });
        }
      }
    }
 
    // ── STOCK section — summarise by product+size (totals, no daily) ──
    if (section === 'stock' && currentProduct && size && size !== 'FARM' && size !== 'GRAND TOTAL') {
      // Read from the TOTAL column (tracked from the day-header row)
      const rawTotal = totalColIdx >= 0 ? row[totalColIdx] : null;
      const total = parseFloat(rawTotal);
      if (!isNaN(total) && total > 0) {
        stock.push({ product: currentProduct, size, units: Math.round(total) });
      }
    }
  }
 
  return { label, received, packed, litres, issued, stock };
}
 
/* ══════════════════════════════════
   GET  /api/processing               — list all uploads
   GET  /api/processing/:id           — full data for one upload
   POST /api/processing/upload        — parse & save a new xlsx (admin)
   DELETE /api/processing/:id         — delete an upload (admin)
══════════════════════════════════ */
 
/* List all uploads */
app.get('/api/processing', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.label, u.uploaded_at, usr.username AS uploaded_by
      FROM processing_uploads u
      LEFT JOIN users usr ON usr.id = u.uploaded_by
      ORDER BY u.uploaded_at DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
 
/* Full data for one upload — returns summary + daily arrays */
app.get('/api/processing/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const uploadRes = await pool.query(
      `SELECT u.id, u.label, u.uploaded_at, usr.username AS uploaded_by
       FROM processing_uploads u LEFT JOIN users usr ON usr.id = u.uploaded_by
       WHERE u.id=$1`,
      [id]
    );
    if (!uploadRes.rows.length) return res.status(404).json({ error: 'Not found' });
 
    const [received, packed, issued, stock] = await Promise.all([
      pool.query(
        `SELECT day, farm_litres, purchased_litres FROM processing_milk_received
         WHERE upload_id=$1 ORDER BY day`, [id]
      ),
      pool.query(
        `SELECT day, product, size, units, litres FROM processing_packed
         WHERE upload_id=$1 ORDER BY product, size, day`, [id]
      ),
      pool.query(
        `SELECT day, product, size, units, litres FROM processing_issued
         WHERE upload_id=$1 ORDER BY product, size, day`, [id]
      ),
      pool.query(
        `SELECT product, size, units FROM processing_stock
         WHERE upload_id=$1 ORDER BY product, size`, [id]
      ),
    ]);
 
    res.json({
      upload:   uploadRes.rows[0],
      received: received.rows,
      packed:   packed.rows,
      issued:   issued.rows,
      stock:    stock.rows,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
 
/* Upload & parse a new xlsx file */
app.post('/api/processing/upload', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
 
  let parsed;
  try {
    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
    // Try to find the monthly sheet (not SUMMARY, not empty "sheet")
    const sheetName =
      wb.SheetNames.find(n => /^\w+ \d{4}$/i.test(n.trim())) ||
      wb.SheetNames.find(n => !n.toUpperCase().includes('SUMMARY') && n.toLowerCase() !== 'sheet') ||
      wb.SheetNames[0];
    parsed = parseProcessingSheet(wb.Sheets[sheetName]);
  } catch (err) {
    return res.status(400).json({ error: 'Failed to parse file: ' + err.message });
  }
 
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
 
    // 1. Create upload record
    const upRes = await client.query(
      `INSERT INTO processing_uploads(label, uploaded_by) VALUES($1,$2) RETURNING id`,
      [parsed.label, req.user.id]
    );
    const uploadId = upRes.rows[0].id;
 
    // 2. Milk received
    for (const [day, vals] of Object.entries(parsed.received)) {
      await client.query(
        `INSERT INTO processing_milk_received(upload_id, day, farm_litres, purchased_litres)
         VALUES($1,$2,$3,$4)`,
        [uploadId, parseInt(day), vals.farm || 0, vals.purchased || 0]
      );
    }
 
    // 3. Packed units + litres (merge by day+product+size)
    const packedMap = {};
    for (const r of parsed.packed) {
      const key = `${r.day}|${r.product}|${r.size}`;
      packedMap[key] = { ...r, litres: 0 };
    }
    for (const r of parsed.litres) {
      const key = `${r.day}|${r.product}|${r.size}`;
      if (packedMap[key]) packedMap[key].litres = r.litres;
      else packedMap[key] = { day: r.day, product: r.product, size: r.size, units: 0, litres: r.litres };
    }
    for (const r of Object.values(packedMap)) {
      await client.query(
        `INSERT INTO processing_packed(upload_id, day, product, size, units, litres)
         VALUES($1,$2,$3,$4,$5,$6)`,
        [uploadId, r.day, r.product, r.size, r.units || 0, r.litres || 0]
      );
    }
 
    // 4. Issued
    for (const r of parsed.issued) {
      await client.query(
        `INSERT INTO processing_issued(upload_id, day, product, size, units, litres)
         VALUES($1,$2,$3,$4,$5,$6)`,
        [uploadId, r.day, r.product, r.size, r.units || 0, 0]
      );
    }
 
    // 5. Stock
    for (const r of parsed.stock) {
      await client.query(
        `INSERT INTO processing_stock(upload_id, product, size, units)
         VALUES($1,$2,$3,$4)`,
        [uploadId, r.product, r.size, r.units || 0]
      );
    }
 
    await client.query('COMMIT');
    res.status(201).json({
      success: true,
      upload_id: uploadId,
      label: parsed.label,
      summary: {
        received_days: Object.keys(parsed.received).length,
        packed_rows:   parsed.packed.length,
        issued_rows:   parsed.issued.length,
        stock_rows:    parsed.stock.length,
      },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});
 
/* Delete an upload */
app.delete('/api/processing/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM processing_uploads WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ── DB migration — run once ──────────────────────────────── */
async function initHealthRecordsTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cow_health_records (
      id                    SERIAL PRIMARY KEY,
      cow_id                INT REFERENCES cows(id) ON DELETE CASCADE,
      cow_tag               TEXT,
      age                   TEXT,
      breed                 TEXT,
      parity                TEXT,
      daily_milk_yield      TEXT,
      days_in_milk          TEXT,
      body_weight           TEXT,
      body_temperature      TEXT,
      pulse_rate            TEXT,
      respiratory_rate      TEXT,
      crt_seconds           TEXT,
      rumino_motility       TEXT,
      present_illness       TEXT,
      past_history          TEXT,
      environment           TEXT,
      system_review         TEXT,
      -- Clinical exam findings stored as JSON: [{system, status, observations}]
      clinical_findings     JSONB DEFAULT '[]',
      tentative_diagnosis   TEXT,
      -- Lab results
      blood_smear           TEXT,
      buffy_coat            TEXT,
      pcv                   TEXT,
      eosinophils           TEXT,
      basophils             TEXT,
      neutrophils           TEXT,
      bacteriology          TEXT,
      skin_scrapings        TEXT,
      fecal_sample          TEXT,
      other_lab             TEXT,
      lab_findings          TEXT,
      final_diagnosis       TEXT,
      -- Treatments stored as JSON: [{drug, prescription}]
      treatments            JSONB DEFAULT '[]',
      milk_withdraw_date    TEXT,
      attending_vet         TEXT,
      license_number        TEXT,
      exam_date             TEXT,
      -- meta
      source_filename       TEXT,
      uploaded_at           TIMESTAMPTZ DEFAULT NOW(),
      created_at            TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}
initHealthRecordsTables().catch(err =>
  console.error('initHealthRecordsTables error:', err.message)
);
 
/* ── Parser: extract raw text → structured fields ─────────── */
function parseHealthDoc(rawText) {
  // mammoth extracts table cells as separate lines — filled form looks like:
  // "Cow ID/Tag\n\nBOSS001\n\nBody weight\n\n320kg"
  // So we build a label->nextValue map from the line sequence
  const lines = rawText.split('\n').map(l => l.trim());
  const nonEmpty = lines.filter(Boolean);

  // Build label->value map: for each non-empty line that looks like a label,
  // the VALUE is the next non-empty line that isn't another label
  const LABELS = new Set([
    'COW ID/TAG','BODY WEIGHT','AGE','BREED','PARITY','DAILY MILK YIELD',
    'DAYS IN MILK','BODY TEMPERATURE','PULSE RATE(BEATS/MINS)','PULSE RATE',
    'RESPIRATORY RATE(BEATS/MIN)','RESPIRATORY RATE','CRT(SECONDS)','CRT',
    'RUMINO-MOTILITY','RUMINOMOTILITY','BLOOD SMEAR','BUFFY COAT SMEAR',
    'BUFFY COAT','PCV','EOSINOPHILS','BASOPHILS','NEUTROPHILS',
    'SYSTEM','STATUS(NORMAL/ABNORMAL)','SPECIFIC OBSERVATIONS',
    'DRUG/VACCINE','PRESCRIPTION(DOSE, DOSAGE AND ROUTE)',
  ]);

  // nextValue(label) — finds label in nonEmpty array, returns next non-label, non-empty line
  function nextValue(labelVariants) {
    for (const label of labelVariants) {
      for (let i = 0; i < nonEmpty.length; i++) {
        const t = nonEmpty[i].toUpperCase().replace(/[_\-\/\(\)]+/g, ' ').trim();
        const lbl = label.toUpperCase().replace(/[_\-\/\(\)]+/g, ' ').trim();
        if (t.startsWith(lbl)) {
          // Value might be on same line after the label
          const sameLine = nonEmpty[i].slice(label.length).replace(/^[\s:_]+/, '').trim();
          if (sameLine && !LABELS.has(sameLine.toUpperCase())) return sameLine;
          // Or next non-empty, non-label line
          for (let j = i + 1; j < nonEmpty.length; j++) {
            const next = nonEmpty[j].trim();
            if (!next) continue;
            // Skip if it looks like a section header or another label
            if (LABELS.has(next.toUpperCase())) break;
            if (/^[A-Z ]{8,}$/.test(next) && !next.match(/\d/)) break; // ALL CAPS header
            if (next.startsWith('_')) continue; // blank line pattern ___
            return next;
          }
        }
      }
    }
    return null;
  }

  // afterLine — finds text after a pattern on the SAME line (for ___ fields)
  function afterLine(labelVariants) {
    for (const label of labelVariants) {
      for (const line of nonEmpty) {
        const idx = line.toUpperCase().indexOf(label.toUpperCase());
        if (idx !== -1) {
          const rest = line.slice(idx + label.length).replace(/^[\s:_]+/, '').trim();
          if (rest && !rest.match(/^_+$/) && rest.length > 1) return rest;
        }
      }
    }
    return null;
  }

  // Clinical systems — look for "SystemName\nNormal/Abnormal\nObservations" pattern
  const SYSTEMS = [
    'General Appearance','Integumentary','Musculoskeletal','Circulatory',
    'Respiratory','Digestive','Genitourinary','Ears/Eyes',
    'Mammary system','Neural system','Lymph nodes','Circulatory(MM/CRT)',
  ];
  const clinicalFindings = [];
  for (const system of SYSTEMS) {
    for (let i = 0; i < nonEmpty.length; i++) {
      if (nonEmpty[i].toUpperCase().startsWith(system.toUpperCase())) {
        const status = nonEmpty[i+1]?.match(/^(Normal|Abnormal)$/i)?.[0] || null;
        const observations = status && nonEmpty[i+2] && !SYSTEMS.some(s => nonEmpty[i+2].toUpperCase().startsWith(s.toUpperCase()))
          ? nonEmpty[i+2] : null;
        if (status) clinicalFindings.push({ system, status, observations });
        break;
      }
    }
  }

  // Treatments: "Drug/vaccine" section — pairs of drug + prescription lines
  const treatments = [];
  let inTreatments = false;
  for (let i = 0; i < nonEmpty.length; i++) {
    if (nonEmpty[i].toUpperCase().includes('DRUG/VACCINE')) { inTreatments = true; continue; }
    if (inTreatments) {
      if (nonEmpty[i].toUpperCase().includes('MILK WITHDRAW')) break;
      if (nonEmpty[i].toUpperCase().includes('PRESCRIPTION')) continue;
      const drug = nonEmpty[i].trim();
      const prescription = nonEmpty[i+1]?.trim() || '';
      if (drug && !drug.match(/^_+$/) && drug.length > 1 &&
          !['DIAGNOSIS','TREATMENT','COMPLIANCE'].some(k => drug.toUpperCase().includes(k))) {
        treatments.push({ drug, prescription: prescription.match(/^_+$/) ? '' : prescription });
        i++; // skip prescription line
      }
    }
  }

  return {
    cow_tag:             nextValue(['Cow ID/Tag','Cow ID']),
    body_weight:         nextValue(['Body weight']),
    age:                 nextValue(['Age']),
    breed:               nextValue(['Breed']),
    parity:              nextValue(['Parity']),
    daily_milk_yield:    nextValue(['Daily milk yield']),
    days_in_milk:        nextValue(['Days in milk']),
    body_temperature:    nextValue(['Body temperature']),
    pulse_rate:          nextValue(['Pulse rate(beats/mins)','Pulse rate']),
    respiratory_rate:    nextValue(['Respiratory rate(beats/min)','Respiratory rate']),
    crt_seconds:         nextValue(['CRT(seconds)','CRT']),
    rumino_motility:     nextValue(['Rumino-motility','Ruminomotility']),
    present_illness:     afterLine(['Present illness']),
    past_history:        afterLine(['Past history']),
    environment:         afterLine(['Environment']),
    system_review:       afterLine(['System review']),
    clinical_findings:   clinicalFindings,
    tentative_diagnosis: afterLine(['TENTATIVE DIAGNOSIS']) ||
                         afterLine(['Tentative/Final diagnosis']) ||
                         afterLine(['Tentative diagnosis']),
    final_diagnosis:     afterLine(['Tentative/Final diagnosis']) ||
                         afterLine(['Final diagnosis']),
    blood_smear:         nextValue(['Blood smear']),
    buffy_coat:          nextValue(['Buffy coat smear','Buffy coat']),
    pcv:                 nextValue(['PCV']),
    eosinophils:         nextValue(['Eosinophils']),
    basophils:           nextValue(['Basophils']),
    neutrophils:         nextValue(['Neutrophils']),
    bacteriology:        afterLine(['Bacteriology culture & sensitivity results','Bacteriology']),
    skin_scrapings:      afterLine(['Skin scrapings']),
    fecal_sample:        afterLine(['Fecal sample']),
    other_lab:           afterLine(['Other laboratory']),
    lab_findings:        afterLine(['Findings']),
    treatments,
    milk_withdraw_date:  afterLine(['Milk withdraw end date','Milk withdraw']),
    attending_vet:       afterLine(['Attending veterinarian/ paraveterinarian','Attending veterinarian']),
    license_number:      afterLine(['License #']),
    exam_date:           afterLine(['Date']),
  };
}
 
/* ── GET  /api/health-records  — list all (optionally by cow) */
app.get('/api/health-records', verifyToken, async (req, res) => {
  const { cow_id } = req.query;
  const params = [];
  const where = cow_id ? (params.push(cow_id), 'WHERE hr.cow_id = $1') : '';
  try {
    const { rows } = await pool.query(`
      SELECT hr.id, hr.cow_id, c.name AS cow_name, hr.cow_tag,
             hr.breed, hr.age, hr.exam_date,
             hr.tentative_diagnosis, hr.final_diagnosis,
             hr.attending_vet, hr.source_filename, hr.uploaded_at,
             JSONB_ARRAY_LENGTH(hr.treatments) AS treatment_count
      FROM cow_health_records hr
      LEFT JOIN cows c ON c.id = hr.cow_id
      ${where}
      ORDER BY hr.uploaded_at DESC
    `, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
 
/* ── GET  /api/health-records/:id  — full record */
app.get('/api/health-records/:id', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT hr.*, c.name AS cow_name
       FROM cow_health_records hr
       LEFT JOIN cows c ON c.id = hr.cow_id
       WHERE hr.id = $1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
 
/* ── POST /api/health-records/import  — upload .docx */
app.post('/api/health-records/import', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const ext = req.file.originalname.split('.').pop().toLowerCase();
  if (!['docx', 'doc'].includes(ext))
    return res.status(400).json({ error: 'Only .docx / .doc files are supported' });
 
  try {
    // 1. Extract text from docx
    const result = await mammoth.extractRawText({ buffer: req.file.buffer });
    const rawText = result.value;
 
    // 2. Parse fields from text
    const parsed = parseHealthDoc(rawText);
 
    // 3. Resolve cow_id — match by tag or name if provided in body or parsed
    let cow_id = req.body.cow_id ? parseInt(req.body.cow_id) : null;
    if (!cow_id && parsed.cow_tag) {
      const match = await pool.query(
        `SELECT id FROM cows WHERE tag = $1 OR UPPER(name) = UPPER($1) LIMIT 1`,
        [parsed.cow_tag]
      );
      if (match.rows.length) cow_id = match.rows[0].id;
    }
 
    // 4. Save to DB
    const { rows } = await pool.query(`
      INSERT INTO cow_health_records (
        cow_id, cow_tag, age, breed, parity, daily_milk_yield, days_in_milk,
        body_weight, body_temperature, pulse_rate, respiratory_rate,
        crt_seconds, rumino_motility, present_illness, past_history,
        environment, system_review, clinical_findings, tentative_diagnosis,
        blood_smear, buffy_coat, pcv, eosinophils, basophils, neutrophils,
        bacteriology, skin_scrapings, fecal_sample, other_lab, lab_findings,
        final_diagnosis, treatments, milk_withdraw_date, attending_vet,
        license_number, exam_date, source_filename
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
        $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,
        $33,$34,$35,$36,$37
      ) RETURNING id, cow_id, cow_tag, exam_date, final_diagnosis, uploaded_at
    `, [
      cow_id,
      parsed.cow_tag,
      parsed.age,
      parsed.breed,
      parsed.parity,
      parsed.daily_milk_yield,
      parsed.days_in_milk,
      parsed.body_weight,
      parsed.body_temperature,
      parsed.pulse_rate,
      parsed.respiratory_rate,
      parsed.crt_seconds,
      parsed.rumino_motility,
      parsed.present_illness,
      parsed.past_history,
      parsed.environment,
      parsed.system_review,
      JSON.stringify(parsed.clinical_findings),
      parsed.tentative_diagnosis,
      parsed.blood_smear,
      parsed.buffy_coat,
      parsed.pcv,
      parsed.eosinophils,
      parsed.basophils,
      parsed.neutrophils,
      parsed.bacteriology,
      parsed.skin_scrapings,
      parsed.fecal_sample,
      parsed.other_lab,
      parsed.lab_findings,
      parsed.final_diagnosis,
      JSON.stringify(parsed.treatments),
      parsed.milk_withdraw_date,
      parsed.attending_vet,
      parsed.license_number,
      parsed.exam_date,
      req.file.originalname,
    ]);
 
    res.status(201).json({
      success: true,
      record: rows[0],
      parsed_fields: Object.fromEntries(
        Object.entries(parsed).filter(([, v]) =>
          v !== null && (Array.isArray(v) ? v.length > 0 : true)
        )
      ),
      warnings: result.messages,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
 
/* ── DELETE /api/health-records/:id */
app.delete('/api/health-records/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_health_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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