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