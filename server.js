require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const multer   = require('multer');
const XLSX     = require('xlsx');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const mammoth   = require('mammoth');
const { pool, ready }            = require('./db');
const {
  verifyToken, SECRET, ROLES,
  requireAdmin, requireProduction, requireHealth, requireRoleForWrites,
  loginRateLimit, recordLoginFailure, clearLoginFailures,
} = require('./auth');
const { parseProcessingWorkbook } = require('./processingParser');
const { buildProcessingTemplate } = require('./processingTemplate');
const aiRoutes                    = require('./aiRoutes');
const { initAiTables }            = require('./aiClient');

const app = express();

/* Uploads are parsed in memory, so cap them — without a limit a single large
   file can exhaust the process. Imports are spreadsheets and Word documents;
   10 MB is far above anything the farm actually uploads. */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* One CORS policy, applied to both real requests and preflights. A bare
   cors() call anywhere here would set Access-Control-Allow-Origin: * and
   silently override the allowlist below, so there must not be one. */
const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'https://bushi-farm.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

/* Start the schema work now, so a warm process has it done already. */
ready(initAiTables).catch(err => console.error('DB Init Error:', err.message));

/* Nothing is served until the schema is in place.

   Migrations begin at module load, but on a serverless host the first
   request can arrive while they are still running — which surfaces as a
   route failing on a column that is about to exist. ready() hands every
   caller the same promise, so this waits on the work already in flight
   rather than repeating it, and costs nothing once it has resolved.

   Calling ready() per request rather than awaiting a promise captured at
   load time also means a failed start is retried: the usual cause is the
   database still coming up, and a process that gave up once would
   otherwise serve 503s until it was redeployed. */
app.use(async (req, res, next) => {
  try {
    await ready(initAiTables);
    next();
  } catch (err) {
    console.error('DB Init Error:', err.message);
    res.status(503).json({
      error: 'The database is not ready yet. Try again in a moment.',
      detail: err.message,
    });
  }
});

/* ══════════════════════════════════
   AUTH ROUTES  (public)
══════════════════════════════════ */
app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username.trim()]);
    const user = rows[0];
    if (!user) { recordLoginFailure(req); return res.status(401).json({ error: 'Invalid credentials' }); }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) { recordLoginFailure(req); return res.status(401).json({ error: 'Invalid credentials' }); }
    clearLoginFailures(req);
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
   ROLE GATES

   Registered before the route handlers so they apply to every method and
   sub-path underneath, including ones added later. This is the authorization
   boundary — the sidebar only decides what is convenient to show, so a route
   that is not covered here is open to any signed-in account.

   Managers own production and the commercial side; vets own animal health.
   Neither can reach the other's data. Reads and writes are both gated for
   these areas, because seeing the data is the thing being restricted.
══════════════════════════════════ */

/* Manager territory. */
app.use('/api/sales',      verifyToken, requireProduction);
app.use('/api/inventory',  verifyToken, requireProduction);
app.use('/api/processing', verifyToken, requireProduction);
app.use('/api/import',     verifyToken, requireProduction);

/* Vet territory. */
app.use('/api/diseases',       verifyToken, requireHealth);
app.use('/api/treatments',     verifyToken, requireHealth);
app.use('/api/pregnancies',    verifyToken, requireHealth);
app.use('/api/health-records', verifyToken, requireHealth);
app.use('/api/cow-history',    verifyToken, requireHealth);

/* Shared reads, restricted writes. Every signed-in account can browse the
   production record; only admins and managers may change it.
   (/api/cows is deliberately not gated here — its writes are guarded on the
   individual routes, because cow history underneath it belongs to the vet.) */
app.use('/api/records', verifyToken, requireRoleForWrites('admin', 'manager'));

/* Account management. */
app.use('/api/users', verifyToken, requireAdmin);

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
  /* Default to the most limited role, and validate against ROLES so this list
     cannot drift from the database constraint the way it did with 'viewer'. */
  const { username, password, role = 'veteran' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: `Role must be one of: ${ROLES.join(', ')}` });
  }
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
    /* The herd list means the herd you have, so archived animals are left
       out unless they are asked for. Their records are untouched either
       way — this filters who is shown, never what is stored. */
    const status = String(req.query.status || 'active').toLowerCase();
    const where = status === 'all'      ? ''
                : status === 'archived' ? `WHERE c.status <> 'active'`
                :                         `WHERE c.status = 'active'`;

    const { rows } = await pool.query(`
      SELECT
        c.id, c.name, c.tag, c.breed, c.created_at,
        c.status, TO_CHAR(c.archived_at, 'YYYY-MM-DD') AS archived_at, c.archived_note,
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
      ${where}
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

/* Take an animal out of the herd without touching her records.

   This is what a death, a sale or a culling calls for — the opposite of a
   delete. She stops appearing in the herd list, stops counting toward
   current averages and stops raising alerts, while every litre she produced
   still counts toward the totals for the period she was alive.

   Open to managers as well as admins: animals leave the herd as a matter of
   routine, and routing that through an admin would push people back toward
   the delete button. */
const ARCHIVE_REASONS = ['dead', 'sold', 'culled'];

app.post('/api/cows/:id/archive', verifyToken, requireProduction, async (req, res) => {
  const status = String(req.body?.status || '').toLowerCase();
  const note   = typeof req.body?.note === 'string' ? req.body.note.trim().slice(0, 500) : '';
  const date   = /^\d{4}-\d{2}-\d{2}$/.test(req.body?.date || '') ? req.body.date : null;

  if (!ARCHIVE_REASONS.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${ARCHIVE_REASONS.join(', ')}` });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE cows
          SET status = $1,
              archived_at = COALESCE($2::date, CURRENT_DATE),
              archived_note = NULLIF($3, ''),
              archived_by = $4
        WHERE id = $5
        RETURNING id, name, status, TO_CHAR(archived_at, 'YYYY-MM-DD') AS archived_at, archived_note`,
      [status, date, note, req.user.id, req.params.id]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cow not found' });
    }

    // Leaving the herd is part of the animal's story, so it goes on her timeline.
    await client.query(
      `INSERT INTO cow_history (cow_id, event_type, date, source, notes)
       VALUES ($1, $2, COALESCE($3::date, CURRENT_DATE), 'archive', NULLIF($4, ''))`,
      [req.params.id, status, date, note]
    );

    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* Undo an archive that was made in error. */
app.post('/api/cows/:id/restore', verifyToken, requireProduction, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE cows
          SET status = 'active', archived_at = NULL, archived_note = NULL, archived_by = NULL
        WHERE id = $1
        RETURNING id, name, status`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Cow not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Permanently remove a cow and everything recorded about her.

   This is for a row that should never have existed — a duplicate, a name
   typed twice. For an animal that has left the herd, archive her instead:
   deleting cascades through milk_records, cow_health_records, pregnancies,
   disease_cows and cow_history, which rewrites past totals that were
   correct when they were reported.

   A cow with production history cannot be deleted without saying so
   explicitly, so this cannot be reached by clicking through a dialog. */
app.delete('/api/cows/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.name, COUNT(r.id)::int AS record_count
         FROM cows c LEFT JOIN milk_records r ON r.cow_id = c.id
        WHERE c.id = $1 GROUP BY c.name`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Cow not found' });

    const { name, record_count } = rows[0];
    if (record_count > 0 && req.query.force !== 'true') {
      return res.status(409).json({
        error: `${name} has ${record_count} milk records. Deleting her removes them from `
             + `the farm's history and changes past totals. Archive her instead, or repeat `
             + `this request with force=true if the record is genuinely a mistake.`,
        record_count,
        archive_instead: `/api/cows/${req.params.id}/archive`,
      });
    }

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


/* Managers own the production record, so they may correct it as well as add
   to it. The /api/records prefix gate above already limits this to
   admin and manager. */
app.delete('/api/records/:id', verifyToken, async (req, res) => {
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
/**
 * Find the daily-readings grid in a workbook.
 *
 * The sheet is chosen by shape — a header row carrying both a cow column and
 * numbered day columns — rather than by position or by name. Position fails
 * because the production workbooks put a month-by-month summary in front of
 * the daily grid; that summary has a "NAME OF COW" column too, so it looks
 * like the right sheet until you notice its columns are month names. Name
 * matching fails because the names are not stable: the same workbook family
 * has "DAIRY PRODUCTION" one month and "DAILY PRODUCTION" the next, with the
 * summary tab spelled "MONTHLY" or "MONTHRRY".
 *
 * Returns the winning sheet plus a note on every sheet examined, so a failure
 * can say what was actually found instead of blaming the file.
 */
function findDailyGrid(wb) {
  const examined = [];

  for (const name of wb.SheetNames) {
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[name], { header: 1 });

    // The header can sit below title rows, so scan for it rather than
    // assuming row 1 — but only consider a row that has day columns on it,
    // otherwise the summary sheet's "NAME OF COW" row wins and the real
    // grid further down the workbook is never reached.
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i] || [];
      const cowColIndex = row.findIndex(c => String(c).toUpperCase().includes('COW'));
      if (cowColIndex === -1) continue;

      const dayColumns = [];
      row.forEach((col, idx) => {
        const day = parseInt(col, 10);
        if (!isNaN(day) && day >= 1 && day <= 31) dayColumns.push({ day, idx });
      });

      if (dayColumns.length) {
        return { sheetName: name, rows, headerIndex: i, cowColIndex, dayColumns, examined };
      }
      examined.push({ sheet: name, found: 'a cow column but no day columns' });
      break;
    }
    if (!examined.some(e => e.sheet === name)) {
      examined.push({ sheet: name, found: 'no cow column' });
    }
  }

  return { sheetName: null, examined };
}

app.post('/api/import', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
    if (!wb.SheetNames.length) return res.status(400).json({ error: 'Empty file' });

    const grid = findDailyGrid(wb);
    if (!grid.sheetName) {
      /* Name the sheets and say what each one was missing. "No day columns
         found" on its own sends people looking for a fault in a file that is
         usually fine — the readings were just on a sheet further along. */
      return res.status(400).json({
        error: 'No sheet in this workbook has a daily readings grid '
             + '(a cow column plus columns numbered 1–31).',
        sheets_checked: grid.examined,
      });
    }

    const { rows, headerIndex, cowColIndex, dayColumns } = grid;

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
    const cowsSeen = new Set();
    try {
      await client.query('BEGIN');
      for (const row of rows.slice(headerIndex + 1)) {
        const cowName = String(row[cowColIndex] || '').trim();
        if (!cowName) continue;
        /* The grid ends in totals and averages rows that have no cow name of
           their own but do carry figures. Anything below the last named row
           is footer, not another animal. */
        if (/^(TOTAL|AVERAGE|AVG|GRAND TOTAL|SUM)\b/i.test(cowName)) continue;
        cowsSeen.add(cowName);
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
    /* The sheet comes back with the result: when a workbook holds several
       candidates, knowing which one was read is the difference between
       trusting the import and re-checking it by hand. */
    res.json({
      success: true, added, skipped,
      detected_month: month, detected_year: year,
      sheet: grid.sheetName,
      cows: cowsSeen.size,
    });
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
      /* Head count is the herd you have today; every other figure here is
         history and keeps the milk archived animals produced. Dropping their
         records would change totals that were correct when reported. */
      SELECT
        COALESCE(COUNT(DISTINCT c.id) FILTER (WHERE c.status = 'active')::int, 0) AS total_cows,
        COALESCE(COUNT(DISTINCT c.id) FILTER (WHERE c.status <> 'active')::int, 0) AS archived_cows,
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

/* Whole-farm production, one row per calendar month.

   Deliberately not filtered by cow status: this is history, and a cow that
   has since died or been sold still produced the milk credited to the month
   she produced it in. Filtering archived animals out here would make last
   year's totals change every time an animal leaves the herd.

   `days_recorded` counts days that actually have readings rather than days
   in the month, so avg_per_day is not dragged down by days nobody milked —
   a half-entered month reads as a half-entered month, not a bad one. */
app.get('/api/analytics/monthly', verifyToken, async (req, res) => {
  const cowId = parseInt(req.query.cow_id, 10);
  const args = [];
  let where = '';
  if (Number.isInteger(cowId)) { args.push(cowId); where = 'WHERE cow_id = $1'; }

  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(date, 'YYYY-MM')                AS month,
             ROUND(SUM(litres)::numeric, 1)          AS total_litres,
             COUNT(*)::int                           AS records,
             COUNT(DISTINCT cow_id)::int             AS cows_milked,
             COUNT(DISTINCT date)::int               AS days_recorded,
             ROUND(AVG(litres)::numeric, 2)          AS avg_per_record,
             ROUND((SUM(litres) / NULLIF(COUNT(DISTINCT date), 0))::numeric, 1) AS avg_per_day,
             ROUND(MAX(litres)::numeric, 1)          AS best_single_record
      FROM milk_records
      ${where}
      GROUP BY 1
      ORDER BY 1 DESC
    `, args);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Which cows made up one month's total. The obvious next question after
   seeing a month move, so it is one request away rather than a page away. */
app.get('/api/analytics/monthly/:month', verifyToken, async (req, res) => {
  const month = String(req.params.month || '');
  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: 'month must be formatted YYYY-MM' });
  }
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.tag, c.status,
             ROUND(SUM(r.litres)::numeric, 1)  AS total_litres,
             ROUND(AVG(r.litres)::numeric, 2)  AS avg_litres,
             COUNT(r.id)::int                  AS days_recorded
      FROM milk_records r
      JOIN cows c ON c.id = r.cow_id
      WHERE TO_CHAR(r.date, 'YYYY-MM') = $1
      GROUP BY c.id
      ORDER BY total_litres DESC
    `, [month]);
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
// app.get('/api/public/stats', async (req, res) => {
//   try {
//     const { rows } = await pool.query(`
//       SELECT
//         COALESCE(COUNT(DISTINCT c.id)::int, 0)       AS total_cows,
//         COALESCE(COUNT(r.id)::int, 0)                AS total_records,
//         COALESCE(ROUND(SUM(r.litres)::numeric, 1), 0) AS total_litres,
//         COALESCE(ROUND(AVG(r.litres)::numeric, 2), 0) AS overall_avg,
//         COALESCE(COUNT(DISTINCT r.date)::int, 0)     AS days_tracked
//       FROM cows c LEFT JOIN milk_records r ON r.cow_id = c.id
//     `);
//     res.json(rows[0]);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

/* ══════════════════════════════════
   DISEASES & TREATMENTS
══════════════════════════════════ */
app.get('/api/diseases', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.id, d.name, d.description, TO_CHAR(d.date,'YYYY-MM-DD') AS date, d.notes,
        COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', c.id, 'name', c.name)) FILTER (WHERE c.id IS NOT NULL), '[]') AS affected_cows,
        COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', t.id, 'medicine', t.medicine_name, 'dosage', t.dosage, 'date', TO_CHAR(t.date,'YYYY-MM-DD'), 'notes', t.notes)) FILTER (WHERE t.id IS NOT NULL), '[]'::json) AS treatments,
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

app.patch('/api/diseases/:id', verifyToken, async (req, res) => {
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

app.delete('/api/diseases/:id', verifyToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM diseases WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/diseases/:id/treatments', verifyToken, async (req, res) => {
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

app.delete('/api/treatments/:id', verifyToken, async (req, res) => {
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

app.post('/api/cows/:id/history', verifyToken, requireHealth, async (req, res) => {
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

app.delete('/api/cow-history/:id', verifyToken, async (req, res) => {
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
      SELECT p.id, p.cow_id, c.name AS cow_name, c.tag AS cow_tag,
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

app.post('/api/pregnancies', verifyToken, async (req, res) => {
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

app.patch('/api/pregnancies/:id', verifyToken, async (req, res) => {
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

app.delete('/api/pregnancies/:id', verifyToken, async (req, res) => {
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
      WHERE c.status = 'active' AND l.litres < a.avg_litres * 0.75
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
      WHERE c.status = 'active'
        AND p.status = 'active' AND p.expected_due_date BETWEEN CURRENT_DATE AND CURRENT_DATE + 14
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
      WHERE c.status = 'active'
        AND p.status = 'active' AND p.expected_due_date < CURRENT_DATE
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
app.post('/api/pregnancies/import', verifyToken, upload.single('file'), async (req, res) => {
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

app.delete('/api/sales/:id', verifyToken, async (req, res) => {
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

app.post('/api/sales/import', verifyToken, upload.single('file'), async (req, res) => {
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

app.post('/api/inventory/items', verifyToken, async (req, res) => {
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

app.patch('/api/inventory/items/:id', verifyToken, async (req, res) => {
  const { name, unit, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE inventory_items SET name=$1, unit=$2, notes=$3 WHERE id=$4 RETURNING *`,
      [name, unit, notes || null, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/inventory/items/:id', verifyToken, async (req, res) => {
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

app.post('/api/inventory/import', verifyToken, upload.single('file'), async (req, res) => {
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
   LATE ADDITIONS

   The two handlers below have no counterpart in the sections above. The rest
   of this block used to be second copies of routes already registered earlier
   in the file, which Express never reached — they have been removed.
══════════════════════════════════ */

/* Treatments for a single disease. The disease list already embeds them, but
   the Health page's treatment modal fetches them on their own. */
app.get('/api/diseases/:id/treatments', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, disease_id, medicine_name, dosage, TO_CHAR(treatments.date,'YYYY-MM-DD') AS date, notes FROM treatments WHERE disease_id=$1 ORDER BY treatments.date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});





/* Nested delete for a cow history entry. The UI uses DELETE /api/cow-history/:id
   instead; this variant is kept for any caller that scopes by cow. */
app.delete('/api/cows/:id/history/:hid', verifyToken, requireHealth, async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_history WHERE id=$1 AND cow_id=$2', [req.params.hid, req.params.id]);
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
      WHERE c.status = 'active' AND r.avg_recent < o.avg_all * 0.80
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
      WHERE c.status = 'active'
        AND p.status = 'active'
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
   PROCESSING UNIT

   GET    /api/processing            — list all uploads
   GET    /api/processing/template   — download the blank workbook
   GET    /api/processing/:id        — full data for one upload
   POST   /api/processing/upload     — parse & save a workbook
   DELETE /api/processing/:id        — delete an upload
══════════════════════════════════ */

/* List all uploads, newest month first.

   Ordering is by the month the figures belong to, not by when the file was
   uploaded — a month keyed in late would otherwise jump to the top of the
   list. Rows imported before month_num existed fall back to upload time. */
app.get('/api/processing', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.label, u.uploaded_at, u.month_num, u.year, u.source,
             usr.username AS uploaded_by
      FROM processing_uploads u
      LEFT JOIN users usr ON usr.id = u.uploaded_by
      ORDER BY u.year DESC NULLS LAST, u.month_num DESC NULLS LAST, u.uploaded_at DESC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Download the blank workbook.

   Generated on demand from the same catalogue the parser validates against,
   so the sheet someone types into can never expect different products from
   the sheet the app reads back. Registered before the /:id route below,
   which would otherwise swallow "template" as an id. */
app.get('/api/processing/template', verifyToken, async (req, res) => {
  try {
    const months = typeof req.query.months === 'string' && req.query.months.trim()
      ? req.query.months.split(',').map(s => s.trim()).filter(Boolean)
      : undefined;
    const year = req.query.year ? parseInt(req.query.year, 10) : undefined;

    const buffer = await buildProcessingTemplate({ months, year });
    const name = `MilkTrack_Processing_${year || new Date().getUTCFullYear()}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    res.send(buffer);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

/* Full data for one upload — daily arrays plus the stock reconciliation. */
app.get('/api/processing/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const uploadRes = await pool.query(
      `SELECT u.id, u.label, u.uploaded_at, u.month_num, u.year, u.source,
              u.opening_fresh_litres, u.fresh_damage_litres,
              usr.username AS uploaded_by
       FROM processing_uploads u LEFT JOIN users usr ON usr.id = u.uploaded_by
       WHERE u.id=$1`,
      [id]
    );
    if (!uploadRes.rows.length) return res.status(404).json({ error: 'Not found' });

    const daily = (table) => pool.query(
      `SELECT day, product, size, units, litres FROM ${table}
       WHERE upload_id=$1 ORDER BY product, size, day`, [id]
    );

    const [received, packed, issued, damaged, stock] = await Promise.all([
      pool.query(
        `SELECT day, farm_litres, mwabulugu_litres, purchased_litres, damaged_litres
         FROM processing_milk_received WHERE upload_id=$1 ORDER BY day`, [id]
      ),
      daily('processing_packed'),
      daily('processing_issued'),
      daily('processing_damaged'),
      pool.query(
        `SELECT product, size, opening_units, packed_units, issued_units,
                damaged_units, units, litres
         FROM processing_stock WHERE upload_id=$1 ORDER BY product, size`, [id]
      ),
    ]);

    res.json({
      upload:   uploadRes.rows[0],
      received: received.rows,
      packed:   packed.rows,
      issued:   issued.rows,
      damaged:  damaged.rows,
      stock:    stock.rows,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Upload & parse a processing workbook (xlsx).

   Two layouts are accepted: the template this app hands out, and the farm's
   own BUSH_PROCESSING_UNIT workbook. See processingParser.js for how each is
   recognised.

   A structural problem returns 422 with the specific list of what is wrong
   rather than importing part of the file. Warnings — a missing pack size, an
   unlabelled cell, a product that closes negative — do not block the import;
   they come back with the result so the operator can check them against the
   original sheet.

   Re-uploading a month REPLACES that month, so a corrected workbook can be
   sent again without creating a second copy. */
app.post('/api/processing/upload', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const parsed = parseProcessingWorkbook(req.file.buffer);

  if (!parsed.ok) {
    return res.status(422).json({
      error:  'The workbook could not be imported. Fix the issues below and re-upload.',
      issues: parsed.errors,
      warnings: parsed.warnings,
    });
  }

  const client  = await pool.connect();
  const results = [];

  try {
    await client.query('BEGIN');

    for (const m of parsed.months) {
      // Replace the month wholesale; ON DELETE CASCADE clears the child rows.
      await client.query('DELETE FROM processing_uploads WHERE label=$1', [m.label]);

      const upRes = await client.query(
        `INSERT INTO processing_uploads
           (label, uploaded_by, month_num, year, source, opening_fresh_litres, fresh_damage_litres)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
        [m.label, req.user.id, m.monthNum, m.year, m.source, m.openingFreshLitres, m.freshDamageLitres]
      );
      const uploadId = upRes.rows[0].id;

      /* ── milk received: one row per day, sources across the columns ── */
      const byDay = new Map();
      const dayRow = (day) => {
        if (!byDay.has(day)) byDay.set(day, { farm: 0, mwabulugu: 0, purchased: 0, damaged: 0 });
        return byDay.get(day);
      };
      for (const r of m.received) {
        const row = dayRow(r.day);
        if (r.source === 'PURCHASED')           row.purchased += r.litres;
        else if (r.source === 'FARM MWABULUGU') row.mwabulugu += r.litres;
        else                                    row.farm      += r.litres;
      }
      /* Fresh milk written off is dated when the sheet dates it; the legacy
         workbook gives only a monthly figure, which lands on day 1. These
         daily rows are a breakdown of processing_uploads.fresh_damage_litres,
         not a second loss — read one or the other, never their sum. */
      for (const d of m.freshDamage) dayRow(d.day || 1).damaged += d.litres;

      for (const [day, v] of byDay) {
        await client.query(
          `INSERT INTO processing_milk_received
             (upload_id, day, farm_litres, mwabulugu_litres, purchased_litres, damaged_litres)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [uploadId, day, v.farm, v.mwabulugu, v.purchased, v.damaged]
        );
      }

      /* ── daily pack movements ── */
      const insertDaily = async (table, rows) => {
        for (const r of rows) {
          await client.query(
            `INSERT INTO ${table} (upload_id, day, product, size, units, litres)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [uploadId, r.day, r.product, r.size, r.units, r.litres]
          );
        }
      };
      await insertDaily('processing_packed',  m.packed);
      await insertDaily('processing_issued',  m.issued);
      await insertDaily('processing_damaged', m.damaged);

      /* ── closing stock, with the movements that produced it ── */
      for (const s of m.stock) {
        await client.query(
          `INSERT INTO processing_stock
             (upload_id, product, size, opening_units, packed_units,
              issued_units, damaged_units, units, litres)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [uploadId, s.product, s.size, s.opening, s.packed,
           s.issued, s.damaged, s.closing, s.closing_litres]
        );
      }

      const total = (rows, key) => rows.reduce((a, r) => a + (r[key] || 0), 0);
      results.push({
        upload_id: uploadId,
        label: m.label,
        source: m.source,
        sheets: m.sheets,
        summary: {
          received_litres: Math.round(total(m.received, 'litres') * 10) / 10,
          packed_units:    total(m.packed, 'units'),
          packed_litres:   Math.round(total(m.packed, 'litres') * 10) / 10,
          issued_units:    total(m.issued, 'units'),
          damaged_units:   total(m.damaged, 'units'),
          closing_units:   total(m.stock, 'closing'),
        },
      });
    }

    await client.query('COMMIT');

    res.status(201).json({
      success:         true,
      months_imported: results.length,
      months:          results,
      // The client shows the newest month it just imported.
      upload_id:       results[0]?.upload_id ?? null,
      warnings:        parsed.warnings,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* Delete an upload */
app.delete('/api/processing/:id', verifyToken, async (req, res) => {
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
app.delete('/api/health-records/:id', verifyToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_health_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   AI REPORTS  (see aiRoutes.js)
══════════════════════════════════ */
app.use('/api/ai', aiRoutes);

/* ══════════════════════════════════
   START (Updated for Vercel)
══════════════════════════════════ */

// 1. Schema setup is kicked off above, next to the middleware that waits on
//    it, so the two cannot drift apart.

// 2. EXPORT the app (Mandatory for Vercel)
module.exports = app;

// 3. ONLY listen if running locally
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`✓ MilkTrack API running on http://localhost:${PORT}`);
  });
}