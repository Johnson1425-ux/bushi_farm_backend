const express = require('express');
const multer  = require('multer');
const { pool } = require('../db');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// NOTE: mounted in server.js as `app.use('/api/pregnancies', verifyToken, requireHealth, pregnanciesRouter)`.

router.get('/', async (req, res) => {
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

router.post('/', async (req, res) => {
  const { cow_id, conception_date, expected_due_date, notes } = req.body;
  if (!cow_id || !conception_date || !expected_due_date) return res.status(400).json({ error: 'cow_id, conception_date and expected_due_date required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO pregnancies(cow_id, conception_date, expected_due_date, notes, status)
       VALUES($1,$2,$3,$4,'active') RETURNING *`,
      [cow_id, conception_date, expected_due_date, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.patch('/:id', async (req, res) => {
  const { status, actual_birth_date, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE pregnancies SET
        status = COALESCE($1, status),
        actual_birth_date = COALESCE($2, actual_birth_date),
        notes = COALESCE($3, notes)
       WHERE id=$4 RETURNING *`,
      [status || null, actual_birth_date || null, notes || null, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM pregnancies WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   PREGNANCY IMPORT FROM EXCEL
══════════════════════════════════ */
router.post('/import', upload.single('file'), async (req, res) => {
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
      r.some(c => String(c || '').toUpperCase().includes('DATE')) &&
      r.some(c => String(c || '').toUpperCase().includes('NAME'))
    );
    if (headerIdx === -1) return res.status(400).json({ error: 'Could not find header row with DATE and NAME OF COW.' });

    const header    = rows[headerIdx];
    const dateCol   = header.findIndex(c => String(c || '').toUpperCase().trim() === 'DATE');
    const nameCol   = header.findIndex(c => String(c || '').toUpperCase().includes('NAME'));
    const breedCol  = header.findIndex(c => String(c || '').toUpperCase().includes('AINA') || String(c || '').toUpperCase().includes('MBEGU'));
    const doctorCol = header.findIndex(c => String(c || '').toUpperCase().includes('MPANDISHAJI') || String(c || '').toUpperCase().includes('DOCTOR'));

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

module.exports = router;
