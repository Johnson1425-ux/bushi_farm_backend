const express = require('express');
const multer  = require('multer');
const { pool } = require('../db');
const { parseHealthDocx } = require('../lib/healthRecordParser');
const { COLUMNS, normaliseRecord, valueFor } = require('../lib/healthRecordForm');
const { buildHealthRecordTemplate } = require('../lib/healthRecordTemplate');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// NOTE: mounted in server.js as `app.use('/api/health-records', verifyToken, requireHealth, healthRecordsRouter)`.

/* ─── shared write path ───────────────────────────────────────
   A record reaches the table two ways — typed into the in-app form, or
   parsed out of an uploaded .docx — and both write the same columns. They
   build their SQL from the same COLUMNS list rather than from two
   hand-written parameter lists, because the hand-written pair is what let
   a field be added to one path and forgotten in the other. */

function insertSql(extraColumns = []) {
  const cols = [...COLUMNS, ...extraColumns];
  const ph   = cols.map((_, i) => `$${i + 1}`).join(',');
  return `INSERT INTO cow_health_records (${cols.join(',')}) VALUES (${ph})
          RETURNING id, cow_id, cow_tag, exam_date, final_diagnosis, uploaded_at`;
}

function insertValues(record, extras = []) {
  return [...COLUMNS.map(c => valueFor(record, c)), ...extras];
}

/**
 * The cow this record belongs to.
 *
 * An explicit choice in the form wins. Failing that the tag written on the
 * sheet is matched against the herd, so an uploaded form finds its cow
 * without anyone picking it from a list. A tag that matches nothing leaves
 * the record unlinked rather than attached to the wrong animal — the list
 * shows it as "Unlinked" and it can be edited afterwards.
 */
async function resolveCowId(explicitId, tag) {
  if (explicitId) {
    const id = parseInt(explicitId, 10);
    if (Number.isInteger(id)) return id;
  }
  if (!tag) return null;
  const { rows } = await pool.query(
    `SELECT id FROM cows WHERE tag = $1 OR UPPER(name) = UPPER($1) LIMIT 1`,
    [tag]
  );
  return rows.length ? rows[0].id : null;
}

/* GET /template — the blank form, as a Word document.

   Declared above `/:id` so the router does not read "template" as a
   record id. */
router.get('/template', async (req, res) => {
  try {
    const buffer = await buildHealthRecordTemplate();
    res.setHeader('Content-Type',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition',
      'attachment; filename="Bushi Dairy Farm Individual Health Record.docx"');
    res.send(buffer);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* GET /  — list all (optionally by cow) */
router.get('/', async (req, res) => {
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

/* GET /:id  — full record */
router.get('/:id', async (req, res) => {
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

/* POST /  — save a form filled in the app.

   The sheet is an examination record, so the one thing it cannot be
   missing is which animal was examined: either a cow picked from the herd
   or the tag written at the top. Everything else on the form is a finding,
   and a finding the vet did not record is a blank, not an error. */
router.post('/', async (req, res) => {
  const record = normaliseRecord(req.body);
  const cow_id = await resolveCowId(req.body.cow_id, record.cow_tag).catch(() => null);

  if (!cow_id && !record.cow_tag)
    return res.status(400).json({ error: 'Choose a cow, or write the ID/Tag no. from the form.' });

  try {
    const { rows } = await pool.query(
      insertSql(['cow_id', 'source_filename']),
      insertValues(record, [cow_id, null])
    );
    res.status(201).json({ success: true, record: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* PUT /:id  — edit a record, whichever way it first arrived.

   A parsed upload is a best reading of someone's handwriting, so the vet
   has to be able to correct it; this is the same write as POST against an
   existing row. source_filename is left alone — where the record came from
   does not change because a field was fixed. */
router.put('/:id', async (req, res) => {
  const record = normaliseRecord(req.body);
  const cow_id = await resolveCowId(req.body.cow_id, record.cow_tag).catch(() => null);

  if (!cow_id && !record.cow_tag)
    return res.status(400).json({ error: 'Choose a cow, or write the ID/Tag no. from the form.' });

  const cols   = [...COLUMNS, 'cow_id'];
  const setSql = cols.map((c, i) => `${c} = $${i + 1}`).join(', ');
  const values = [...insertValues(record, [cow_id]), req.params.id];

  try {
    const { rows } = await pool.query(
      `UPDATE cow_health_records
          SET ${setSql}, updated_at = NOW()
        WHERE id = $${values.length}
        RETURNING id, cow_id, cow_tag, exam_date, final_diagnosis, uploaded_at`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, record: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* POST /import  — upload a filled .docx of the same form */
router.post('/import', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const ext = req.file.originalname.split('.').pop().toLowerCase();
  if (!['docx', 'doc'].includes(ext))
    return res.status(400).json({ error: 'Only .docx / .doc files are supported' });

  try {
    // 1. Read the form's fields out of the document, then put them through
    //    the same normalisation the in-app form uses, so a parsed record and
    //    a typed one are stored identically.
    const { fields, warnings } = await parseHealthDocx(req.file.buffer);
    const parsed = normaliseRecord(fields);

    // 2. Resolve the cow — an explicit choice in the upload dialog, else
    //    the tag written on the sheet.
    const cow_id = await resolveCowId(req.body.cow_id, parsed.cow_tag);

    // 3. Save
    const { rows } = await pool.query(
      insertSql(['cow_id', 'source_filename']),
      insertValues(parsed, [cow_id, req.file.originalname])
    );

    res.status(201).json({
      success: true,
      record: rows[0],
      parsed_fields: Object.fromEntries(
        Object.entries(parsed).filter(([, v]) =>
          v !== null && (Array.isArray(v) ? v.length > 0 : true)
        )
      ),
      warnings,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* DELETE /:id */
router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_health_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
