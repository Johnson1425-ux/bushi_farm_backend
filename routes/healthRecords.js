const express = require('express');
const multer  = require('multer');
const mammoth = require('mammoth');
const { pool } = require('../db');
const { parseHealthDoc } = require('../lib/parsers');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// NOTE: mounted in server.js as `app.use('/api/health-records', verifyToken, requireHealth, healthRecordsRouter)`.

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

/* POST /import  — upload .docx */
router.post('/import', upload.single('file'), async (req, res) => {
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

/* DELETE /:id */
router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_health_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
