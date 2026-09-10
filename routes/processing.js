const express = require('express');
const multer  = require('multer');
const { pool } = require('../db');
const { parseProcessingWorkbook } = require('../processingParser');
const { buildProcessingTemplate } = require('../processingTemplate');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// NOTE: mounted in server.js as `app.use('/api/processing', verifyToken, requireProduction, processingRouter)`.

/* List all uploads, newest month first.

   Ordering is by the month the figures belong to, not by when the file was
   uploaded — a month keyed in late would otherwise jump to the top of the
   list. Rows imported before month_num existed fall back to upload time. */
router.get('/', async (req, res) => {
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
router.get('/template', async (req, res) => {
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
router.get('/:id', async (req, res) => {
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
router.post('/upload', upload.single('file'), async (req, res) => {
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
router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM processing_uploads WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
