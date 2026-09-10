const express = require('express');
const multer  = require('multer');
const XLSX    = require('xlsx');
const { pool } = require('../db');
const { findDailyGrid } = require('../lib/parsers');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// NOTE: mounted in server.js as
// `app.use('/api/import', verifyToken, requireProduction, importRouter)`.

router.post('/', upload.single('file'), async (req, res) => {
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
      january: 1, jan: 1,
      february: 2, feb: 2,
      march: 3, mar: 3,
      april: 4, apr: 4,
      may: 5,
      june: 6, jun: 6,
      july: 7, jul: 7,
      august: 8, aug: 8,
      september: 9, sep: 9,
      october: 10, oct: 10,
      november: 11, nov: 11,
      december: 12, dec: 12,
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
          const date = `${year}-${String(month).padStart(2, '0')}-${String(d.day).padStart(2, '0')}`;
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

module.exports = router;
