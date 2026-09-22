const XLSX = require('xlsx');

/* ══════════════════════════════════
   Small generic helpers
══════════════════════════════════ */

function findKey(sample, candidates) {
  const keys = Object.keys(sample);
  for (const c of candidates) {
    const k = keys.find(k => k.toLowerCase().replace(/[\s_\-]/g, '').includes(c));
    if (k) return k;
  }
  return null;
}

function parseDate(val) {
  if (!val) return null;
  if (val instanceof Date) return val.toISOString().slice(0, 10);
  const s = String(val).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const parts = s.split(/[\/\-\.]/);
  if (parts.length === 3) {
    const [a, b, c] = parts.map(Number);
    if (c > 1000) return `${c}-${String(b).padStart(2, '0')}-${String(a).padStart(2, '0')}`;
    return new Date(s).toISOString().slice(0, 10);
  }
  const d = new Date(s);
  return isNaN(d) ? null : d.toISOString().slice(0, 10);
}

/* ══════════════════════════════════
   Bulk-import grid finder (used by routes/importData.js)
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

/* ══════════════════════════════════
   The Individual Health Record form is read by lib/healthRecordParser.js,
   which works from the document's tables rather than from flattened text
   and shares its labels with the blank form the app hands out.
══════════════════════════════════ */

module.exports = { findKey, parseDate, findDailyGrid };
