/* ══════════════════════════════════════════════════════════════
   THE EXPENSE CATALOGUE

   The farm keeps one workbook a month — "2026 SEPTEMBER EXPENSES" — and
   every figure in it lands on one of a dozen lines. Those lines are the
   rows of its SUMMARY sheet, and they are the same twelve from January
   to December, which is what makes the summary readable across a year.

   So the categories are a fixed list, seeded here, rather than free text
   typed at entry time. Two spellings of "Home affairs" would split a
   line in half and quietly take money out of the month's total.

   Each category also carries the sheet names it is known by, because a
   category and a sheet are not the same thing:

     • FARM MWANZA holds three categories side by side — food, medical
       and operating cost — as three blocks of columns on one sheet.
     • The spelling moves around. CSR is filed as "CRS", the summary
       writes "MARKETING &ADV" where the sheet says "MARKERTING,
       ADVERTISEMENT & BUSSINESS DEVELOPMENT", and the mini tractor is
       "MIN TRACTOR" on the tab and "min trector" in the rows beneath.

   Matching is on letters and digits alone, so spacing, punctuation and
   case cannot decide which line a sheet belongs to.
══════════════════════════════════════════════════════════════ */

/** Letters and digits only — the form every name is compared in. */
const norm = (s) => String(s ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');

/* The summary's own order, because that is the order the farm reads its
   month in. `sort_order` follows it, and the app's grid follows that. */
const CATEGORIES = [
  {
    name: 'Investment',
    sheets: ['INVESTMENT', 'INVESTMENTCOST', 'INVESTMENTCOSTMWANZA'],
    note: 'What the farm builds or buys to keep — not what it spends to run.',
  },
  {
    name: 'Farm food',
    sheets: ['FARMFOOD', 'FOOD'],
    note: 'Feed bought for the herd: machicha, pumba, mashudu, nyasi, minerals.',
  },
  {
    name: 'Farm medical',
    sheets: ['FARMMEDICAL', 'MEDICALANDOTHERS', 'MEDICAL'],
    note: 'Drugs, vaccines and the vet, for the herd.',
  },
  {
    name: 'Farm operating cost',
    sheets: ['FARMOPERATINGCOST', 'FARMOPERATINGEXPENSES', 'OPERATINGEXPENSES'],
    note: 'Running the farm day to day: fuel, repairs, fares, casual labour.',
  },
  {
    name: 'Home affairs',
    sheets: ['HOMEAFFAIRS'],
    note: 'The household, kept on the same book but on its own line.',
  },
  {
    name: 'Salaries',
    sheets: ['SALARY', 'SALARIES', 'PAYROLL', 'PAYROLLS'],
    note: 'The monthly payroll, net of advances already drawn.',
  },
  {
    name: 'Marketing & advertising',
    sheets: ['MARKETING', 'MARKERTING', 'MARKETINGADV', 'ADVERTISEMENT'],
    note: 'Advertising and business development.',
  },
  {
    name: 'Finance & statutory',
    sheets: ['FINANCESTATUTORY', 'FINANCEANDSTATUTORY', 'INTERESTSTATUTORYCOST', 'FINANCE'],
    note: 'Interest, bank charges, licences, taxes and fees.',
  },
  {
    name: 'BMH',
    sheets: ['BMH', 'BMHEXPENSES'],
    note: 'Milk bought in and the shops that sell it — the trading side.',
  },
  {
    name: 'Scania',
    sheets: ['SCANIA'],
    note: 'The lorry: diesel, repairs, fines, the driver\'s allowance.',
  },
  {
    name: 'CSR',
    sheets: ['CSR', 'CRS'],
    note: 'What the farm gives back — contributions and community spending.',
  },
  {
    name: 'Min tractor',
    sheets: ['MINTRACTOR', 'MINITRACTOR', 'MINTRECTOR', 'MINITRECTOR'],
    note: 'The mini tractor and the trailer built for it.',
  },

  /* Below the summary's twelve: lines the year-end sheet carries and the
     month sheets keep open, so a figure filed under one of them has
     somewhere to land instead of being forced onto a neighbouring line. */
  { name: 'Marya',       sheets: ['MARYA'] },
  { name: 'Electronics', sheets: ['ELECTRONICS'] },
  { name: 'Shop expenses', sheets: ['SHOPEXPENSES'], note: 'Running the shops themselves.' },
  {
    name: 'Shop (home affairs)',
    sheets: ['SHOPHOMEAFFAIRS', 'SHOPHOMEAFFARIS'],
    note: 'Household shopping put through the shop.',
  },
];

/* ── sheets that are read by something other than the ledger ──

   Recognised and skipped on purpose, each for a reason worth saying out
   loud at import time. Silence here would look like the importer had
   missed them.

   The three payment sheets and the two consumption sheets are not extra
   spending: they are the same money cut a different way — by supplier,
   by drug, by what the herd ate in a day. Importing them alongside the
   detail sheets would count every shilling twice. */
const IGNORED_SHEETS = [
  { match: ['SUMMARY'],        why: 'the month-by-month totals, which the app works out from the entries themselves' },
  { match: ['YEAR'],           why: 'the year-on-year totals, which the app works out from the entries themselves' },
  { match: ['FOODCONSUMPTION'],    why: 'what the herd ate valued day by day, not money paid out — the feed itself is bought under Farm food' },
  { match: ['FOODWAFANYAKAZI'],    why: 'the workers\' food valued day by day, not a separate payment' },
  { match: ['PAYMENTSERVICE'],     why: 'the same spending arranged by service; it is already in the detail sheets' },
  { match: ['PAYMENTFOOD'],        why: 'the same spending arranged by feed type; it is already in Farm food' },
  { match: ['PAYMENTMEDICATION'],  why: 'the same spending arranged by drug; it is already in Farm medical' },
  { match: ['ADVANCES'],           why: 'money lent against a wage and recovered from it — the workbook\'s own summary leaves it out, and the payroll already shows it deducted' },
];

const MONTHS = {
  JANUARY: 1, FEBRUARY: 2, MARCH: 3, APRIL: 4, MAY: 5, JUNE: 6,
  JULY: 7, AUGUST: 8, SEPTEMBER: 9, OCTOBER: 10, NOVEMBER: 11, DECEMBER: 12,
};

const MONTH_NAMES = Object.keys(MONTHS);

/**
 * Which category a sheet name, banner or summary row belongs to.
 *
 * Exact on the normalised name first, then containment — "BMH EXPENSES"
 * and "INVESTMENT COST MWANZA" are banners rather than bare names, and
 * the longest match wins so that "SHOP (HOME AFFAIRS)" cannot be taken
 * for "HOME AFFAIRS".
 */
function categoryFor(text) {
  const n = norm(text);
  if (!n) return null;

  for (const cat of CATEGORIES) {
    if (cat.sheets.some(s => s === n) || norm(cat.name) === n) return cat;
  }

  let best = null, bestLen = 0;
  for (const cat of CATEGORIES) {
    for (const s of [...cat.sheets, norm(cat.name)]) {
      if (s.length > bestLen && (n.includes(s) || s.includes(n))) {
        best = cat; bestLen = s.length;
      }
    }
  }
  return best;
}

/** The reason a sheet is skipped, or null if it is not one of them. */
function ignoredSheet(name) {
  const n = norm(name);
  const hit = IGNORED_SHEETS.find(s => s.match.some(m => n === m || n.includes(m)));
  return hit ? hit.why : null;
}

/** "PAYROLLS FOR THE MONTH OF JULY 2026" → { monthNum: 7, year: 2026 } */
function periodFromText(text) {
  const n = norm(text);
  const month = MONTH_NAMES.find(m => n.includes(m));
  const year  = String(text ?? '').match(/\b(20\d{2})\b/);
  if (!month && !year) return null;
  return {
    monthNum: month ? MONTHS[month] : null,
    year: year ? Number(year[1]) : null,
  };
}

const monthName = (n) => MONTH_NAMES[n - 1] || '';

/** "SEPTEMBER 2026", the label a month is filed under. */
const monthLabel = (monthNum, year) => `${monthName(monthNum)} ${year}`;

module.exports = {
  CATEGORIES, IGNORED_SHEETS, MONTHS, MONTH_NAMES,
  norm, categoryFor, ignoredSheet, periodFromText, monthName, monthLabel,
};
