/* ══════════════════════════════════════════════════════════════
   PROCESSING UNIT CATALOGUE

   One place that defines what the processing unit makes, how each pack
   size converts to litres, and which spellings of a name mean the same
   thing. The template generator, the parser and the reporting code all
   read from here, so a new product or pack size is added once.

   The spellings come from the farm's own BUSH_PROCESSING_UNIT workbook,
   which has been maintained by hand for years and is inconsistent about
   them: "PACT O.5L" and "PACK 0.5L" are the same product, and so are
   "0.5 CHUPA" and "0.5L CHUPA". Rejecting an upload over that would be
   useless to the person filling the sheet, so the aliases below are
   treated as correct input and normalised on the way in.
══════════════════════════════════════════════════════════════ */

/** Sources of raw milk, in the order they appear on the sheet. */
const RECEIVED_SOURCES = ['FARM MWABULUGU', 'FARM', 'PURCHASED'];

/**
 * Products and their pack sizes, in sheet order.
 *
 * VANILLA 2L and STRAWBERRY 2L are carried even though some months have
 * never used them — the farm's own SUMMARY sheet reserves a line for both,
 * and a size that exists in the summary but not the daily sheet is exactly
 * how a month's figures end up unaccounted for.
 */
const PRODUCTS = [
  { product: 'VANILLA',      sizes: ['150ML', '0.5L CUP', '0.5L CHUPA', '1L', '2L', '3L', '5L'] },
  { product: 'STRAWBERRY',   sizes: ['150ML', '0.5L', '1L', '2L', '3L', '5L'] },
  { product: 'MTINDI BONGE', sizes: ['PACK 0.5L', '0.5L CUP', '0.5L CHUPA', '1L', '2L', '3L', '5L', '10L'] },
];

/** Flat [{ product, size }] in sheet order — the row order of every block. */
const PRODUCT_ROWS = PRODUCTS.flatMap(p => p.sizes.map(size => ({ product: p.product, size })));

/** Litres in one pack of a given size. Keyed by canonical size name. */
const LITRES_PER_PACK = {
  '150ML': 0.15,
  '0.5L': 0.5,
  '0.5L CUP': 0.5,
  '0.5L CHUPA': 0.5,
  'PACK 0.5L': 0.5,
  '1L': 1,
  '2L': 2,
  '3L': 3,
  '5L': 5,
  '10L': 10,
};

/* ── name normalisation ──────────────────────────────────────
   norm() folds away the cosmetic differences (case, spacing, the
   handwritten letter O typed where a zero was meant). ALIASES then maps
   the remaining genuine spelling variants onto the canonical name. */

function norm(s) {
  return String(s == null ? '' : s)
    .toUpperCase()
    .replace(/O(?=\.?\d)/g, '0')       // "O.5L" -> "0.5L"
    .replace(/[^A-Z0-9. ]+/g, ' ')     // stray punctuation from hand-typed cells
    .replace(/\s+/g, ' ')
    .trim();
}

/** Variant spelling (already norm()ed) -> canonical name. */
const ALIASES = new Map(Object.entries({
  // milk sources
  'PURCHESED': 'PURCHASED',
  'PURCHASE': 'PURCHASED',
  'RARM MWABULUGU': 'FARM MWABULUGU',   // typo in the source workbook
  'FARM MWABULUGU': 'FARM MWABULUGU',
  // products
  'MTINDI': 'MTINDI BONGE',
  'VANILA': 'VANILLA',
  'STRAWBERY': 'STRAWBERRY',
  // pack sizes
  'PACT 0.5L': 'PACK 0.5L',
  'PACK 0.5': 'PACK 0.5L',
  'PACT 0.5': 'PACK 0.5L',
  '0.5 CHUPA': '0.5L CHUPA',
  '0.5 CUP': '0.5L CUP',
  '150 ML': '150ML',
  '0.15L': '150ML',
  '.5L': '0.5L',
}));

/** Canonical form of any product / size / source label. */
function canonical(raw) {
  const n = norm(raw);
  return ALIASES.get(n) || n;
}

/* ── lookup sets built from the catalogue ─────────────────── */

const VALID_SOURCES = new Set(RECEIVED_SOURCES.map(canonical));
const VALID_PRODUCT_ROWS = new Map(
  PRODUCT_ROWS.map(r => [`${canonical(r.product)}|${canonical(r.size)}`, r])
);

/** Resolve a (product, size) pair to its catalogue row, or null. */
function lookupProductRow(product, size) {
  return VALID_PRODUCT_ROWS.get(`${canonical(product)}|${canonical(size)}`) || null;
}

/** Litres represented by `units` packs of `size`. Unknown sizes yield 0. */
function litresFor(size, units) {
  const factor = LITRES_PER_PACK[canonical(size)];
  if (!factor) return 0;
  return Math.round(factor * Number(units || 0) * 1000) / 1000;
}

/** Days in a given month, so a 31st-day entry in June can be rejected. */
function daysInMonth(monthNum, year) {
  if (!monthNum || !year) return 31;
  return new Date(Date.UTC(year, monthNum, 0)).getUTCDate();
}

const MONTHS = {
  JANUARY: 1, FEBRUARY: 2, MARCH: 3, APRIL: 4, MAY: 5, JUNE: 6,
  JULY: 7, AUGUST: 8, SEPTEMBER: 9, OCTOBER: 10, NOVEMBER: 11, DECEMBER: 12,
};
const MONTH_NAMES = Object.keys(MONTHS);

module.exports = {
  RECEIVED_SOURCES,
  PRODUCTS,
  PRODUCT_ROWS,
  LITRES_PER_PACK,
  MONTHS,
  MONTH_NAMES,
  VALID_SOURCES,
  norm,
  canonical,
  lookupProductRow,
  litresFor,
  daysInMonth,
};
