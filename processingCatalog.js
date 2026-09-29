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

/* ── a catalogue built from the products table ─────────────

   The lists above are what the unit made when the app was written, and
   they seed the products table on first boot. From then on the table is
   the catalogue: a manager adds a product in the app, and the parser and
   the template read it from there. buildCatalogue() turns table rows into
   the same lookups the constants above provide, so the parser does not
   care which one it was handed. */

/** Best guess at litres per pack from a size label, or null. "250ML" -> 0.25, "1L" -> 1. */
function guessLitresPerPack(size) {
  const c = canonical(size);
  if (LITRES_PER_PACK[c]) return LITRES_PER_PACK[c];
  const m = /(\d*\.?\d+)\s*(ML|LTR|LITRES?|L)\b/.exec(c);
  if (!m) return null;
  const n = Number(m[1]);
  if (!(n > 0)) return null;
  return m[2] === 'ML' ? Math.round(n) / 1000 : n;
}

const keyOf = (product, size) => `${canonical(product)}|${canonical(size)}`;

/**
 * @param {Array<{product, size, litres_per_pack?, active?}>} rows  in sheet order
 * @returns {{ rows, activeRows, lookup(product, size), litresFor(size, units, product?) }}
 */
function buildCatalogue(rows) {
  const entries = [];
  const byKey = new Map();
  const bySize = new Map();
  for (const r of rows) {
    const k = keyOf(r.product, r.size);
    if (byKey.has(k)) continue;
    const factor = Number(r.litres_per_pack) || guessLitresPerPack(r.size) || 0;
    const e = { product: r.product, size: r.size, litres_per_pack: factor, active: r.active !== false };
    entries.push(e);
    byKey.set(k, e);
    if (factor && !bySize.has(canonical(r.size))) bySize.set(canonical(r.size), factor);
  }

  const factorOf = (size, product) => {
    const e = product != null ? byKey.get(keyOf(product, size)) : null;
    if (e && e.litres_per_pack) return e.litres_per_pack;
    return bySize.get(canonical(size)) || LITRES_PER_PACK[canonical(size)] || 0;
  };

  return {
    rows: entries,
    activeRows: entries.filter(e => e.active),
    /** The catalogue's own spelling of a (product, size) pair, or null. */
    lookup(product, size) {
      const e = byKey.get(keyOf(product, size));
      return e ? { product: e.product, size: e.size } : null;
    },
    /** Litres in `units` packs. Pass the product when it is known: two
        products may one day share a size label and not its volume. */
    litresFor(size, units, product) {
      const factor = factorOf(size, product);
      if (!factor) return 0;
      return Math.round(factor * Number(units || 0) * 1000) / 1000;
    },
  };
}

/** The catalogue as the code defines it, for callers with no database to hand. */
const DEFAULT_CATALOGUE = buildCatalogue(
  PRODUCT_ROWS.map(r => ({ ...r, litres_per_pack: LITRES_PER_PACK[canonical(r.size)] }))
);

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
  guessLitresPerPack,
  buildCatalogue,
  DEFAULT_CATALOGUE,
  daysInMonth,
};
