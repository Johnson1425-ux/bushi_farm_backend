const { pool } = require('../db');
const { canonical, buildCatalogue, DEFAULT_CATALOGUE } = require('../processingCatalog');

/* Resolving a workbook's product names against the products table.

   The processing_* tables store product and size as the free text the
   parser normalised them to; the products table stores the same catalogue
   with an id. Matching the two on raw strings would fail on exactly the
   spellings processingCatalog.js exists to forgive, so both sides are put
   through canonical() before they are compared. */

/** @returns {Promise<Map<string, {id, product, size, litres_per_pack}>>} keyed "PRODUCT|SIZE". */
async function productKeyMap(client = pool) {
  const { rows } = await client.query(
    'SELECT id, product, size, litres_per_pack FROM products'
  );
  return new Map(rows.map(r => [`${canonical(r.product)}|${canonical(r.size)}`, r]));
}

/** Look up one (product, size) pair in a map from productKeyMap(). */
function findProduct(map, product, size) {
  return map.get(`${canonical(product)}|${canonical(size)}`) || null;
}

/* The processing catalogue as the farm has it now: every sealed product in
   the products table, retired ones included, so an old month that still
   names a retired line reads back in full. Ordered for the sheet — each new
   size sits with the rest of its product rather than at the bottom — which
   is the order the blank template is generated in.

   Falls back to the list in processingCatalog.js only while the table is
   empty, which is the moment between creating it and seeding it. */
async function loadCatalogue(client = pool) {
  const { rows } = await client.query(`
    SELECT product, size, litres_per_pack, active, sort_order
    FROM products WHERE sold_by = 'pack'
    ORDER BY MIN(sort_order) OVER (PARTITION BY product), product, sort_order, id
  `);
  return rows.length ? buildCatalogue(rows) : DEFAULT_CATALOGUE;
}

/** Edit distance between two strings — small inputs only. */
function editDistance(a, b) {
  const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/* What a new product name might be a misspelling of.

   A product added by mistake is worse than one never added: the next
   upload files that row's figures under a second name, and the month's
   VANILLA total comes up short with nothing to say why. So a name within
   a couple of letters of an existing one, or one that contains it, is put
   back to the person adding it to confirm — it is theirs to decide, since
   "VANILLA" and "VANILLA MIX" may well be two real products. */
function similarProducts(name, existing) {
  const n = canonical(name);
  return [...new Set(existing.map(canonical))].filter(e => {
    if (e === n) return false;
    const limit = Math.min(e.length, n.length) >= 8 ? 2 : 1;
    return editDistance(e, n) <= limit
      || (e.length >= 4 && n.replace(/\s+/g, '').includes(e.replace(/\s+/g, '')));
  });
}

module.exports = { productKeyMap, findProduct, loadCatalogue, similarProducts };
