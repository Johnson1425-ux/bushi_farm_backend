const { pool } = require('../db');
const { canonical } = require('../processingCatalog');

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

module.exports = { productKeyMap, findProduct };
