const express = require('express');
const { pool } = require('../db');
const { requireProduction } = require('../auth');
const { canonical, guessLitresPerPack } = require('../processingCatalog');
const { loadCatalogue, similarProducts } = require('../lib/products');

const router = express.Router();

/* NOTE: mounted in server.js as
   `app.use('/api/products', verifyToken, requireBranchAccess, productsRouter)`.

   This table is the product catalogue. processingCatalog.js seeds it with
   what the unit made when the app was written (lib/initStock.js); products
   added since are added here, and the workbook parser and the blank
   template read the table, so all three always agree. */

router.get('/', async (req, res) => {
  const where = req.query.active === 'true' ? 'WHERE active' : '';
  try {
    const { rows } = await pool.query(`
      SELECT id, product, size, litres_per_pack, sold_by,
             retail_price, wholesale_price, active, sort_order
      FROM products ${where}
      -- A size added later sits with the rest of its product, not at the bottom.
      ORDER BY MIN(sort_order) OVER (PARTITION BY product), product, sort_order, size
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Prices, availability, and litres per pack.

   Product and size are deliberately not editable. They are the join between
   this table and every workbook the parser has ever read — renaming a row
   here would quietly detach it from its own history. A product that is no
   longer made is retired (active = false): the parser still reads it on old
   months, and new templates leave it out.

   Litres per pack can be corrected for a sealed product, since it may have
   been guessed from the size label when the product was added. Figures
   already imported keep the litres they were imported with; months
   uploaded from now on use the new figure. */
router.patch('/:id', requireProduction, async (req, res) => {
  const { retail_price, wholesale_price, active, litres_per_pack } = req.body;
  for (const [name, value] of [['retail_price', retail_price], ['wholesale_price', wholesale_price]]) {
    if (value != null && !(Number(value) >= 0)) {
      return res.status(400).json({ error: `${name} must be zero or more` });
    }
  }
  if (litres_per_pack != null && !(Number(litres_per_pack) > 0)) {
    return res.status(400).json({ error: 'litres_per_pack must be more than zero' });
  }
  try {
    const { rows } = await pool.query(
      `UPDATE products SET
         retail_price    = COALESCE($1, retail_price),
         wholesale_price = COALESCE($2, wholesale_price),
         active          = COALESCE($3, active),
         litres_per_pack = CASE WHEN sold_by = 'pack' THEN COALESCE($5, litres_per_pack)
                                ELSE litres_per_pack END
       WHERE id = $4
       RETURNING id, product, size, litres_per_pack, sold_by,
                 retail_price, wholesale_price, active, sort_order`,
      [retail_price    != null ? Number(retail_price)    : null,
       wholesale_price != null ? Number(wholesale_price) : null,
       typeof active === 'boolean' ? active : null,
       req.params.id,
       litres_per_pack != null ? Number(litres_per_pack) : null]
    );
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Add a product.

   Two kinds of line come through here. Loose milk sold from the churn
   ('litre') is stored with litres_per_pack of 1, so a "unit" in the stock
   ledger simply is a litre and bulk milk is issued, sold, counted and
   reported through exactly the same path as a bottle.

   Sealed products ('pack') are what the processing unit makes. This table
   is the catalogue the workbook parser and the blank template read, so a
   product added here is recognised on the next upload and gets its own
   rows on the next template downloaded.

   Names go through canonical() first, the same folding the parser applies
   to the sheet, so "vanila 250ml" is stored as VANILLA 250ML and cannot sit
   beside VANILLA as a second family. A name that is merely close to an
   existing one comes back with 409 and `needs_confirmation` rather than
   being refused: whether "VANILLA MIX" is a new product or a slip is the
   farm's call, and the person adding it confirms with `confirm_new`. */
router.post('/', requireProduction, async (req, res) => {
  const {
    product, size, sold_by = 'litre', litres_per_pack,
    retail_price, wholesale_price, confirm_new,
  } = req.body;
  if (!product || !String(product).trim()) return res.status(400).json({ error: 'product required' });
  if (!['pack', 'litre'].includes(sold_by)) {
    return res.status(400).json({ error: 'sold_by must be pack or litre' });
  }

  let name, label, factor;
  if (sold_by === 'pack') {
    name  = canonical(product);
    label = canonical(size);
    if (!name)  return res.status(400).json({ error: 'Give the product a name' });
    if (!label) return res.status(400).json({ error: 'Give the pack size, for example 1L or 250ML' });
    factor = litres_per_pack != null && String(litres_per_pack).trim() !== ''
      ? Number(litres_per_pack)
      : guessLitresPerPack(label);
    if (!(factor > 0)) {
      return res.status(400).json({ error: `How many litres is one pack of ${name} ${label}? Enter litres per pack.` });
    }
  } else {
    name   = String(product).trim().toUpperCase();
    label  = String(size || 'LITRE').trim().toUpperCase();
    factor = 1;
  }

  try {
    if (sold_by === 'pack') {
      const cat = await loadCatalogue();
      const existing = cat.lookup(name, label);
      if (existing) {
        return res.status(409).json({
          error: `${existing.product} ${existing.size} is already a product.`,
          existing,
        });
      }
      if (!confirm_new) {
        const families = cat.rows.map(r => r.product);
        const known = families.map(canonical).includes(name);
        const similar = known ? [] : similarProducts(name, families);
        /* Same product, a size spelled differently but holding the same
           volume — "1LT" beside "1L". Could be a new pack (VANILLA has both
           a 0.5L cup and a 0.5L chupa), could be a slip. */
        const sameVolume = known
          ? cat.rows.filter(r => canonical(r.product) === name && r.litres_per_pack === factor)
              .map(r => `${r.product} ${r.size}`)
          : [];
        if (similar.length || sameVolume.length) {
          return res.status(409).json({
            needs_confirmation: true,
            error: similar.length
              ? `"${name}" is close to ${similar.join(', ')}. If it is the same product, use that name; `
                + `if it is a different product, confirm to add it.`
              : `${sameVolume.join(', ')} already holds ${factor} L. If ${name} ${label} is a `
                + `different pack, confirm to add it.`,
            similar, same_volume: sameVolume,
          });
        }
      }
    }

    const { rows } = await pool.query(
      `INSERT INTO products (product, size, litres_per_pack, sold_by,
                             retail_price, wholesale_price, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM products))
       RETURNING id, product, size, litres_per_pack, sold_by,
                 retail_price, wholesale_price, active, sort_order`,
      [name, label, factor, sold_by,
       Number(retail_price) >= 0 ? Number(retail_price) : 0,
       Number(wholesale_price) >= 0 ? Number(wholesale_price) : 0]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That product and size already exists' });
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
