const express = require('express');
const { pool } = require('../db');
const { requireProduction } = require('../auth');

const router = express.Router();

/* NOTE: mounted in server.js as
   `app.use('/api/products', verifyToken, requireBranchAccess, productsRouter)`.

   The catalogue itself is defined in processingCatalog.js and copied into
   this table at boot — see lib/initStock.js. What lives here and nowhere
   else is the part the farm sets rather than the code: the selling price,
   and whether a line is still being made. */

router.get('/', async (req, res) => {
  const where = req.query.active === 'true' ? 'WHERE active' : '';
  try {
    const { rows } = await pool.query(`
      SELECT id, product, size, litres_per_pack, unit_price, active, sort_order
      FROM products ${where} ORDER BY sort_order, product, size
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Price and availability only.

   Product and size are deliberately not editable. They are the join between
   this table and every workbook the parser has ever read, matched through
   processingCatalog.js — renaming a row here would quietly detach it from
   its own history. A genuinely new line is added to the catalogue instead,
   where the template generator and the parser learn about it too. */
router.patch('/:id', requireProduction, async (req, res) => {
  const { unit_price, active } = req.body;
  if (unit_price != null && !(Number(unit_price) >= 0)) {
    return res.status(400).json({ error: 'unit_price must be zero or more' });
  }
  try {
    const { rows } = await pool.query(
      `UPDATE products SET
         unit_price = COALESCE($1, unit_price),
         active     = COALESCE($2, active)
       WHERE id = $3
       RETURNING id, product, size, litres_per_pack, unit_price, active, sort_order`,
      [unit_price != null ? Number(unit_price) : null,
       typeof active === 'boolean' ? active : null,
       req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Product not found' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
