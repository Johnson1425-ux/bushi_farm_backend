const express = require('express');
const multer  = require('multer');
const XLSX    = require('xlsx');
const { pool } = require('../db');
const { parseDate } = require('../lib/parsers');
const {
  TYPES, CARD_COLUMNS, balance, signedQty,
  onHandFor, shortfallMessage, stockState,
  packSize, packCost, toPacks, toBase, lineCost, averageCost,
  num, round,
} = require('../lib/inventoryLedger');

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* ══════════════════════════════════════════════════════════════
   STORE INVENTORY

   Mounted in server.js as
   `app.use('/api/inventory', verifyToken, requireProduction, inventoryRouter)`.

   Everything the unit consumes rather than sells: packaging bottles, caps,
   labels and crates; cultures and flavours; CIP chemicals; machine spares;
   PPE. The balance is always `inventory_logs` summed — see
   lib/inventoryLedger.js for why nothing caches it and what the five
   movement types mean.

   Three things this module refuses to do, all of them for the same reason:

     · take stock out that is not there — a negative balance is not a
       shortage, it is a record that stopped being true at some earlier
       point nobody can now identify;
     · delete an item that has movements filed against it — that cascade
       takes a year of consumption history with it;
     · let a stock count be edited once posted — the correction it wrote is
       already in the ledger, and re-posting would write it a second time.

   Corrections have a documented path instead: a stock count, or an
   opposite movement that says why.
══════════════════════════════════════════════════════════════ */

const CATEGORIES = ['packaging', 'ingredient', 'medicine', 'chemical', 'spare', 'tool', 'ppe', 'general'];

/* The columns an item row is made of, named once. Both spellings are
   generated from this list so a column added to one cannot go missing
   from the other. */
const ITEM_COLUMNS = [
  'id', 'name', 'code', 'category', 'unit', 'pack_unit', 'pack_size',
  'notes', 'supplier', 'location',
  'reorder_level', 'reorder_qty', 'unit_cost', 'status',
  'created_at', 'updated_at', 'archived_at',
];
const ITEM_FIELDS    = ITEM_COLUMNS.map(c => `i.${c}`).join(', ');
const ITEM_RETURNING = ITEM_COLUMNS.join(', ');

/** Shape one items row the way every caller wants it: numbers as numbers. */
function shapeItem(r) {
  const current_stock = num(r.current_stock);
  const unit_cost     = num(r.unit_cost);
  return {
    ...numericItem(r),
    total_in:       num(r.total_in),
    total_out:      num(r.total_out),
    total_damaged:  num(r.total_damaged),
    total_returned: num(r.total_returned),
    total_adjusted: num(r.total_adjusted),
    current_stock,
    /* 480 ml is four bottles and a bit; both readings are useful and the
       page should not have to guess the pack size to work one out. */
    current_packs:  toPacks(current_stock, r),
    stock_value:    round(current_stock * unit_cost, 2),
    state:          stockState(current_stock, r.reorder_level),
  };
}

/**
 * The numeric columns of an item row, as numbers.
 *
 * node-postgres hands NUMERIC back as a string, so a row returned straight
 * from an INSERT or UPDATE carries `"2000"` where the same row read through
 * /items carries `2000`. The page then has one code path where a reorder
 * level compares as a number and another where it compares as text, and
 * `"900" > "2000"` is true. Every item the API returns goes through one of
 * these two functions.
 */
function numericItem(r) {
  const item = {
    ...r,
    reorder_level: num(r.reorder_level),
    reorder_qty:   num(r.reorder_qty),
    unit_cost:     num(r.unit_cost),
    pack_size:     packSize(r),
  };
  /* The invoice figure, sent alongside the per-unit one. The page shows
     and edits the pack cost — 9,000 a bottle — because that is what the
     delivery note says; deriving it in one place stops each screen doing
     the multiplication itself and rounding it differently. */
  item.pack_cost = packCost(item);
  return item;
}

/** A trimmed string, or null — so a cleared form field clears the column. */
const text = (v) => {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
};

/* ══════════════════════════════════
   ITEMS
══════════════════════════════════ */

/**
 * The stock list.
 *
 * Archived items are left out unless asked for: an item is retired
 * precisely so it stops appearing in the daily list, and a store sheet
 * padded with lines nobody carries any more is one nobody reads.
 */
router.get('/items', async (req, res) => {
  const { q, category, status = 'active', state } = req.query;
  const conditions = [], params = [];

  if (status !== 'all') {
    params.push(status === 'archived' ? 'archived' : 'active');
    conditions.push(`i.status = $${params.length}`);
  }
  if (category && category !== 'all') {
    params.push(category);
    conditions.push(`i.category = $${params.length}`);
  }
  if (q) {
    params.push(`%${q.trim()}%`);
    conditions.push(
      `(i.name ILIKE $${params.length} OR i.code ILIKE $${params.length} OR i.supplier ILIKE $${params.length})`
    );
  }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const { rows } = await pool.query(`
      SELECT ${ITEM_FIELDS},
             ${CARD_COLUMNS('l')},
             TO_CHAR(MAX(l.date) FILTER (WHERE l.type = 'in'),  'YYYY-MM-DD') AS last_received,
             TO_CHAR(MAX(l.date) FILTER (WHERE l.type = 'out'), 'YYYY-MM-DD') AS last_issued
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      ${where}
      GROUP BY i.id
      ORDER BY i.category, i.name
    `, params);

    let items = rows.map(shapeItem);
    /* Filtered here rather than in a HAVING clause: "low" depends on the
       item's own reorder level, and keeping that comparison in one place
       (stockState) is what stops the list, the alerts and the summary tiles
       disagreeing about which items need ordering. */
    if (state === 'low')      items = items.filter(i => i.state === 'low');
    else if (state === 'out') items = items.filter(i => i.state === 'out');
    else if (state === 'attention') items = items.filter(i => i.state !== 'ok');

    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * One item, with its stock card.
 *
 * The movements come back with a running balance worked out in the
 * database, oldest first, so the page can show how the shelf got to its
 * present figure rather than only what that figure is.
 */
router.get('/items/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ${ITEM_FIELDS}, ${CARD_COLUMNS('l')}
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      WHERE i.id = $1
      GROUP BY i.id
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Item not found' });

    const { rows: movements } = await pool.query(`
      SELECT l.id, l.type, l.quantity, TO_CHAR(l.date,'YYYY-MM-DD') AS date,
             l.notes, l.reference, l.party, l.unit_cost, l.cost, l.count_id, l.created_at,
             u.username AS recorded_by,
             SUM(${signedQty('l')}) OVER (ORDER BY l.date, l.id) AS running_balance
      FROM inventory_logs l
      LEFT JOIN users u ON u.id = l.created_by
      WHERE l.item_id = $1
      ORDER BY l.date DESC, l.id DESC
      LIMIT 500
    `, [req.params.id]);

    res.json({
      ...shapeItem(rows[0]),
      movements: movements.map(m => ({
        ...m,
        quantity:  num(m.quantity),
        packs:     toPacks(m.quantity, rows[0]),
        unit_cost: m.unit_cost === null ? null : num(m.unit_cost),
        /* Rows filed before movements were costed carry no rate. Falling
           back to today's would put a confident figure on a dose whose
           price nobody recorded, so they stay null and read as "—". */
        cost:      m.cost === null ? null : num(m.cost),
        running_balance: num(m.running_balance),
      })),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/items', async (req, res) => {
  const name = text(req.body.name);
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const category = CATEGORIES.includes(req.body.category) ? req.body.category : 'general';
  const pack     = num(req.body.pack_size) > 0 ? num(req.body.pack_size) : 1;

  /* The form offers whichever price the user actually has in front of
     them: the invoice figure for a pack, or a per-unit rate. Both land in
     the same column, because the ledger only ever costs base units. */
  const unitCost = 'pack_cost' in req.body && req.body.pack_cost !== ''
    ? round(num(req.body.pack_cost) / pack, 6)
    : num(req.body.unit_cost);

  /* Opening stock is entered in whichever unit was counted. A store
     keeper counting the medicine shelf writes "3 bottles", not "300". */
  const opening = req.body.opening_in_packs
    ? toBase(req.body.opening_stock, { pack_size: pack })
    : num(req.body.opening_stock);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(`
      INSERT INTO inventory_items
        (name, code, category, unit, pack_unit, pack_size, notes, supplier, location,
         reorder_level, reorder_qty, unit_cost)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING ${ITEM_RETURNING}
    `, [
      name, text(req.body.code), category, text(req.body.unit) || 'pcs',
      text(req.body.pack_unit), pack,
      text(req.body.notes), text(req.body.supplier), text(req.body.location),
      num(req.body.reorder_level), num(req.body.reorder_qty), unitCost,
    ]);

    /* Opening stock is a real receipt, not a column on the item.
       Recording it as a movement is what lets the first stock card start
       from a figure that has a date and an author attached to it. */
    if (opening > 0) {
      await client.query(`
        INSERT INTO inventory_logs
          (item_id, type, quantity, date, notes, unit_cost, cost, created_by)
        VALUES ($1, 'in', $2, COALESCE($3::date, CURRENT_DATE), 'Opening stock', $4, $5, $6)
      `, [rows[0].id, opening, parseDate(req.body.opening_date) || null,
          unitCost || null, unitCost ? lineCost(opening, unitCost) : null,
          req.user?.id ?? null]);
    }

    await client.query('COMMIT');
    res.status(201).json({ ...numericItem(rows[0]), current_stock: opening });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      return res.status(409).json({ error: `An item called "${name}" already exists.` });
    }
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/**
 * Edit an item.
 *
 * Every column is optional and an absent one is left alone. The old
 * handler wrote `name`, `unit` and `notes` unconditionally, so a request
 * that meant to change only the reorder level blanked the other two —
 * and a PATCH is the one verb that promises not to do that.
 */
router.patch('/items/:id', async (req, res) => {
  const sets = [], params = [];
  const set = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };

  if ('name' in req.body) {
    const name = text(req.body.name);
    if (!name) return res.status(400).json({ error: 'Name cannot be empty' });
    set('name', name);
  }
  if ('unit' in req.body) {
    const unit = text(req.body.unit);
    if (!unit) return res.status(400).json({ error: 'Unit cannot be empty' });
    set('unit', unit);
  }
  if ('category' in req.body) {
    if (!CATEGORIES.includes(req.body.category)) {
      return res.status(400).json({ error: `Category must be one of: ${CATEGORIES.join(', ')}` });
    }
    set('category', req.body.category);
  }
  for (const col of ['code', 'notes', 'supplier', 'location']) {
    if (col in req.body) set(col, text(req.body[col]));
  }
  for (const col of ['reorder_level', 'reorder_qty']) {
    if (col in req.body) set(col, num(req.body[col]));
  }
  if ('pack_unit' in req.body) set('pack_unit', text(req.body.pack_unit));

  /* Changing the pack size re-expresses the same shelf in the same base
     units — 100 ml is 100 ml whether the label calls it one bottle or
     two half-bottles — so no stock moves and no movement is rewritten.
     The cost per base unit is held steady across the change for the same
     reason: it is the pack price that has to follow the new size, not
     the value of what is already on the shelf. */
  const newPack = 'pack_size' in req.body && num(req.body.pack_size) > 0
    ? num(req.body.pack_size) : null;
  if (newPack) set('pack_size', newPack);

  if ('pack_cost' in req.body && req.body.pack_cost !== '') {
    const { rows: [cur] } = await pool.query(
      'SELECT pack_size FROM inventory_items WHERE id = $1', [req.params.id]
    );
    if (!cur) return res.status(404).json({ error: 'Item not found' });
    set('unit_cost', round(num(req.body.pack_cost) / (newPack ?? packSize(cur)), 6));
  } else if ('unit_cost' in req.body) {
    set('unit_cost', num(req.body.unit_cost));
  }

  if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });

  sets.push('updated_at = NOW()');
  params.push(req.params.id);

  try {
    const { rows } = await pool.query(
      `UPDATE inventory_items SET ${sets.join(', ')} WHERE id = $${params.length}
       RETURNING ${ITEM_RETURNING}`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Item not found' });
    res.json(numericItem(rows[0]));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Another item already uses that name or code.' });
    res.status(500).json({ error: err.message });
  }
});

/** Retire a line without losing what it consumed. */
router.post('/items/:id/archive', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      UPDATE inventory_items
      SET status = 'archived', archived_at = NOW(), updated_at = NOW()
      WHERE id = $1 RETURNING ${ITEM_RETURNING}
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Item not found' });
    res.json(numericItem(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/items/:id/restore', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      UPDATE inventory_items
      SET status = 'active', archived_at = NULL, updated_at = NOW()
      WHERE id = $1 RETURNING ${ITEM_RETURNING}
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Item not found' });
    res.json(numericItem(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Delete an item — only one that never moved.
 *
 * inventory_logs cascades from here, so deleting a line the store has
 * actually used erases every movement ever filed against it. That quietly
 * changes last year's consumption figures, and nothing on the page said so.
 * An item with history is archived instead, and the refusal says as much.
 */
router.delete('/items/:id', async (req, res) => {
  try {
    const { rows: [used] } = await pool.query(
      'SELECT COUNT(*)::int AS n FROM inventory_logs WHERE item_id = $1', [req.params.id]
    );
    if (used.n > 0) {
      return res.status(409).json({
        error: `This item has ${used.n} movement(s) recorded against it. `
             + 'Archive it instead — deleting would erase that history from the records.',
        movements: used.n,
      });
    }
    const { rowCount } = await pool.query('DELETE FROM inventory_items WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Item not found' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   MOVEMENTS
══════════════════════════════════ */

router.get('/logs', async (req, res) => {
  const { item_id, from, to, type, category, q, limit = 300 } = req.query;
  const conditions = [], params = [];
  if (item_id) { params.push(item_id); conditions.push(`l.item_id = $${params.length}`); }
  if (from)    { params.push(from);    conditions.push(`l.date >= $${params.length}`); }
  if (to)      { params.push(to);      conditions.push(`l.date <= $${params.length}`); }
  if (type && type !== 'all') { params.push(type); conditions.push(`l.type = $${params.length}`); }
  if (category && category !== 'all') { params.push(category); conditions.push(`i.category = $${params.length}`); }
  if (q) {
    params.push(`%${q.trim()}%`);
    conditions.push(`(i.name ILIKE $${params.length} OR l.reference ILIKE $${params.length} OR l.party ILIKE $${params.length} OR l.notes ILIKE $${params.length})`);
  }
  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(Math.min(parseInt(limit, 10) || 300, 2000));

  try {
    const { rows } = await pool.query(`
      SELECT l.id, l.item_id, l.type, l.quantity, TO_CHAR(l.date,'YYYY-MM-DD') AS date,
             l.notes, l.reference, l.party, l.unit_cost, l.cost, l.count_id, l.created_at,
             i.name AS item_name, i.unit, i.pack_unit, i.pack_size, i.category,
             u.username AS recorded_by
      FROM inventory_logs l
      JOIN inventory_items i ON i.id = l.item_id
      LEFT JOIN users u ON u.id = l.created_by
      ${where}
      ORDER BY l.date DESC, l.id DESC
      LIMIT $${params.length}
    `, params);
    res.json(rows.map(r => ({
      ...r,
      quantity:  num(r.quantity),
      pack_size: packSize(r),
      packs:     toPacks(r.quantity, r),
      unit_cost: r.unit_cost === null ? null : num(r.unit_cost),
      cost:      r.cost === null ? null : num(r.cost),
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Record a movement.
 *
 * Everything is checked before anything is written, inside the transaction
 * that will do the writing: an item that exists, a type the ledger knows, a
 * quantity above zero, and — for anything leaving the shelf — enough on
 * hand to cover it. The old handler checked none of that and would happily
 * take 200 bottles out of a store holding 150.
 *
 * 'adjust' is not accepted here. A correction to the book comes from a
 * posted stock count, so the variance always has a document behind it.
 */
router.post('/logs', async (req, res) => {
  const { item_id, type, date } = req.body;

  if (!item_id || !type || !date) {
    return res.status(400).json({ error: 'Item, movement type and date are required' });
  }
  if (type === 'adjust') {
    return res.status(400).json({
      error: 'Corrections are made by posting a stock count, not by typing an adjustment.',
    });
  }
  if (!TYPES.includes(type)) {
    return res.status(400).json({ error: `Movement type must be one of: in, out, damage, return` });
  }
  const when = parseDate(date);
  if (!when) return res.status(400).json({ error: 'Date could not be read' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [item] } = await client.query(
      `SELECT id, name, unit, pack_unit, pack_size, unit_cost, status
       FROM inventory_items WHERE id = $1 FOR UPDATE`, [item_id]
    );
    if (!item) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Item not found' });
    }
    if (item.status === 'archived' && (type === 'in' || type === 'return')) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `${item.name} is archived. Restore it before booking stock in.` });
    }

    /* A delivery is counted in packs — "5 bottles" — and a dose is drawn
       in base units — "20 ml". The caller says which it typed; the ledger
       only ever stores base units, so the conversion happens once, here,
       rather than in each screen that can file a movement. */
    const quantity = req.body.in_packs
      ? toBase(req.body.quantity, item)
      : num(req.body.quantity);

    if (!(quantity > 0)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Quantity must be greater than zero' });
    }

    const onHand = await onHandFor(client, item_id);
    const short  = shortfallMessage({ type, quantity, onHand, name: item.name, unit: item.unit });
    if (short) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: short, on_hand: onHand });
    }

    /* What this movement is worth.

       A delivery is priced by whoever booked it in, as a pack price off
       the invoice or a rate per base unit. Everything going the other way
       is costed at the item's prevailing average — nobody types what a
       dose is worth, and asking them to would be asking them to do the
       division the store keeps this figure for.

       The rate is written onto the row. That is the whole point: it is
       what the stock was worth when it moved, and re-deriving it later
       would reprice every past treatment the next time a delivery landed
       at a different price. */
    const priced = 'pack_cost' in req.body && req.body.pack_cost !== ''
      ? round(num(req.body.pack_cost) / packSize(item), 6)
      : req.body.unit_cost === undefined || req.body.unit_cost === ''
        ? null
        : num(req.body.unit_cost);

    const rate = type === 'in'
      ? (priced ?? num(item.unit_cost))
      : num(item.unit_cost);

    const { rows } = await client.query(`
      INSERT INTO inventory_logs
        (item_id, type, quantity, date, notes, reference, party, unit_cost, cost, created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING id, item_id, type, quantity, TO_CHAR(date,'YYYY-MM-DD') AS date,
                notes, reference, party, unit_cost, cost
    `, [
      item_id, type, quantity, when, text(req.body.notes), text(req.body.reference),
      text(req.body.party),
      rate > 0 ? rate : null,
      rate > 0 ? lineCost(quantity, rate) : null,
      req.user?.id ?? null,
    ]);

    /* A priced delivery moves the item's average — see averageCost() for
       why an average rather than simply the latest invoice. */
    let newCost = num(item.unit_cost);
    if (type === 'in' && priced > 0) {
      newCost = averageCost({
        onHand, currentCost: item.unit_cost, receivedQty: quantity, receivedCost: priced,
      });
      await client.query(
        'UPDATE inventory_items SET unit_cost = $1, updated_at = NOW() WHERE id = $2',
        [newCost, item_id]
      );
    }

    await client.query('COMMIT');
    const after = type === 'in' || type === 'return' ? onHand + quantity : onHand - quantity;
    res.status(201).json({
      ...rows[0],
      quantity: num(rows[0].quantity),
      unit_cost: rows[0].unit_cost === null ? null : num(rows[0].unit_cost),
      cost: rows[0].cost === null ? null : num(rows[0].cost),
      balance_after: round(after, 3),
      packs_after:   toPacks(after, item),
      item_unit_cost: newCost,
      item_pack_cost: packCost({ pack_size: packSize(item), unit_cost: newCost }),
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/**
 * Remove a mistyped movement.
 *
 * Allowed, because the alternative is a store keeper who cannot undo a
 * fat-fingered "1000" and starts keeping the real figures on paper. Two
 * things are refused: an adjustment written by a stock count, which would
 * leave the count claiming a correction that is no longer in the ledger,
 * and any removal that would drop the item's balance below zero.
 */
router.delete('/logs/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [log] } = await client.query(`
      SELECT l.id, l.item_id, l.type, l.quantity, l.count_id, i.name, i.unit
      FROM inventory_logs l JOIN inventory_items i ON i.id = l.item_id
      WHERE l.id = $1 FOR UPDATE OF l
    `, [req.params.id]);
    if (!log) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Movement not found' });
    }
    if (log.count_id) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'This adjustment belongs to a posted stock count and cannot be removed on its own. '
             + 'Post a further count to correct the balance.',
      });
    }

    const onHand = await onHandFor(client, log.item_id);
    const effect = ['out', 'damage'].includes(log.type) ? -num(log.quantity) : num(log.quantity);
    if (onHand - effect < 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `Removing this would leave ${log.name} at ${onHand - effect} ${log.unit}. `
             + 'Reverse the movements filed after it first.',
      });
    }

    await client.query('DELETE FROM inventory_logs WHERE id = $1', [req.params.id]);
    await client.query('COMMIT');
    res.json({ ok: true, balance_after: onHand - effect });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/* ══════════════════════════════════
   STOCK COUNTS

   The shelf counted against the book. A draft is typed up, and posting it
   writes one 'adjust' movement per line that disagrees — so every
   correction is traceable to the day somebody stood in the store with a
   clipboard, and no balance is ever quietly overwritten.
══════════════════════════════════ */

router.get('/counts', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.ref, TO_CHAR(c.count_date,'YYYY-MM-DD') AS count_date,
             c.status, c.notes, c.created_at, c.posted_at,
             cu.username AS counted_by, pu.username AS posted_by,
             COUNT(cl.id)::int AS lines,
             COUNT(cl.id) FILTER (WHERE cl.counted_qty IS NOT NULL)::int AS counted,
             COUNT(cl.id) FILTER (WHERE cl.book_qty IS NOT NULL AND cl.counted_qty IS NOT NULL
                                    AND cl.counted_qty <> cl.book_qty)::int AS variances
      FROM inventory_counts c
      LEFT JOIN inventory_count_lines cl ON cl.count_id = c.id
      LEFT JOIN users cu ON cu.id = c.counted_by
      LEFT JOIN users pu ON pu.id = c.posted_by
      GROUP BY c.id, cu.username, pu.username
      ORDER BY c.count_date DESC, c.id DESC
      LIMIT 100
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * One count, with its lines.
 *
 * A draft shows the book figure as it stands right now, because that is
 * what the counter is about to disagree with. A posted count shows the
 * figure as it stood when it was posted — re-deriving it from a ledger the
 * count itself has since changed would give a different, and wrong, answer
 * every time the page was opened.
 */
router.get('/counts/:id', async (req, res) => {
  try {
    const { rows: [count] } = await pool.query(`
      SELECT c.id, c.ref, TO_CHAR(c.count_date,'YYYY-MM-DD') AS count_date,
             c.status, c.notes, c.created_at, c.posted_at,
             cu.username AS counted_by, pu.username AS posted_by
      FROM inventory_counts c
      LEFT JOIN users cu ON cu.id = c.counted_by
      LEFT JOIN users pu ON pu.id = c.posted_by
      WHERE c.id = $1
    `, [req.params.id]);
    if (!count) return res.status(404).json({ error: 'Stock count not found' });

    const { rows: lines } = await pool.query(`
      SELECT cl.id, cl.item_id, cl.counted_qty, cl.book_qty, cl.notes,
             i.name, i.unit, i.pack_unit, i.pack_size, i.category, i.unit_cost,
             ${balance('l')} AS live_book_qty
      FROM inventory_count_lines cl
      JOIN inventory_items i ON i.id = cl.item_id
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      WHERE cl.count_id = $1
      GROUP BY cl.id, i.id
      ORDER BY i.category, i.name
    `, [req.params.id]);

    res.json({
      ...count,
      lines: lines.map(l => {
        const book = count.status === 'posted' ? num(l.book_qty) : num(l.live_book_qty);
        const isCounted = l.counted_qty !== null;
        const counted = num(l.counted_qty);
        const variance = isCounted ? round(counted - book, 3) : 0;
        return {
          ...l,
          counted,
          counted_qty: isCounted ? counted : null,
          book_qty: book,
          pack_size: packSize(l),
          book_packs: toPacks(book, l),
          unit_cost: num(l.unit_cost),
          variance,
          variance_value: round(variance * num(l.unit_cost), 2),
        };
      }),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * Open a count.
 *
 * With no lines given it seeds one per active item — which is what a full
 * stock take is, and typing forty item names in by hand is how lines get
 * left out of it. Pass `item_ids` to count part of the store instead.
 */
router.post('/counts', async (req, res) => {
  const when = parseDate(req.body.count_date) || new Date().toISOString().slice(0, 10);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ref = text(req.body.ref)
      || `SC-${String(when).replace(/-/g, '').slice(0, 8)}-${Date.now().toString().slice(-4)}`;

    const { rows: [count] } = await client.query(`
      INSERT INTO inventory_counts (ref, count_date, notes, counted_by)
      VALUES ($1,$2,$3,$4) RETURNING id, ref, status
    `, [ref, when, text(req.body.notes), req.user?.id ?? null]);

    const ids = Array.isArray(req.body.item_ids) && req.body.item_ids.length
      ? req.body.item_ids
      : (await client.query("SELECT id FROM inventory_items WHERE status = 'active' ORDER BY category, name")).rows.map(r => r.id);

    for (const itemId of ids) {
      /* NULL, not 0 — nobody has been to the shelf yet. */
      await client.query(
        `INSERT INTO inventory_count_lines (count_id, item_id, counted_qty)
         VALUES ($1,$2,NULL) ON CONFLICT (count_id, item_id) DO NOTHING`,
        [count.id, itemId]
      );
    }

    await client.query('COMMIT');
    res.status(201).json({ ...count, lines: ids.length });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'A count with that reference already exists.' });
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/** Type in what was counted. Drafts only. */
router.patch('/counts/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [count] } = await client.query(
      'SELECT id, status FROM inventory_counts WHERE id = $1 FOR UPDATE', [req.params.id]
    );
    if (!count) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Stock count not found' });
    }
    if (count.status !== 'draft') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `This count is ${count.status} and can no longer be edited.` });
    }

    if ('notes' in req.body || 'count_date' in req.body) {
      await client.query(
        `UPDATE inventory_counts
         SET notes = COALESCE($1, notes), count_date = COALESCE($2::date, count_date)
         WHERE id = $3`,
        [text(req.body.notes), parseDate(req.body.count_date) || null, req.params.id]
      );
    }

    for (const line of req.body.lines || []) {
      if (!line.item_id) continue;
      /* An empty box is "not counted", which is different from a zero
         somebody actually wrote down after looking at an empty shelf. */
      const counted = line.counted_qty === null || line.counted_qty === undefined || line.counted_qty === ''
        ? null : num(line.counted_qty);
      await client.query(`
        INSERT INTO inventory_count_lines (count_id, item_id, counted_qty, notes)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (count_id, item_id)
        DO UPDATE SET counted_qty = EXCLUDED.counted_qty, notes = EXCLUDED.notes
      `, [req.params.id, line.item_id, counted, text(line.notes)]);
    }

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

/**
 * Post the count.
 *
 * The book figure is read and frozen onto each line, and every line that
 * disagrees with it gets one 'adjust' movement carrying the difference —
 * signed, so a count can correct in either direction. Lines that agree
 * write nothing: a stock take that found everything in order should leave
 * no trace in the movement log beyond the count itself.
 *
 * All of it in one transaction. A count that froze its book figures but
 * failed before writing the adjustments would leave a document claiming
 * corrections the ledger never received.
 */
router.post('/counts/:id/post', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [count] } = await client.query(
      `SELECT id, ref, status, TO_CHAR(count_date,'YYYY-MM-DD') AS count_date
       FROM inventory_counts WHERE id = $1 FOR UPDATE`, [req.params.id]
    );
    if (!count) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Stock count not found' });
    }
    if (count.status !== 'draft') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `This count is already ${count.status}.` });
    }

    const { rows: lines } = await client.query(`
      SELECT cl.id, cl.item_id, cl.counted_qty, i.name, i.unit, i.unit_cost
      FROM inventory_count_lines cl
      JOIN inventory_items i ON i.id = cl.item_id
      WHERE cl.count_id = $1
    `, [req.params.id]);

    if (!lines.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This count has no lines to post.' });
    }

    const counted = lines.filter(l => l.counted_qty !== null);
    if (!counted.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Nothing on this count has been counted yet, so there is nothing to post.',
      });
    }

    const adjustments = [];
    const skipped = lines.length - counted.length;
    for (const line of counted) {
      const book     = await onHandFor(client, line.item_id);
      const counted  = num(line.counted_qty);
      const variance = round(counted - book, 3);

      await client.query('UPDATE inventory_count_lines SET book_qty = $1 WHERE id = $2', [book, line.id]);
      if (variance === 0) continue;

      /* An adjustment is valued like any other movement: stock found or
         lost is worth what the shelf it came off was worth. The sign
         follows the variance, so a shortage reads as a cost. */
      const rate = num(line.unit_cost);
      await client.query(`
        INSERT INTO inventory_logs
          (item_id, type, quantity, date, notes, reference, unit_cost, cost, created_by, count_id)
        VALUES ($1,'adjust',$2,$3,$4,$5,$6,$7,$8,$9)
      `, [
        line.item_id, variance, count.count_date,
        `Stock count ${count.ref}: book ${book}, counted ${counted}`,
        count.ref,
        rate > 0 ? rate : null,
        rate > 0 ? round(variance * rate, 2) : null,
        req.user?.id ?? null, count.id,
      ]);

      adjustments.push({
        item: line.name, unit: line.unit, book, counted, variance,
        value: rate > 0 ? round(variance * rate, 2) : null,
      });
    }

    await client.query(
      `UPDATE inventory_counts SET status = 'posted', posted_at = NOW(), posted_by = $1 WHERE id = $2`,
      [req.user?.id ?? null, req.params.id]
    );
    await client.query('COMMIT');
    res.json({
      ok: true, ref: count.ref,
      lines: lines.length, counted: counted.length,
      /* Lines nobody got to. They keep whatever the book says and can be
         picked up by the next count. */
      not_counted: skipped,
      adjustments,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

router.post('/counts/:id/cancel', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE inventory_counts SET status = 'cancelled'
       WHERE id = $1 AND status = 'draft' RETURNING id, ref, status`,
      [req.params.id]
    );
    if (!rows.length) {
      return res.status(409).json({ error: 'Only a draft count can be cancelled.' });
    }
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.delete('/counts/:id', async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      "DELETE FROM inventory_counts WHERE id = $1 AND status <> 'posted'", [req.params.id]
    );
    if (!rowCount) {
      return res.status(409).json({ error: 'A posted count cannot be deleted — it is the record behind the adjustments it made.' });
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   REPORTING
══════════════════════════════════ */

/** The headline figures: what is held, what it is worth, what needs ordering. */
router.get('/summary', async (req, res) => {
  const to   = parseDate(req.query.to)   || new Date().toISOString().slice(0, 10);
  const from = parseDate(req.query.from) || new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10);

  try {
    const [items, period] = await Promise.all([
      pool.query(`
        SELECT i.id, i.name, i.unit, i.pack_unit, i.pack_size, i.category,
               i.unit_cost, i.reorder_level, i.reorder_qty,
               ${balance('l')} AS current_stock
        FROM inventory_items i
        LEFT JOIN inventory_logs l ON l.item_id = i.id
        WHERE i.status = 'active'
        GROUP BY i.id
      `),
      /* COALESCE down to the item's rate for rows filed before movements
         carried a cost of their own — otherwise a store with a year of
         history reports nothing spent until the day this shipped. */
      pool.query(`
        SELECT l.type, COALESCE(SUM(l.quantity), 0) AS qty,
               COALESCE(SUM(COALESCE(l.cost, l.quantity * COALESCE(l.unit_cost, i.unit_cost))), 0) AS value
        FROM inventory_logs l
        JOIN inventory_items i ON i.id = l.item_id
        WHERE l.date BETWEEN $1 AND $2
        GROUP BY l.type
      `, [from, to]),
    ]);

    const rows = items.rows.map(r => ({
      ...r,
      current_stock: num(r.current_stock),
      unit_cost: num(r.unit_cost),
      reorder_level: num(r.reorder_level),
      reorder_qty: num(r.reorder_qty),
      state: stockState(r.current_stock, r.reorder_level),
    }));

    const byType = Object.fromEntries(period.rows.map(r => [r.type, { qty: num(r.qty), value: num(r.value) }]));
    const of = (t) => byType[t] || { qty: 0, value: 0 };

    /* Damage as a share of everything that left the shelf, not of stock
       held: a store that turns over its bottles weekly and one that holds
       a year of them are not comparable on the second measure. */
    const consumed = of('out').qty + of('damage').qty;

    res.json({
      from, to,
      items: rows.length,
      stock_value: Math.round(rows.reduce((t, r) => t + r.current_stock * r.unit_cost, 0) * 100) / 100,
      out_of_stock: rows.filter(r => r.state === 'out').length,
      low_stock:    rows.filter(r => r.state === 'low').length,
      period: {
        received:  of('in').qty,
        received_value: round(of('in').value, 2),
        returned:  of('return').qty,
        issued:    of('out').qty,
        /* What the store spent on what it actually used, as opposed to
           what it spent restocking. For the veterinary shelf this is the
           cost of the medicines that went into animals this month. */
        issued_value: round(of('out').value, 2),
        damaged:   of('damage').qty,
        damaged_value: round(of('damage').value, 2),
        consumed_value: round(of('out').value + of('damage').value, 2),
        adjusted:  of('adjust').qty,
        damage_rate: consumed > 0 ? Math.round((of('damage').qty / consumed) * 1000) / 10 : 0,
      },
      /* Sorted by how short they are of their own reorder level, so the
         list reads as an order sheet rather than as an alphabet. */
      needs_ordering: rows
        .filter(r => r.state !== 'ok')
        .sort((a, b) => (a.current_stock - a.reorder_level) - (b.current_stock - b.reorder_level))
        .slice(0, 20)
        .map(r => {
          const order = Math.max(r.reorder_qty, Math.max(0, r.reorder_level - r.current_stock));
          return {
            id: r.id, name: r.name, unit: r.unit, category: r.category,
            pack_unit: r.pack_unit, pack_size: packSize(r),
            current_stock: r.current_stock, reorder_level: r.reorder_level,
            suggested_order: order,
            /* An order is placed in packs — you ask the supplier for six
               bottles, not for 600 ml — so the sheet says how many, and
               rounds up: half a bottle is not orderable. */
            suggested_packs: r.pack_unit ? Math.ceil(toPacks(order, r)) : null,
            estimated_cost:  round(order * r.unit_cost, 2),
            state: r.state,
          };
        }),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/**
 * The movement report: one row per item for a period.
 *
 * Opening, received, returned, issued, damaged, adjusted, closing — and
 * closing is worked out as opening plus the period's movements rather than
 * read from a separate query, so the row visibly adds up. If it ever did
 * not, the arithmetic on the page would be the first thing to say so.
 */
router.get('/report', async (req, res) => {
  const to   = parseDate(req.query.to)   || new Date().toISOString().slice(0, 10);
  const from = parseDate(req.query.from) || new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10);
  const { category } = req.query;

  const params = [from, to];
  let categoryFilter = '';
  if (category && category !== 'all') {
    params.push(category);
    categoryFilter = `AND i.category = $${params.length}`;
  }

  try {
    const { rows } = await pool.query(`
      SELECT i.id, i.name, i.unit, i.pack_unit, i.pack_size, i.category,
             i.unit_cost, i.reorder_level, i.status,
             COALESCE(SUM(CASE WHEN l.date <  $1 THEN ${signedQty('l')} ELSE 0 END), 0) AS opening,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'in'     THEN l.quantity ELSE 0 END), 0) AS received,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'return' THEN l.quantity ELSE 0 END), 0) AS returned,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'out'    THEN l.quantity ELSE 0 END), 0) AS issued,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'damage' THEN l.quantity ELSE 0 END), 0) AS damaged,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'adjust' THEN l.quantity ELSE 0 END), 0) AS adjusted,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'in'     THEN COALESCE(l.cost, l.quantity * COALESCE(l.unit_cost, i.unit_cost)) ELSE 0 END), 0) AS received_cost,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'out'    THEN COALESCE(l.cost, l.quantity * COALESCE(l.unit_cost, i.unit_cost)) ELSE 0 END), 0) AS issued_cost,
             COALESCE(SUM(CASE WHEN l.date BETWEEN $1 AND $2 AND l.type = 'damage' THEN COALESCE(l.cost, l.quantity * COALESCE(l.unit_cost, i.unit_cost)) ELSE 0 END), 0) AS damaged_cost
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id AND l.date <= $2
      WHERE (i.status = 'active' OR EXISTS (
              SELECT 1 FROM inventory_logs x
              WHERE x.item_id = i.id AND x.date BETWEEN $1 AND $2))
        ${categoryFilter}
      GROUP BY i.id
      ORDER BY i.category, i.name
    `, params);

    const report = rows.map(r => {
      const opening  = num(r.opening);
      const received = num(r.received);
      const returned = num(r.returned);
      const issued   = num(r.issued);
      const damaged  = num(r.damaged);
      const adjusted = num(r.adjusted);
      const closing  = round(opening + received + returned - issued - damaged + adjusted, 3);
      const consumed = issued + damaged;
      const unitCost = num(r.unit_cost);
      /* Costs come from the movements, each carrying the rate that stood
         when it happened — not from closing × today's price, which would
         restate every past period the next time a delivery moved the
         average. Only closing_value uses the current rate, because that
         is what the shelf is worth now. */
      const issuedCost  = round(num(r.issued_cost), 2);
      const damagedCost = round(num(r.damaged_cost), 2);
      return {
        id: r.id, name: r.name, unit: r.unit, category: r.category, status: r.status,
        pack_unit: r.pack_unit, pack_size: packSize(r),
        unit_cost: unitCost, pack_cost: packCost(r), reorder_level: num(r.reorder_level),
        opening, received, returned, issued, damaged, adjusted, closing,
        closing_packs: toPacks(closing, r),
        closing_value: round(closing * unitCost, 2),
        received_value: round(num(r.received_cost), 2),
        issued_value:   issuedCost,
        damaged_value:  damagedCost,
        consumed_value: round(issuedCost + damagedCost, 2),
        damage_rate: consumed > 0 ? Math.round((damaged / consumed) * 1000) / 10 : 0,
        state: stockState(closing, r.reorder_level),
      };
    });

    const sum   = (k) => round(report.reduce((t, r) => t + r[k], 0), 3);
    const money = (k) => round(report.reduce((t, r) => t + r[k], 0), 2);
    res.json({
      from, to,
      rows: report,
      totals: {
        received: sum('received'), returned: sum('returned'),
        issued: sum('issued'), damaged: sum('damaged'), adjusted: sum('adjusted'),
        closing_value:  money('closing_value'),
        received_value: money('received_value'),
        issued_value:   money('issued_value'),
        damaged_value:  money('damaged_value'),
        consumed_value: money('consumed_value'),
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ══════════════════════════════════
   IMPORT
══════════════════════════════════ */

/* Whatever the spreadsheet calls a column. The store's own sheets say
   "Item", the supplier's say "Description", and an import that only
   accepted one spelling sent everybody back to retyping by hand. */
const COLUMN = {
  name:      ['item', 'name', 'description', 'product', 'particulars'],
  code:      ['code', 'sku', 'item code', 'item_code'],
  category:  ['category', 'group', 'type of item'],
  type:      ['type', 'movement', 'movement type', 'in/out'],
  quantity:  ['quantity', 'qty', 'units', 'amount'],
  /* A separate column, deliberately. "Qty 4" beside "UOM: ml" means four
     millilitres; a sheet that means four vials has to say so, or a
     delivery of four 20 ml vials imports as four millilitres and the
     shelf is short by a factor of twenty with nothing to show for it. */
  packs:     ['packs', 'qty in packs', 'packs received', 'containers', 'bottles', 'no. of packs'],
  date:      ['date', 'day'],
  unit:      ['unit', 'uom', 'units of measure'],
  cost:      ['unit cost', 'unit_cost', 'cost', 'price', 'rate'],
  packCost:  ['pack cost', 'pack price', 'bottle price', 'price per pack'],
  packSize:  ['pack size', 'pack_size', 'per pack', 'units per pack', 'content', 'volume'],
  packUnit:  ['pack unit', 'pack', 'container', 'bought as'],
  reference: ['reference', 'ref', 'invoice', 'delivery note', 'grn'],
  party:     ['supplier', 'party', 'issued to', 'from', 'vendor'],
  notes:     ['notes', 'remarks', 'comment', 'comments'],
};

/** Read one logical field from a row, whatever the sheet titled it. */
function pick(row, field) {
  const wanted = COLUMN[field];
  for (const key of Object.keys(row)) {
    if (wanted.includes(String(key).trim().toLowerCase())) {
      const v = row[key];
      if (v !== undefined && v !== null && String(v).trim() !== '') return v;
    }
  }
  return undefined;
}

/* A sheet says "damaged", "broken", "expired", "wastage" — all one thing
   to the ledger. Without this they all fell through to 'in', which added
   the breakages to the shelf instead of taking them off it. */
const TYPE_WORDS = {
  in:     ['in', 'received', 'receipt', 'purchase', 'delivery', 'grn', 'stock in'],
  out:    ['out', 'issued', 'issue', 'used', 'consumed', 'stock out'],
  damage: ['damage', 'damaged', 'broken', 'expired', 'spoilt', 'spoiled', 'wastage', 'waste', 'loss'],
  return: ['return', 'returned', 'returns'],
};

function readType(raw) {
  const v = String(raw ?? 'in').trim().toLowerCase();
  for (const [type, words] of Object.entries(TYPE_WORDS)) {
    if (words.includes(v)) return type;
  }
  return null;
}

/**
 * Import movements from a spreadsheet.
 *
 * Every row is validated and the whole file is applied in one transaction:
 * a file that is half wrong used to leave the store half updated, with no
 * way to tell which half. Errors name the sheet row number, because
 * "Skipped row: missing data" — repeated eleven times, as the old handler
 * did — tells nobody which rows to go and fix.
 */
router.post('/import', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  let rows;
  try {
    const wb    = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    rows        = XLSX.utils.sheet_to_json(sheet);
  } catch (err) {
    return res.status(400).json({ error: `That file could not be read as a spreadsheet: ${err.message}` });
  }
  if (!rows.length) return res.status(400).json({ error: 'The first sheet is empty.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const errors = [];
    const parsed = [];
    let rowNo = 1; // the header occupies sheet row 1

    for (const row of rows) {
      rowNo++;
      const name  = String(pick(row, 'name') ?? '').trim();
      const packs = pick(row, 'packs');
      const qty   = packs !== undefined ? num(packs) : num(pick(row, 'quantity'));
      const date = parseDate(pick(row, 'date'));
      const type = readType(pick(row, 'type'));

      if (!name)        { errors.push(`Row ${rowNo}: no item name`); continue; }
      if (!(qty > 0))   { errors.push(`Row ${rowNo}: ${name} — quantity must be greater than zero`); continue; }
      if (!date)        { errors.push(`Row ${rowNo}: ${name} — date could not be read`); continue; }
      if (!type)        { errors.push(`Row ${rowNo}: ${name} — "${pick(row, 'type')}" is not a movement this store knows`); continue; }

      const rawCategory = String(pick(row, 'category') ?? '').trim().toLowerCase();
      parsed.push({
        rowNo, name, qty, date, type,
        qtyInPacks: packs !== undefined,
        unit:      String(pick(row, 'unit') ?? 'pcs').trim() || 'pcs',
        code:      text(pick(row, 'code')),
        category:  CATEGORIES.includes(rawCategory) ? rawCategory : 'general',
        /* A sheet that prices the bottle rather than the millilitre is the
           normal case for veterinary stock, and reading 9,000 as the cost
           of one millilitre would value the shelf at a hundred times what
           the farm paid. */
        cost:       pick(row, 'packCost') !== undefined ? num(pick(row, 'packCost'))
                  : pick(row, 'cost')     !== undefined ? num(pick(row, 'cost'))
                  : null,
        costIsPack: pick(row, 'packCost') !== undefined,
        packSize:   num(pick(row, 'packSize')) > 0 ? num(pick(row, 'packSize')) : 1,
        packUnit:   text(pick(row, 'packUnit')),
        reference: text(pick(row, 'reference')),
        party:     text(pick(row, 'party')),
        notes:     text(pick(row, 'notes')),
      });
    }

    if (!parsed.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'No usable rows in that file — nothing was imported.',
        errors: errors.slice(0, 50),
      });
    }

    /* Oldest first, so the running balance the shortfall check reads is
       built in the order the movements actually happened. A file listing
       an issue before the delivery that covered it would otherwise be
       rejected for a shortage that never existed. */
    parsed.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.rowNo - b.rowNo));

    const itemIds = new Map();
    let imported = 0, created = 0;

    for (const r of parsed) {
      let itemId = itemIds.get(r.name.toLowerCase());
      if (!itemId) {
        const { rows: [existing] } = await client.query(
          'SELECT id FROM inventory_items WHERE LOWER(name) = LOWER($1)', [r.name]
        );
        if (existing) {
          itemId = existing.id;
        } else {
          const { rows: [made] } = await client.query(`
            INSERT INTO inventory_items
              (name, code, unit, pack_unit, pack_size, category, unit_cost)
            VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id
          `, [
            r.name, r.code, r.unit, r.packUnit, r.packSize, r.category,
            r.cost === null ? 0 : (r.costIsPack ? round(r.cost / r.packSize, 6) : r.cost),
          ]);
          itemId = made.id;
          created++;
        }
        itemIds.set(r.name.toLowerCase(), itemId);
      }

      const { rows: [state] } = await client.query(
        'SELECT unit_cost, pack_size FROM inventory_items WHERE id = $1', [itemId]
      );
      const onHand = await onHandFor(client, itemId);

      /* Packs to base units, now that the item's pack size is known —
         which it may only be because this same row just created it. */
      const qty = r.qtyInPacks ? toBase(r.qty, state) : r.qty;

      if (r.type === 'out' || r.type === 'damage') {
        if (qty > onHand) {
          errors.push(
            `Row ${r.rowNo}: ${r.name} — ${r.type === 'damage' ? 'writing off' : 'issuing'} ${qty} `
            + `would take the balance below zero (${onHand} on hand at that point). Skipped.`
          );
          continue;
        }
      }

      /* Same rule as a movement typed into the page: a delivery carries
         the price on the sheet, everything else is costed at the average
         standing when it happened. A sheet priced per pack says so in its
         own column, so the two are not silently mixed up. */
      const sheetRate = r.cost === null ? null
        : r.costIsPack ? round(num(r.cost) / packSize(state), 6)
        : num(r.cost);
      const rate = r.type === 'in' ? (sheetRate ?? num(state.unit_cost)) : num(state.unit_cost);

      await client.query(`
        INSERT INTO inventory_logs
          (item_id, type, quantity, date, notes, reference, party, unit_cost, cost, created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      `, [
        itemId, r.type, qty, r.date, r.notes, r.reference, r.party,
        rate > 0 ? rate : null,
        rate > 0 ? lineCost(qty, rate) : null,
        req.user?.id ?? null,
      ]);

      if (r.type === 'in' && sheetRate > 0) {
        await client.query(
          'UPDATE inventory_items SET unit_cost = $1, updated_at = NOW() WHERE id = $2',
          [averageCost({
            onHand, currentCost: state.unit_cost, receivedQty: qty, receivedCost: sheetRate,
          }), itemId]
        );
      }
      imported++;
    }

    await client.query('COMMIT');
    res.json({
      imported, created, skipped: rows.length - imported,
      errors: errors.slice(0, 50),
      truncated: errors.length > 50 ? errors.length - 50 : 0,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

module.exports = router;
