const express = require('express');
const { pool } = require('../db');
const { requireAdmin, requireProduction, requireHealth } = require('../auth');

const router = express.Router();

// NOTE: verifyToken is applied once, at the mount point in server.js
// (`app.use('/api/cows', verifyToken, cowsRouter)`). Everything below is
// per-route on top of that, exactly as it was in server.js.

/* ══════════════════════════════════
   COWS  (all authenticated)
══════════════════════════════════ */
router.get('/', async (req, res) => {
  try {
    /* The herd list means the herd you have, so archived animals are left
       out unless they are asked for. Their records are untouched either
       way — this filters who is shown, never what is stored. */
    const status = String(req.query.status || 'active').toLowerCase();
    const where = status === 'all'      ? ''
                : status === 'archived' ? `WHERE c.status <> 'active'`
                :                         `WHERE c.status = 'active'`;

    const { rows } = await pool.query(`
      SELECT
        c.id, c.name, c.tag, c.breed, c.created_at,
        c.status, TO_CHAR(c.archived_at, 'YYYY-MM-DD') AS archived_at, c.archived_note,
        COUNT(r.id)::int                      AS record_count,
        ROUND(AVG(r.litres)::numeric, 2)      AS avg_litres,
        ROUND(SUM(r.litres)::numeric, 2)      AS total_litres,
        ROUND(MAX(r.litres)::numeric, 2)      AS max_litres,
        ROUND(MIN(r.litres)::numeric, 2)      AS min_litres,
        ROUND(STDDEV(r.litres)::numeric, 2)   AS stddev_litres,
        MIN(r.date)                            AS first_date,
        MAX(r.date)                            AS last_date
      FROM cows c
      LEFT JOIN milk_records r ON r.cow_id = c.id
      ${where}
      GROUP BY c.id
      ORDER BY avg_litres DESC NULLS LAST
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/', requireAdmin, async (req, res) => {
  const { name, tag, breed } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO cows(name,tag,breed) VALUES($1,$2,$3) ON CONFLICT(name) DO UPDATE SET tag=EXCLUDED.tag, breed=EXCLUDED.breed RETURNING *',
      [name.trim(), tag || null, breed || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const ARCHIVE_REASONS = ['dead', 'sold', 'culled'];

/* Take an animal out of the herd without touching her records.

   This is what a death, a sale or a culling calls for — the opposite of a
   delete. She stops appearing in the herd list, stops counting toward
   current averages and stops raising alerts, while every litre she produced
   still counts toward the totals for the period she was alive.

   Open to managers as well as admins: animals leave the herd as a matter of
   routine, and routing that through an admin would push people back toward
   the delete button. */
router.post('/:id/archive', requireProduction, async (req, res) => {
  const status = String(req.body?.status || '').toLowerCase();
  const note   = typeof req.body?.note === 'string' ? req.body.note.trim().slice(0, 500) : '';
  const date   = /^\d{4}-\d{2}-\d{2}$/.test(req.body?.date || '') ? req.body.date : null;

  if (!ARCHIVE_REASONS.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${ARCHIVE_REASONS.join(', ')}` });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE cows
          SET status = $1,
              archived_at = COALESCE($2::date, CURRENT_DATE),
              archived_note = NULLIF($3, ''),
              archived_by = $4
        WHERE id = $5
        RETURNING id, name, status, TO_CHAR(archived_at, 'YYYY-MM-DD') AS archived_at, archived_note`,
      [status, date, note, req.user.id, req.params.id]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cow not found' });
    }

    // Leaving the herd is part of the animal's story, so it goes on her timeline.
    await client.query(
      `INSERT INTO cow_history (cow_id, event_type, date, source, notes)
       VALUES ($1, $2, COALESCE($3::date, CURRENT_DATE), 'archive', NULLIF($4, ''))`,
      [req.params.id, status, date, note]
    );

    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* Undo an archive that was made in error. */
router.post('/:id/restore', requireProduction, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE cows
          SET status = 'active', archived_at = NULL, archived_note = NULL, archived_by = NULL
        WHERE id = $1
        RETURNING id, name, status`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Cow not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Wipe the herd and everything recorded about it, in one statement.

   This is what the "Clear all data" button needs. It used to be a loop of
   per-cow deletes from the browser, which the guard below now blocks on the
   first animal that has records — and which could leave the farm half
   deleted if it failed partway, since each request stood alone.

   A single DELETE cascades through milk_records, cow_health_records,
   pregnancies, disease_cows and cow_history, and either all of it goes or
   none of it does. Archived cows go too: this clears everything, and a
   herd list filtered to active animals would have quietly left them behind.

   The confirm parameter is required so this cannot be reached by a stray
   DELETE to a collection URL. */
router.delete('/', requireAdmin, async (req, res) => {
  if (req.query.confirm !== 'DELETE_ALL') {
    return res.status(400).json({
      error: 'Refusing to delete every cow without confirm=DELETE_ALL. '
           + 'To retire a single animal, archive her instead.',
    });
  }
  try {
    const { rowCount } = await pool.query('DELETE FROM cows');
    res.json({ ok: true, deleted: rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Permanently remove a cow and everything recorded about her.

   This is for a row that should never have existed — a duplicate, a name
   typed twice. For an animal that has left the herd, archive her instead:
   deleting cascades through milk_records, cow_health_records, pregnancies,
   disease_cows and cow_history, which rewrites past totals that were
   correct when they were reported.

   A cow with production history cannot be deleted without saying so
   explicitly, so this cannot be reached by clicking through a dialog. */
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.name, COUNT(r.id)::int AS record_count
         FROM cows c LEFT JOIN milk_records r ON r.cow_id = c.id
        WHERE c.id = $1 GROUP BY c.name`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Cow not found' });

    const { name, record_count } = rows[0];
    if (record_count > 0 && req.query.force !== 'true') {
      return res.status(409).json({
        error: `${name} has ${record_count} milk records. Deleting her removes them from `
             + `the farm's history and changes past totals. Archive her instead, or repeat `
             + `this request with force=true if the record is genuinely a mistake.`,
        record_count,
        archive_instead: `/api/cows/${req.params.id}/archive`,
      });
    }

    await pool.query('DELETE FROM cows WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   COW HISTORY (nested under a cow)

   Reading is open to anyone who can read the cow; writing belongs to the
   vet side of the house, same as it did in server.js.
══════════════════════════════════ */
router.get('/:id/history', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, event_type, TO_CHAR(date,'YYYY-MM-DD') AS date, source, notes
       FROM cow_history WHERE cow_id=$1 ORDER BY date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/:id/history', requireHealth, async (req, res) => {
  const { event_type, date, source, notes } = req.body;
  if (!event_type || !date) return res.status(400).json({ error: 'event_type and date required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO cow_history(cow_id, event_type, date, source, notes) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.params.id, event_type, date, source || null, notes || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* Nested delete for a cow history entry. The UI uses DELETE /api/cow-history/:id
   instead (see routes/cowHistory.js); this variant is kept for any caller
   that scopes by cow. */
router.delete('/:id/history/:hid', requireHealth, async (req, res) => {
  try {
    await pool.query('DELETE FROM cow_history WHERE id=$1 AND cow_id=$2', [req.params.hid, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
