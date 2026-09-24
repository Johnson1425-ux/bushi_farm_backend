const express = require('express');
const { pool } = require('../db');
const { requireRole, requireProduction, requireAdmin } = require('../auth');

const router = express.Router();

/* NOTE: verifyToken is applied once, at the mount point in server.js
   (`app.use('/api/calves', verifyToken, calvesRouter)`). Reading is open to
   anyone signed in — the vet needs the young stock as much as the manager
   does — and the writes below are guarded per route.

   Registering a birth belongs to both sides of the house: the vet is the
   one standing there when it happens, the manager is the one who counts
   the herd. Moving a grown calf into the milking herd creates a row in
   `cows`, which is production's book, so that one is narrower. */
const canRecord = requireRole('admin', 'manager', 'veteran');

const SEXES    = ['female', 'male'];
const STATUSES = ['on_farm', 'weaned', 'moved_to_herd', 'dead', 'sold'];
/* The ways a calf stops being young stock without becoming a milking cow. */
const LEFT     = ['dead', 'sold'];

const isDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(String(v || ''));
const trim   = (v, max = 200) =>
  typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null;

/* Every read of a calf returns the same shape, so the list and the row
   handed back after a write cannot drift apart. */
const SELECT = `
  SELECT
    cf.id, cf.name, cf.tag, cf.sex, cf.breed, cf.sire,
    TO_CHAR(cf.date_of_birth, 'YYYY-MM-DD') AS date_of_birth,
    (CURRENT_DATE - cf.date_of_birth)::int  AS age_days,
    cf.dam_id, dam.name AS dam_name, dam.tag AS dam_tag,
    cf.pregnancy_id,
    cf.birth_weight, cf.status,
    TO_CHAR(cf.weaned_on, 'YYYY-MM-DD') AS weaned_on,
    TO_CHAR(cf.left_on,   'YYYY-MM-DD') AS left_on,
    cf.cow_id, herd.name AS herd_name,
    cf.notes, cf.created_at
  FROM calves cf
  LEFT JOIN cows dam  ON dam.id  = cf.dam_id
  LEFT JOIN cows herd ON herd.id = cf.cow_id
`;

/* ══════════════════════════════════
   THE YOUNG STOCK
══════════════════════════════════ */

/* Default to the calves that are actually on the farm.

   `on_farm` and `weaned` are both still young stock — weaning is a
   milestone, not a departure — so "current" covers the two of them. The
   ones that have moved into the herd or left it are still here to be
   asked for, because a calf that died last season is part of how this
   season's calving rate reads. */
router.get('/', async (req, res) => {
  const status = String(req.query.status || 'current').toLowerCase();
  const where =
      status === 'all'     ? ''
    : status === 'current' ? `WHERE cf.status IN ('on_farm','weaned')`
    : STATUSES.includes(status) ? `WHERE cf.status = '${status}'`
    : `WHERE cf.status IN ('on_farm','weaned')`;

  const params = [];
  let damFilter = '';
  if (req.query.dam_id) {
    params.push(req.query.dam_id);
    damFilter = `${where ? 'AND' : 'WHERE'} cf.dam_id = $${params.length}`;
  }

  try {
    const { rows } = await pool.query(
      `${SELECT} ${where} ${damFilter} ORDER BY cf.date_of_birth DESC, cf.id DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(`${SELECT} WHERE cf.id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Calf not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Record a birth.

   Three things happen together or not at all: the calf is written, the
   calving goes on the dam's timeline where the rest of her story is, and
   the pregnancy it came from is closed. Doing them in one transaction is
   what keeps the pregnancy register honest — the alternative is a calf on
   the ground and a pregnancy still counting down to a due date that has
   already passed. */
router.post('/', canRecord, async (req, res) => {
  const name = trim(req.body?.name, 100);
  const dob  = req.body?.date_of_birth;
  const sex  = String(req.body?.sex || 'female').toLowerCase();

  if (!name) return res.status(400).json({ error: 'name is required' });
  if (!isDate(dob)) return res.status(400).json({ error: 'date_of_birth is required (YYYY-MM-DD)' });
  if (!SEXES.includes(sex)) return res.status(400).json({ error: `sex must be one of: ${SEXES.join(', ')}` });

  const weight = req.body?.birth_weight === '' || req.body?.birth_weight == null
    ? null
    : Number(req.body.birth_weight);
  if (weight !== null && (!Number.isFinite(weight) || weight <= 0)) {
    return res.status(400).json({ error: 'birth_weight must be a number of kilograms' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      `INSERT INTO calves (name, tag, sex, breed, date_of_birth, dam_id, sire,
                           pregnancy_id, birth_weight, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id`,
      [
        name,
        trim(req.body?.tag, 50),
        sex,
        trim(req.body?.breed, 100),
        dob,
        req.body?.dam_id || null,
        trim(req.body?.sire, 200),
        req.body?.pregnancy_id || null,
        weight,
        trim(req.body?.notes, 1000),
      ]
    );

    /* The dam's own page is where anybody looks to find out what she has
       done, so a calving belongs on it. */
    if (req.body?.dam_id) {
      await client.query(
        `INSERT INTO cow_history (cow_id, event_type, date, source, notes)
         VALUES ($1, 'calving', $2, 'calf', $3)`,
        [req.body.dam_id, dob, `${sex === 'male' ? 'Bull calf' : 'Heifer calf'}: ${name}`]
      );
    }

    /* Only an active pregnancy is closed. One already marked delivered or
       lost has been ruled on by somebody, and a second calf recorded
       against it must not quietly rewrite that. */
    if (req.body?.pregnancy_id) {
      await client.query(
        `UPDATE pregnancies
            SET status = 'delivered', actual_birth_date = COALESCE(actual_birth_date, $1::date)
          WHERE id = $2 AND status = 'active'`,
        [dob, req.body.pregnancy_id]
      );
    }

    const { rows: full } = await client.query(`${SELECT} WHERE cf.id = $1`, [rows[0].id]);
    await client.query('COMMIT');
    res.status(201).json(full[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* Correct the details, or move the calf along: weaned, dead, sold.

   Every field is optional and an absent one is left alone, so the edit
   form can send only what changed. `moved_to_herd` is not settable here —
   it means a row exists in `cows`, and only the route below can make one. */
router.patch('/:id', canRecord, async (req, res) => {
  const b = req.body || {};

  if (b.sex !== undefined && !SEXES.includes(String(b.sex).toLowerCase())) {
    return res.status(400).json({ error: `sex must be one of: ${SEXES.join(', ')}` });
  }
  if (b.status !== undefined) {
    const s = String(b.status).toLowerCase();
    if (!STATUSES.includes(s)) {
      return res.status(400).json({ error: `status must be one of: ${STATUSES.join(', ')}` });
    }
    if (s === 'moved_to_herd') {
      return res.status(400).json({
        error: 'Use POST /api/calves/:id/move-to-herd to move a calf into the milking herd, '
             + 'so that she gets a cow record to carry her milk.',
      });
    }
  }
  if (b.date_of_birth !== undefined && !isDate(b.date_of_birth)) {
    return res.status(400).json({ error: 'date_of_birth must be YYYY-MM-DD' });
  }

  const weight = b.birth_weight === '' || b.birth_weight == null ? null : Number(b.birth_weight);
  if (b.birth_weight !== undefined && weight !== null && (!Number.isFinite(weight) || weight <= 0)) {
    return res.status(400).json({ error: 'birth_weight must be a number of kilograms' });
  }

  const status = b.status === undefined ? null : String(b.status).toLowerCase();

  try {
    const { rows } = await pool.query(
      `UPDATE calves SET
         name          = COALESCE($1, name),
         tag           = CASE WHEN $2::boolean THEN $3 ELSE tag END,
         sex           = COALESCE($4, sex),
         breed         = CASE WHEN $5::boolean THEN $6 ELSE breed END,
         date_of_birth = COALESCE($7::date, date_of_birth),
         dam_id        = CASE WHEN $8::boolean THEN $9::int ELSE dam_id END,
         sire          = CASE WHEN $10::boolean THEN $11 ELSE sire END,
         birth_weight  = CASE WHEN $12::boolean THEN $13::numeric ELSE birth_weight END,
         status        = COALESCE($14, status),
         /* Weaning and leaving each carry a date. It is taken from the
            request when one is given, and otherwise stamped as today the
            first time the status says it happened — so the milestone
            never sits there without a date against it. */
         weaned_on     = CASE
                           WHEN $15::date IS NOT NULL THEN $15::date
                           WHEN $14 = 'weaned' AND weaned_on IS NULL THEN CURRENT_DATE
                           ELSE weaned_on
                         END,
         left_on       = CASE
                           WHEN $16::date IS NOT NULL THEN $16::date
                           WHEN $14 = ANY($17::text[]) AND left_on IS NULL THEN CURRENT_DATE
                           ELSE left_on
                         END,
         notes         = CASE WHEN $18::boolean THEN $19 ELSE notes END,
         updated_at    = NOW()
       WHERE id = $20
       RETURNING id`,
      [
        trim(b.name, 100),
        b.tag !== undefined,          trim(b.tag, 50),
        b.sex === undefined ? null : String(b.sex).toLowerCase(),
        b.breed !== undefined,        trim(b.breed, 100),
        isDate(b.date_of_birth) ? b.date_of_birth : null,
        b.dam_id !== undefined,       b.dam_id || null,
        b.sire !== undefined,         trim(b.sire, 200),
        b.birth_weight !== undefined, weight,
        status,
        isDate(b.weaned_on) ? b.weaned_on : null,
        isDate(b.left_on)   ? b.left_on   : null,
        LEFT,
        b.notes !== undefined,        trim(b.notes, 1000),
        req.params.id,
      ]
    );
    if (!rows.length) return res.status(404).json({ error: 'Calf not found' });

    const { rows: full } = await pool.query(`${SELECT} WHERE cf.id = $1`, [rows[0].id]);
    res.json(full[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* She is old enough to milk: give her a place in the herd.

   This writes the `cows` row that milk records, health records and
   pregnancies all hang off, and remembers on the calf which cow she
   became. Her calf record is kept rather than deleted — where she came
   from, who her dam was and what she weighed at birth are the things
   anybody asks about a cow years later.

   Admin and manager only: the herd list is production's book, and this is
   the one calf action that writes into it. */
router.post('/:id/move-to-herd', requireProduction, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      `SELECT id, name, tag, breed, sex, status, cow_id,
              TO_CHAR(date_of_birth,'YYYY-MM-DD') AS date_of_birth
         FROM calves WHERE id = $1 FOR UPDATE`,
      [req.params.id]
    );
    if (!rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Calf not found' });
    }
    const calf = rows[0];

    if (calf.status === 'moved_to_herd') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `${calf.name} is already in the herd.` });
    }
    if (LEFT.includes(calf.status)) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `${calf.name} is recorded as ${calf.status} and cannot be moved into the herd. `
             + 'Correct her status first if that was entered by mistake.',
      });
    }
    /* The herd list is the milking herd: every average, ranking and yield
       alert in the app is a query over it. A bull has no place in that
       arithmetic, so he stays in the young stock until he is sold. */
    if (calf.sex !== 'female') {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `${calf.name} is a bull calf. The herd list holds the milking animals, `
             + 'so moving him into it would put an animal with no yield into every '
             + 'production average. Record him as sold when he leaves instead.',
      });
    }

    /* The cow name is unique, and it is how the milk sheets and the
       importer find an animal. A clash here is a real collision — some
       other animal already answers to this name — so it is worth saying
       plainly rather than quietly overwriting that cow's breed. */
    const name = trim(req.body?.name, 100) || calf.name;
    const clash = await client.query('SELECT id FROM cows WHERE name = $1', [name]);
    if (clash.rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `The herd already has a cow called ${name}. Give her a different name to `
             + 'tell the two apart.',
      });
    }

    const cow = await client.query(
      `INSERT INTO cows (name, tag, breed) VALUES ($1,$2,$3) RETURNING id, name`,
      [name, trim(req.body?.tag, 50) || calf.tag, trim(req.body?.breed, 100) || calf.breed]
    );

    /* She was born here, and now the herd knows it: the cow's timeline
       starts on the day she was born rather than on the day somebody
       typed her in. */
    await client.query(
      `INSERT INTO cow_history (cow_id, event_type, date, source, notes)
       VALUES ($1, 'born', $2, 'calf', $3)`,
      [cow.rows[0].id, calf.date_of_birth, 'Born on the farm and raised as young stock']
    );

    await client.query(
      `UPDATE calves SET status = 'moved_to_herd', cow_id = $1, updated_at = NOW() WHERE id = $2`,
      [cow.rows[0].id, calf.id]
    );

    const { rows: full } = await client.query(`${SELECT} WHERE cf.id = $1`, [calf.id]);
    await client.query('COMMIT');
    res.status(201).json({ calf: full[0], cow: cow.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* For a row that should never have existed — a calf typed in twice.

   A calf that died or was sold should be given that status instead: she
   was born on this farm, and the calving she came from is part of how the
   season reads. The cow she became, if she has been moved into the herd,
   is left alone — deleting the calf record must not take a milking animal
   and her production history with it. */
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'DELETE FROM calves WHERE id = $1 RETURNING id',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Calf not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
