/* ══════════════════════════════════════════════════════════════
   AI CONTEXT LAYER

   Gathers whole-farm data into compact, plain-JSON structures that
   get handed to Claude. Every AI feature (period report, chat,
   daily briefing, per-cow summary) pulls its facts from here, so
   there is exactly one place that decides what the model can see.

   Rules for anything added to this file:
     • Aggregate in SQL, not in JS — keep payloads small.
     • Round numbers. The model does not need 14 decimal places.
     • Never return raw rows for an unbounded table.
══════════════════════════════════════════════════════════════ */
const { pool } = require('./db');

/* ── helpers ─────────────────────────────────────────────── */

const num = (v) => (v === null || v === undefined ? null : Number(v));
/* Same, but for arithmetic: a missing figure is zero, never NaN. */
const num0 = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
};

/** Clamp a user-supplied date to YYYY-MM-DD, or null. */
function safeDate(v) {
  if (!v) return null;
  const s = String(v).trim().slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : null;
}

/**
 * Resolve a period. Defaults to the last 30 days ending today.
 * Also returns the immediately preceding window of equal length,
 * which the report uses for period-over-period comparison.
 */
function resolvePeriod(from, to) {
  const end   = safeDate(to)   || new Date().toISOString().slice(0, 10);
  let   start = safeDate(from);
  if (!start) {
    const d = new Date(end);
    d.setDate(d.getDate() - 29);
    start = d.toISOString().slice(0, 10);
  }
  if (start > end) [start] = [end];

  const days = Math.max(
    1,
    Math.round((new Date(end) - new Date(start)) / 86400000) + 1
  );
  const prevEnd   = new Date(start); prevEnd.setDate(prevEnd.getDate() - 1);
  const prevStart = new Date(prevEnd); prevStart.setDate(prevStart.getDate() - days + 1);

  return {
    from: start,
    to: end,
    days,
    prevFrom: prevStart.toISOString().slice(0, 10),
    prevTo:   prevEnd.toISOString().slice(0, 10),
  };
}

/* ── production ──────────────────────────────────────────── */

async function productionContext({ from, to, prevFrom, prevTo }) {
  const [totals, prevTotals, daily, perCow] = await Promise.all([
    pool.query(`
      SELECT COUNT(*)::int                        AS records,
             COUNT(DISTINCT cow_id)::int          AS cows_milked,
             COUNT(DISTINCT date)::int            AS days_with_data,
             ROUND(SUM(litres)::numeric, 1)       AS total_litres,
             ROUND(AVG(litres)::numeric, 2)       AS avg_litres_per_record
      FROM milk_records WHERE date BETWEEN $1 AND $2
    `, [from, to]),

    pool.query(`
      SELECT ROUND(SUM(litres)::numeric, 1) AS total_litres,
             ROUND(AVG(litres)::numeric, 2) AS avg_litres_per_record
      FROM milk_records WHERE date BETWEEN $1 AND $2
    `, [prevFrom, prevTo]),

    pool.query(`
      SELECT TO_CHAR(date, 'YYYY-MM-DD')       AS date,
             ROUND(SUM(litres)::numeric, 1)    AS litres,
             COUNT(*)::int                     AS cows
      FROM milk_records WHERE date BETWEEN $1 AND $2
      GROUP BY date ORDER BY date
    `, [from, to]),

    // Per-cow stats for the period, with the prior period alongside so the
    // model can talk about who improved and who slipped.
    pool.query(`
      WITH cur AS (
        SELECT cow_id,
               ROUND(AVG(litres)::numeric, 2) AS avg_litres,
               ROUND(SUM(litres)::numeric, 1) AS total_litres,
               COUNT(*)::int                  AS records
        FROM milk_records WHERE date BETWEEN $1 AND $2 GROUP BY cow_id
      ),
      prev AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric, 2) AS prev_avg_litres
        FROM milk_records WHERE date BETWEEN $3 AND $4 GROUP BY cow_id
      )
      SELECT c.name, c.tag, c.breed, c.status,
             cur.avg_litres, cur.total_litres, cur.records,
             prev.prev_avg_litres,
             CASE WHEN prev.prev_avg_litres > 0
                  THEN ROUND(((cur.avg_litres - prev.prev_avg_litres)
                              / prev.prev_avg_litres * 100)::numeric, 1)
             END AS change_pct
      FROM cur
      JOIN cows c ON c.id = cur.cow_id
      LEFT JOIN prev ON prev.cow_id = cur.cow_id
      ORDER BY cur.avg_litres DESC
    `, [from, to, prevFrom, prevTo]),
  ]);

  const cows = perCow.rows.map(r => ({
    name: r.name,
    tag: r.tag,
    breed: r.breed,
    // Present only when she has left the herd, so 'active' stays unstated.
    status: r.status === 'active' ? undefined : r.status,
    avg_litres: num(r.avg_litres),
    total_litres: num(r.total_litres),
    records: r.records,
    prev_avg_litres: num(r.prev_avg_litres),
    change_pct: num(r.change_pct),
  }));

  const t = totals.rows[0];
  const p = prevTotals.rows[0];

  return {
    totals: {
      records: t.records,
      cows_milked: t.cows_milked,
      days_with_data: t.days_with_data,
      total_litres: num(t.total_litres),
      avg_litres_per_record: num(t.avg_litres_per_record),
    },
    previous_period: {
      total_litres: num(p.total_litres),
      avg_litres_per_record: num(p.avg_litres_per_record),
    },
    daily: daily.rows.map(r => ({
      date: r.date, litres: num(r.litres), cows: r.cows,
    })),
    // Full list is fine for a farm-sized herd; the model benefits from seeing
    // every cow rather than an arbitrary top-N slice.
    per_cow: cows,
  };
}

/* ── health ──────────────────────────────────────────────── */

async function healthContext({ from, to }) {
  const [diseases, treatments, records, history] = await Promise.all([
    pool.query(`
      SELECT d.name, d.description,
             TO_CHAR(d.date, 'YYYY-MM-DD') AS date,
             d.notes,
             COALESCE(
               ARRAY_AGG(c.name ORDER BY c.name) FILTER (WHERE c.name IS NOT NULL),
               '{}'
             ) AS affected_cows
      FROM diseases d
      LEFT JOIN disease_cows dc ON dc.disease_id = d.id
      LEFT JOIN cows c          ON c.id = dc.cow_id
      WHERE d.date BETWEEN $1 AND $2
      GROUP BY d.id ORDER BY d.date DESC
    `, [from, to]),

    pool.query(`
      SELECT t.medicine_name, t.dosage,
             TO_CHAR(t.date, 'YYYY-MM-DD') AS date,
             t.notes, d.name AS disease
      FROM treatments t
      LEFT JOIN diseases d ON d.id = t.disease_id
      WHERE t.date BETWEEN $1 AND $2
      ORDER BY t.date DESC
    `, [from, to]),

    // cow_health_records stores exam_date as free text, so filter on the
    // upload timestamp instead — it is the only reliable ordering we have.
    pool.query(`
      SELECT r.cow_tag, r.breed, r.exam_date,
             r.tentative_diagnosis, r.final_diagnosis,
             r.attending_vet, r.milk_withdraw_date,
             c.name AS cow_name
      FROM cow_health_records r
      LEFT JOIN cows c ON c.id = r.cow_id
      WHERE r.uploaded_at::date BETWEEN $1 AND $2
      ORDER BY r.uploaded_at DESC LIMIT 60
    `, [from, to]),

    pool.query(`
      SELECT h.event_type,
             TO_CHAR(h.date, 'YYYY-MM-DD') AS date,
             h.notes, h.source, c.name AS cow_name
      FROM cow_history h
      LEFT JOIN cows c ON c.id = h.cow_id
      WHERE h.date BETWEEN $1 AND $2
      ORDER BY h.date DESC LIMIT 100
    `, [from, to]),
  ]);

  return {
    diseases:   diseases.rows,
    treatments: treatments.rows,
    vet_records: records.rows,
    cow_events: history.rows,
  };
}

/* ── pregnancies ─────────────────────────────────────────── */

async function pregnancyContext({ from, to }) {
  const [active, births, conceptions] = await Promise.all([
    pool.query(`
      SELECT c.name AS cow_name,
             TO_CHAR(p.conception_date, 'YYYY-MM-DD')   AS conception_date,
             TO_CHAR(p.expected_due_date, 'YYYY-MM-DD') AS expected_due_date,
             (p.expected_due_date - CURRENT_DATE)::int  AS days_remaining,
             p.notes
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE p.status = 'active'
      ORDER BY p.expected_due_date
    `),

    pool.query(`
      SELECT c.name AS cow_name,
             TO_CHAR(p.actual_birth_date, 'YYYY-MM-DD')  AS actual_birth_date,
             TO_CHAR(p.expected_due_date, 'YYYY-MM-DD')  AS expected_due_date,
             p.notes
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE p.actual_birth_date BETWEEN $1 AND $2
      ORDER BY p.actual_birth_date DESC
    `, [from, to]),

    pool.query(`
      SELECT c.name AS cow_name,
             TO_CHAR(p.conception_date, 'YYYY-MM-DD') AS conception_date,
             p.status
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE p.conception_date BETWEEN $1 AND $2
      ORDER BY p.conception_date DESC
    `, [from, to]),
  ]);

  return {
    active: active.rows,
    births_in_period: births.rows,
    conceptions_in_period: conceptions.rows,
  };
}

/* ── sales ───────────────────────────────────────────────── */

async function salesContext({ from, to, prevFrom, prevTo }) {
  const totalsSql = `
    SELECT COUNT(*)::int                                   AS entries,
           ROUND(SUM(litres_sold)::numeric, 1)             AS litres_sold,
           ROUND(SUM(litres_sold * price_per_litre)::numeric, 2) AS revenue,
           ROUND(AVG(price_per_litre)::numeric, 2)         AS avg_price_per_litre
    FROM sales WHERE date BETWEEN $1 AND $2
  `;

  const [totals, prevTotals, daily] = await Promise.all([
    pool.query(totalsSql, [from, to]),
    pool.query(totalsSql, [prevFrom, prevTo]),
    pool.query(`
      SELECT TO_CHAR(date, 'YYYY-MM-DD')                          AS date,
             ROUND(SUM(litres_sold)::numeric, 1)                  AS litres_sold,
             ROUND(SUM(litres_sold * price_per_litre)::numeric, 2) AS revenue
      FROM sales WHERE date BETWEEN $1 AND $2
      GROUP BY date ORDER BY date
    `, [from, to]),
  ]);

  const shape = (r) => ({
    entries: r.entries,
    litres_sold: num(r.litres_sold),
    revenue: num(r.revenue),
    avg_price_per_litre: num(r.avg_price_per_litre),
  });

  return {
    totals: shape(totals.rows[0]),
    previous_period: shape(prevTotals.rows[0]),
    daily: daily.rows.map(r => ({
      date: r.date, litres_sold: num(r.litres_sold), revenue: num(r.revenue),
    })),
  };
}

/* ── inventory ───────────────────────────────────────────── */

async function inventoryContext({ from, to }) {
  const [stock, movements] = await Promise.all([
    pool.query(`
      SELECT i.name, i.unit, i.notes,
             ROUND(COALESCE(SUM(
               CASE WHEN l.type = 'in' THEN l.quantity ELSE -l.quantity END
             ), 0)::numeric, 2) AS current_stock
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      GROUP BY i.id, i.name, i.unit, i.notes
      ORDER BY current_stock ASC
    `),

    pool.query(`
      SELECT i.name, i.unit,
             ROUND(SUM(CASE WHEN l.type = 'in'  THEN l.quantity ELSE 0 END)::numeric, 2) AS received,
             ROUND(SUM(CASE WHEN l.type = 'out' THEN l.quantity ELSE 0 END)::numeric, 2) AS used
      FROM inventory_logs l
      JOIN inventory_items i ON i.id = l.item_id
      WHERE l.date BETWEEN $1 AND $2
      GROUP BY i.id, i.name, i.unit
      ORDER BY used DESC
    `, [from, to]),
  ]);

  const items = stock.rows.map(r => ({
    name: r.name,
    unit: r.unit,
    current_stock: num(r.current_stock),
    notes: r.notes,
  }));

  return {
    items,
    out_of_stock: items.filter(i => i.current_stock <= 0).map(i => i.name),
    movements_in_period: movements.rows.map(r => ({
      name: r.name, unit: r.unit, received: num(r.received), used: num(r.used),
    })),
  };
}

/* ── processing unit ─────────────────────────────────────── */

/**
 * Processing data is keyed by month + day-of-month rather than a real date,
 * so it cannot be filtered by the report period. We return the most recent
 * months instead and label them clearly so the model does not silently
 * present them as period-aligned.
 *
 * Alongside the raw figures each month carries a `reconciliation` block: how
 * much of the milk taken in came back out as packed litres, what share was
 * written off, and whether stock balances. Those are the questions anyone
 * actually asks of a processing unit, and computing them here means every
 * report and every chat answer works from the same arithmetic rather than
 * each one re-deriving it from the tables — differently.
 */
async function processingContext(limit = 2) {
  const { rows: uploads } = await pool.query(`
    SELECT id, label, month_num, year, source,
           opening_fresh_litres, fresh_damage_litres,
           TO_CHAR(uploaded_at, 'YYYY-MM-DD') AS uploaded_at
    FROM processing_uploads
    ORDER BY year DESC NULLS LAST, month_num DESC NULLS LAST, uploaded_at DESC
    LIMIT $1
  `, [limit]);

  if (!uploads.length) return { note: 'No processing unit data uploaded yet.', months: [] };

  const ids = uploads.map(u => u.id);

  const agg = (table) => pool.query(`
    SELECT upload_id, product, size,
           ROUND(SUM(units)::numeric, 1)  AS units,
           ROUND(SUM(litres)::numeric, 1) AS litres
    FROM ${table} WHERE upload_id = ANY($1)
    GROUP BY upload_id, product, size ORDER BY product, size
  `, [ids]);

  const [received, packed, issued, damaged, stock] = await Promise.all([
    pool.query(`
      SELECT upload_id,
             ROUND(SUM(farm_litres)::numeric, 1)      AS farm_litres,
             ROUND(SUM(mwabulugu_litres)::numeric, 1) AS mwabulugu_litres,
             ROUND(SUM(purchased_litres)::numeric, 1) AS purchased_litres,
             ROUND(SUM(damaged_litres)::numeric, 1)   AS damaged_litres,
             COUNT(*)::int                            AS days_recorded
      FROM processing_milk_received WHERE upload_id = ANY($1) GROUP BY upload_id
    `, [ids]),
    agg('processing_packed'),
    agg('processing_issued'),
    agg('processing_damaged'),
    pool.query(`
      SELECT upload_id, product, size,
             opening_units, packed_units, issued_units, damaged_units,
             units AS closing_units, litres AS closing_litres
      FROM processing_stock WHERE upload_id = ANY($1)
      ORDER BY product, size
    `, [ids]),
  ]);

  const byUpload = (rows, id) => rows.filter(r => r.upload_id === id)
    .map(({ upload_id, ...rest }) => rest);

  const months = uploads.map((u) => {
    const rec = byUpload(received.rows, u.id)[0] || null;
    const p = byUpload(packed.rows, u.id);
    const i = byUpload(issued.rows, u.id);
    const d = byUpload(damaged.rows, u.id);
    const s = byUpload(stock.rows, u.id);

    const sum = (rows, key) => rows.reduce((a, r) => a + num0(r[key]), 0);
    const receivedLitres = rec
      ? num0(rec.farm_litres) + num0(rec.mwabulugu_litres) + num0(rec.purchased_litres)
      : 0;
    const packedLitres = sum(p, 'litres');
    const packedUnits = sum(p, 'units');
    const damagedUnits = sum(d, 'units');
    const availableLitres = receivedLitres + num0(u.opening_fresh_litres);

    const pct = (part, whole) => (whole > 0 ? Math.round((part / whole) * 1000) / 10 : null);

    return {
      label: u.label,
      month_num: u.month_num,
      year: u.year,
      /* 'legacy' means the figures came from the farm's own hand-kept
         workbook rather than the app's template — worth knowing before
         drawing a fine distinction from them. */
      read_from: u.source,
      uploaded_at: u.uploaded_at,
      milk_received: rec && {
        ...rec,
        total_litres: Math.round(receivedLitres * 10) / 10,
        opening_fresh_litres: num0(u.opening_fresh_litres),
      },
      packed: p,
      issued: i,
      damaged: d,
      stock: s,
      reconciliation: {
        milk_available_litres: Math.round(availableLitres * 10) / 10,
        packed_litres: Math.round(packedLitres * 10) / 10,
        /* Litres that went in but never came out as a sealed pack: spillage,
           residue, and mis-keying all land here together, so treat a figure
           in the low single-digit percentages as normal. */
        unaccounted_litres: Math.round((availableLitres - packedLitres) * 10) / 10,
        yield_pct: pct(packedLitres, availableLitres),
        packed_units: packedUnits,
        issued_units: sum(i, 'units'),
        damaged_units: damagedUnits,
        damage_rate_pct: pct(damagedUnits, packedUnits),
        /* The month total, from the upload row. The per-day figures in
           processing_milk_received.damaged_litres are the same litres broken
           out by date — adding both would count the loss twice. */
        fresh_milk_damaged_litres: num0(u.fresh_damage_litres),
        closing_units: sum(s, 'closing_units'),
        closing_litres: Math.round(sum(s, 'closing_litres') * 10) / 10,
        /* Closing below zero is arithmetically impossible: it means the sheet
           issued or wrote off more packs than were ever made. Naming the lines
           keeps the model from reporting the negative total as real stock. */
        negative_lines: s.filter(r => num0(r.closing_units) < 0)
          .map(r => ({ product: r.product, size: r.size, closing_units: num0(r.closing_units) })),
      },
    };
  });

  return {
    note: 'Processing records are organised by month, not by calendar date, so they may '
        + 'not align exactly with the report period. Litres for packed, issued and damaged '
        + 'goods are derived from the pack size, not typed in.',
    months,
    // Kept under the old key so anything still reading `uploads` keeps working.
    uploads: months,
  };
}

/**
 * Everything recorded for one processing month, day by day.
 *
 * The aggregate view above answers "how did the month go"; this answers
 * "what happened on the 14th", which is the form most follow-up questions
 * take once something looks wrong.
 */
async function processingMonth(label) {
  const { rows } = await pool.query(`
    SELECT id, label, month_num, year, source,
           opening_fresh_litres, fresh_damage_litres
    FROM processing_uploads WHERE UPPER(label) = UPPER($1) LIMIT 1
  `, [String(label || '').trim()]);

  if (!rows.length) {
    const { rows: available } = await pool.query(`
      SELECT label FROM processing_uploads
      ORDER BY year DESC NULLS LAST, month_num DESC NULLS LAST LIMIT 24
    `);
    return {
      error: `No processing data for "${label}".`,
      available_months: available.map(r => r.label),
    };
  }

  const up = rows[0];
  const daily = (table) => pool.query(`
    SELECT day, product, size, units, litres FROM ${table}
    WHERE upload_id = $1 AND units <> 0 ORDER BY day, product, size
  `, [up.id]);

  const [received, packed, issued, damaged, stock] = await Promise.all([
    pool.query(`
      SELECT day, farm_litres, mwabulugu_litres, purchased_litres, damaged_litres
      FROM processing_milk_received WHERE upload_id = $1 ORDER BY day
    `, [up.id]),
    daily('processing_packed'),
    daily('processing_issued'),
    daily('processing_damaged'),
    pool.query(`
      SELECT product, size, opening_units, packed_units, issued_units,
             damaged_units, units AS closing_units, litres AS closing_litres
      FROM processing_stock WHERE upload_id = $1 ORDER BY product, size
    `, [up.id]),
  ]);

  return {
    label: up.label,
    read_from: up.source,
    opening_fresh_litres: num0(up.opening_fresh_litres),
    fresh_damage_litres: num0(up.fresh_damage_litres),
    daily_milk_received: received.rows,
    daily_packed: packed.rows,
    daily_issued: issued.rows,
    daily_damaged: damaged.rows,
    stock_by_product: stock.rows,
  };
}

/* ── herd roster ─────────────────────────────────────────── */

async function herdContext() {
  const { rows } = await pool.query(`
    SELECT c.name, c.tag, c.breed, c.status,
           TO_CHAR(c.archived_at, 'YYYY-MM-DD') AS left_herd_on,
           c.archived_note,
           COUNT(r.id)::int               AS lifetime_records,
           ROUND(AVG(r.litres)::numeric, 2) AS lifetime_avg_litres,
           TO_CHAR(MAX(r.date), 'YYYY-MM-DD') AS last_milked
    FROM cows c LEFT JOIN milk_records r ON r.cow_id = c.id
    GROUP BY c.id ORDER BY c.name
  `);

  const shape = (r) => ({
    name: r.name, tag: r.tag, breed: r.breed,
    lifetime_records: r.lifetime_records,
    lifetime_avg_litres: num(r.lifetime_avg_litres),
    last_milked: r.last_milked,
  });

  /* Split rather than tagged, so "how many cows are there" cannot be answered
     with a number that includes animals which have died or been sold. Their
     figures are still here to answer questions about them. */
  return {
    herd_size: rows.filter(r => r.status === 'active').length,
    cows: rows.filter(r => r.status === 'active').map(shape),
    no_longer_in_herd: rows.filter(r => r.status !== 'active').map(r => ({
      ...shape(r),
      status: r.status,
      left_herd_on: r.left_herd_on,
      note: r.archived_note || undefined,
    })),
  };
}

/* ── single cow dossier ──────────────────────────────────── */

async function cowDossier(cowId) {
  const { rows: cowRows } = await pool.query(
    `SELECT id, name, tag, breed, status,
            TO_CHAR(created_at, 'YYYY-MM-DD')  AS added_on,
            TO_CHAR(archived_at, 'YYYY-MM-DD') AS archived_at,
            archived_note
       FROM cows WHERE id = $1`,
    [cowId]
  );
  const cow = cowRows[0];
  if (!cow) return null;

  const [stats, monthly, recent, diseases, treatments, pregnancies, history, vet] =
    await Promise.all([
      pool.query(`
        SELECT COUNT(*)::int                    AS records,
               ROUND(AVG(litres)::numeric, 2)   AS avg_litres,
               ROUND(MAX(litres)::numeric, 2)   AS max_litres,
               ROUND(MIN(litres)::numeric, 2)   AS min_litres,
               ROUND(STDDEV(litres)::numeric, 2) AS stddev_litres,
               TO_CHAR(MIN(date), 'YYYY-MM-DD') AS first_record,
               TO_CHAR(MAX(date), 'YYYY-MM-DD') AS last_record
        FROM milk_records WHERE cow_id = $1
      `, [cowId]),

      pool.query(`
        SELECT TO_CHAR(DATE_TRUNC('month', date), 'YYYY-MM') AS month,
               ROUND(AVG(litres)::numeric, 2) AS avg_litres,
               ROUND(SUM(litres)::numeric, 1) AS total_litres,
               COUNT(*)::int                  AS records
        FROM milk_records WHERE cow_id = $1
        GROUP BY 1 ORDER BY 1
      `, [cowId]),

      pool.query(`
        SELECT TO_CHAR(date, 'YYYY-MM-DD') AS date, litres, notes
        FROM milk_records WHERE cow_id = $1 ORDER BY date DESC LIMIT 30
      `, [cowId]),

      pool.query(`
        SELECT d.name, d.description, TO_CHAR(d.date, 'YYYY-MM-DD') AS date, d.notes
        FROM diseases d JOIN disease_cows dc ON dc.disease_id = d.id
        WHERE dc.cow_id = $1 ORDER BY d.date DESC
      `, [cowId]),

      pool.query(`
        SELECT t.medicine_name, t.dosage, TO_CHAR(t.date, 'YYYY-MM-DD') AS date,
               t.notes, d.name AS disease
        FROM treatments t
        JOIN diseases d      ON d.id = t.disease_id
        JOIN disease_cows dc ON dc.disease_id = d.id
        WHERE dc.cow_id = $1 ORDER BY t.date DESC
      `, [cowId]),

      pool.query(`
        SELECT TO_CHAR(conception_date, 'YYYY-MM-DD')   AS conception_date,
               TO_CHAR(expected_due_date, 'YYYY-MM-DD') AS expected_due_date,
               TO_CHAR(actual_birth_date, 'YYYY-MM-DD') AS actual_birth_date,
               status, notes
        FROM pregnancies WHERE cow_id = $1 ORDER BY conception_date DESC
      `, [cowId]),

      pool.query(`
        SELECT event_type, TO_CHAR(date, 'YYYY-MM-DD') AS date, notes, source
        FROM cow_history WHERE cow_id = $1 ORDER BY date DESC LIMIT 50
      `, [cowId]),

      pool.query(`
        SELECT exam_date, age, parity, body_weight, body_temperature, pulse_rate,
               respiratory_rate, days_in_milk, daily_milk_yield, present_illness,
               clinical_findings, tentative_diagnosis, final_diagnosis,
               lab_findings, treatments, milk_withdraw_date, attending_vet
        FROM cow_health_records WHERE cow_id = $1
        ORDER BY uploaded_at DESC LIMIT 10
      `, [cowId]),
    ]);

  const s = stats.rows[0];

  // Herd baseline so the model can say "above/below average" with a real number.
  const { rows: baseline } = await pool.query(
    'SELECT ROUND(AVG(litres)::numeric, 2) AS herd_avg_litres FROM milk_records'
  );

  return {
    cow,
    herd_avg_litres: num(baseline[0].herd_avg_litres),
    production: {
      records: s.records,
      avg_litres: num(s.avg_litres),
      max_litres: num(s.max_litres),
      min_litres: num(s.min_litres),
      stddev_litres: num(s.stddev_litres),
      first_record: s.first_record,
      last_record: s.last_record,
      monthly: monthly.rows.map(r => ({
        month: r.month,
        avg_litres: num(r.avg_litres),
        total_litres: num(r.total_litres),
        records: r.records,
      })),
      recent_30: recent.rows.map(r => ({
        date: r.date, litres: num(r.litres), notes: r.notes,
      })),
    },
    diseases: diseases.rows,
    treatments: treatments.rows,
    pregnancies: pregnancies.rows,
    events: history.rows,
    vet_records: vet.rows,
  };
}

/* ── alert signals (shared with the daily briefing) ──────── */

async function alertSignals() {
  const [drops, dueSoon, lowStock, staleCows, recentDisease] = await Promise.all([
    pool.query(`
      WITH overall AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric, 2) AS avg_all
        FROM milk_records GROUP BY cow_id
      ),
      recent AS (
        SELECT cow_id, ROUND(AVG(litres)::numeric, 2) AS avg_recent
        FROM milk_records WHERE date >= CURRENT_DATE - 7 GROUP BY cow_id
      )
      SELECT c.name, o.avg_all, r.avg_recent,
             ROUND(((o.avg_all - r.avg_recent) / NULLIF(o.avg_all, 0) * 100)::numeric, 1) AS drop_pct
      FROM overall o
      JOIN recent r ON r.cow_id = o.cow_id
      JOIN cows c   ON c.id = o.cow_id
      WHERE c.status = 'active' AND r.avg_recent < o.avg_all * 0.80
      ORDER BY drop_pct DESC
    `),

    pool.query(`
      SELECT c.name AS cow_name,
             TO_CHAR(p.expected_due_date, 'YYYY-MM-DD') AS expected_due_date,
             (p.expected_due_date - CURRENT_DATE)::int  AS days_remaining
      FROM pregnancies p JOIN cows c ON c.id = p.cow_id
      WHERE c.status = 'active'
        AND p.status = 'active'
        AND p.expected_due_date BETWEEN CURRENT_DATE - 7 AND CURRENT_DATE + 21
      ORDER BY p.expected_due_date
    `),

    pool.query(`
      SELECT i.name, i.unit,
             ROUND(COALESCE(SUM(
               CASE WHEN l.type = 'in' THEN l.quantity ELSE -l.quantity END
             ), 0)::numeric, 2) AS current_stock
      FROM inventory_items i
      LEFT JOIN inventory_logs l ON l.item_id = i.id
      GROUP BY i.id, i.name, i.unit
      HAVING COALESCE(SUM(
        CASE WHEN l.type = 'in' THEN l.quantity ELSE -l.quantity END
      ), 0) <= 0
    `),

    // Cows with no milk record in the last 3 days despite having history —
    // usually a missed data entry rather than a dry cow, worth surfacing.
    pool.query(`
      SELECT c.name, TO_CHAR(MAX(r.date), 'YYYY-MM-DD') AS last_record,
             (CURRENT_DATE - MAX(r.date))::int AS days_since
      FROM cows c JOIN milk_records r ON r.cow_id = c.id
      WHERE c.status = 'active'
      GROUP BY c.id, c.name
      HAVING (CURRENT_DATE - MAX(r.date))::int BETWEEN 3 AND 60
      ORDER BY days_since DESC LIMIT 20
    `),

    pool.query(`
      SELECT d.name, TO_CHAR(d.date, 'YYYY-MM-DD') AS date,
             COUNT(dc.cow_id)::int AS affected_count
      FROM diseases d
      LEFT JOIN disease_cows dc ON dc.disease_id = d.id
      WHERE d.date >= CURRENT_DATE - 14
      GROUP BY d.id ORDER BY d.date DESC
    `),
  ]);

  /* Processing signals for the most recent month on file.

     These are not date-filtered like the rest — the processing unit is
     recorded a month at a time, so "recent" means the latest month uploaded.
     A stale month is itself worth flagging, which is why days_since_upload
     comes back rather than the row being dropped. */
  const { rows: procRows } = await pool.query(`
    WITH latest AS (
      SELECT id, label, uploaded_at, fresh_damage_litres
      FROM processing_uploads
      ORDER BY year DESC NULLS LAST, month_num DESC NULLS LAST, uploaded_at DESC
      LIMIT 1
    )
    SELECT l.label,
           (CURRENT_DATE - l.uploaded_at::date)::int AS days_since_upload,
           ROUND(l.fresh_damage_litres::numeric, 1)  AS fresh_damage_litres,
           (SELECT COALESCE(SUM(units), 0) FROM processing_packed  WHERE upload_id = l.id) AS packed_units,
           (SELECT COALESCE(SUM(units), 0) FROM processing_damaged WHERE upload_id = l.id) AS damaged_units,
           (SELECT COALESCE(SUM(litres), 0) FROM processing_packed WHERE upload_id = l.id) AS packed_litres,
           (SELECT COALESCE(SUM(farm_litres + mwabulugu_litres + purchased_litres), 0)
              FROM processing_milk_received WHERE upload_id = l.id) AS received_litres,
           (SELECT COALESCE(JSON_AGG(JSON_BUILD_OBJECT(
                     'product', product, 'size', size, 'closing_units', units)), '[]')
              FROM processing_stock WHERE upload_id = l.id AND units < 0) AS negative_stock
    FROM latest l
  `);

  const proc = procRows[0] ? (() => {
    const r = procRows[0];
    const packedUnits = num0(r.packed_units);
    const damagedUnits = num0(r.damaged_units);
    const receivedLitres = num0(r.received_litres);
    return {
      month: r.label,
      days_since_upload: r.days_since_upload,
      packed_units: packedUnits,
      damaged_units: damagedUnits,
      damage_rate_pct: packedUnits > 0
        ? Math.round((damagedUnits / packedUnits) * 1000) / 10 : null,
      received_litres: Math.round(receivedLitres * 10) / 10,
      packed_litres: Math.round(num0(r.packed_litres) * 10) / 10,
      yield_pct: receivedLitres > 0
        ? Math.round((num0(r.packed_litres) / receivedLitres) * 1000) / 10 : null,
      fresh_milk_damaged_litres: num0(r.fresh_damage_litres),
      // Impossible balances: more issued or written off than ever produced.
      negative_stock_lines: r.negative_stock,
    };
  })() : null;

  return {
    as_of: new Date().toISOString().slice(0, 10),
    processing_unit: proc,
    production_drops: drops.rows.map(r => ({
      name: r.name,
      avg_all: num(r.avg_all),
      avg_recent: num(r.avg_recent),
      drop_pct: num(r.drop_pct),
    })),
    births_window: dueSoon.rows,
    out_of_stock: lowStock.rows.map(r => ({
      name: r.name, unit: r.unit, current_stock: num(r.current_stock),
    })),
    cows_missing_records: staleCows.rows,
    recent_diseases: recentDisease.rows,
  };
}

/* ── the whole farm, for a period ────────────────────────── */

async function farmSnapshot({ from, to } = {}) {
  const period = resolvePeriod(from, to);

  const [production, health, pregnancies, sales, inventory, processing] =
    await Promise.all([
      productionContext(period),
      healthContext(period),
      pregnancyContext(period),
      salesContext(period),
      inventoryContext(period),
      processingContext(),
    ]);

  return { period, production, health, pregnancies, sales, inventory, processing };
}

module.exports = {
  resolvePeriod,
  safeDate,
  farmSnapshot,
  productionContext,
  healthContext,
  pregnancyContext,
  salesContext,
  inventoryContext,
  processingContext,
  processingMonth,
  herdContext,
  cowDossier,
  alertSignals,
};
