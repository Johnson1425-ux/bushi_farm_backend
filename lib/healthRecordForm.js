/* ══════════════════════════════════════════════════════════════
   INDIVIDUAL HEALTH RECORD — FIELD CATALOGUE

   The Bushi Dairy Farm Individual Health Records form, written down once.

   Three things have to agree about what is on that form: the blank .docx
   the vet is handed, the parser that reads it back when they upload the
   filled copy, and the in-app form that replaces the paper round trip
   entirely. Each used to carry its own idea of the labels — which is how
   the old parser ended up hunting for "Cow ID/Tag" and "Present illness"
   on a sheet that says "ID/Tag no." and "Major complaint", and quietly
   returning null for both.

   So the labels live here, beside the column each one lands in, and the
   template, the parser and the insert all read from this file. A field
   added to the paper form is added once, here.

   `label` is verbatim from the printed sheet, down to its spelling
   ("Feacal sample", "Licence #") — the parser matches on it, so changing
   it to taste would break the reading of forms already in circulation.
   `aliases` carry the wordings older uploads may use.
══════════════════════════════════════════════════════════════ */

/* ─── SECTION HEADINGS ────────────────────────────────────────
   The headings printed across the form. They are here rather than inline
   in the template because the parser needs them too: a heading is the one
   thing that can follow a field on the page without being that field's
   answer, so the reader has to recognise one to refuse it. */
const SECTIONS = {
  title:          'BUSHI DAIRY FARM INDIVIDUAL HEALTH RECORDS',
  identification: 'ANIMAL IDENTIFICATION AND HISTORY',
  examination:    'CLINICAL EXAMINATION',
  findings:       'CLINICAL EXAMINATION FINDINGS',
  laboratory:     'LABORATORY FINDING AND FINAL DIAGNOSIS',
  treatment:      'DIAGNOSIS, TREATMENT AND WITHDRAW COMPLIANCE',
};

/* ─── ANIMAL IDENTIFICATION AND HISTORY ───────────────────────
   A two-column table on the sheet: label down the left, a blank box
   on the right. */
const IDENTIFICATION = [
  { key: 'cow_tag',          label: 'ID/Tag no.',   aliases: ['Cow ID/Tag', 'Cow ID', 'ID/Tag'] },
  { key: 'age',              label: 'Age' },
  { key: 'breed',            label: 'Breed' },
  { key: 'sex',              label: 'sex' },
  { key: 'body_weight',      label: 'Body weight' },
  { key: 'repro_status',     label: 'Status(pregnant/cycling/serviced)', aliases: ['Status'] },
  { key: 'parity',           label: 'Parity' },
  { key: 'daily_milk_yield', label: 'Daily milk yield' },
  { key: 'days_in_milk',     label: 'Days in milk' },
];

/* ─── CLINICAL EXAMINATION ────────────────────────────────────
   The numbered free-text lines under the heading. */
const HISTORY = [
  { key: 'present_illness', label: 'Major complaint', aliases: ['Present illness'] },
  { key: 'past_history',    label: 'Past history (Medical, surgical, Trauma, Vaccination, Deworming)', aliases: ['Past history'] },
  { key: 'environment',     label: 'Environment' },
  { key: 'system_review',   label: 'System review' },
];

/* ─── VITALS ──────────────────────────────────────────────────
   One wide five-cell table, headings across the top, values beneath. */
const VITALS = [
  { key: 'body_temperature', label: 'Body temperature' },
  { key: 'pulse_rate',       label: 'Pulse rate(beats/mins)',      aliases: ['Pulse rate'] },
  { key: 'respiratory_rate', label: 'Respiratory rate(beats/min)', aliases: ['Respiratory rate'] },
  { key: 'crt_seconds',      label: 'CRT (2seconds)',              aliases: ['CRT(seconds)', 'CRT'] },
  { key: 'rumino_motility',  label: 'Rumino-motility (2 min)',     aliases: ['Rumino-motility', 'Ruminomotility'] },
];

/* ─── CLINICAL EXAMINATION FINDINGS ───────────────────────────
   SYSTEM | STATUS(Normal/Abnormal) | SPECIFIC OBSERVATIONS, one row per
   body system. Stored as JSONB so a row the vet left blank costs nothing
   and the twelve stay in the sheet's order.

   "Circulatory" appears twice on the paper form — once plainly and once
   as "Circulatory (MM/CRT)" near the bottom. Both are kept: the vet fills
   whichever their examination followed, and a parser that collapsed them
   would drop one of the two readings. */
const SYSTEMS = [
  'General appearance (BCS)',
  'Integumentary',
  'Musculoskeletal',
  'Circulatory',
  'Respiratory',
  'Digestive',
  'Genitourinary',
  'Ears/Eyes',
  'Mammary system/Udder',
  'Neural system',
  'Lymph nodes',
  'Circulatory (MM/CRT)',
];

const SYSTEM_STATUSES = ['Normal', 'Abnormal'];

/* Older sheets and the previous parser used shorter names for some rows.
   Reading one of these back maps it onto the row above it. */
const SYSTEM_ALIASES = {
  'General appearance':    'General appearance (BCS)',
  'General Appearance':    'General appearance (BCS)',
  'Mammary system':        'Mammary system/Udder',
  'Udder':                 'Mammary system/Udder',
  'Circulatory(MM/CRT)':   'Circulatory (MM/CRT)',
};

/* ─── FINDINGS AND TENTATIVE DIAGNOSIS ────────────────────────
   The two ruled lines that close the examination page. */
const FINDINGS = [
  { key: 'significant_findings', label: 'Significant findings' },
  { key: 'tentative_diagnosis',  label: 'Tentative diagnosis' },
];

/* ─── LABORATORY FINDING AND FINAL DIAGNOSIS ──────────────────
   A small blood-smear grid, then ruled lines for each sample type. */
const BLOOD_SMEAR = [
  { key: 'pcv',         label: 'PCV' },
  { key: 'eosinophils', label: 'Eosinophils' },
  { key: 'basophils',   label: 'Basophils' },
  { key: 'neutrophils', label: 'Neutrophils' },
];

const LABORATORY = [
  { key: 'bacteriology',   label: 'Bacteriology culture & senstivity results', aliases: ['Bacteriology culture & sensitivity results', 'Bacteriology'] },
  { key: 'skin_scrapings', label: 'Skin scrapings' },
  { key: 'fecal_sample',   label: 'Feacal sample', aliases: ['Fecal sample', 'Faecal sample'] },
  { key: 'other_lab',      label: 'Other laboratory' },
  { key: 'lab_findings',   label: 'Findings' },
];

/* ─── DIAGNOSIS, TREATMENT AND WITHDRAW COMPLIANCE ────────────
   The prescription table plus the sign-off block. */
const TREATMENT_COLUMNS = [
  { key: 'drug',         label: 'Drug/vaccine' },
  { key: 'prescription', label: 'Prescription (dose, dosage and route)' },
];

/* How many blank prescription rows the paper form prints. The in-app form
   starts with the same number and lets the vet add more; the parser reads
   as many as were filled. */
const TREATMENT_ROWS = 4;

const SIGN_OFF = [
  { key: 'final_diagnosis',     label: 'Tentative/Final diagnosis', aliases: ['Final diagnosis'] },
  { key: 'recommendation',      label: 'Recommendation' },
  { key: 'milk_withdraw_date',  label: 'Milk withdraw end date', aliases: ['Milk withdraw'] },
  { key: 'attending_vet',       label: 'Attending veterinarian/paraveterinarian', aliases: ['Attending veterinarian/ paraveterinarian', 'Attending veterinarian'] },
  { key: 'license_number',      label: 'Licence #', aliases: ['License #', 'Licence no', 'License no'] },
  { key: 'exam_date',           label: 'Date' },
];

/* ─── DERIVED ─────────────────────────────────────────────────
   Everything below is assembled from the blocks above, so nothing has to
   be kept in step by hand. */

/* Every plain text field, in the order it appears on the sheet. */
const TEXT_FIELDS = [
  ...IDENTIFICATION, ...HISTORY, ...VITALS, ...FINDINGS,
  { key: 'blood_smear', label: 'Blood smear' },
  ...BLOOD_SMEAR, ...LABORATORY, ...SIGN_OFF,
];

/* The columns a record writes, text fields plus the two JSONB tables.
   `cow_id` and `source_filename` are set by the route, not the form. */
const JSON_FIELDS = ['clinical_findings', 'treatments'];
const COLUMNS = [...TEXT_FIELDS.map(f => f.key), ...JSON_FIELDS];

/* Legacy column carried by records imported before the catalogue existed.
   Nothing writes it any more, but it is still read back and displayed. */
const LEGACY_COLUMNS = ['buffy_coat'];

const LABELS = Object.fromEntries(TEXT_FIELDS.map(f => [f.key, f.label]));

/* Every wording a field may be found under in an uploaded document, the
   printed label first so it wins when a sheet carries both. */
function lookupsFor(field) {
  return [field.label, ...(field.aliases || [])];
}

/* ─── NORMALISATION ───────────────────────────────────────────
   What the route hands to the database, whether the values came from the
   in-app form or from a parsed upload.

   Blank strings become NULL: a field the vet skipped and a field they
   typed a space into are the same fact, and only one of the two reads
   back as "not recorded" everywhere else in the app. */

function clean(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

/**
 * Clinical findings, as the twelve rows of the printed sheet.
 *
 * Rows are matched to the catalogue by name so an upload cannot invent a
 * thirteenth system or reorder the table, and a row with neither a status
 * nor an observation is dropped — the sheet prints all twelve whether or
 * not the vet examined all twelve.
 */
function normaliseFindings(input) {
  if (!Array.isArray(input)) return [];
  const byName = new Map();
  for (const row of input) {
    if (!row || typeof row !== 'object') continue;
    const raw    = clean(row.system);
    if (!raw) continue;
    const system = SYSTEM_ALIASES[raw] ||
                   SYSTEMS.find(s => s.toLowerCase() === raw.toLowerCase()) ||
                   raw;
    const status = SYSTEM_STATUSES.find(
      s => s.toLowerCase() === String(row.status || '').trim().toLowerCase()
    ) || null;
    const observations = clean(row.observations);
    if (!status && !observations) continue;
    byName.set(system, { system, status, observations });
  }
  /* Catalogue order first, then anything an older upload carried that the
     current sheet no longer prints — kept rather than silently dropped. */
  const ordered = SYSTEMS.filter(s => byName.has(s)).map(s => byName.get(s));
  for (const [name, row] of byName) if (!SYSTEMS.includes(name)) ordered.push(row);
  return ordered;
}

/**
 * Prescription rows. A row needs a drug to mean anything; a prescription
 * with no drug beside it is a stray line, not a treatment.
 */
function normaliseTreatments(input) {
  if (!Array.isArray(input)) return [];
  return input
    .filter(r => r && typeof r === 'object' && clean(r.drug))
    .map(r => ({ drug: clean(r.drug), prescription: clean(r.prescription) || '' }));
}

/**
 * A request body reduced to exactly the columns the table has, in the
 * order COLUMNS lists them — so the insert and the update can both build
 * their parameter list by mapping over COLUMNS and cannot drift out of
 * step with each other.
 */
function normaliseRecord(body = {}) {
  const out = {};
  for (const field of TEXT_FIELDS) out[field.key] = clean(body[field.key]);
  out.clinical_findings = normaliseFindings(body.clinical_findings);
  out.treatments        = normaliseTreatments(body.treatments);
  return out;
}

/** The value to bind for a column, JSONB columns serialised. */
function valueFor(record, column) {
  return JSON_FIELDS.includes(column)
    ? JSON.stringify(record[column] || [])
    : record[column];
}

module.exports = {
  SECTIONS, IDENTIFICATION, HISTORY, VITALS, SYSTEMS, SYSTEM_STATUSES, SYSTEM_ALIASES,
  FINDINGS, BLOOD_SMEAR, LABORATORY, TREATMENT_COLUMNS, TREATMENT_ROWS, SIGN_OFF,
  TEXT_FIELDS, JSON_FIELDS, COLUMNS, LEGACY_COLUMNS, LABELS,
  lookupsFor, normaliseRecord, normaliseFindings, normaliseTreatments, valueFor,
};
