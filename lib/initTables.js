const { pool } = require('../db');

/* diseases, disease_cows, treatments, cow_history, pregnancies */
async function initNewTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS diseases (
      id          SERIAL PRIMARY KEY,
      name        TEXT NOT NULL,
      description TEXT,
      date        DATE NOT NULL,
      notes       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS disease_cows (
      disease_id INT REFERENCES diseases(id) ON DELETE CASCADE,
      cow_id     INT REFERENCES cows(id) ON DELETE CASCADE,
      PRIMARY KEY (disease_id, cow_id)
    );
    CREATE TABLE IF NOT EXISTS treatments (
      id            SERIAL PRIMARY KEY,
      disease_id    INT REFERENCES diseases(id) ON DELETE CASCADE,
      medicine_name TEXT NOT NULL,
      dosage        TEXT,
      date          DATE NOT NULL,
      notes         TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS cow_history (
      id         SERIAL PRIMARY KEY,
      cow_id     INT REFERENCES cows(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      date       DATE NOT NULL,
      source     TEXT,
      notes      TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pregnancies (
      id                SERIAL PRIMARY KEY,
      cow_id            INT REFERENCES cows(id) ON DELETE CASCADE,
      conception_date   DATE NOT NULL,
      expected_due_date DATE NOT NULL,
      actual_birth_date DATE,
      status            TEXT DEFAULT 'active',
      notes             TEXT,
      created_at        TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

/* cow_health_records — the Individual Health Records form, whether the vet
   filled it in the app or uploaded a filled .docx of the same sheet */
async function initHealthRecordsTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cow_health_records (
      id                    SERIAL PRIMARY KEY,
      cow_id                INT REFERENCES cows(id) ON DELETE CASCADE,
      cow_tag               TEXT,
      age                   TEXT,
      breed                 TEXT,
      -- Parentage. Not on the printed sheet; the farm asked for it.
      dam                   TEXT,
      sire                  TEXT,
      sex                   TEXT,
      -- "Status(pregnant/cycling/serviced)" on the sheet. Not named status,
      -- which would read as the state of the record itself.
      repro_status          TEXT,
      parity                TEXT,
      daily_milk_yield      TEXT,
      days_in_milk          TEXT,
      body_weight           TEXT,
      body_temperature      TEXT,
      pulse_rate            TEXT,
      respiratory_rate      TEXT,
      crt_seconds           TEXT,
      rumino_motility       TEXT,
      present_illness       TEXT,
      past_history          TEXT,
      environment           TEXT,
      system_review         TEXT,
      -- Clinical exam findings stored as JSON: [{system, status, observations}]
      clinical_findings     JSONB DEFAULT '[]',
      significant_findings  TEXT,
      tentative_diagnosis   TEXT,
      -- Lab results
      blood_smear           TEXT,
      buffy_coat            TEXT,
      pcv                   TEXT,
      eosinophils            TEXT,
      basophils              TEXT,
      neutrophils            TEXT,
      bacteriology           TEXT,
      skin_scrapings         TEXT,
      fecal_sample           TEXT,
      other_lab               TEXT,
      lab_findings             TEXT,
      final_diagnosis          TEXT,
      -- Treatments stored as JSON: [{drug, prescription}]
      treatments               JSONB DEFAULT '[]',
      recommendation           TEXT,
      milk_withdraw_date       TEXT,
      attending_vet            TEXT,
      license_number           TEXT,
      exam_date                TEXT,
      -- meta
      source_filename          TEXT,
      uploaded_at              TIMESTAMPTZ DEFAULT NOW(),
      created_at               TIMESTAMPTZ DEFAULT NOW(),
      updated_at               TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  /* Farms already running carry the table as it was first written: parsed
     from an upload, with no room for the four fields the printed sheet has
     and the importer never read, and no updated_at because a parsed record
     was never edited. The in-app form fills all of them, so add them where
     the table predates it. */
  await pool.query(`
    ALTER TABLE cow_health_records
      ADD COLUMN IF NOT EXISTS dam                  TEXT,
      ADD COLUMN IF NOT EXISTS sire                 TEXT,
      ADD COLUMN IF NOT EXISTS sex                  TEXT,
      ADD COLUMN IF NOT EXISTS repro_status         TEXT,
      ADD COLUMN IF NOT EXISTS significant_findings TEXT,
      ADD COLUMN IF NOT EXISTS recommendation       TEXT,
      ADD COLUMN IF NOT EXISTS updated_at           TIMESTAMPTZ DEFAULT NOW();
  `);

  /* The list is filtered by cow and sorted newest-first on every visit. */
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_health_records_cow
      ON cow_health_records (cow_id, uploaded_at DESC);
  `);
}

/* calves — the young stock.

   Kept apart from `cows` on purpose. Every production figure the farm
   reads — the herd average, the per-cow ranking, the "she is off her
   yield" alerts — is a query over `cows` joined to `milk_records`. A calf
   has no yield and will not have one for two years, so putting her in
   that table would drag the herd average down by however many calves were
   born this season and light up the alert list with animals nobody
   expects milk from.

   She moves across when she is old enough to milk: POST /api/calves/:id/
   move-to-herd writes the `cows` row and records which one she became, so
   the calfhood and the milking life stay joined up.

   dam_id and pregnancy_id are ON DELETE SET NULL rather than CASCADE: if
   the dam is deleted the calf is still a calf on this farm, and losing her
   row would be a second mistake on top of the first. */
async function initCalvesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS calves (
      id            SERIAL PRIMARY KEY,
      name          TEXT NOT NULL,
      tag           TEXT,
      sex           TEXT NOT NULL DEFAULT 'female' CHECK (sex IN ('female','male')),
      breed         TEXT,
      date_of_birth DATE NOT NULL,
      -- The mother, when she is an animal the farm has on the books.
      dam_id        INT REFERENCES cows(id) ON DELETE SET NULL,
      -- The father is usually a semen batch rather than a bull on the
      -- farm, so it is free text, same as on the health record sheet.
      sire          TEXT,
      -- The pregnancy this birth closed, when the calf was recorded from
      -- the pregnancy register.
      pregnancy_id  INT REFERENCES pregnancies(id) ON DELETE SET NULL,
      birth_weight  NUMERIC,
      status        TEXT NOT NULL DEFAULT 'on_farm'
                    CHECK (status IN ('on_farm','weaned','moved_to_herd','dead','sold')),
      weaned_on     DATE,
      -- The cow she became, once she has been moved into the milking herd.
      cow_id        INT REFERENCES cows(id) ON DELETE SET NULL,
      left_on       DATE,
      notes         TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  /* The list is filtered by status and read youngest-first; the dam's own
     page asks for her calves by dam_id. */
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_calves_status ON calves (status, date_of_birth DESC);
    CREATE INDEX IF NOT EXISTS idx_calves_dam    ON calves (dam_id);
  `);
}

module.exports = { initNewTables, initHealthRecordsTables, initCalvesTable };
