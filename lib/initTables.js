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

/* cow_health_records — parsed from uploaded .docx Individual Health Records */
async function initHealthRecordsTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cow_health_records (
      id                    SERIAL PRIMARY KEY,
      cow_id                INT REFERENCES cows(id) ON DELETE CASCADE,
      cow_tag               TEXT,
      age                   TEXT,
      breed                 TEXT,
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
      milk_withdraw_date       TEXT,
      attending_vet            TEXT,
      license_number           TEXT,
      exam_date                TEXT,
      -- meta
      source_filename          TEXT,
      uploaded_at              TIMESTAMPTZ DEFAULT NOW(),
      created_at               TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

module.exports = { initNewTables, initHealthRecordsTables };
