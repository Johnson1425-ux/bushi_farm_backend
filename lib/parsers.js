const XLSX = require('xlsx');

/* ══════════════════════════════════
   Small generic helpers
══════════════════════════════════ */

function findKey(sample, candidates) {
  const keys = Object.keys(sample);
  for (const c of candidates) {
    const k = keys.find(k => k.toLowerCase().replace(/[\s_\-]/g, '').includes(c));
    if (k) return k;
  }
  return null;
}

function parseDate(val) {
  if (!val) return null;
  if (val instanceof Date) return val.toISOString().slice(0, 10);
  const s = String(val).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const parts = s.split(/[\/\-\.]/);
  if (parts.length === 3) {
    const [a, b, c] = parts.map(Number);
    if (c > 1000) return `${c}-${String(b).padStart(2, '0')}-${String(a).padStart(2, '0')}`;
    return new Date(s).toISOString().slice(0, 10);
  }
  const d = new Date(s);
  return isNaN(d) ? null : d.toISOString().slice(0, 10);
}

/* ══════════════════════════════════
   Bulk-import grid finder (used by routes/importData.js)
══════════════════════════════════ */

/**
 * Find the daily-readings grid in a workbook.
 *
 * The sheet is chosen by shape — a header row carrying both a cow column and
 * numbered day columns — rather than by position or by name. Position fails
 * because the production workbooks put a month-by-month summary in front of
 * the daily grid; that summary has a "NAME OF COW" column too, so it looks
 * like the right sheet until you notice its columns are month names. Name
 * matching fails because the names are not stable: the same workbook family
 * has "DAIRY PRODUCTION" one month and "DAILY PRODUCTION" the next, with the
 * summary tab spelled "MONTHLY" or "MONTHRRY".
 *
 * Returns the winning sheet plus a note on every sheet examined, so a failure
 * can say what was actually found instead of blaming the file.
 */
function findDailyGrid(wb) {
  const examined = [];

  for (const name of wb.SheetNames) {
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[name], { header: 1 });

    // The header can sit below title rows, so scan for it rather than
    // assuming row 1 — but only consider a row that has day columns on it,
    // otherwise the summary sheet's "NAME OF COW" row wins and the real
    // grid further down the workbook is never reached.
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i] || [];
      const cowColIndex = row.findIndex(c => String(c).toUpperCase().includes('COW'));
      if (cowColIndex === -1) continue;

      const dayColumns = [];
      row.forEach((col, idx) => {
        const day = parseInt(col, 10);
        if (!isNaN(day) && day >= 1 && day <= 31) dayColumns.push({ day, idx });
      });

      if (dayColumns.length) {
        return { sheetName: name, rows, headerIndex: i, cowColIndex, dayColumns, examined };
      }
      examined.push({ sheet: name, found: 'a cow column but no day columns' });
      break;
    }
    if (!examined.some(e => e.sheet === name)) {
      examined.push({ sheet: name, found: 'no cow column' });
    }
  }

  return { sheetName: null, examined };
}

/* ══════════════════════════════════
   Individual health-record .docx parser (used by routes/healthRecords.js)
══════════════════════════════════ */

/** Parser: extract raw text (already run through mammoth) → structured fields. */
function parseHealthDoc(rawText) {
  // mammoth extracts table cells as separate lines — filled form looks like:
  // "Cow ID/Tag\n\nBOSS001\n\nBody weight\n\n320kg"
  // So we build a label->nextValue map from the line sequence
  const lines = rawText.split('\n').map(l => l.trim());
  const nonEmpty = lines.filter(Boolean);

  // Build label->value map: for each non-empty line that looks like a label,
  // the VALUE is the next non-empty line that isn't another label
  const LABELS = new Set([
    'COW ID/TAG', 'BODY WEIGHT', 'AGE', 'BREED', 'PARITY', 'DAILY MILK YIELD',
    'DAYS IN MILK', 'BODY TEMPERATURE', 'PULSE RATE(BEATS/MINS)', 'PULSE RATE',
    'RESPIRATORY RATE(BEATS/MIN)', 'RESPIRATORY RATE', 'CRT(SECONDS)', 'CRT',
    'RUMINO-MOTILITY', 'RUMINOMOTILITY', 'BLOOD SMEAR', 'BUFFY COAT SMEAR',
    'BUFFY COAT', 'PCV', 'EOSINOPHILS', 'BASOPHILS', 'NEUTROPHILS',
    'SYSTEM', 'STATUS(NORMAL/ABNORMAL)', 'SPECIFIC OBSERVATIONS',
    'DRUG/VACCINE', 'PRESCRIPTION(DOSE, DOSAGE AND ROUTE)',
  ]);

  // nextValue(label) — finds label in nonEmpty array, returns next non-label, non-empty line
  function nextValue(labelVariants) {
    for (const label of labelVariants) {
      for (let i = 0; i < nonEmpty.length; i++) {
        const t = nonEmpty[i].toUpperCase().replace(/[_\-\/\(\)]+/g, ' ').trim();
        const lbl = label.toUpperCase().replace(/[_\-\/\(\)]+/g, ' ').trim();
        if (t.startsWith(lbl)) {
          // Value might be on same line after the label
          const sameLine = nonEmpty[i].slice(label.length).replace(/^[\s:_]+/, '').trim();
          if (sameLine && !LABELS.has(sameLine.toUpperCase())) return sameLine;
          // Or next non-empty, non-label line
          for (let j = i + 1; j < nonEmpty.length; j++) {
            const next = nonEmpty[j].trim();
            if (!next) continue;
            // Skip if it looks like a section header or another label
            if (LABELS.has(next.toUpperCase())) break;
            if (/^[A-Z ]{8,}$/.test(next) && !next.match(/\d/)) break; // ALL CAPS header
            if (next.startsWith('_')) continue; // blank line pattern ___
            return next;
          }
        }
      }
    }
    return null;
  }

  // afterLine — finds text after a pattern on the SAME line (for ___ fields)
  function afterLine(labelVariants) {
    for (const label of labelVariants) {
      for (const line of nonEmpty) {
        const idx = line.toUpperCase().indexOf(label.toUpperCase());
        if (idx !== -1) {
          const rest = line.slice(idx + label.length).replace(/^[\s:_]+/, '').trim();
          if (rest && !rest.match(/^_+$/) && rest.length > 1) return rest;
        }
      }
    }
    return null;
  }

  // Clinical systems — look for "SystemName\nNormal/Abnormal\nObservations" pattern
  const SYSTEMS = [
    'General Appearance', 'Integumentary', 'Musculoskeletal', 'Circulatory',
    'Respiratory', 'Digestive', 'Genitourinary', 'Ears/Eyes',
    'Mammary system', 'Neural system', 'Lymph nodes', 'Circulatory(MM/CRT)',
  ];
  const clinicalFindings = [];
  for (const system of SYSTEMS) {
    for (let i = 0; i < nonEmpty.length; i++) {
      if (nonEmpty[i].toUpperCase().startsWith(system.toUpperCase())) {
        const status = nonEmpty[i + 1]?.match(/^(Normal|Abnormal)$/i)?.[0] || null;
        const observations = status && nonEmpty[i + 2] && !SYSTEMS.some(s => nonEmpty[i + 2].toUpperCase().startsWith(s.toUpperCase()))
          ? nonEmpty[i + 2] : null;
        if (status) clinicalFindings.push({ system, status, observations });
        break;
      }
    }
  }

  // Treatments: "Drug/vaccine" section — pairs of drug + prescription lines
  const treatments = [];
  let inTreatments = false;
  for (let i = 0; i < nonEmpty.length; i++) {
    if (nonEmpty[i].toUpperCase().includes('DRUG/VACCINE')) { inTreatments = true; continue; }
    if (inTreatments) {
      if (nonEmpty[i].toUpperCase().includes('MILK WITHDRAW')) break;
      if (nonEmpty[i].toUpperCase().includes('PRESCRIPTION')) continue;
      const drug = nonEmpty[i].trim();
      const prescription = nonEmpty[i + 1]?.trim() || '';
      if (drug && !drug.match(/^_+$/) && drug.length > 1 &&
          !['DIAGNOSIS', 'TREATMENT', 'COMPLIANCE'].some(k => drug.toUpperCase().includes(k))) {
        treatments.push({ drug, prescription: prescription.match(/^_+$/) ? '' : prescription });
        i++; // skip prescription line
      }
    }
  }

  return {
    cow_tag:             nextValue(['Cow ID/Tag', 'Cow ID']),
    body_weight:         nextValue(['Body weight']),
    age:                 nextValue(['Age']),
    breed:               nextValue(['Breed']),
    parity:              nextValue(['Parity']),
    daily_milk_yield:    nextValue(['Daily milk yield']),
    days_in_milk:        nextValue(['Days in milk']),
    body_temperature:    nextValue(['Body temperature']),
    pulse_rate:          nextValue(['Pulse rate(beats/mins)', 'Pulse rate']),
    respiratory_rate:    nextValue(['Respiratory rate(beats/min)', 'Respiratory rate']),
    crt_seconds:         nextValue(['CRT(seconds)', 'CRT']),
    rumino_motility:     nextValue(['Rumino-motility', 'Ruminomotility']),
    present_illness:     afterLine(['Present illness']),
    past_history:        afterLine(['Past history']),
    environment:         afterLine(['Environment']),
    system_review:       afterLine(['System review']),
    clinical_findings:   clinicalFindings,
    tentative_diagnosis: afterLine(['TENTATIVE DIAGNOSIS']) ||
                         afterLine(['Tentative/Final diagnosis']) ||
                         afterLine(['Tentative diagnosis']),
    final_diagnosis:     afterLine(['Tentative/Final diagnosis']) ||
                         afterLine(['Final diagnosis']),
    blood_smear:         nextValue(['Blood smear']),
    buffy_coat:          nextValue(['Buffy coat smear', 'Buffy coat']),
    pcv:                 nextValue(['PCV']),
    eosinophils:         nextValue(['Eosinophils']),
    basophils:           nextValue(['Basophils']),
    neutrophils:         nextValue(['Neutrophils']),
    bacteriology:        afterLine(['Bacteriology culture & sensitivity results', 'Bacteriology']),
    skin_scrapings:      afterLine(['Skin scrapings']),
    fecal_sample:        afterLine(['Fecal sample']),
    other_lab:           afterLine(['Other laboratory']),
    lab_findings:        afterLine(['Findings']),
    treatments,
    milk_withdraw_date:  afterLine(['Milk withdraw end date', 'Milk withdraw']),
    attending_vet:       afterLine(['Attending veterinarian/ paraveterinarian', 'Attending veterinarian']),
    license_number:      afterLine(['License #']),
    exam_date:           afterLine(['Date']),
  };
}

module.exports = { findKey, parseDate, findDailyGrid, parseHealthDoc };
