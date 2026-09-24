/* ══════════════════════════════════════════════════════════════
   INDIVIDUAL HEALTH RECORD — THE WORD FORM

   Builds the .docx the vet downloads: blank to fill in by hand, or
   carrying a saved record when they want a copy of one to print, file or
   send on.

   Both come out of the same builder. A filled sheet that was laid out
   separately would drift from the blank one, and then a vet holding the
   two side by side would be reading two different forms — and the parser,
   which is written against this layout, would read back only one of
   them.

   It is generated from healthRecordForm.js rather than kept as a file on
   disk for the same reason the processing workbook is: the sheet people
   type into and the parser that reads it back are then the same list of
   labels, and a field cannot be added to one without appearing in the
   other. The layout follows the printed form section for section, so a
   vet holding the paper copy can fill this one without re-reading it.

   Answers go in table cells rather than after a run of underscores.
   Underscores are what the old form used and what made the upload
   unreliable: whether an answer typed onto a ruled line lands before,
   after or inside the underscores is up to Word, and the parser has to
   guess. A cell has exactly one answer in it.
══════════════════════════════════════════════════════════════ */

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, BorderStyle, AlignmentType, HeadingLevel, ShadingType,
} = require('docx');

const {
  SECTIONS, IDENTIFICATION, HISTORY, VITALS, SYSTEMS, FINDINGS, BLOOD_SMEAR,
  LABORATORY, TREATMENT_COLUMNS, TREATMENT_ROWS, SIGN_OFF,
} = require('./healthRecordForm');

const PAGE_WIDTH = 9360;              // usable width in DXA, A4 with 1" margins
const BORDER     = { style: BorderStyle.SINGLE, size: 4, color: '999999' };
const BORDERS    = { top: BORDER, bottom: BORDER, left: BORDER, right: BORDER };
const HEADER_BG  = { type: ShadingType.CLEAR, fill: 'F0ECE0' };

/* An answer box: what the record says, or empty for the vet to type into.
   Empty rather than ruled — the emptiness is what tells the parser this
   cell is an answer and not another question. */
const BLANK = '';

const answer = (record, key) => {
  const v = record?.[key];
  return v === null || v === undefined ? BLANK : String(v);
};

function text(value, { bold = false, size = 20, italics = false } = {}) {
  return new Paragraph({
    children: [new TextRun({ text: value, bold, size, italics, font: 'Times New Roman' })],
  });
}

function heading(value) {
  return new Paragraph({
    spacing: { before: 280, after: 120 },
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text: value, bold: true, size: 24, font: 'Times New Roman' })],
  });
}

function cell(value, { bold = false, width, bg, size = 20 } = {}) {
  return new TableCell({
    borders: BORDERS,
    shading: bg,
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    width: width ? { size: width, type: WidthType.DXA } : undefined,
    children: [text(value, { bold, size })],
  });
}

function table(rows) {
  return new Table({
    width: { size: PAGE_WIDTH, type: WidthType.DXA },
    borders: BORDERS,
    rows,
  });
}

/**
 * A label-and-answer table: the label in the left column, an empty cell on
 * the right for the answer. This is the shape the parser reads — the cell
 * after a known label is that field's value.
 */
function fieldTable(fields, labelWidth = 3600, record) {
  return table(fields.map(f => new TableRow({
    children: [
      cell(f.label, { bold: false, width: labelWidth, bg: HEADER_BG }),
      cell(answer(record, f.key), { width: PAGE_WIDTH - labelWidth }),
    ],
  })));
}

/** The vitals strip: five headings across, five empty cells beneath. */
function vitalsTable(record) {
  const width = Math.floor(PAGE_WIDTH / VITALS.length);
  return table([
    new TableRow({ children: VITALS.map(v => cell(v.label, { bold: true, width, bg: HEADER_BG })) }),
    new TableRow({ children: VITALS.map(v => cell(answer(record, v.key), { width })) }),
  ]);
}

/**
 * SYSTEM | STATUS(Normal/Abnormal) | SPECIFIC OBSERVATIONS.
 *
 * All twelve systems print whether or not the record filled them in — on
 * the sheet they are a checklist of what to examine, and a filled copy
 * that listed only the abnormal ones would not say which of the rest were
 * looked at and found normal.
 */
function findingsTable(record) {
  const head = ['SYSTEM', 'STATUS(Normal/Abnormal)', 'SPECIFIC OBSERVATIONS'];
  const cols = [2800, 2600, PAGE_WIDTH - 5400];
  const found = new Map(
    (Array.isArray(record?.clinical_findings) ? record.clinical_findings : [])
      .map(f => [f.system, f])
  );
  const extra = [...found.keys()].filter(name => !SYSTEMS.includes(name));

  return table([
    new TableRow({
      tableHeader: true,
      children: head.map((h, i) => cell(h, { bold: true, width: cols[i], bg: HEADER_BG })),
    }),
    ...[...SYSTEMS, ...extra].map(system => new TableRow({
      children: [
        cell(system, { width: cols[0] }),
        cell(found.get(system)?.status       || BLANK, { width: cols[1] }),
        cell(found.get(system)?.observations || BLANK, { width: cols[2] }),
      ],
    })),
  ]);
}

/** The blood-smear grid: two label/value pairs per row, as printed. */
function bloodSmearTable(record) {
  const w = Math.floor(PAGE_WIDTH / 4);
  const rows = [];
  for (let i = 0; i < BLOOD_SMEAR.length; i += 2) {
    const pair = BLOOD_SMEAR.slice(i, i + 2);
    rows.push(new TableRow({
      children: pair.flatMap(f => [
        cell(f.label, { width: w, bg: HEADER_BG }),
        cell(answer(record, f.key), { width: w }),
      ]),
    }));
  }
  return table(rows);
}

/**
 * Drug/vaccine against prescription.
 *
 * A blank sheet prints the four lines the paper form has. A filled one
 * prints what was prescribed, and keeps printing four at minimum so the
 * copy still looks like the form it came from — and so a vet adding a
 * drug by hand to a printout has somewhere to write it.
 */
function treatmentTable(record) {
  const cols = [3000, PAGE_WIDTH - 3000];
  const given = Array.isArray(record?.treatments) ? record.treatments : [];
  const rows  = [
    ...given,
    ...Array.from({ length: Math.max(0, TREATMENT_ROWS - given.length) }, () => ({})),
  ];
  return table([
    new TableRow({
      tableHeader: true,
      children: TREATMENT_COLUMNS.map((c, i) =>
        cell(c.label, { bold: true, width: cols[i], bg: HEADER_BG })),
    }),
    ...rows.map(t => new TableRow({
      children: TREATMENT_COLUMNS.map((c, i) => cell(answer(t, c.key), { width: cols[i] })),
    })),
  ]);
}

/** "Boss · tag BOSS001", as much of it as the record knows. */
function subject(record) {
  return [
    record.cow_name,
    record.cow_tag ? `tag ${record.cow_tag}` : null,
  ].filter(Boolean).join(' · ');
}

/** Where a printed copy came from, and when. */
function provenance(record) {
  const taken = record.exam_date
    ? `Examination dated ${record.exam_date}.`
    : null;
  const saved = record.uploaded_at
    ? `Recorded in Milktrack on ${new Date(record.uploaded_at).toISOString().slice(0, 10)}.`
    : null;
  return [taken, saved, 'Printed from Milktrack — Individual Health Records.']
    .filter(Boolean).join(' ');
}

/**
 * The form, as a Buffer ready to send.
 *
 * With no record it is the blank sheet the vet downloads to fill in. With
 * one it is that record on the same sheet — a copy to print, file, or
 * hand to whoever asked for it. Passing it back through the upload reads
 * it straight back, because it is the layout the parser is written for.
 */
async function buildHealthRecordTemplate(record) {
  const filled = Boolean(record);
  const doc = new Document({
    creator: 'Milktrack',
    title: 'Bushi Dairy Farm Individual Health Record',
    description: filled
      ? 'Individual health record.'
      : 'Blank individual health record form. Fill it in, then upload it in Milktrack under Individual Health Records.',
    sections: [{
      properties: { page: { margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
      children: [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: filled ? 60 : 200 },
          children: [new TextRun({
            text: SECTIONS.title,
            bold: true, size: 30, font: 'Times New Roman',
          })],
        }),

        /* Which animal, said once at the top. The sheet identifies her by
           tag further down, but a copy being read across a desk should not
           need finding that row first. cow_name is the herd's name for her
           and is not a field on the form, so it goes here rather than into
           a row the parser would then try to read back. */
        ...(filled && subject(record) ? [new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({
            text: subject(record), size: 22, font: 'Times New Roman', color: '666650',
          })],
        })] : []),

        heading(SECTIONS.identification),
        fieldTable(IDENTIFICATION, 3600, record),

        heading(SECTIONS.examination),
        fieldTable(HISTORY, 4600, record),

        new Paragraph({ spacing: { before: 200 } }),
        vitalsTable(record),

        heading(SECTIONS.findings),
        findingsTable(record),

        new Paragraph({ spacing: { before: 200 } }),
        fieldTable(FINDINGS, 3600, record),

        heading(SECTIONS.laboratory),
        fieldTable([{ key: 'blood_smear', label: 'Blood smear' }], 3600, record),
        bloodSmearTable(record),
        new Paragraph({ spacing: { before: 200 } }),
        fieldTable(LABORATORY, 4600, record),

        heading(SECTIONS.treatment),
        fieldTable(SIGN_OFF.filter(f => f.key === 'final_diagnosis'), 4600, record),
        new Paragraph({ spacing: { before: 200 } }),
        treatmentTable(record),
        new Paragraph({ spacing: { before: 200 } }),
        fieldTable(SIGN_OFF.filter(f => f.key !== 'final_diagnosis'), 4600, record),

        /* A blank sheet closes with how to fill it in. A filled one closes
           with where it came from, so a printed copy on someone's desk
           says which animal it is about and when it was taken. */
        new Paragraph({
          spacing: { before: 360 },
          children: [new TextRun({
            text: filled ? provenance(record)
              : 'Fill this form in, save it, and upload it in Milktrack under Individual Health Records. '
                + 'Type each answer into the box beside its label — leave a box empty if the field does not apply.',
            italics: true, size: 18, font: 'Times New Roman', color: '666650',
          })],
        }),
      ],
    }],
  });

  return Packer.toBuffer(doc);
}

module.exports = { buildHealthRecordTemplate };
