/* ══════════════════════════════════════════════════════════════
   INDIVIDUAL HEALTH RECORD — BLANK WORD FORM

   Builds the .docx the vet downloads, fills, and uploads back.

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

/* An answer box, left for the vet to type into. Empty rather than ruled:
   the emptiness is what tells the parser this cell is an answer and not
   another question. */
const BLANK = '';

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
function fieldTable(fields, labelWidth = 3600) {
  return table(fields.map(f => new TableRow({
    children: [
      cell(f.label, { bold: false, width: labelWidth, bg: HEADER_BG }),
      cell(BLANK,   { width: PAGE_WIDTH - labelWidth }),
    ],
  })));
}

/** The vitals strip: five headings across, five empty cells beneath. */
function vitalsTable() {
  const width = Math.floor(PAGE_WIDTH / VITALS.length);
  return table([
    new TableRow({ children: VITALS.map(v => cell(v.label, { bold: true, width, bg: HEADER_BG })) }),
    new TableRow({ children: VITALS.map(()  => cell(BLANK, { width })) }),
  ]);
}

/** SYSTEM | STATUS(Normal/Abnormal) | SPECIFIC OBSERVATIONS. */
function findingsTable() {
  const head = ['SYSTEM', 'STATUS(Normal/Abnormal)', 'SPECIFIC OBSERVATIONS'];
  const cols = [2800, 2600, PAGE_WIDTH - 5400];
  return table([
    new TableRow({
      tableHeader: true,
      children: head.map((h, i) => cell(h, { bold: true, width: cols[i], bg: HEADER_BG })),
    }),
    ...SYSTEMS.map(system => new TableRow({
      children: [
        cell(system, { width: cols[0] }),
        cell(BLANK,  { width: cols[1] }),
        cell(BLANK,  { width: cols[2] }),
      ],
    })),
  ]);
}

/** The blood-smear grid: two label/value pairs per row, as printed. */
function bloodSmearTable() {
  const w = Math.floor(PAGE_WIDTH / 4);
  const rows = [];
  for (let i = 0; i < BLOOD_SMEAR.length; i += 2) {
    const pair = BLOOD_SMEAR.slice(i, i + 2);
    rows.push(new TableRow({
      children: pair.flatMap(f => [
        cell(f.label, { width: w, bg: HEADER_BG }),
        cell(BLANK,   { width: w }),
      ]),
    }));
  }
  return table(rows);
}

/** Drug/vaccine against prescription, with the four blank rows the sheet prints. */
function treatmentTable() {
  const cols = [3000, PAGE_WIDTH - 3000];
  return table([
    new TableRow({
      tableHeader: true,
      children: TREATMENT_COLUMNS.map((c, i) =>
        cell(c.label, { bold: true, width: cols[i], bg: HEADER_BG })),
    }),
    ...Array.from({ length: TREATMENT_ROWS }, () => new TableRow({
      children: cols.map(w => cell(BLANK, { width: w })),
    })),
  ]);
}

/**
 * The blank form, as a Buffer ready to send.
 */
async function buildHealthRecordTemplate() {
  const doc = new Document({
    creator: 'Milktrack',
    title: 'Bushi Dairy Farm Individual Health Record',
    description: 'Blank individual health record form. Fill it in, then upload it in Milktrack under Individual Health Records.',
    sections: [{
      properties: { page: { margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
      children: [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({
            text: SECTIONS.title,
            bold: true, size: 30, font: 'Times New Roman',
          })],
        }),

        heading(SECTIONS.identification),
        fieldTable(IDENTIFICATION),

        heading(SECTIONS.examination),
        fieldTable(HISTORY, 4600),

        new Paragraph({ spacing: { before: 200 } }),
        vitalsTable(),

        heading(SECTIONS.findings),
        findingsTable(),

        new Paragraph({ spacing: { before: 200 } }),
        fieldTable(FINDINGS, 3600),

        heading(SECTIONS.laboratory),
        text('Blood smear', { bold: true }),
        bloodSmearTable(),
        new Paragraph({ spacing: { before: 200 } }),
        fieldTable(LABORATORY, 4600),

        heading(SECTIONS.treatment),
        fieldTable(SIGN_OFF.filter(f => f.key === 'final_diagnosis'), 4600),
        new Paragraph({ spacing: { before: 200 } }),
        treatmentTable(),
        new Paragraph({ spacing: { before: 200 } }),
        fieldTable(SIGN_OFF.filter(f => f.key !== 'final_diagnosis'), 4600),

        new Paragraph({
          spacing: { before: 360 },
          children: [new TextRun({
            text: 'Fill this form in, save it, and upload it in Milktrack under Individual Health Records. '
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
