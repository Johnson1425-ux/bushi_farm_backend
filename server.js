require('dotenv').config();
const express = require('express');
const cors    = require('cors');

const { pool, ready } = require('./db');
const {
  verifyToken,
  requireAdmin, requireProduction, requireHealth, requireRoleForWrites,
  requireBranchAccess,
} = require('./auth');

const aiRoutes         = require('./aiRoutes');
const { initAiTables }  = require('./aiClient');
const { initNewTables, initHealthRecordsTables } = require('./lib/initTables');
const { initStockTables } = require('./lib/initStock');
const { initPosTables }   = require('./lib/initPos');

/* Route modules — one file per resource, each a plain express.Router().
   Role gates are applied once, here, at the mount point (see the "ROLE
   GATES" section below) rather than repeated inside every handler. */
const authRoutes        = require('./routes/authRoutes');
const usersRoutes       = require('./routes/users');
const cowsRoutes        = require('./routes/cows');
const recordsRoutes     = require('./routes/records');
const importRoutes      = require('./routes/importData');
const analyticsRoutes   = require('./routes/analytics');
const diseasesRoutes    = require('./routes/diseases');
const treatmentsRoutes  = require('./routes/treatments');
const cowHistoryRoutes  = require('./routes/cowHistory');
const pregnanciesRoutes = require('./routes/pregnancies');
const alertsRoutes      = require('./routes/alerts');
const salesRoutes       = require('./routes/sales');
const inventoryRoutes   = require('./routes/inventory');
const processingRoutes  = require('./routes/processing');
const healthRecordsRoutes = require('./routes/healthRecords');
const branchesRoutes    = require('./routes/branches');
const productsRoutes    = require('./routes/products');
const stockRoutes       = require('./routes/stock');
const issuesRoutes      = require('./routes/issues');
const posRoutes         = require('./routes/pos');
const reportsRoutes     = require('./routes/reports');

const app = express();

/* ── CORS ─────────────────────────────────────────────────
   One policy, applied to both real requests and preflights. A bare cors()
   call anywhere else would set Access-Control-Allow-Origin: * and silently
   override the allowlist below, so there must not be one. */
const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'https://bushi-farm.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

/* Start the schema work now, so a warm process has it done already. */
const initAllTables = () => Promise.all([
  initAiTables(), initNewTables(), initHealthRecordsTables(),
  /* POS tables reference branches and products, so the stock schema has to
     be in place before they are created. */
  initStockTables().then(initPosTables),
]);
ready(initAllTables).catch(err => console.error('DB Init Error:', err.message));

/* Nothing is served until the schema is in place.

   Migrations begin at module load, but on a serverless host the first
   request can arrive while they are still running — which surfaces as a
   route failing on a column that is about to exist. ready() hands every
   caller the same promise, so this waits on the work already in flight
   rather than repeating it, and costs nothing once it has resolved.

   Calling ready() per request rather than awaiting a promise captured at
   load time also means a failed start is retried: the usual cause is the
   database still coming up, and a process that gave up once would
   otherwise serve 503s until it was redeployed. */
app.use(async (req, res, next) => {
  try {
    await ready(initAllTables);
    next();
  } catch (err) {
    console.error('DB Init Error:', err.message);
    res.status(503).json({
      error: 'The database is not ready yet. Try again in a moment.',
      detail: err.message,
    });
  }
});

/* ══════════════════════════════════
   AUTH ROUTES  (public, except /me)
══════════════════════════════════ */
app.use('/api/auth', authRoutes);

/* ══════════════════════════════════
   ROLE GATES

   Applied here, at the mount point, so they cover every method and
   sub-path in the router underneath — this is the authorization boundary.
   The sidebar only decides what is convenient to show; the API enforces
   the same boundaries independently.

   Managers own production and the commercial side; vets own animal health.
   Neither can reach the other's data. Reads and writes are both gated for
   these areas, because seeing the data is the thing being restricted.
══════════════════════════════════ */

/* Manager territory. */
app.use('/api/sales',      verifyToken, requireProduction, salesRoutes);
app.use('/api/inventory',  verifyToken, requireProduction, inventoryRoutes);
app.use('/api/processing', verifyToken, requireProduction, processingRoutes);
app.use('/api/import',     verifyToken, requireProduction, importRoutes);

/* ── Branch distribution ──────────────────────────────────
   Wider than manager territory, because a branch attendant has to see the
   catalogue, their own branch, its stock and the notes coming to it — and
   nothing beyond that.

   The role gate here is only the outer boundary. Which branch an attendant
   may act on is decided inside each router by assertBranchAllowed(), from
   the branch on their token rather than the id in the request, and the
   write operations that belong to the store (raising and dispatching notes,
   recording production, adjusting a balance) carry requireProduction on the
   individual route. */
app.use('/api/branches', verifyToken, requireBranchAccess, branchesRoutes);
app.use('/api/products', verifyToken, requireBranchAccess, productsRoutes);
app.use('/api/stock',    verifyToken, requireBranchAccess, stockRoutes);
app.use('/api/issues',   verifyToken, requireBranchAccess, issuesRoutes);
app.use('/api/pos',      verifyToken, requireBranchAccess, posRoutes);

/* Reports span every branch and are management's view of the business, so
   they stay in manager territory rather than following the branch gate
   above — an attendant reads their own day through /api/pos. */
app.use('/api/reports',  verifyToken, requireProduction, reportsRoutes);

/* Vet territory. */
app.use('/api/diseases',       verifyToken, requireHealth, diseasesRoutes);
app.use('/api/treatments',     verifyToken, requireHealth, treatmentsRoutes);
app.use('/api/pregnancies',    verifyToken, requireHealth, pregnanciesRoutes);
app.use('/api/health-records', verifyToken, requireHealth, healthRecordsRoutes);
app.use('/api/cow-history',    verifyToken, requireHealth, cowHistoryRoutes);

/* Shared reads, restricted writes. Every signed-in account can browse the
   production record; only admins and managers may change it. */
app.use('/api/records', verifyToken, requireRoleForWrites('admin', 'manager'), recordsRoutes);

/* Account management. */
app.use('/api/users', verifyToken, requireAdmin, usersRoutes);

/* ══════════════════════════════════
   EVERYONE SIGNED IN

   /api/cows is deliberately not role-gated at the prefix — its writes are
   guarded on the individual routes inside routes/cows.js, because the
   cow-history endpoints nested under it belong to the vet side.
══════════════════════════════════ */
app.use('/api/cows',      verifyToken, cowsRoutes);
app.use('/api/analytics', verifyToken, analyticsRoutes);
app.use('/api/alerts',    verifyToken, alertsRoutes);

/* ══════════════════════════════════
   AI REPORTS  (see aiRoutes.js)
══════════════════════════════════ */
app.use('/api/ai', aiRoutes);

/* ══════════════════════════════════
   START (Updated for Vercel)
══════════════════════════════════ */

// 1. Schema setup is kicked off above, next to the middleware that waits on
//    it, so the two cannot drift apart.

// 2. EXPORT the app (Mandatory for Vercel)
module.exports = app;

// 3. ONLY listen if running locally
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`✓ MilkTrack API running on http://localhost:${PORT}`);
  });
}
