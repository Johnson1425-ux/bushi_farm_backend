const jwt = require('jsonwebtoken');

/* A hardcoded fallback secret means anyone who has seen this repository can
   mint a valid admin token, so production refuses to start without a real one
   rather than coming up quietly forgeable. Development still gets a fallback,
   loudly, so local setup does not need any configuration. */
const DEV_FALLBACK_SECRET = 'milktrack-insecure-development-secret';

if (!process.env.JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'JWT_SECRET is not set. Refusing to start in production with a known ' +
      'signing key — set JWT_SECRET in the environment.'
    );
  }
  console.warn(
    '⚠  JWT_SECRET is not set — signing tokens with the insecure development ' +
    'fallback. Set JWT_SECRET before deploying.'
  );
}

const SECRET = process.env.JWT_SECRET || DEV_FALLBACK_SECRET;

function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  const token  = header && header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ══════════════════════════════════
   ROLES

   admin    — everything
   manager  — production, sales, inventory, processing
   veteran  — animal health: diseases, treatments, pregnancies, vet records

   Managers and vets share read access to the herd and the farm overview, but
   neither can see the other's area. Hiding a page in the sidebar is not a
   permission, so every restricted route is gated here as well.
══════════════════════════════════ */
const ROLES = ['admin', 'manager', 'veteran'];

/** Gate a route to specific roles. */
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.user?.role)) {
      return res.status(403).json({
        error: `This action is limited to ${allowed.join(' and ')} accounts`,
      });
    }
    next();
  };
}

/**
 * Let reads through for any signed-in user but gate writes to the given roles.
 * Used as a path-prefix guard where GET is shared but POST/PATCH/DELETE is not.
 */
function requireRoleForWrites(...allowed) {
  const gate = requireRole(...allowed);
  return (req, res, next) =>
    (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS')
      ? next()
      : gate(req, res, next);
}

const requireAdmin      = requireRole('admin');
/** Production, sales, inventory and the processing unit. */
const requireProduction = requireRole('admin', 'manager');
/** Animal health: diseases, treatments, pregnancies, veterinary records. */
const requireHealth     = requireRole('admin', 'veteran');

/* ══════════════════════════════════
   LOGIN THROTTLING

   Counts consecutive *failed* sign-ins per IP + username, so a legitimate user
   is never locked out by their own successful logins. Held in memory, which is
   right for a single server but resets on restart and is not shared across
   instances — a serverless deployment would need a shared store to be effective.
══════════════════════════════════ */
const WINDOW_MS    = 15 * 60 * 1000;
const MAX_FAILURES = 10;
const failures     = new Map();   // key -> { count, firstAt }

function attemptKey(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
          || req.socket?.remoteAddress
          || 'unknown';
  return `${ip}|${String(req.body?.username || '').trim().toLowerCase()}`;
}

/** Drop expired entries so the map cannot grow without bound. */
function prune(now) {
  for (const [key, rec] of failures) {
    if (now - rec.firstAt >= WINDOW_MS) failures.delete(key);
  }
}

function loginRateLimit(req, res, next) {
  const now = Date.now();
  if (failures.size > 500) prune(now);

  const rec = failures.get(attemptKey(req));
  if (rec && now - rec.firstAt < WINDOW_MS && rec.count >= MAX_FAILURES) {
    const retryAfter = Math.ceil((WINDOW_MS - (now - rec.firstAt)) / 1000);
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({
      error: `Too many failed sign-in attempts. Try again in ${Math.ceil(retryAfter / 60)} minute(s).`,
    });
  }
  next();
}

function recordLoginFailure(req) {
  const key = attemptKey(req);
  const now = Date.now();
  const rec = failures.get(key);
  if (!rec || now - rec.firstAt >= WINDOW_MS) failures.set(key, { count: 1, firstAt: now });
  else rec.count++;
}

function clearLoginFailures(req) {
  failures.delete(attemptKey(req));
}

module.exports = {
  verifyToken, SECRET, ROLES,
  requireRole, requireRoleForWrites,
  requireAdmin, requireProduction, requireHealth,
  loginRateLimit, recordLoginFailure, clearLoginFailures,
};
