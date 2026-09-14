/* ══════════════════════════════════════════════════════════════
   WHO MAY CALL THIS API

   One list, used twice: by CORS, to decide whose browser may read a
   response, and by the guard below, to decide whose page may make a
   cookie-authenticated request at all.
══════════════════════════════════════════════════════════════ */

const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://bushi-farm.vercel.app',
  /* A deployment serving the API under the app's own domain — the setup
     that makes the refresh cookie first-party — adds that origin here. */
  ...String(process.env.EXTRA_ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim()).filter(Boolean),
];

/**
 * Guard the endpoints whose credential is the cookie itself.
 *
 * A cookie is attached by the browser to any request that reaches this
 * host, including one triggered by a page the user did not expect to be
 * on. Nothing is readable from such a page — CORS sees to that — but
 * /auth/refresh rotates the session as a side effect, and an attacker who
 * can trigger a rotation they do not see can knock someone out of the
 * till by spending their token for them.
 *
 * Two cheap checks close it:
 *
 * The Origin header must be one we know, when it is present at all. A
 * browser sets it on every cross-origin request and never lets a page lie
 * about it.
 *
 * A custom header must be present. Sending one requires a successful CORS
 * preflight, which an origin outside the list above cannot get — so a
 * form post or an <img> from a hostile page, neither of which can carry a
 * custom header, does not reach the handler. Requests with no Origin at
 * all (curl, a server-side caller) still have to set it deliberately.
 */
const CLIENT_HEADER = 'x-requested-with';

function rejectForeignOrigin(req, res, next) {
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ error: 'This request did not come from a known client' });
  }
  if (!req.headers[CLIENT_HEADER]) {
    return res.status(403).json({ error: 'This request did not come from a known client' });
  }
  next();
}

module.exports = { ALLOWED_ORIGINS, CLIENT_HEADER, rejectForeignOrigin };
