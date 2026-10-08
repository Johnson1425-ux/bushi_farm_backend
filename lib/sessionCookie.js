/* ══════════════════════════════════════════════════════════════
   THE REFRESH COOKIE

   The refresh token is the long-lived half of a session, so it is the
   half worth stealing. Kept in localStorage it is one line of injected
   script away from being read and posted elsewhere — and a token taken
   that way outlives the page it was taken from, which is exactly what a
   month-long credential must not do.

   In an httpOnly cookie no script can read it at all, XSS included. An
   injected script on the page can still *use* the session it is sitting
   in, because the browser attaches the cookie to requests it makes; what
   it cannot do is take the token away and use it later, somewhere else.
   That is the difference between a compromised page and a compromised
   account.

   The access token stays out of storage entirely — the client holds it in
   memory — so there is nothing left on disk for a script to read.

   ── Attributes, and why ─────────────────────────────────────
   httpOnly  no script may read it. The whole point.
   secure    HTTPS only, so it never crosses the network in the clear.
   sameSite  see below — it depends on where the API is deployed.
   path      /api/auth, so the cookie rides only on the three endpoints
             that need it and is not attached to every other API call.
   maxAge    matches the token's own lifetime, so the browser drops it at
             the same moment the server stops honouring it.
══════════════════════════════════════════════════════════════ */

const REFRESH_COOKIE = 'mt_refresh';
const COOKIE_PATH    = '/api/auth';

const isProduction = () => process.env.NODE_ENV === 'production';

/**
 * SameSite for the deployment this is running in.
 *
 * If the API answers on the same site as the app — the same domain, or a
 * path proxied through it — the cookie is first-party and 'lax' is both
 * safe and universally supported.
 *
 * Deployed as it stands, the app is on one *.vercel.app host and the API
 * on another. vercel.app is a public suffix, so those are different sites
 * and the cookie is third-party: it needs 'none', and Safari declines to
 * store third-party cookies at all. Serving the API under the app's own
 * domain is what makes this cookie work in every browser; COOKIE_SAMESITE
 * is how that deployment says so.
 */
function sameSite() {
  const configured = String(process.env.COOKIE_SAMESITE || '').toLowerCase();
  if (['lax', 'strict', 'none'].includes(configured)) return configured;
  return isProduction() ? 'none' : 'lax';
}

function cookieOptions(maxAgeMs) {
  const policy = sameSite();
  return {
    httpOnly: true,
    /* SameSite=None is only honoured on a secure cookie, so the two move
       together. Local development over plain http stays on 'lax'. */
    secure: policy === 'none' ? true : isProduction(),
    sameSite: policy,
    path: COOKIE_PATH,
    /* Only for a deployment sharing one parent domain between app and API
       (app.example.com and api.example.com want '.example.com'). Left
       unset the cookie is bound to the exact host that set it. */
    ...(process.env.COOKIE_DOMAIN ? { domain: process.env.COOKIE_DOMAIN } : {}),
    ...(maxAgeMs ? { maxAge: maxAgeMs } : {}),
  };
}

/**
 * Set the cookie to expire exactly when the token does.
 *
 * `expiresAt` comes from the row itself, which already accounts for the
 * twelve-hour cap — so the browser drops the cookie at the same moment
 * the server would refuse it, and a capped-out session does not sit in
 * the jar being presented and rejected for the rest of the month.
 */
function setRefreshCookie(res, token, expiresAt) {
  const maxAgeMs = Math.max(0, new Date(expiresAt).getTime() - Date.now());
  res.cookie(REFRESH_COOKIE, token, cookieOptions(maxAgeMs));
}

/* Cleared with the same attributes it was set with — a browser matches a
   deletion to an existing cookie by name, domain and path, so a mismatch
   here leaves the old cookie in place. */
function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, cookieOptions());
}

/**
 * Read the refresh cookie off the request.
 *
 * Written out rather than pulled in as a dependency: one cookie, whose
 * value is hex, is not worth a package on the path that authenticates
 * every session.
 */
function readRefreshCookie(req) {
  const header = req.headers?.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== REFRESH_COOKIE) continue;
    const raw = part.slice(eq + 1).trim().replace(/^"|"$/g, '');
    try { return decodeURIComponent(raw); } catch { return raw; }
  }
  return null;
}

module.exports = {
  REFRESH_COOKIE, COOKIE_PATH,
  setRefreshCookie, clearRefreshCookie, readRefreshCookie,
  sameSite,
};
