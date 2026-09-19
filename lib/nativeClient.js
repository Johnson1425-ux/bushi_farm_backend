/* ══════════════════════════════════════════════════════════════
   NATIVE CLIENTS

   The whole session design rests on the refresh token living in an
   httpOnly cookie, where no script can read it. That works because a
   browser has a cookie jar and attaches it for us.

   The iOS app has neither. Its requests come from a native fetch, not a
   document, so there is no origin, no cookie jar worth relying on, and
   nothing the system will re-attach on the next launch. WKWebView's jar
   is not durable across app restarts either, which is the trap the
   obvious "just wrap the web app" approach falls into.

   What it has instead is better than a cookie: the iOS Keychain. Storage
   the OS encrypts, scoped to the app, unreadable by any other app, and
   survives reinstall only if we ask it to. So for a native client the
   refresh token is returned in the body once and put there.

   ── Why a browser cannot ask for this ───────────────────────
   Handing a refresh token to a body is exactly what the cookie exists to
   prevent, so it must not be something a page can opt into. An XSS on the
   farm's own web app already runs on an allowed origin — if setting one
   header were enough, that XSS could ask for the month-long credential
   and walk away with it, which is the one outcome the cookie design
   rules out.

   Two things are required together, and a browser cannot present the
   second:

     the header        X-Client-Platform: ios | android
     no Origin header  browsers set Origin on every fetch that carries a
                       body, same-origin ones included. A native fetch
                       does not set it at all.

   So a page can set the header and still not be treated as native: its
   Origin gives it away. A native client sets the header and has no
   Origin to give. The XSS is back to spending a fifteen-minute access
   token, which is where the cookie design leaves it.
══════════════════════════════════════════════════════════════ */

const NATIVE_PLATFORMS = ['ios', 'android'];

/**
 * Whether this request is the native app asking for a token it can store
 * itself, rather than a browser that wants the cookie.
 */
function isNativeClient(req) {
  const platform = String(req.headers?.['x-client-platform'] || '').trim().toLowerCase();
  if (!NATIVE_PLATFORMS.includes(platform)) return false;
  /* An Origin means a document made this request. Whatever it claims to
     be, it has a cookie jar and it gets the cookie. */
  if (req.headers?.origin) return false;
  return true;
}

module.exports = { isNativeClient, NATIVE_PLATFORMS };
