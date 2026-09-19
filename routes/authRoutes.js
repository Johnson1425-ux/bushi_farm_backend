const express = require('express');
const bcrypt  = require('bcrypt');
const { pool } = require('../db');
const {
  verifyToken, signAccessToken, ACCESS_TTL_SECONDS,
  loginRateLimit, recordLoginFailure, clearLoginFailures,
} = require('../auth');
const {
  issueRefreshToken, rotateRefreshToken,
  revokeRefreshToken, revokeAllForUser, listSessions,
  REFRESH_DAYS,
} = require('../lib/refreshTokens');
const {
  setRefreshCookie, clearRefreshCookie, readRefreshCookie,
} = require('../lib/sessionCookie');
const { rejectForeignOrigin } = require('../lib/origins');
const { isNativeClient } = require('../lib/nativeClient');

const router = express.Router();

/* ══════════════════════════════════
   SIGNING IN

   A sign-in produces two things, which leave by different doors:

     the access token   — a JWT good for ACCESS_TTL_SECONDS (15 minutes),
                          returned in the response body, sent on every
                          request, verified with nothing but the key.
     the refresh token  — an opaque secret good for a month, set as an
                          httpOnly cookie and never put in a body,
                          revocable, and rotated every time it is used.

   Before this split there was one seven-day JWT in localStorage and no
   way to end a session: signing out only forgot the token, it did not
   stop it working, and any injected script could read it and keep it.

   The refresh token now never passes through JavaScript at all. What an
   injected script can still reach is the access token, for the fifteen
   minutes it lasts — bad, but survivable, and it ends on its own.
══════════════════════════════════ */

/**
 * Hand the client its session.
 *
 * A browser gets the refresh token as a cookie it cannot read and the
 * access token in the body — the arrangement described above.
 *
 * The iOS app gets both in the body, because it has no cookie jar that
 * survives a relaunch and does have the Keychain, which is a better place
 * for a month-long credential than a cookie is. isNativeClient() is what
 * decides, and lib/nativeClient.js explains why a page cannot pretend to
 * be one.
 */
async function sendSession(res, user, refresh, req) {
  const native = isNativeClient(req);

  if (native) {
    /* Belt and braces: a native client should have no cookie, but if one
       was ever set on this response path it must not linger as a second,
       staler copy of the session. */
    clearRefreshCookie(res);
  } else {
    setRefreshCookie(res, refresh.token, REFRESH_DAYS);
  }

  res.json({
    token: signAccessToken(user, { sid: refresh.familyId }),
    expiresIn: ACCESS_TTL_SECONDS,
    ...(native
      ? { refreshToken: refresh.token, refreshExpiresInDays: REFRESH_DAYS }
      : {}),
    user: await withBranchName(user),
  });
}

/* Guarded like the other two: a sign-in now sets a cookie, and a hostile
   page that could trigger one would be setting *its* session in the
   user's browser, leaving them typing the day's takings into an account
   that is not theirs. */
router.post('/login', rejectForeignOrigin, loginRateLimit, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username.trim()]);
    const user = rows[0];
    if (!user) { recordLoginFailure(req); return res.status(401).json({ error: 'Invalid credentials' }); }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) { recordLoginFailure(req); return res.status(401).json({ error: 'Invalid credentials' }); }
    clearLoginFailures(req);
    /* branch_id rides on the access token so every branch-scoped route can
       settle "which branch is this?" without a lookup — and, more to the
       point, without trusting a branch id the client sent. The token is
       reminted from the users row on every refresh, so moving an attendant
       now reaches their till within one access-token lifetime instead of
       waiting for their next sign-in; a shift in progress is not
       interrupted, because the till they are standing at only changes when
       an admin actually moves them. */
    const claims = {
      id: user.id, username: user.username,
      role: user.role, branch_id: user.branch_id ?? null,
    };
    await sendSession(res, claims, await issueRefreshToken(user.id, { req }), req);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   REFRESH

   No access token required: the cookie is the credential, and needing a
   live access token to obtain a live access token would defeat the whole
   arrangement. rejectForeignOrigin is what stands in its place, because a
   cookie is sent by the browser whether or not the page meant it.

   The user row is re-read inside rotateRefreshToken(), so the new access
   token reflects the account as it stands now. A deleted account has no
   row to join against and cannot refresh at all.
══════════════════════════════════ */
router.post('/refresh', rejectForeignOrigin, async (req, res) => {
  /* The cookie first, because for a browser it is the only credential
     that counts.

     `refreshToken` in the body serves two callers. The iOS app, which has
     no cookie and presents the token it keeps in the Keychain — see
     lib/nativeClient.js. And, still, a browser carrying over a session
     from the release that kept the token in localStorage: it sends what
     it had once, gets a cookie back, and forgets it. */
  const presented = readRefreshCookie(req) || req.body?.refreshToken;
  try {
    const result = await rotateRefreshToken(presented, { req });
    if (result.error) {
      /* Take the cookie with it. A rejected token is never going to work
         again, and leaving it in the browser means every later refresh
         presents the same dead credential. */
      clearRefreshCookie(res);
      return res.status(401).json({ error: result.error, code: 'refresh_rejected' });
    }
    await sendSession(res, result.user, result, req);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Signing out now actually ends the session rather than only forgetting
   it. No access token is required — a client whose access token has
   already expired still has to be able to sign out — and an unknown token
   is a silent no-op, so this cannot be used to probe which tokens exist.
   The cookie is cleared either way, so the browser is left signed out
   even if there was nothing on the server to revoke. */
router.post('/logout', rejectForeignOrigin, async (req, res) => {
  try {
    await revokeRefreshToken(readRefreshCookie(req) || req.body?.refreshToken);
    clearRefreshCookie(res);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** Every device this account is signed in on. */
router.get('/sessions', verifyToken, async (req, res) => {
  try {
    res.json(await listSessions(req.user.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Sign out everywhere — the answer to a lost phone. Access tokens already
   handed out stay valid until they expire, which is the fifteen-minute
   window the short lifetime is there to bound. */
router.post('/logout-all', verifyToken, async (req, res) => {
  try {
    const ended = await revokeAllForUser(req.user.id);
    clearRefreshCookie(res);
    res.json({ ok: true, sessions_ended: ended });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/me', verifyToken, async (req, res) => {
  try {
    res.json({ user: await withBranchName(req.user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* The branch name is for the sidebar to show, not for any decision — those
   are all made from branch_id. A token naming a branch that has since been
   deleted simply comes back without a name rather than failing sign-in. */
async function withBranchName(user) {
  const claims = {
    id: user.id, username: user.username,
    role: user.role, branch_id: user.branch_id ?? null,
  };
  if (!claims.branch_id) return { ...claims, branch_name: null };
  const { rows } = await pool.query('SELECT name FROM branches WHERE id=$1', [claims.branch_id]);
  return { ...claims, branch_name: rows[0]?.name ?? null };
}

module.exports = router;
