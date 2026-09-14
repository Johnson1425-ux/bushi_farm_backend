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
} = require('../lib/refreshTokens');

const router = express.Router();

/* ══════════════════════════════════
   SIGNING IN

   A sign-in produces two things:

     token        — a JWT good for ACCESS_TTL_SECONDS (15 minutes), sent on
                    every request and verified with nothing but the key.
     refreshToken — an opaque secret good for a month, sent only to
                    /auth/refresh, revocable, and rotated every time it is
                    used.

   Before this split there was one seven-day JWT and no way to end a
   session: signing out only forgot the token, it did not stop it working.

   `token` keeps its name in the response so a client that has not been
   updated yet still finds what it expects — it simply expires sooner than
   it used to, and a client that ignores refreshToken will ask its user to
   sign in again after fifteen minutes rather than breaking.
══════════════════════════════════ */

/** What the client is given after a successful sign-in or refresh. */
async function sessionPayload(user, refresh) {
  return {
    token: signAccessToken(user, { sid: refresh.familyId }),
    refreshToken: refresh.token,
    expiresIn: ACCESS_TTL_SECONDS,
    user: await withBranchName(user),
  };
}

router.post('/login', loginRateLimit, async (req, res) => {
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
    res.json(await sessionPayload(claims, await issueRefreshToken(user.id, { req })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ══════════════════════════════════
   REFRESH

   Public: the refresh token is the credential, and the expired access
   token it replaces cannot be required here — needing a live access token
   to get a live access token would defeat the whole arrangement.

   The user row is re-read inside rotateRefreshToken(), so the new access
   token reflects the account as it stands now. A deleted account has no
   row to join against and cannot refresh at all.
══════════════════════════════════ */
router.post('/refresh', async (req, res) => {
  const presented = req.body?.refreshToken;
  try {
    const result = await rotateRefreshToken(presented, { req });
    if (result.error) {
      /* 401 with a code the client can act on: it clears the stored
         session and sends the user to sign in, rather than retrying a
         token that will never work again. */
      return res.status(401).json({ error: result.error, code: 'refresh_rejected' });
    }
    res.json(await sessionPayload(result.user, result));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* Signing out now actually ends the session rather than only forgetting
   it. No access token is required — a client whose access token has
   already expired still has to be able to sign out — and an unknown token
   is a silent no-op, so this cannot be used to probe which tokens exist. */
router.post('/logout', async (req, res) => {
  try {
    await revokeRefreshToken(req.body?.refreshToken);
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
