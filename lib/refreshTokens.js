const crypto = require('crypto');
const { pool } = require('../db');

/* ══════════════════════════════════════════════════════════════
   REFRESH TOKENS

   A sign-in used to hand out one JWT that was good for seven days and
   could not be taken back: the server kept no record of it, so a stolen
   token stayed valid for its whole life, a sacked attendant kept working
   until it expired, and a role change only took effect whenever the user
   next happened to sign in.

   Sessions are now two tokens with different jobs:

     access   — a short-lived JWT (15 minutes by default), still verified
                with nothing but the signing key, so no route pays a
                database round-trip to authenticate.
     refresh  — a long-lived opaque secret, one row per session in the
                table below, exchanged for a new access token when the old
                one expires.

   The refresh token is deliberately NOT a JWT. The whole point of it is
   that the server can revoke it, and a self-contained signed token cannot
   be revoked without keeping a list anyway — so it is 256 bits of
   randomness and the list is the authority.

   Only the SHA-256 of the token is stored. A leaked database backup
   therefore yields no usable session, the same reasoning that keeps
   passwords hashed. Plain SHA-256 is right here where bcrypt is not: the
   token is full-entropy random, so there is nothing to brute-force, and a
   deliberately slow hash would only be a cost on every refresh.

   ── Rotation and reuse detection ────────────────────────────
   Each refresh spends the old token and issues a new one. That bounds how
   long a stolen refresh token is useful, and it makes theft detectable:
   if a token that was already spent comes back, two clients are holding
   the same session, so the entire family — every token descended from
   that sign-in — is revoked at once and both parties have to sign in
   again. A false alarm costs one sign-in; missing a real theft costs the
   whole account.
══════════════════════════════════════════════════════════════ */

/** How long a session can survive without the user signing in again. */
const REFRESH_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS, 10) > 0
  ? parseInt(process.env.REFRESH_TOKEN_DAYS, 10)
  : 30;

/**
 * How long a session may sit unused before it ends.
 *
 * "Unused" means no request reached the API. Nothing in the app polls, so
 * an untouched tab really is idle — a till left on the counter at the end
 * of a shift stops being signed in half an hour later.
 *
 * The window stored below is this plus half an access-token lifetime, and
 * the reason is worth stating. The server only hears from a session when
 * it rotates, so someone who stops working right after a rotation was
 * last seen some minutes before they actually left. Measured from that
 * moment alone, thirty minutes of window would sign people out after
 * rather less than thirty minutes of real idleness, which is not what the
 * setting says.
 *
 * The client renews once its access token is past half its life, so the
 * server's idea of "last used" is never more than half a lifetime stale.
 * Padding by exactly that much makes thirty minutes the floor: nobody is
 * signed out before being genuinely idle that long, and with the default
 * fifteen-minute token nobody lasts past about thirty-eight.
 *
 * The two halves have to agree. If the client stops renewing at half-life
 * the padding is wrong, so that rule lives in one place — RENEW_AT_FRACTION
 * in the app's src/lib/session.js — and is named here.
 */
const IDLE_MINUTES = parseInt(process.env.SESSION_IDLE_MINUTES, 10) > 0
  ? parseInt(process.env.SESSION_IDLE_MINUTES, 10)
  : 30;

/**
 * The longest a single sign-in may last, however busy it is.
 *
 * The idle timeout alone never ends a session someone keeps using, and a
 * till in daily use would stay signed in for good. Twelve hours outlasts
 * a shift and not much else, so the counter is handed over with a sign-in
 * rather than with whoever was on it this morning.
 */
const MAX_HOURS = parseInt(process.env.SESSION_MAX_HOURS, 10) > 0
  ? parseInt(process.env.SESSION_MAX_HOURS, 10)
  : 12;

/**
 * How long after a rotation the old token is still forgiven.
 *
 * Two tabs whose access tokens expire in the same second both present the
 * same refresh token; one wins, and the loser is holding a token that was
 * spent a moment ago through no fault of anyone. Treating that as theft
 * would sign the user out of the farm office for having two tabs open.
 *
 * Inside this window a spent token is re-issued into the same session
 * instead of ending it. Outside it — a token replayed minutes or days
 * later — nothing benign explains the delay, and the family is revoked.
 * Only rotation is forgiven this way: a token revoked by a sign-out or an
 * account change is dead the moment it is revoked, whatever the clock says.
 */
const REUSE_LEEWAY_SECONDS = Number.isFinite(parseInt(process.env.REFRESH_REUSE_LEEWAY_SECONDS, 10))
  ? parseInt(process.env.REFRESH_REUSE_LEEWAY_SECONDS, 10)
  : 30;

/* The access-token lifetime, in minutes, read from the same place auth.js
   reads it so the idle window cannot drift from it. */
const ACCESS_TTL_MINUTES = (parseInt(process.env.ACCESS_TOKEN_SECONDS, 10) > 0
  ? parseInt(process.env.ACCESS_TOKEN_SECONDS, 10)
  : 15 * 60) / 60;

const hash = (token) => crypto.createHash('sha256').update(token).digest('hex');

/* pg hands back an INTERVAL as an object of parts, not a number. Only the
   coarse ones can appear here — these intervals are differences between
   two timestamps hours or minutes apart — but days and months are folded
   in anyway so a long-abandoned session cannot read as a short one. */
function intervalToMs(interval) {
  if (interval == null) return 0;
  if (typeof interval === 'number') return interval;
  const { milliseconds = 0, seconds = 0, minutes = 0, hours = 0, days = 0, months = 0, years = 0 } = interval;
  return milliseconds
    + seconds * 1000
    + minutes * 60_000
    + hours   * 3_600_000
    + days    * 86_400_000
    + months  * 30 * 86_400_000
    + years   * 365 * 86_400_000;
}

async function initRefreshTokenTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      /* SHA-256 of the token, never the token itself. */
      token_hash  TEXT NOT NULL UNIQUE,
      /* Every token rotated out of one sign-in shares this id, so a reuse
         can revoke the session rather than only the one stolen token. */
      family_id   TEXT NOT NULL,
      issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      /* When this sign-in happened, carried across every rotation, so the
         cap below is measured from the sign-in and not from the token
         that happens to be current. */
      family_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      /* When the session was last heard from. Set on every rotation; the
         idle timeout is measured from here. */
      last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at  TIMESTAMPTZ NOT NULL,
      /* Set when the token is spent by a rotation, by a sign-out, or by a
         change that should end the session. A row is kept after that: it
         is what makes a replayed token recognisable rather than merely
         unknown. */
      revoked_at  TIMESTAMPTZ,
      /* Why it was revoked: 'rotated' (spent normally), 'logout',
         'account_change' or 'reuse'. Only a rotation is eligible for the
         leeway above, so this is part of the security decision, not just a
         note for the audit trail. */
      revoked_reason TEXT,
      user_agent  TEXT,
      ip          TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);
  `);

  /* Added after the table shipped; CREATE TABLE IF NOT EXISTS above would
     leave an existing deployment without them. Sessions already running
     when this lands are treated as having started now, so the twelve-hour
     cap gives them a full window rather than ending them on deploy. */
  await pool.query(`
    ALTER TABLE refresh_tokens
      ADD COLUMN IF NOT EXISTS revoked_reason    TEXT,
      ADD COLUMN IF NOT EXISTS family_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS last_used_at      TIMESTAMPTZ NOT NULL DEFAULT NOW();
  `);
}

/** Where the session is being used from, for the sessions list and for audit. */
function describeClient(req) {
  const ip = req?.headers?.['x-forwarded-for']?.split(',')[0].trim()
          || req?.socket?.remoteAddress
          || null;
  const ua = req?.headers?.['user-agent'] || null;
  return { ip, user_agent: ua ? String(ua).slice(0, 300) : null };
}

/**
 * Start a session, or continue an existing one.
 *
 * Returns the plaintext token — the only moment it exists outside the
 * client, since the table keeps nothing but its hash.
 */
async function issueRefreshToken(userId, { req, familyId } = {}) {
  const token  = crypto.randomBytes(32).toString('hex');
  const family = familyId || crypto.randomUUID();
  const { ip, user_agent } = describeClient(req);

  /* The row cannot outlive the session cap, so expires_at is whichever
     comes first. With a twelve-hour cap it is always the cap — but the
     two are configured separately, and this way the column means "no use
     after this" whatever they are set to. */
  const { rows } = await pool.query(
    `INSERT INTO refresh_tokens
       (user_id, token_hash, family_id, expires_at, user_agent, ip)
     VALUES ($1, $2, $3,
             LEAST(NOW() + ($4 || ' days')::INTERVAL,
                   NOW() + ($5 || ' hours')::INTERVAL),
             $6, $7)
     RETURNING expires_at`,
    [userId, hash(token), family, String(REFRESH_DAYS), String(MAX_HOURS), user_agent, ip]
  );

  return { token, familyId: family, expiresAt: rows[0].expires_at };
}

/**
 * Spend a refresh token and issue its successor.
 *
 * Resolves to `{ user, token, familyId }` on success, or `{ error }` with a
 * message fit to show the user. The caller mints the access token from the
 * `user` row returned here — read fresh from the database on every refresh,
 * so a role change or a branch move takes effect within one access-token
 * lifetime instead of waiting for the next sign-in.
 */
async function rotateRefreshToken(presented, { req } = {}) {
  if (!presented || typeof presented !== 'string') {
    return { error: 'No refresh token supplied' };
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    /* FOR UPDATE, so two tabs refreshing at the same instant cannot both
       spend the same row and hand out two live successors. The loser waits
       here and then sees the row already revoked. */
    const { rows } = await client.query(
      `SELECT t.*, u.id AS uid, u.username, u.role, u.branch_id,
              NOW() - t.last_used_at      AS idle_for,
              NOW() - t.family_started_at AS session_age
         FROM refresh_tokens t
         JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1
        FOR UPDATE OF t`,
      [hash(presented)]
    );
    const row = rows[0];

    if (!row) {
      await client.query('ROLLBACK');
      return { error: 'Session has ended. Please sign in again.' };
    }

    if (row.revoked_at) {
      const ageSeconds = (Date.now() - new Date(row.revoked_at)) / 1000;
      const raced = row.revoked_reason === 'rotated' && ageSeconds <= REUSE_LEEWAY_SECONDS;

      if (!raced) {
        /* Replayed long after it was spent, or after the session was
           deliberately ended. Either someone is using a stolen token or
           the account has been changed underneath it; both end the same
           way, and the whole family goes rather than this one token. */
        await client.query(
          `UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = 'reuse'
            WHERE family_id = $1 AND revoked_at IS NULL`,
          [row.family_id]
        );
        await client.query('COMMIT');
        return { error: 'This session was used from somewhere else and has been ended. Please sign in again.' };
      }
      /* Inside the leeway: two tabs refreshed together. Fall through and
         hand this one its own successor in the same session. */
    }

    /* Ended by the clock rather than by anyone's decision. Both take the
       whole family, because both are statements about the sign-in, not
       about one token: another device holding a token from this session
       is just as stale. */
    const endSession = async (reason, message) => {
      await client.query(
        `UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = $2
          WHERE family_id = $1 AND revoked_at IS NULL`,
        [row.family_id, reason]
      );
      await client.query('COMMIT');
      return { error: message };
    };

    const idleMs = intervalToMs(row.idle_for);
    if (idleMs > (IDLE_MINUTES + ACCESS_TTL_MINUTES / 2) * 60_000) {
      return endSession('idle',
        `Signed out after ${IDLE_MINUTES} minutes without activity. Please sign in again.`);
    }

    if (intervalToMs(row.session_age) > MAX_HOURS * 60 * 60_000) {
      return endSession('max_age',
        `This sign-in has reached its ${MAX_HOURS}-hour limit. Please sign in again.`);
    }

    if (new Date(row.expires_at) <= new Date()) {
      await client.query(
        `UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = 'expired'
          WHERE id = $1 AND revoked_at IS NULL`,
        [row.id]
      );
      await client.query('COMMIT');
      return { error: 'Session has expired. Please sign in again.' };
    }

    /* Spend it. `revoked_at IS NULL` makes this a no-op on the leeway path,
       where the row was already spent by the tab that got here first — its
       revocation time is the one that counts. */
    await client.query(
      `UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = 'rotated'
        WHERE id = $1 AND revoked_at IS NULL`,
      [row.id]
    );

    const token  = crypto.randomBytes(32).toString('hex');
    const { ip, user_agent } = describeClient(req);
    const { rows: fresh } = await client.query(
      `INSERT INTO refresh_tokens
         (user_id, token_hash, family_id, family_started_at, last_used_at,
          expires_at, user_agent, ip)
       VALUES ($1, $2, $3, $4, NOW(),
               LEAST(NOW() + ($5 || ' days')::INTERVAL,
                     $4::timestamptz + ($6 || ' hours')::INTERVAL),
               $7, $8)
       RETURNING expires_at`,
      [row.user_id, hash(token), row.family_id, row.family_started_at,
       String(REFRESH_DAYS), String(MAX_HOURS), user_agent, ip]
    );

    await client.query('COMMIT');

    return {
      token,
      familyId: row.family_id,
      expiresAt: fresh[0].expires_at,
      user: {
        id: row.uid, username: row.username,
        role: row.role, branch_id: row.branch_id ?? null,
      },
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/** End one session — what signing out does. Unknown tokens are a no-op. */
async function revokeRefreshToken(presented) {
  if (!presented || typeof presented !== 'string') return;
  /* The whole family, not just the token presented: a sign-out on a device
     that had already rotated has to take the successor with it, and the
     leeway above would otherwise let the spent token buy a new one. */
  await pool.query(
    `UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = 'logout'
      WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
        AND revoked_at IS NULL`,
    [hash(presented)]
  );
}

/**
 * End every session an account has.
 *
 * Used when the account changes underneath its sessions — a new password, a
 * different role, a move to another branch — so the change cannot be
 * outlived by a token issued before it. Their access tokens still work
 * until they expire; that window is what the short access lifetime buys.
 */
async function revokeAllForUser(userId) {
  const { rowCount } = await pool.query(
    `UPDATE refresh_tokens SET revoked_at = NOW(), revoked_reason = 'account_change'
      WHERE user_id = $1 AND revoked_at IS NULL`,
    [userId]
  );
  return rowCount;
}

/** List a user's live sessions, newest first. Never exposes a token. */
async function listSessions(userId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (family_id)
            family_id, issued_at, family_started_at, last_used_at,
            expires_at, user_agent, ip
       FROM refresh_tokens
      WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY family_id, issued_at DESC`,
    [userId]
  );
  return rows.sort((a, b) => new Date(b.issued_at) - new Date(a.issued_at));
}

/**
 * Drop rows no longer worth keeping.
 *
 * Revoked rows are held for a week after expiry rather than deleted on the
 * spot, because a deleted row is indistinguishable from a token that never
 * existed and reuse detection would lose its evidence.
 */
async function purgeExpiredTokens() {
  const { rowCount } = await pool.query(
    `DELETE FROM refresh_tokens WHERE expires_at < NOW() - INTERVAL '7 days'`
  );
  return rowCount;
}

module.exports = {
  initRefreshTokenTables,
  issueRefreshToken, rotateRefreshToken,
  revokeRefreshToken, revokeAllForUser,
  listSessions, purgeExpiredTokens,
  REFRESH_DAYS, REUSE_LEEWAY_SECONDS, IDLE_MINUTES, MAX_HOURS,
};
