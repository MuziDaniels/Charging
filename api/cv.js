// ChargeVault 20 API: team logins + live shared data in a private Vercel Blob.
//
// Roles
//   owner  = can run the stand: check people in/out, swap bays, manage the team.
//   viewer = read only (e.g. watching sales from home).
//
// Accounts
//   A master owner/viewer password always works (set below in Vercel env vars) -
//   this is the permanent fallback that can never be locked out.
//   On top of that, Muzi (or any owner) can add named team accounts from inside the
//   app (Settings > Team). Each person gets their own name + password, so the shift
//   log shows who actually checked a phone in or released it, and removing someone
//   signs them out immediately - no app redeploy needed.
//
// Environment variables (Vercel > Project > Settings > Environment Variables)
//   CV_OWNER_PASSWORD   master password, full control
//   CV_VIEWER_PASSWORD  master password, read only
//   BLOB_READ_WRITE_TOKEN  added automatically when the Blob store is connected
//
// Locker PINs and customer cellphone numbers ARE stored in the private live data now
// (every team member running the stand needs to see them), but they are always
// stripped out before anything is sent to a viewer-role session.

const crypto = require('crypto');
const { put, get } = require('@vercel/blob');

const DATA_PATH = 'chargevault/live.json';
const TEAM_PATH = 'chargevault/team.json';
const COOKIE = 'cv_session';
const MAX_AGE_S = 60 * 60 * 24 * 30; // stay logged in for 30 days
const MAX_BAY_COUNT = 20; // the bigger of the two machines (10-bay and 20-bay)
const MAX_BYTES = 3 * 1024 * 1024;
const MAX_TEAM = 25;

const OWNER = () => process.env.CV_OWNER_PASSWORD || '';
const VIEWER = () => process.env.CV_VIEWER_PASSWORD || '';

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const b64u = buf => Buffer.from(buf).toString('base64url');
const hexHash = s => sha(s).toString('hex');

// Changing either master password signs everyone out, because the key is derived from them.
function sessionKey() {
  return sha(`cv-session|${OWNER()}|${VIEWER()}|${process.env.BLOB_READ_WRITE_TOKEN || ''}`);
}
function hmac(body) { return b64u(crypto.createHmac('sha256', sessionKey()).update(body).digest()); }

function signSession(payload) {
  const body = b64u(JSON.stringify(payload));
  return `${body}.${hmac(body)}`;
}

// Only checks the signature + expiry here. Team-member sessions are re-checked against
// the live roster on every request (see resolveSession), so removing someone takes effect
// immediately without waiting for their token to expire.
function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  const expected = hmac(body);
  if (!mac || mac.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!p || !p.exp || p.exp < Date.now()) return null;
    if (p.personId == null) {
      if (!['owner', 'viewer'].includes(p.role)) return null;
    } else if (typeof p.personId !== 'string') return null;
    return p;
  } catch (e) { return null; }
}

function samePassword(input, actual) {
  if (!actual || typeof input !== 'string' || !input) return false;
  return crypto.timingSafeEqual(sha(input), sha(actual));
}

function cookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function setSessionCookie(res, value, maxAge) {
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
}

async function readJson(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BYTES) throw Object.assign(new Error('too_large'), { status: 413 });
    chunks.push(c);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

function stripPrivate(row) {
  if (!row || typeof row !== 'object') return row;
  const { lockerPin, phone, ...rest } = row;
  return rest;
}

const hasActivity = d => !!d && ((Array.isArray(d.history) && d.history.length > 0) || (Array.isArray(d.bays) && d.bays.some(b => b && b.occupied)));

async function readBlobJson(path, etag) {
  const r = await get(path, { access: 'private', useCache: false, ifNoneMatch: etag || undefined });
  if (!r) return { data: null, etag: null };
  if (r.statusCode === 304) return { unchanged: true, etag: r.blob.etag };
  const text = await new Response(r.stream).text();
  return { data: JSON.parse(text), etag: r.blob.etag };
}

async function readData(etag) { return readBlobJson(DATA_PATH, etag); }

async function readTeam() {
  const out = await readBlobJson(TEAM_PATH);
  const people = out.data && Array.isArray(out.data.people) ? out.data.people : [];
  return { people, etag: out.etag };
}

// Read-modify-write with retry on a stale ETag, so two admins editing the team
// list (or two devices syncing) at the same moment can never silently clobber
// each other - one of them just retries against the fresh copy.
async function withBlobRetry(path, mutate, { emptyShape }) {
  let lastErr;
  for (let attempt = 0; attempt < 5; attempt++) {
    const existing = await readBlobJson(path);
    const current = existing.data || emptyShape;
    const result = await mutate(current, existing.etag);
    if (!result || result.ok === false) return result;
    const json = JSON.stringify(result.data);
    if (json.length > MAX_BYTES) return { ok: false, error: 'too_large' };
    try {
      await put(path, json, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        ifMatch: existing.etag || undefined,
        contentType: 'application/json',
        cacheControlMaxAge: 0
      });
      return { ok: true, data: result.data };
    } catch (e) {
      if (e && e.name === 'BlobPreconditionFailedError' && attempt < 4) { lastErr = e; continue; }
      throw e;
    }
  }
  throw lastErr || new Error('conflict_retry_exceeded');
}

// Resolves a verified token into the acting person. For a master login the
// role/name are trusted from the token. For a team login, the roster is the
// source of truth every time - if they were removed, this returns null, which
// ends the session immediately everywhere they're logged in.
async function resolveSession(token) {
  const p = verifySessionToken(token);
  if (!p) return null;
  if (p.personId == null) return { role: p.role, name: p.role === 'owner' ? 'Owner' : 'Viewer', personId: null };
  const { people } = await readTeam();
  const person = people.find(x => x.id === p.personId);
  if (!person) return null;
  return { role: person.role, name: person.name, personId: person.id };
}

module.exports = async function handler(req, res) {
  const action = new URL(req.url, 'http://localhost').searchParams.get('a');

  try {
    if (!OWNER() || !VIEWER()) return send(res, 503, { error: 'not_configured' });

    if (action === 'login') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method' });
      const { password } = await readJson(req);
      if (samePassword(password, OWNER())) {
        setSessionCookie(res, signSession({ role: 'owner', personId: null, exp: Date.now() + MAX_AGE_S * 1000 }), MAX_AGE_S);
        return send(res, 200, { role: 'owner', name: 'Owner' });
      }
      if (samePassword(password, VIEWER())) {
        setSessionCookie(res, signSession({ role: 'viewer', personId: null, exp: Date.now() + MAX_AGE_S * 1000 }), MAX_AGE_S);
        return send(res, 200, { role: 'viewer', name: 'Viewer' });
      }
      const { people } = await readTeam();
      const hash = typeof password === 'string' ? hexHash(password) : null;
      const person = hash ? people.find(x => x.passwordHash === hash) : null;
      if (!person) { await sleep(900); return send(res, 401, { error: 'wrong_password' }); }
      setSessionCookie(res, signSession({ role: person.role, personId: person.id, exp: Date.now() + MAX_AGE_S * 1000 }), MAX_AGE_S);
      return send(res, 200, { role: person.role, name: person.name });
    }

    if (action === 'logout') {
      setSessionCookie(res, '', 0);
      return send(res, 200, { ok: true });
    }

    const session = await resolveSession(cookies(req)[COOKIE]);
    if (!session) return send(res, 401, { error: 'not_logged_in' });

    if (action === 'me') return send(res, 200, { role: session.role, name: session.name });

    if (action === 'state') {
      if (req.method !== 'GET') return send(res, 405, { error: 'method' });
      const known = req.headers['x-cv-etag'];
      const out = await readData(typeof known === 'string' ? known : undefined);
      if (out.unchanged) return send(res, 200, { unchanged: true, etag: out.etag });
      let data = out.data;
      if (data && session.role === 'viewer') {
        data = { ...data, bays: data.bays.map(stripPrivate), history: data.history.map(stripPrivate) };
      }
      return send(res, 200, { data, etag: out.etag });
    }

    if (action === 'sync') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method' });
      if (session.role !== 'owner') return send(res, 403, { error: 'read_only' });
      const body = await readJson(req);
      const d = body && body.data;
      if (!d || !Array.isArray(d.bays) || !d.bays.length || d.bays.length > MAX_BAY_COUNT || !Array.isArray(d.history)) {
        return send(res, 400, { error: 'bad_data' });
      }
      // Never let an empty phone wipe real data unless it is a deliberate "End shift & reset"
      if (!hasActivity(d) && !body.reset) {
        const existing = await readData();
        if (hasActivity(existing.data)) return send(res, 409, { error: 'server_has_data' });
      }
      const clean = {
        app: 'ChargeVault 20',
        updatedAt: Number(d.updatedAt) || Date.now(),
        savedAt: Date.now(),
        savedBy: session.name,
        settingsRev: Number(d.settingsRev) || 0,
        settings: d.settings && typeof d.settings === 'object' ? {
          eventName: String(d.settings.eventName || '').slice(0, 80),
          priceHour: Number(d.settings.priceHour) || 0,
          priceFull: Number(d.settings.priceFull) || 0,
          priceExt: Number(d.settings.priceExt) || 0,
          checkIntervalMins: Number(d.settings.checkIntervalMins) || 10,
          bayCount: Number(d.settings.bayCount) === 10 ? 10 : 20,
          hourMins: Math.max(5, Number(d.settings.hourMins) || 60),
          extMins: Math.max(5, Number(d.settings.extMins) || 60)
        } : {},
        bays: d.bays.slice(0, MAX_BAY_COUNT),
        history: d.history.slice(0, 5000),
        swaps: Array.isArray(d.swaps) ? d.swaps.slice(0, 2000) : []
      };
      const json = JSON.stringify(clean);
      if (json.length > MAX_BYTES) return send(res, 413, { error: 'too_large' });
      await put(DATA_PATH, json, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/json',
        cacheControlMaxAge: 0
      });
      return send(res, 200, { ok: true, savedAt: clean.savedAt });
    }

    if (action === 'team-list') {
      if (req.method !== 'GET') return send(res, 405, { error: 'method' });
      if (session.role !== 'owner') return send(res, 403, { error: 'read_only' });
      const { people } = await readTeam();
      return send(res, 200, { people: people.map(({ id, name, role, addedAt, addedBy }) => ({ id, name, role, addedAt, addedBy })) });
    }

    if (action === 'team-add') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method' });
      if (session.role !== 'owner') return send(res, 403, { error: 'read_only' });
      const body = await readJson(req);
      const name = String(body.name || '').trim().slice(0, 40);
      const password = String(body.password || '');
      const role = body.role === 'viewer' ? 'viewer' : 'owner';
      if (!name) return send(res, 400, { error: 'name_required' });
      if (password.length < 4) return send(res, 400, { error: 'weak_password' });
      const result = await withBlobRetry(TEAM_PATH, (current) => {
        const people = Array.isArray(current.people) ? current.people.slice() : [];
        if (people.length >= MAX_TEAM) return { ok: false, error: 'too_many' };
        if (samePassword(password, OWNER()) || samePassword(password, VIEWER()) || people.some(p => p.passwordHash === hexHash(password))) {
          return { ok: false, error: 'password_in_use' };
        }
        const person = { id: crypto.randomUUID(), name, passwordHash: hexHash(password), role, addedAt: Date.now(), addedBy: session.name };
        people.push(person);
        return { ok: true, data: { people } };
      }, { emptyShape: { people: [] } });
      if (!result.ok) return send(res, result.error === 'too_many' ? 409 : 400, { error: result.error });
      return send(res, 200, { people: result.data.people.map(({ id, name, role, addedAt, addedBy }) => ({ id, name, role, addedAt, addedBy })) });
    }

    if (action === 'team-remove') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method' });
      if (session.role !== 'owner') return send(res, 403, { error: 'read_only' });
      const body = await readJson(req);
      const id = String(body.id || '');
      const result = await withBlobRetry(TEAM_PATH, (current) => {
        const people = (Array.isArray(current.people) ? current.people : []).filter(p => p.id !== id);
        return { ok: true, data: { people } };
      }, { emptyShape: { people: [] } });
      if (!result.ok) return send(res, 400, { error: result.error });
      return send(res, 200, { people: result.data.people.map(({ id, name, role, addedAt, addedBy }) => ({ id, name, role, addedAt, addedBy })) });
    }

    return send(res, 404, { error: 'unknown_action' });
  } catch (e) {
    console.error('ChargeVault API error', e);
    return send(res, e.status || 500, { error: e.status === 413 ? 'too_large' : 'server_error' });
  }
};
