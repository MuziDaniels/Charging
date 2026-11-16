// ChargeVault 20 API: login for two people + live data in a private Vercel Blob.
//
// Roles
//   owner  = the stand phone (Muzi). Can push data.
//   viewer = sister at home. Read only.
//
// Environment variables (Vercel > Project > Settings > Environment Variables)
//   CV_OWNER_PASSWORD   password for the stand phone
//   CV_VIEWER_PASSWORD  password for the read-only viewer
//   BLOB_READ_WRITE_TOKEN  added automatically when the Blob store is connected
//
// Locker PINs and customer cellphone numbers are stripped before saving and never stored here.

const crypto = require('crypto');
const { put, get } = require('@vercel/blob');

const DATA_PATH = 'chargevault/live.json';
const COOKIE = 'cv_session';
const MAX_AGE_S = 60 * 60 * 24 * 30; // stay logged in for 30 days
const BAY_COUNT = 20;
const MAX_BYTES = 3 * 1024 * 1024;

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

// Changing either password signs everyone out, because the key is derived from them.
function sessionKey() {
  return sha(`cv-session|${OWNER()}|${VIEWER()}|${process.env.BLOB_READ_WRITE_TOKEN || ''}`);
}
function hmac(body) { return b64u(crypto.createHmac('sha256', sessionKey()).update(body).digest()); }

function signSession(payload) {
  const body = b64u(JSON.stringify(payload));
  return `${body}.${hmac(body)}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  const expected = hmac(body);
  if (!mac || mac.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!p || !['owner', 'viewer'].includes(p.role) || !p.exp || p.exp < Date.now()) return null;
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

async function readData(etag) {
  const r = await get(DATA_PATH, { access: 'private', useCache: false, ifNoneMatch: etag || undefined });
  if (!r) return { data: null, etag: null };
  if (r.statusCode === 304) return { unchanged: true, etag: r.blob.etag };
  const text = await new Response(r.stream).text();
  return { data: JSON.parse(text), etag: r.blob.etag };
}

module.exports = async function handler(req, res) {
  const action = new URL(req.url, 'http://localhost').searchParams.get('a');

  try {
    if (!OWNER() || !VIEWER()) return send(res, 503, { error: 'not_configured' });

    if (action === 'login') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method' });
      const { password } = await readJson(req);
      let role = null;
      if (samePassword(password, OWNER())) role = 'owner';
      else if (samePassword(password, VIEWER())) role = 'viewer';
      if (!role) { await sleep(900); return send(res, 401, { error: 'wrong_password' }); }
      setSessionCookie(res, signSession({ role, exp: Date.now() + MAX_AGE_S * 1000 }), MAX_AGE_S);
      return send(res, 200, { role });
    }

    if (action === 'logout') {
      setSessionCookie(res, '', 0);
      return send(res, 200, { ok: true });
    }

    const session = verifySession(cookies(req)[COOKIE]);
    if (!session) return send(res, 401, { error: 'not_logged_in' });

    if (action === 'me') return send(res, 200, { role: session.role });

    if (action === 'state') {
      if (req.method !== 'GET') return send(res, 405, { error: 'method' });
      const known = req.headers['x-cv-etag'];
      const out = await readData(typeof known === 'string' ? known : undefined);
      if (out.unchanged) return send(res, 200, { unchanged: true, etag: out.etag });
      return send(res, 200, { data: out.data, etag: out.etag });
    }

    if (action === 'sync') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method' });
      if (session.role !== 'owner') return send(res, 403, { error: 'read_only' });
      const body = await readJson(req);
      const d = body && body.data;
      if (!d || !Array.isArray(d.bays) || d.bays.length !== BAY_COUNT || !Array.isArray(d.history)) {
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
        settings: d.settings && typeof d.settings === 'object' ? {
          eventName: String(d.settings.eventName || '').slice(0, 80),
          priceHour: Number(d.settings.priceHour) || 0,
          priceFull: Number(d.settings.priceFull) || 0,
          priceExt: Number(d.settings.priceExt) || 0
        } : {},
        bays: d.bays.map(stripPrivate),
        history: d.history.map(stripPrivate)
      };
      const json = JSON.stringify(clean);
      if (json.length > MAX_BYTES) return send(res, 413, { error: 'too_large' });
      await put(DATA_PATH, json, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/json',
        cacheControlMaxAge: 60
      });
      return send(res, 200, { ok: true, savedAt: clean.savedAt });
    }

    return send(res, 404, { error: 'unknown_action' });
  } catch (e) {
    console.error('ChargeVault API error', e);
    return send(res, e.status || 500, { error: e.status === 413 ? 'too_large' : 'server_error' });
  }
};
