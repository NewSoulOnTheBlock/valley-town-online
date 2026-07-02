import express from 'express';
import helmet from 'helmet';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import pg from 'pg';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'profiles.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_BYTES = 32;
const PASSWORD_ITERS = 120_000;
const DATABASE_URL = process.env.DATABASE_URL;

const pool = DATABASE_URL ? new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
}) : null;

let fileDb = { users: {}, sessions: {} };
let schemaReady = false;

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 24);
}
function displayUsername(username) {
  const cleaned = normalizeUsername(username);
  return cleaned || 'raider';
}
function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(10).toString('hex')}`;
}
function newToken() {
  return crypto.randomBytes(SESSION_BYTES).toString('base64url');
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('base64url')) {
  const hash = crypto.pbkdf2Sync(String(password), salt, PASSWORD_ITERS, 32, 'sha256').toString('base64url');
  return `${PASSWORD_ITERS}:${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [iters, salt, hash] = String(stored || '').split(':');
  if (!iters || !salt || !hash) return false;
  const got = crypto.pbkdf2Sync(String(password), salt, Number(iters), 32, 'sha256').toString('base64url');
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(hash));
}
function publicProfile(row) {
  return { id: row.id, username: row.username, data: row.data || {}, updatedAt: row.updated_at || row.updatedAt || null };
}

async function loadFileDb() {
  if (pool) return;
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    fileDb = JSON.parse(raw);
    fileDb.users ||= {};
    fileDb.sessions ||= {};
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await saveFileDb();
  }
}
async function saveFileDb() {
  if (pool) return;
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(DATA_FILE, JSON.stringify(fileDb, null, 2));
}
async function ensureSchema() {
  if (schemaReady) return;
  if (!pool) { await loadFileDb(); schemaReady = true; return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS profiles (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  schemaReady = true;
}
async function createProfile(username, password) {
  await ensureSchema();
  const clean = displayUsername(username);
  if (clean.length < 3) throw Object.assign(new Error('name must be at least 3 characters'), { status: 400 });
  if (String(password || '').length < 4) throw Object.assign(new Error('password must be at least 4 characters'), { status: 400 });
  const id = newId('profile');
  const passwordHash = hashPassword(password);
  const initialData = {};
  if (pool) {
    try {
      const { rows } = await pool.query(
        'INSERT INTO profiles (id, username, password_hash, data) VALUES ($1,$2,$3,$4) RETURNING id, username, data, updated_at',
        [id, clean, passwordHash, initialData]
      );
      return rows[0];
    } catch (e) {
      if (String(e.code) === '23505') throw Object.assign(new Error('profile name already exists'), { status: 409 });
      throw e;
    }
  }
  if (fileDb.users[clean]) throw Object.assign(new Error('profile name already exists'), { status: 409 });
  const row = { id, username: clean, password_hash: passwordHash, data: initialData, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  fileDb.users[clean] = row;
  await saveFileDb();
  return row;
}
async function loginProfile(username, password) {
  await ensureSchema();
  const clean = displayUsername(username);
  let row;
  if (pool) {
    const out = await pool.query('SELECT id, username, password_hash, data, updated_at FROM profiles WHERE username=$1', [clean]);
    row = out.rows[0];
  } else row = fileDb.users[clean];
  if (!row || !verifyPassword(password, row.password_hash)) throw Object.assign(new Error('invalid name or password'), { status: 401 });
  const token = newToken();
  if (pool) await pool.query('INSERT INTO sessions (token, profile_id) VALUES ($1,$2)', [token, row.id]);
  else { fileDb.sessions[token] = { profile_id: row.id, username: clean, createdAt: new Date().toISOString() }; await saveFileDb(); }
  return { token, profile: publicProfile(row) };
}
async function authFromToken(token) {
  await ensureSchema();
  if (!token) return null;
  if (pool) {
    const { rows } = await pool.query(
      `SELECT p.id, p.username, p.data, p.updated_at
       FROM sessions s JOIN profiles p ON p.id=s.profile_id
       WHERE s.token=$1`, [token]
    );
    if (!rows[0]) return null;
    await pool.query('UPDATE sessions SET last_seen=NOW() WHERE token=$1', [token]);
    return rows[0];
  }
  const session = fileDb.sessions[token];
  if (!session) return null;
  return Object.values(fileDb.users).find(u => u.id === session.profile_id) || null;
}
async function saveProfileData(profileId, data) {
  await ensureSchema();
  const cleanData = data && typeof data === 'object' ? data : {};
  if (pool) {
    const { rows } = await pool.query('UPDATE profiles SET data=$2, updated_at=NOW() WHERE id=$1 RETURNING id, username, data, updated_at', [profileId, cleanData]);
    return rows[0];
  }
  const user = Object.values(fileDb.users).find(u => u.id === profileId);
  if (!user) throw Object.assign(new Error('profile not found'), { status: 404 });
  user.data = cleanData;
  user.updatedAt = new Date().toISOString();
  await saveFileDb();
  return user;
}

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));

async function requireAuth(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const profile = await authFromToken(token);
    if (!profile) return res.status(401).json({ error: 'unauthorized' });
    req.profile = profile;
    next();
  } catch (e) { next(e); }
}

app.get('/api/health', async (_req, res, next) => {
  try { await ensureSchema(); res.json({ ok: true, store: pool ? 'postgres' : 'file' }); }
  catch (e) { next(e); }
});
app.post('/api/register', async (req, res, next) => {
  try {
    const profile = await createProfile(req.body.username, req.body.password);
    const out = await loginProfile(req.body.username, req.body.password);
    out.profile = publicProfile(profile);
    res.status(201).json(out);
  } catch (e) { next(e); }
});
app.post('/api/login', async (req, res, next) => {
  try { res.json(await loginProfile(req.body.username, req.body.password)); }
  catch (e) { next(e); }
});
app.get('/api/profile', requireAuth, (req, res) => res.json({ profile: publicProfile(req.profile) }));
app.put('/api/profile', requireAuth, async (req, res, next) => {
  try { res.json({ profile: publicProfile(await saveProfileData(req.profile.id, req.body.data)) }); }
  catch (e) { next(e); }
});

app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: err.message || 'server error' });
});

const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, { cors: { origin: true } });
io.on('connection', socket => {
  socket.emit('hello', { t: 'hello', socketId: socket.id, note: 'Lobby/matchmaking transport placeholder ready.' });
  socket.on('party:create', () => socket.emit('party:update', { id: newId('party'), code: crypto.randomBytes(3).toString('hex').toUpperCase(), members: [socket.id] }));
});

const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
await ensureSchema();
httpServer.listen(port, host, () => {
  console.log(`Valley Town backend listening on http://${host}:${port} using ${pool ? 'postgres' : 'file'} store`);
});
