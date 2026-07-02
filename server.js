import express from 'express';
import helmet from 'helmet';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import pg from 'pg';
import { getAddress, verifyMessage } from 'ethers';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'profiles.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_BYTES = 32;
const PASSWORD_ITERS = 120_000;
const DATABASE_URL = process.env.DATABASE_URL;
const ROBINHOOD_CHAIN_ID = process.env.ROBINHOOD_CHAIN_ID || '';
const ROBINHOOD_CHAIN_NAME = process.env.ROBINHOOD_CHAIN_NAME || 'Robinhood Chain';

const pool = DATABASE_URL ? new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
}) : null;

let fileDb = { users: {}, sessions: {} };
let schemaReady = false;
const walletNonces = new Map();

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
  return { id: row.id, username: row.username, walletAddress: row.wallet_address || row.walletAddress || row.data?.walletAddress || null, data: row.data || {}, updatedAt: row.updated_at || row.updatedAt || null };
}
function normalizeWalletAddress(address) {
  try { return getAddress(String(address || '').trim()); }
  catch { throw Object.assign(new Error('invalid wallet address'), { status: 400 }); }
}
function walletLoginMessage(address, nonce) {
  return `Valley Town login\nWallet: ${address}\nNonce: ${nonce}\nChain: ${ROBINHOOD_CHAIN_NAME}`;
}
function newWalletNonce(address) {
  const nonce = crypto.randomBytes(24).toString('base64url');
  walletNonces.set(address.toLowerCase(), { nonce, createdAt: Date.now() });
  return nonce;
}
function consumeWalletNonce(address, nonce) {
  const key = address.toLowerCase();
  const rec = walletNonces.get(key);
  walletNonces.delete(key);
  return !!rec && rec.nonce === nonce && Date.now() - rec.createdAt < 10 * 60_000;
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
      wallet_address TEXT UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE profiles ADD COLUMN IF NOT EXISTS wallet_address TEXT UNIQUE;
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
async function walletProfile(address, profileName) {
  await ensureSchema();
  const wallet = normalizeWalletAddress(address);
  const clean = profileName ? displayUsername(profileName) : '';
  if (pool) {
    const existing = await pool.query('SELECT id, username, wallet_address, data, updated_at FROM profiles WHERE lower(wallet_address)=lower($1)', [wallet]);
    if (existing.rows[0]) return existing.rows[0];
    if (!clean || clean.length < 3) throw Object.assign(new Error('choose a profile name to bind this wallet'), { status: 409, needProfileName: true });
    try {
      const id = newId('profile');
      const initialData = { walletAddress: wallet, auth: 'wallet', chain: ROBINHOOD_CHAIN_NAME };
      const { rows } = await pool.query(
        'INSERT INTO profiles (id, username, password_hash, wallet_address, data) VALUES ($1,$2,$3,$4,$5) RETURNING id, username, wallet_address, data, updated_at',
        [id, clean, 'wallet:' + wallet.toLowerCase(), wallet, initialData]
      );
      return rows[0];
    } catch (e) {
      if (String(e.code) === '23505') throw Object.assign(new Error('profile name or wallet already exists'), { status: 409 });
      throw e;
    }
  }
  const existing = Object.values(fileDb.users).find(u => String(u.wallet_address || u.walletAddress || '').toLowerCase() === wallet.toLowerCase());
  if (existing) return existing;
  if (!clean || clean.length < 3) throw Object.assign(new Error('choose a profile name to bind this wallet'), { status: 409, needProfileName: true });
  if (fileDb.users[clean]) throw Object.assign(new Error('profile name already exists'), { status: 409 });
  const row = { id: newId('profile'), username: clean, password_hash: 'wallet:' + wallet.toLowerCase(), wallet_address: wallet, data: { walletAddress: wallet, auth: 'wallet', chain: ROBINHOOD_CHAIN_NAME }, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  fileDb.users[clean] = row;
  await saveFileDb();
  return row;
}
async function loginWithWallet({ address, signature, nonce, profileName }) {
  const wallet = normalizeWalletAddress(address);
  if (!consumeWalletNonce(wallet, nonce)) throw Object.assign(new Error('wallet login challenge expired'), { status: 401 });
  const recovered = getAddress(verifyMessage(walletLoginMessage(wallet, nonce), signature || ''));
  if (recovered.toLowerCase() !== wallet.toLowerCase()) throw Object.assign(new Error('wallet signature did not match'), { status: 401 });
  const row = await walletProfile(wallet, profileName);
  const token = newToken();
  if (pool) await pool.query('INSERT INTO sessions (token, profile_id) VALUES ($1,$2)', [token, row.id]);
  else { fileDb.sessions[token] = { profile_id: row.id, username: row.username, createdAt: new Date().toISOString() }; await saveFileDb(); }
  return { token, profile: publicProfile(row) };
}
async function authFromToken(token) {
  await ensureSchema();
  if (!token) return null;
  if (pool) {
    const { rows } = await pool.query(
      `SELECT p.id, p.username, p.wallet_address, p.data, p.updated_at
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
    const { rows } = await pool.query('UPDATE profiles SET data=$2, updated_at=NOW() WHERE id=$1 RETURNING id, username, wallet_address, data, updated_at', [profileId, cleanData]);
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
app.get('/api/wallet-config', (_req, res) => res.json({ chainName: ROBINHOOD_CHAIN_NAME, chainId: ROBINHOOD_CHAIN_ID || null }));
app.post('/api/wallet-challenge', async (req, res, next) => {
  try {
    const address = normalizeWalletAddress(req.body.address);
    const nonce = newWalletNonce(address);
    res.json({ address, nonce, message: walletLoginMessage(address, nonce), chainName: ROBINHOOD_CHAIN_NAME, chainId: ROBINHOOD_CHAIN_ID || null });
  } catch (e) { next(e); }
});
app.post('/api/wallet-login', async (req, res, next) => {
  try { res.json(await loginWithWallet(req.body)); }
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

const MATCH_CONFIG = {
  individual: { label: 'Individual', size: 8, teams: false },
  teams: { label: 'Teams', size: 8, teams: true, teamSize: 4 },
};
const queues = { individual: [], teams: [] };
let matchSeq = 1;

function queueView(mode) {
  const cfg = MATCH_CONFIG[mode] || MATCH_CONFIG.individual;
  return { mode, label: cfg.label, count: queues[mode].length, needed: cfg.size, players: queues[mode].map((t, i) => ({ name: t.username, position: i + 1 })) };
}
function removeFromQueues(socketId) {
  let removed = false;
  for (const mode of Object.keys(queues)) {
    const before = queues[mode].length;
    queues[mode] = queues[mode].filter(t => t.socketId !== socketId);
    removed ||= queues[mode].length !== before;
  }
  if (removed) broadcastQueues();
}
function broadcastQueue(mode) {
  const view = queueView(mode);
  for (const t of queues[mode]) io.to(t.socketId).emit('queue:update', { ...view, position: queues[mode].findIndex(x => x.socketId === t.socketId) + 1 });
}
function broadcastQueues() { Object.keys(queues).forEach(broadcastQueue); }
function tryMakeMatches(mode) {
  const cfg = MATCH_CONFIG[mode] || MATCH_CONFIG.individual;
  while (queues[mode].length >= cfg.size) {
    const tickets = queues[mode].splice(0, cfg.size);
    const matchId = `match_${String(matchSeq++).padStart(5, '0')}`;
    const seed = crypto.randomInt(1, 2 ** 31 - 1);
    const roster = tickets.map((t, i) => ({
      id: t.profileId || t.socketId,
      name: t.username,
      slot: i + 1,
      team: cfg.teams ? (i < cfg.teamSize ? 'A' : 'B') : null,
    }));
    for (const t of tickets) {
      const socket = io.sockets.sockets.get(t.socketId);
      if (!socket) continue;
      socket.join(`match:${matchId}`);
      const mine = roster.find(r => r.id === (t.profileId || t.socketId));
      socket.emit('match:found', { matchId, mode, label: cfg.label, seed, roster, team: mine?.team || null, slot: mine?.slot || null, launchInMs: 3500 });
    }
    console.log(`match formed ${matchId} ${mode} players=${tickets.length}`);
  }
  broadcastQueue(mode);
}

io.on('connection', socket => {
  socket.data.username = `Raider-${socket.id.slice(0, 4)}`;
  socket.emit('hello', { t: 'hello', socketId: socket.id, note: 'Socket.IO matchmaking ready.' });
  socket.on('auth:hello', async ({ token, username } = {}) => {
    try {
      const profile = await authFromToken(token);
      socket.data.profileId = profile?.id || null;
      socket.data.username = profile?.username || displayUsername(username || socket.data.username);
      socket.emit('auth:ok', { username: socket.data.username, profileId: socket.data.profileId });
    } catch {
      socket.data.username = displayUsername(username || socket.data.username);
      socket.emit('auth:ok', { username: socket.data.username, profileId: null });
    }
  });
  socket.on('queue:join', ({ mode = 'individual' } = {}) => {
    mode = MATCH_CONFIG[mode] ? mode : 'individual';
    removeFromQueues(socket.id);
    queues[mode].push({ socketId: socket.id, profileId: socket.data.profileId || null, username: socket.data.username || `Raider-${socket.id.slice(0, 4)}`, enqueuedAt: Date.now() });
    socket.emit('queue:joined', { mode, ...queueView(mode) });
    broadcastQueue(mode);
    tryMakeMatches(mode);
  });
  socket.on('queue:leave', () => { removeFromQueues(socket.id); socket.emit('queue:left'); });
  socket.on('party:create', () => socket.emit('party:update', { id: newId('party'), code: crypto.randomBytes(3).toString('hex').toUpperCase(), members: [socket.id] }));
  socket.on('disconnect', () => removeFromQueues(socket.id));
});

const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
await ensureSchema();
httpServer.listen(port, host, () => {
  console.log(`Valley Town backend listening on http://${host}:${port} using ${pool ? 'postgres' : 'file'} store`);
});
