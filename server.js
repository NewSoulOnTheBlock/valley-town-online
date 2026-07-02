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
  teams: { label: 'Teams', size: 8, teams: true, teamSize: 2, teamLabels: ['A','B','C','D'] },
};
const queues = { individual: [], teams: [] };
const queueTimers = {};
const activeMatches = new Map();
const SERVER_TICK_MS = 100;
const SERVER_EXTRACTION_MS = Number(process.env.SERVER_EXTRACTION_MS || 35_000);
const SERVER_ENEMY_DAMAGE = { drone: 10, hornet: 16, sentry: 24, stalker: 30, centipede: 54 };
const AI_RAIDER_CLASSES = ['Assault_Class','Grenadier_Class','MachineGunner_Class','RadioOperator_Class','Sniper_Class','SquadLeader'];
const QUEUE_TIMEOUT_MS = Number(process.env.QUEUE_TIMEOUT_MS || 60_000);
let matchSeq = 1;

function queueDeadline(mode) { return queues[mode][0] ? queues[mode][0].enqueuedAt + QUEUE_TIMEOUT_MS : null; }
function queueView(mode) {
  const cfg = MATCH_CONFIG[mode] || MATCH_CONFIG.individual;
  const queueEndsAt = queueDeadline(mode);
  return { mode, label: cfg.label, count: queues[mode].length, needed: cfg.size, queueEndsAt, timeoutMs: QUEUE_TIMEOUT_MS, players: queues[mode].map((t, i) => ({ name: t.username, position: i + 1 })) };
}
function removeFromQueues(socketId) {
  let removed = false;
  for (const mode of Object.keys(queues)) {
    const before = queues[mode].length;
    queues[mode] = queues[mode].filter(t => t.socketId !== socketId);
    removed ||= queues[mode].length !== before;
  }
  if (removed) { broadcastQueues(); Object.keys(queues).forEach(scheduleQueueTimer); }
}
function broadcastQueue(mode) {
  const view = queueView(mode);
  for (const t of queues[mode]) io.to(t.socketId).emit('queue:update', { ...view, position: queues[mode].findIndex(x => x.socketId === t.socketId) + 1 });
}
function broadcastQueues() { Object.keys(queues).forEach(broadcastQueue); }
function scheduleQueueTimer(mode) {
  clearTimeout(queueTimers[mode]);
  const deadline = queueDeadline(mode);
  if (!deadline) return;
  queueTimers[mode] = setTimeout(() => tryMakeMatches(mode, true), Math.max(0, deadline - Date.now()));
}
function emitMatch(mode, tickets, forcedByTimer = false) {
  const cfg = MATCH_CONFIG[mode] || MATCH_CONFIG.individual;
  const matchId = `match_${String(matchSeq++).padStart(5, '0')}`;
  const seed = crypto.randomInt(1, 2 ** 31 - 1);
  const roster = [];
  for (let i = 0; i < cfg.size; i++) {
    const t = tickets[i];
    roster.push({
      id: t ? (t.profileId || t.socketId) : `ai:${matchId}:${i + 1}`,
      name: t ? t.username : `AI Raider ${i + 1}`,
      slot: i + 1,
      team: cfg.teams ? (cfg.teamLabels?.[Math.floor(i / cfg.teamSize)] || 'A') : null,
      isAI: !t,
    });
  }
  const aiCount = roster.filter(r => r.isAI).length;
  activeMatches.set(matchId, { matchId, mode, roster, players: new Map(), enemies: new Map(), loot: new Map(), lootClaims: new Set(), revives: [], bullets: [], inventories: new Map(), extraction: { started: false, by: null, at: null, endsAt: null, complete: false }, lastTick: Date.now(), createdAt: Date.now(), tick: null, seq: 1 });
  startMatchTicker(matchId);
  for (const t of tickets) {
    const socket = io.sockets.sockets.get(t.socketId);
    if (!socket) continue;
    socket.join(`match:${matchId}`);
    socket.data.matchId = matchId;
    socket.data.matchMode = mode;
    const mine = roster.find(r => r.id === (t.profileId || t.socketId));
    socket.data.team = mine?.team || null; socket.data.slot = mine?.slot || null;
    socket.emit('match:found', { matchId, mode, label: cfg.label, seed, roster, aiCount, forcedByTimer, team: mine?.team || null, slot: mine?.slot || null, launchInMs: 3500 });
  }
  console.log(`match formed ${matchId} ${mode} humans=${tickets.length} ai=${aiCount}${forcedByTimer ? ' timer' : ''}`);
}
function tryMakeMatches(mode, forceTimer = false) {
  const cfg = MATCH_CONFIG[mode] || MATCH_CONFIG.individual;
  while (queues[mode].length >= cfg.size) emitMatch(mode, queues[mode].splice(0, cfg.size), false);
  const deadline = queueDeadline(mode);
  if (forceTimer && queues[mode].length > 0 && deadline && Date.now() >= deadline) emitMatch(mode, queues[mode].splice(0, cfg.size), true);
  broadcastQueue(mode);
  scheduleQueueTimer(mode);
}


function cleanMatch(matchId) {
  const room = io.sockets.adapter.rooms.get(`match:${matchId}`);
  if (!room || room.size === 0) { const m=activeMatches.get(matchId); if(m?.tick) clearInterval(m.tick); activeMatches.delete(matchId); }
}
function playerPayload(socket, data = {}) {
  return {
    id: socket.data.profileId || socket.id,
    socketId: socket.id,
    name: socket.data.username || `Raider-${socket.id.slice(0, 4)}`,
    team: data.team || socket.data.team || null,
    slot: data.slot || socket.data.slot || null,
    x: Number(data.x) || 0,
    y: Number(data.y) || 0,
    ang: Number(data.ang) || 0,
    hp: Number(data.hp) || 0,
    maxHp: Number(data.maxHp) || 0,
    dead: !!data.dead,
    weaponKey: String(data.weaponKey || 'pistol'),
    meds: Math.max(0, Math.min(9, Number(data.meds)||0)),
    nades: Math.max(0, Math.min(9, Number(data.nades)||0)),
    defibs: Math.max(0, Math.min(9, Number(data.defibs)||0)),
    shield: Math.max(0, Math.min(12, Number(data.shield)||0)),
    lootBagDropped: !!data.lootBagDropped,
    aiLoot: Math.max(0, Number(data.aiLoot)||0),
    interior: data.interior || null,
    raiderClass: data.raiderClass || socket.data.raiderClass || 'Assault_Class',
    isAI: !!data.isAI,
    t: Date.now(),
  };
}
function seedAiRaiders(match, anchor = {}) {
  if (!match || match.aiSeeded) return;
  const ax = Number(anchor.x) || 0, ay = Number(anchor.y) || 0;
  let n = 0;
  for (const r of match.roster || []) {
    if (!r.isAI) continue;
    const a = (Math.PI * 2 * n) / Math.max(1, (match.roster || []).filter(x => x.isAI).length);
    const d = 70 + (n % 3) * 34;
    match.players.set(r.id, {
      id: r.id, socketId: null, name: r.name || `AI Raider ${r.slot || n + 1}`,
      team: r.team || null, slot: r.slot || null, isAI: true,
      x: ax + Math.cos(a) * d, y: ay + Math.sin(a) * d,
      ang: a + Math.PI, hp: 6, maxHp: 6, dead: false, interior: null,
      weaponKey: n % 3 === 0 ? 'shotgun' : 'pistol', meds: 1, nades: n % 2, defibs: 1, shield: 0, aiLoot: 0, lootBagDropped: false,
      raiderClass: AI_RAIDER_CLASSES[n % AI_RAIDER_CLASSES.length],
      aiPhase: a, t: Date.now(),
    });
    n++;
  }
  match.aiSeeded = true;
}

function emitSnapshot(matchId) {
  const match = activeMatches.get(matchId);
  if (!match) return;
  io.to(`match:${matchId}`).emit('raid:snapshot', {
    matchId,
    serverTime: Date.now(),
    players: [...match.players.values()],
    enemies: [...match.enemies.values()],
    loot: [...(match.loot?.values() || [])],
    lootClaims: [...match.lootClaims.values()],
    bullets: match.bullets || [],
    revives: match.revives.slice(-20),
    extraction: match.extraction,
  });
}

function addServerLoot(match, loot) {
  const id = loot.id || `srvloot:${match.matchId}:${match.seq++}`;
  const obj = { ...loot, id, x: Number(loot.x)||0, y: Number(loot.y)||0 };
  match.loot.set(id, obj);
  io.to(`match:${match.matchId}`).emit('raid:lootSpawn', obj);
  return obj;
}
function dropPlayerLoot(match, player, killer = null) {
  if (!match || !player || player.lootBagDropped) return [];
  player.lootBagDropped = true;
  const drops = [];
  const x = Number(player.x)||0, y = Number(player.y)||0;
  const jitter = () => ({ x: x + (Math.random() * 52 - 26), y: y + (Math.random() * 52 - 26) });
  if (player.weaponKey && player.weaponKey !== 'pistol') drops.push(addServerLoot(match, { kind: 'weapon', weapon: player.weaponKey, ...jitter() }));
  for (let i = 0; i < Math.min(3, player.meds || 0); i++) drops.push(addServerLoot(match, { kind: 'item', item: 'medkit', val: 1, ...jitter() }));
  for (let i = 0; i < Math.min(3, player.nades || 0); i++) drops.push(addServerLoot(match, { kind: 'item', item: 'grenade', val: 1, ...jitter() }));
  for (let i = 0; i < Math.min(3, player.defibs || 0); i++) drops.push(addServerLoot(match, { kind: 'item', item: 'defib', val: 1, ...jitter() }));
  if ((player.shield || 0) > 0) drops.push(addServerLoot(match, { kind: 'item', item: 'plate', val: 1, ...jitter() }));
  if ((player.aiLoot || 0) > 0) drops.push(addServerLoot(match, { kind: 'scrap', val: Math.max(4, Math.min(80, player.aiLoot * 6)), ...jitter() }));
  io.to(`match:${match.matchId}`).emit('raid:playerKilled', { matchId: match.matchId, victim: player.id, victimName: player.name, killer, team: player.team, x, y, drops });
  return drops;
}
function segDist2(px, py, ax, ay, bx, by) {
  const vx = bx - ax, vy = by - ay, wx = px - ax, wy = py - ay;
  const c = vx * vx + vy * vy || 1;
  const t = Math.max(0, Math.min(1, (wx * vx + wy * vy) / c));
  const x = ax + vx * t, y = ay + vy * t;
  return (px - x) ** 2 + (py - y) ** 2;
}
function damageServerPlayer(match, player, amount, source) {
  if (!match || !player || player.dead) return;
  const dmg = Math.max(1, Math.min(20, Number(amount)||1));
  if ((player.shield || 0) > 0) player.shield = Math.max(0, player.shield - dmg);
  else player.hp = Math.max(0, (Number(player.hp)||0) - dmg);
  player.lastDamageAt = Date.now(); player.lastDamageSource = source || null;
  if (player.hp <= 0) { player.dead = true; dropPlayerLoot(match, player, source); }
}

function serverLoot(match, x, y) {
  return addServerLoot(match, { kind: 'scrap', val: 4 + Math.floor(Math.random() * 14), x, y });
}
function startMatchTicker(matchId) {
  const match = activeMatches.get(matchId);
  if (!match || match.tick) return;
  match.tick = setInterval(() => tickMatch(matchId), SERVER_TICK_MS);
}
function tickMatch(matchId) {
  const match = activeMatches.get(matchId);
  if (!match) return;
  const now = Date.now();
  const dt = Math.min(0.25, (now - (match.lastTick || now)) / 1000);
  match.lastTick = now;
  const alivePlayers = [...match.players.values()].filter(p => !p.dead);
  const humanPlayers = alivePlayers.filter(p => !p.isAI);
  for (const ai of alivePlayers.filter(p => p.isAI)) {
    let targetEnemy = null, bestEnemy = Infinity;
    for (const e of match.enemies.values()) {
      if (e.dead || e.hp <= 0) continue;
      const d2 = (e.x-ai.x)**2 + (e.y-ai.y)**2;
      if (d2 < bestEnemy) { bestEnemy = d2; targetEnemy = e; }
    }
    let targetLoot = null, bestLoot = Infinity;
    for (const l of match.loot.values()) {
      const d2 = (l.x-ai.x)**2 + (l.y-ai.y)**2;
      if (d2 < bestLoot) { bestLoot = d2; targetLoot = l; }
    }
    const follow = humanPlayers.find(p => !ai.team || p.team === ai.team) || humanPlayers[0];
    let tx = ai.x, ty = ai.y;
    if (targetLoot && bestLoot < 420*420) { tx = targetLoot.x; ty = targetLoot.y; }
    else if (targetEnemy && bestEnemy < 760*760) { tx = targetEnemy.x; ty = targetEnemy.y; }
    else if (follow) {
      const desired = 180 + ((ai.slot || 1) % 4) * 34;
      const phase = (ai.aiPhase || 0) + now / 1500;
      tx = follow.x + Math.cos(phase) * desired; ty = follow.y + Math.sin(phase) * desired;
    }
    const dx = tx - ai.x, dy = ty - ai.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
    const stop = targetEnemy && bestEnemy < 360*360 ? 220 : 18;
    if (d > stop) { const sp = 102; ai.x += (dx / d) * sp * dt; ai.y += (dy / d) * sp * dt; ai.ang = Math.atan2(dy, dx); ai.t = now; }
    if (targetEnemy && bestEnemy < 620*620 && now - (ai.lastShot || 0) > 700) {
      ai.lastShot = now; ai.ang = Math.atan2(targetEnemy.y-ai.y, targetEnemy.x-ai.x);
      const sp = 520;
      const bullet = { id: `srvb:${matchId}:${match.seq++}`, owner: ai.id, x: ai.x, y: ai.y, vx: Math.cos(ai.ang)*sp, vy: Math.sin(ai.ang)*sp, t: 1.2, dmg: 3, pierce: 0, hit: [], ai: true };
      match.bullets.push(bullet);
      io.to(`match:${matchId}`).emit('raid:bullet', { matchId, from: ai.id, bullets: [bullet], serverTime: now });
    }
    if (targetLoot && bestLoot < 28*28) { match.loot.delete(targetLoot.id); match.lootClaims.add(targetLoot.id); ai.aiLoot = (ai.aiLoot || 0) + 1; io.to(`match:${matchId}`).emit('raid:lootClaim', { matchId, lootId: targetLoot.id, by: ai.name, from: ai.id }); }
    if (!match.extraction.started && (ai.aiLoot || 0) >= 2 && now - (match.createdAt || 0) > 12000) match.extraction = { started: true, by: ai.id, at: now, endsAt: now + SERVER_EXTRACTION_MS, complete: false, x: ai.x, y: ai.y };
  }
  for (const e of match.enemies.values()) {
    if (e.dead || e.hp <= 0 || !alivePlayers.length) continue;
    let target = alivePlayers[0], best = Infinity;
    for (const p of alivePlayers) { const d = (p.x-e.x)**2 + (p.y-e.y)**2; if (d < best) { best = d; target = p; } }
    const d = Math.sqrt(best) || 1, speed = Number(e.speed) || 45;
    if (d > 38 && d < 900) { e.x += ((target.x-e.x)/d)*speed*dt; e.y += ((target.y-e.y)/d)*speed*dt; e.serverTime = now; }
    if (d < (Number(e.r)||18) + 14 && now - (target.lastMobDamage || 0) > 900) { target.lastMobDamage = now; damageServerPlayer(match, target, e.contactDamage || 1, { type: 'mob', enemyId: e.id }); }
    if ((e.type === 'hornet' || e.type === 'sentry' || e.type === 'stalker' || e.type === 'centipede') && d < 560 && now - (e.lastServerShot || 0) > 1200) { e.lastServerShot = now; damageServerPlayer(match, target, e.shotDamage || 1, { type: 'mob-shot', enemyId: e.id }); }
  }
  for (const b of match.bullets) {
    if (b.dead) continue;
    const ox = b.x, oy = b.y;
    b.x += b.vx * dt; b.y += b.vy * dt; b.t -= dt;
    if (b.t <= 0 || b.x < 0 || b.y < 0 || b.x > 14000 || b.y > 14000) { b.dead = true; continue; }
    for (const e of match.enemies.values()) {
      if (e.dead || e.hp <= 0 || b.hit?.includes(e.id)) continue;
      const r = Number(e.r) || 18;
      if (segDist2(e.x,e.y,ox,oy,b.x,b.y) <= (r+6)*(r+6)) {
        b.hit = b.hit || []; b.hit.push(e.id);
        e.hp = Math.max(0, Number(e.hp || SERVER_ENEMY_DAMAGE[e.type] || 20) - Math.min(80, Number(b.dmg) || 1));
        e.serverTime = now;
        if (e.hp <= 0) { e.dead = true; const loot = serverLoot(match, e.x, e.y); io.to(`match:${matchId}`).emit('raid:lootSpawn', loot); }
        if (!b.pierce || b.hit.length > b.pierce) b.dead = true;
        break;
      }
    }
      if (!b.dead) {
      const owner = match.players.get(b.owner);
      for (const p of match.players.values()) {
        if (p.dead || p.id === b.owner || b.hit?.includes(p.id)) continue;
        if (match.mode === 'teams' && owner?.team && p.team && owner.team === p.team) continue;
        if (segDist2(p.x,p.y,ox,oy,b.x,b.y) <= (18+6)*(18+6)) {
          b.hit = b.hit || []; b.hit.push(p.id);
          damageServerPlayer(match, p, Math.max(1, Math.min(10, Number(b.dmg)||1)), { type: 'pvp', attacker: b.owner, attackerName: owner?.name || 'Raider' });
          io.to(`match:${matchId}`).emit('raid:playerHit', { matchId, victim: p.id, attacker: b.owner, hp: p.hp, shield: p.shield || 0, dead: p.dead, x: p.x, y: p.y });
          if (!b.pierce || b.hit.length > b.pierce) b.dead = true;
          break;
        }
      }
    }
  }
  match.bullets = match.bullets.filter(b => !b.dead);
  if (match.extraction.started && !match.extraction.complete) {
    const remainMs = Math.max(0, match.extraction.endsAt - now);
    io.to(`match:${matchId}`).emit('raid:extractUpdate', { matchId, remainingMs: remainMs, extraction: match.extraction });
    if (remainMs <= 0) { match.extraction.complete = true; io.to(`match:${matchId}`).emit('raid:extractComplete', { matchId, extraction: match.extraction }); }
  }
  io.to(`match:${matchId}`).emit('raid:serverTick', { matchId, serverTime: now, players: [...match.players.values()], enemies: [...match.enemies.values()], bullets: match.bullets, loot: [...match.loot.values()], extraction: match.extraction });
}
function sanitizeEnemy(e) { return { id: String(e.id || `enemy:${Math.random()}`), type: String(e.type || 'drone'), x: Number(e.x)||0, y: Number(e.y)||0, r: Number(e.r)||18, hp: Math.max(0, Number(e.hp)||SERVER_ENEMY_DAMAGE[e.type]||20), speed: Math.min(160, Number(e.speed)||45), dead: !!e.dead, serverTime: Date.now() }; }
function sanitizeLoot(l) { return { id: String(l.id || `loot:${Math.random()}`), kind: String(l.kind || 'scrap'), x: Number(l.x)||0, y: Number(l.y)||0, val: Math.max(1, Math.min(999, Number(l.val)||1)), ammo: l.ammo || null, mat: l.mat || null, weapon: l.weapon || null, blueprint: l.blueprint || null, item: l.item || null }; }
function relayAuthoritative(socket, event, payload = {}) {
  const matchId = socket.data.matchId;
  if (!matchId || payload.matchId !== matchId) return;
  const match = activeMatches.get(matchId);
  if (!match) return;
  const from = socket.data.profileId || socket.id;
  const data = { ...payload, from, by: socket.data.username, serverTime: Date.now() };
  if (event === 'raid:enemyHit') {
    const id = String(payload.enemyId || '');
    const e = id ? (match.enemies.get(id) || sanitizeEnemy(payload)) : null;
    if (e) {
      const dmg = Math.max(0, Math.min(80, Number(payload.damage ?? payload.dmg ?? 1)));
      e.hp = Math.max(0, Number(e.hp || SERVER_ENEMY_DAMAGE[e.type] || 20) - dmg);
      e.x = Number(payload.x) || e.x; e.y = Number(payload.y) || e.y; e.dead = e.hp <= 0 || !!payload.dead; e.serverTime = Date.now();
      match.enemies.set(id, e); data.hp = e.hp; data.dead = e.dead;
      if (e.dead) data.loot = serverLoot(match, e.x, e.y);
    }
  }
  if (event === 'raid:lootClaim' && payload.lootId) {
    const id = String(payload.lootId);
    if (match.lootClaims.has(id)) return;
    match.lootClaims.add(id);
    match.loot?.delete(id);
  }
  if (event === 'raid:revive') match.revives.push(data);
  if (event === 'raid:extract' && !match.extraction.started) match.extraction = { started: true, by: from, at: Date.now(), endsAt: Date.now() + SERVER_EXTRACTION_MS, complete: false, x: Number(payload.x)||0, y: Number(payload.y)||0 };
  socket.to(`match:${matchId}`).emit(event, data);
  emitSnapshot(matchId);
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
    scheduleQueueTimer(mode);
  });
  socket.on('queue:leave', () => { removeFromQueues(socket.id); socket.emit('queue:left'); });
  socket.on('raid:seedState', (data = {}) => {
    const matchId = socket.data.matchId;
    if (!matchId || data.matchId !== matchId) return;
    const match = activeMatches.get(matchId);
    if (!match || match.seeded) return;
    for (const e of (data.enemies || []).slice(0, 260).map(sanitizeEnemy)) match.enemies.set(e.id, e);
    for (const l of (data.loot || []).slice(0, 600).map(sanitizeLoot)) match.loot.set(l.id, l);
    match.seeded = true;
    emitSnapshot(matchId);
  });
  socket.on('raid:ready', (data = {}) => {
    const matchId = socket.data.matchId;
    if (!matchId || data.matchId !== matchId) return;
    const match = activeMatches.get(matchId);
    if (!match) return;
    match.players.set(socket.data.profileId || socket.id, playerPayload(socket, data));
    seedAiRaiders(match, data);
    match.inventories.set(socket.data.profileId || socket.id, { ammo: {}, lastFire: 0 });
    emitSnapshot(matchId);
  });
  socket.on('raid:update', (data = {}) => {
    const matchId = socket.data.matchId;
    if (!matchId || data.matchId !== matchId) return;
    const match = activeMatches.get(matchId);
    if (!match) return;
    const player = playerPayload(socket, data);
    const old = match.players.get(player.id);
    if (old) { player.hp = Math.min(Number(player.hp)||0, Number(old.hp)||player.hp); player.shield = Math.min(Number(player.shield)||0, Number(old.shield)||player.shield); player.dead = old.dead || player.dead; player.lootBagDropped = old.lootBagDropped || player.lootBagDropped; player.aiLoot = old.aiLoot || player.aiLoot; }
    match.players.set(player.id, player);
    seedAiRaiders(match, data);
    socket.to(`match:${matchId}`).emit('raid:peer', player);
    emitSnapshot(matchId);
  });
  socket.on('raid:fire', (data = {}) => {
    const matchId = socket.data.matchId;
    if (!matchId || data.matchId !== matchId) return;
    const match = activeMatches.get(matchId); if (!match) return;
    const id = socket.data.profileId || socket.id;
    const inv = match.inventories.get(id) || { ammo: {}, lastFire: 0 };
    const now = Date.now(); if (now - inv.lastFire < 35) return;
    inv.lastFire = now; inv.ammo = {}; match.inventories.set(id, inv);
    const bullets = (data.bullets || []).slice(0, 12).map((b, i) => ({ id: `srvb:${matchId}:${match.seq++}`, owner: id, x: Number(b.x)||0, y: Number(b.y)||0, vx: Math.max(-1800, Math.min(1800, Number(b.vx)||0)), vy: Math.max(-1800, Math.min(1800, Number(b.vy)||0)), t: Math.max(.05, Math.min(2.5, Number(b.t)||.8)), dmg: Math.max(1, Math.min(80, Number(b.dmg)||1)), pierce: Math.max(0, Math.min(8, Number(b.pierce)||0)), hit: [] }));
    match.bullets.push(...bullets);
    io.to(`match:${matchId}`).emit('raid:bullet', { matchId, from: id, bullets, serverTime: now });
  });
  socket.on('raid:bullet', data => relayAuthoritative(socket, 'raid:bullet', data));
  socket.on('raid:enemyHit', data => relayAuthoritative(socket, 'raid:enemyHit', data));
  socket.on('raid:lootClaim', data => relayAuthoritative(socket, 'raid:lootClaim', data));
  socket.on('raid:revive', data => relayAuthoritative(socket, 'raid:revive', data));
  socket.on('raid:extract', data => relayAuthoritative(socket, 'raid:extract', data));
  socket.on('party:create', () => socket.emit('party:update', { id: newId('party'), code: crypto.randomBytes(3).toString('hex').toUpperCase(), members: [socket.id] }));
  socket.on('disconnect', () => { if (socket.data.matchId) { const id = socket.data.profileId || socket.id; const match = activeMatches.get(socket.data.matchId); if (match) match.players.delete(id); socket.to(`match:${socket.data.matchId}`).emit('raid:left', { id }); emitSnapshot(socket.data.matchId); cleanMatch(socket.data.matchId); } removeFromQueues(socket.id); });
});

const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
await ensureSchema();
httpServer.listen(port, host, () => {
  console.log(`Valley Town backend listening on http://${host}:${port} using ${pool ? 'postgres' : 'file'} store`);
});
