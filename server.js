/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { promisify } from 'util';

const port = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;
const HEARTBEAT_INTERVAL = 30000; /* 30 sec */
const MAX_FILE_SIZE = 100 * 1024 * 1024; /* 100MB */
const UPLOAD_TIMEOUT = 30000; /* 30 sec */
const SHUTDOWN_TIMEOUT = 5000; /* 5 sec */

const ID_RE = /^[a-z0-9_-]{1,64}$/i;
const FILE_ID_RE = /^[a-f0-9]{32}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const SAFE_UPLOAD_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'stelno-'));

const rooms = new Map(); /* roomId => { peers: Set(ws), lastActive: timestamp } */
const files = new Map(); /* fileId => { path, dir, createdAt, size, sha256, name, mime } */
const sockets = new Set();

let shuttingDown = false;

/* ─────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────── */
function makeId() {
  return crypto.randomBytes(16).toString('hex');
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function isShortString(v, max = 64) {
  return typeof v === 'string' && v.length > 0 && v.length <= max;
}

function isValidRoomId(v) {
  return isShortString(v, 64) && ID_RE.test(v);
}

function isValidFileId(v) {
  return isShortString(v, 64) && FILE_ID_RE.test(v) && files.has(v);
}

function isValidSha256(v) {
  return isShortString(v, 64) && SHA256_RE.test(v);
}

function safeHeaderString(v) {
  return typeof v === 'string' ? v : '';
}

function safeFileName(v, fallback = 'upload.bin') {
  const s = isShortString(v, 255) ? v : fallback;
  const b = path.basename(s).replace(/[^\w.\-()+\s]/g, '_').replace(/\s+/g, ' ').trim();
  return b || fallback;
}

function isInsideRoot(p) {
  const rel = path.relative(SAFE_UPLOAD_ROOT, p);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function normalizeSignal(v) {
  /* normalize candidate object to remove extra keys */
  if (v.type === 'candidate') {
	return {
	  type: 'candidate',
	  candidate: v.candidate,
	  sdpMid: typeof v.sdpMid === 'string' ? v.sdpMid : undefined,
	  sdpMLineIndex: typeof v.sdpMLineIndex === 'number' ? v.sdpMLineIndex : undefined,
	  usernameFragment: typeof v.usernameFragment === 'string' ? v.usernameFragment : undefined
	};
  }
  return v;
}

function isValidSignal(v) {
  if (!isPlainObject(v)) return false;

  if (v.type === 'offer' || v.type === 'answer') {
	return Object.keys(v).length === 2 && typeof v.sdp === 'string' && v.sdp.length > 0;
  }

  if (v.type === 'candidate') {
	const keys = Object.keys(v);
	if (!keys.every(k => ['type', 'candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment'].includes(k))) return false;
	if (typeof v.candidate !== 'string' || v.candidate.length === 0) return false;
	if (Object.prototype.hasOwnProperty.call(v, 'sdpMid') && typeof v.sdpMid !== 'string') return false;
	if (Object.prototype.hasOwnProperty.call(v, 'sdpMLineIndex') && typeof v.sdpMLineIndex !== 'number') return false;
	if (Object.prototype.hasOwnProperty.call(v, 'usernameFragment') && typeof v.usernameFragment !== 'string') return false;
	return true;
  }

  return false;
}

function validateMessage(msg) {
  if (!isPlainObject(msg)) return null;

  const keys = Object.keys(msg);
  if (!keys.length) return null;

  if (Object.prototype.hasOwnProperty.call(msg, 'join')) {
	if (!keys.every(k => k === 'join' || k === 'token')) return null;
	if (!isValidRoomId(msg.join)) return null;
	if (Object.prototype.hasOwnProperty.call(msg, 'token') && !isShortString(msg.token, 256)) return null;
	return 'join';
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'signal')) {
	if (keys.length !== 1) return null;
	return isValidSignal(msg.signal) ? 'signal' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'file')) {
	if (keys.length !== 1) return null;
	return isValidFileId(msg.file) ? 'file' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'checkPeers')) {
	if (keys.length !== 1) return null;
	return msg.checkPeers === true ? 'checkPeers' : null;
  }

  return null;
}

/* ── ASYNC FILE HELPERS ── */
async function safeUnlinkAsync(p) {
  try { await fs.promises.unlink(p); } catch {}
}

async function safeRmAsync(d) {
  try { await fs.promises.rm(d, { recursive: true, force: true }); } catch {}
}

async function cleanupUploadAsync(id) {
  const f = files.get(id);
  if (!f) return;
  await safeUnlinkAsync(f.path);
  await safeRmAsync(f.dir);
  files.delete(id);
}

/* ── ROOM / FILE CLEANUP ── */
async function cleanupRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
	for (const peer of room.peers) {
	  if (!peer.isAlive) {
		try { peer.terminate(); } catch {}
		room.peers.delete(peer);
	  } else {
		peer.isAlive = false;
		try { peer.ping(); } catch {}
	  }
	}
	if (now - room.lastActive > ROOM_TTL || room.peers.size === 0) {
	  rooms.delete(id);
	  console.log('Deleted stale room:', id);
	}
  }
}

async function cleanupFiles() {
  const now = Date.now();
  for (const [id, f] of files) {
	if (now - f.createdAt > ROOM_TTL) await cleanupUploadAsync(id);
  }
}

/* ── SHUTDOWN ── */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`Received ${signal}, shutting down...`);

  try { server.close(); } catch {}
  try { wss.close(); } catch {}

  for (const ws of wss.clients) {
	try { ws.close(1001, 'Server shutting down'); } catch {}
  }

  setTimeout(async () => {
	for (const ws of wss.clients) {
	  try { ws.terminate(); } catch {}
	}
	for (const s of sockets) {
	  try { s.destroy(); } catch {}
	}
	for (const id of files.keys()) await cleanupUploadAsync(id);
	rooms.clear();

	try { process.exit(0); } catch {}
  }, SHUTDOWN_TIMEOUT).unref();
}

setInterval(cleanupRooms, HEARTBEAT_INTERVAL).unref();
setInterval(cleanupFiles, HEARTBEAT_INTERVAL).unref();
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

/* ─────────────────────────────────────────────
   HTTP + WS SERVER
───────────────────────────────────────────── */
const server = http.createServer(async (req, res) => {
  if (shuttingDown) {
	res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
	res.end('Server shutting down');
	return;
  }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-File-Name, X-File-Mime, X-File-Size, X-File-Sha256');

  if (req.method === 'OPTIONS') {
	res.writeHead(204);
	res.end();
	return;
  }

  /* ── ASYNC UPLOAD ── */
  if (req.method === 'POST') {
	const id = makeId();
	const dir = await fs.promises.mkdtemp(path.join(SAFE_UPLOAD_ROOT, `${id}-`));
	const filePath = path.join(dir, 'upload.bin');
	const stream = fs.createWriteStream(filePath, { flags: 'w' });

	const expectedName = safeFileName(safeHeaderString(req.headers['x-file-name']) || 'upload.bin');
	const expectedMime = safeHeaderString(req.headers['x-file-mime']) || safeHeaderString(req.headers['content-type']) || 'application/octet-stream';
	const expectedSizeRaw = safeHeaderString(req.headers['x-file-size']);
	const expectedSize = expectedSizeRaw && /^[0-9]+$/.test(expectedSizeRaw) ? Number(expectedSizeRaw) : null;
	const expectedHashRaw = safeHeaderString(req.headers['x-file-sha256']).toLowerCase();
	const expectedHash = expectedHashRaw && isValidSha256(expectedHashRaw) ? expectedHashRaw : null;

	const hash = crypto.createHash('sha256');
	let size = 0;
	let done = false;

	const cleanup = async () => {
	  try { stream.destroy(); } catch {}
	  try { req.destroy(); } catch {}
	  await safeUnlinkAsync(filePath);
	  await safeRmAsync(dir);
	};

	const finishOk = async () => {
	  if (done) return;
	  done = true;
	  clearTimeout(timer);

	  const actualHash = hash.digest('hex');

	  if (expectedHash && expectedHash !== actualHash) {
		await cleanup();
		if (!res.headersSent) { res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Hash mismatch'); }
		return;
	  }

	  if (expectedSize !== null && size !== expectedSize) {
		await cleanup();
		if (!res.headersSent) { res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Size mismatch'); }
		return;
	  }

	  files.set(id, {
		path: filePath,
		dir,
		createdAt: Date.now(),
		size,
		sha256: actualHash,
		name: expectedName,
		mime: expectedMime
	  });

	  if (!res.headersSent) { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(id); }
	};

	const fail = async (code = 500, msg = 'Upload failed') => {
	  if (done) return;
	  done = true;
	  clearTimeout(timer);
	  await cleanup();
	  if (!res.headersSent) { res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(msg); }
	};

	const timer = setTimeout(() => { fail(408, 'Upload timeout'); }, UPLOAD_TIMEOUT);
	timer.unref();

	req.setTimeout(UPLOAD_TIMEOUT, () => { fail(408, 'Upload timeout'); });

	const len = Number(req.headers['content-length'] || 0);
	if (len && len > MAX_FILE_SIZE) { await fail(413, 'File too large'); return; }

	req.on('data', chunk => {
	  if (done) return;

	  size += chunk.length;
	  if (size > MAX_FILE_SIZE) { fail(413, 'File too large'); return; }

	  hash.update(chunk);
	  if (!stream.write(chunk)) req.pause();
	});

	stream.on('drain', () => { if (!done) req.resume(); });

	req.on('end', () => { if (!done) stream.end(() => finishOk()); });
	req.on('aborted', () => { fail(499, 'Client aborted'); });
	req.on('close', () => { if (!done && size > 0) fail(499, 'Client closed'); });
	req.on('error', () => { fail(); });
	stream.on('error', () => { fail(); });

	return;
  }

  /* ── ASYNC DOWNLOAD ── */
  if (req.method === 'GET' && req.url.startsWith('/f/')) {
	const id = req.url.slice(3).split('?')[0].split('#')[0];
	const f = files.get(id);

	if (!f || !fs.existsSync(f.path) || !isInsideRoot(f.path)) {
	  res.writeHead(404); res.end(); return;
	}

	res.setHeader('Content-Type', f.mime || 'application/octet-stream');
	res.setHeader('Content-Disposition', `attachment; filename="${safeFileName(f.name, id)}"`);
	res.setHeader('Cache-Control', 'no-store');
	res.setHeader('X-Content-Type-Options', 'nosniff');
	res.setHeader('X-File-Sha256', f.sha256 || '');

	const s = fs.createReadStream(f.path);
	s.on('error', () => { try { res.destroy(); } catch {} });
	s.pipe(res);
	return;
  }

  res.end('stelno alive');
});

server.on('connection', socket => {
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {}
});

/* ─────────────────────────────────────────────
   WEBSOCKET SERVER
───────────────────────────────────────────── */
const wss = new WebSocketServer({ server, maxPayload: 128 * 1024 });

/* ── CONNECTION HANDLER ── */
wss.on('connection', ws => {
  if (shuttingDown) { try { ws.close(1001, 'Server shutting down'); } catch {} return; }

  let roomId = null;
  ws.isAlive = true;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', data => {
	if (shuttingDown) return;

	const raw = typeof data === 'string' ? data : data.toString();
	if (raw.length > 128 * 1024) return;

	let msg;
	try { msg = JSON.parse(raw); } catch { return; }

	const kind = validateMessage(msg);
	if (!kind) return;

	if (kind === 'join') {
	  roomId = msg.join;
	  if (!rooms.has(roomId)) rooms.set(roomId, { peers: new Set(), lastActive: Date.now() });
	  const room = rooms.get(roomId);

	  if (room.peers.size >= MAX_PEERS_PER_ROOM) {
		try { ws.send(JSON.stringify({ error: 'Room full' })); } catch {}
		try { ws.close(); } catch {}
		return;
	  }

	  room.peers.add(ws);
	  room.lastActive = Date.now();

	  for (const peer of room.peers) {
		if (peer !== ws && peer.readyState === 1) try { peer.send(JSON.stringify({ peerJoined: true })); } catch {}
	  }

	  return;
	}

	if (!roomId || !rooms.has(roomId)) return;

	const room = rooms.get(roomId);
	room.lastActive = Date.now();

	if (kind === 'signal' || kind === 'file' || kind === 'checkPeers') {
	  const normalizedMsg = kind === 'signal' ? { signal: normalizeSignal(msg.signal) } : msg;
	  for (const peer of room.peers) {
		if (peer !== ws && peer.readyState === 1) try { peer.send(JSON.stringify(normalizedMsg)); } catch {}
	  }
	}
  });

  ws.on('close', () => {
	if (!roomId) return;
	const room = rooms.get(roomId);
	if (!room) return;

	room.peers.delete(ws);
	room.lastActive = Date.now();
	if (room.peers.size === 0) rooms.delete(roomId);
  });

  ws.on('error', () => {});
});

server.listen(port, () => { console.log('WebSocket server running on port', port); });
