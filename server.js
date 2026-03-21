/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';

const port = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;
const HEARTBEAT_INTERVAL = 30000; /* 30 sec */
const MAX_FILE_SIZE = 100 * 1024 * 1024; /* 100MB */
const UPLOAD_TIMEOUT = 30000; /* 30 sec */

const rooms = new Map(); /* roomId => { peers: Set(ws), lastActive: timestamp } */
const files = new Map(); /* fileId => { path, dir, createdAt, size } */

const uploadRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'stelno-'));
try { fs.mkdirSync(uploadRoot, { recursive: true }); } catch {}

/* ─────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────── */
function isShortString(v, max = 64) {
  return typeof v === 'string' && v.length > 0 && v.length <= max;
}

function isValidSignal(v) {
  if (!v || typeof v !== 'object') return false;
  if (v.type === 'offer' || v.type === 'answer') return true;
  return typeof v.candidate === 'string' && v.candidate.length > 0;
}

function isKnownFileId(v) {
  return isShortString(v, 128) && files.has(v);
}

function validateMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return null;

  const keys = Object.keys(msg);
  if (!keys.length) return null;

  const allowed = ['join', 'signal', 'file', 'checkPeers'];
  if (!keys.every(k => allowed.includes(k))) return null;

  if (Object.prototype.hasOwnProperty.call(msg, 'join')) {
    return isShortString(msg.join, 64) ? 'join' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'signal')) {
    return isValidSignal(msg.signal) ? 'signal' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'file')) {
    return isKnownFileId(msg.file) ? 'file' : null;
  }

  if (msg.checkPeers === true) {
    return 'checkPeers';
  }

  return null;
}

function cleanupUpload(id) {
  const f = files.get(id);
  if (!f) return;
  try { fs.unlinkSync(f.path); } catch {}
  try { fs.rmSync(f.dir, { recursive: true, force: true }); } catch {}
  files.delete(id);
}

function cleanupRooms() {
  const now = Date.now();

  for (const [id, room] of rooms) {
    for (const peer of room.peers) {
      if (peer.isAlive === false) {
        peer.terminate();
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

setInterval(cleanupRooms, HEARTBEAT_INTERVAL);

setInterval(() => {
  const now = Date.now();
  for (const [id, f] of files) {
    if (now - f.createdAt > ROOM_TTL) {
      cleanupUpload(id);
    }
  }
}, HEARTBEAT_INTERVAL);

/* ─────────────────────────────────────────────
   HTTP + WS SERVER
───────────────────────────────────────────── */
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  /* ── Fallback upload ── */
  if (req.method === 'POST') {
    const id = Math.random().toString(36).slice(2);
    const dir = fs.mkdtempSync(path.join(uploadRoot, `${id}-`));
    const filePath = path.join(dir, 'upload.bin');
    const stream = fs.createWriteStream(filePath);

    let size = 0;
    let done = false;
    let timedOut = false;

    const finishOk = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      files.set(id, {
        path: filePath,
        dir,
        createdAt: Date.now(),
        size
      });
      res.end(id);
    };

    const fail = (code = 500, msg = 'Upload failed') => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { stream.destroy(); } catch {}
      try { req.destroy(); } catch {}
      try { res.writeHead(code); } catch {}
      try { res.end(msg); } catch {}
      try { fs.unlinkSync(filePath); } catch {}
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    };

    const timer = setTimeout(() => {
      timedOut = true;
      fail(408, 'Upload timeout');
    }, UPLOAD_TIMEOUT);

    req.on('data', chunk => {
      if (done) return;

      size += chunk.length;
      if (size > MAX_FILE_SIZE) {
        fail(413, 'File too large');
        try { req.destroy(new Error('File too large')); } catch {}
        return;
      }

      if (!stream.write(chunk)) {
        req.pause();
      }
    });

    stream.on('drain', () => {
      try { req.resume(); } catch {}
    });

    req.on('end', () => {
      if (done || timedOut) return;
      stream.end(() => finishOk());
    });

    req.on('aborted', () => {
      fail(499, 'Client aborted');
    });

    req.on('close', () => {
      if (!done && size > 0) {
        fail(499, 'Client closed');
      }
    });

    req.on('error', () => {
      fail();
    });

    stream.on('error', () => {
      fail();
    });

    return;
  }

  /* ── Fallback download ── */
  if (req.method === 'GET' && req.url.startsWith('/f/')) {
    const id = req.url.split('/f/')[1];
    const f = files.get(id);

    if (!f) {
      res.writeHead(404);
      res.end();
      return;
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${id}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    fs.createReadStream(f.path)
      .on('error', () => {
        try { res.end(); } catch {}
      })
      .pipe(res);

    return;
  }

  res.end('stelno alive');
});

const wss = new WebSocketServer({ server });

/* ─────────────────────────────────────────────
   CONNECTION HANDLER
───────────────────────────────────────────── */
wss.on('connection', ws => {
  let roomId = null;
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', data => {
    let msg;
    try {
      msg = JSON.parse(typeof data === 'string' ? data : data.toString());
    } catch {
      return;
    }

    const kind = validateMessage(msg);
    if (!kind) return;

    if (kind === 'join') {
      roomId = msg.join;

      if (!rooms.has(roomId)) {
        rooms.set(roomId, { peers: new Set(), lastActive: Date.now() });
      }

      const room = rooms.get(roomId);

      if (room.peers.size >= MAX_PEERS_PER_ROOM) {
        try { ws.send(JSON.stringify({ error: 'Room full' })); } catch {}
        try { ws.close(); } catch {}
        return;
      }

      room.peers.add(ws);
      room.lastActive = Date.now();

      room.peers.forEach(peer => {
        if (peer !== ws && peer.readyState === 1) {
          try { peer.send(JSON.stringify({ peerJoined: true })); } catch {}
        }
      });

      return;
    }

    if (!roomId || !rooms.has(roomId)) return;

    const room = rooms.get(roomId);
    room.lastActive = Date.now();

    if (kind === 'signal' || kind === 'file' || kind === 'checkPeers') {
      room.peers.forEach(peer => {
        if (peer !== ws && peer.readyState === 1) {
          try {
            peer.send(JSON.stringify(msg));
          } catch {}
        }
      });
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

server.listen(port, () => {
  console.log('WebSocket server running on port', port);
});
