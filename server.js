/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';

const port = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */

/* rooms */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;
const CLEANUP_INTERVAL = 1000 * 60;

/* files */
const FILE_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_FILE_SIZE = 100 * 1024 * 1024; /* 100MB */

/* ───────────────────────────────────────────── */

const rooms = {};
const files = {}; /* { id: { path, createdAt, size } } */

/* ─────────────────────────────────────────────
   HTTP SERVER
───────────────────────────────────────────── */

const server = http.createServer((req, res) => {

  /* CORS */
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  /* ── UPLOAD (fallback) ── */
  if (req.method === 'POST') {

    let size = 0;
    const id = Math.random().toString(36).slice(2);
    const path = 'tmp_' + id;

    const stream = fs.createWriteStream(path);

    req.on('data', chunk => {
      size += chunk.length;

      /* enforce max size */
      if (size > MAX_FILE_SIZE) {
        stream.destroy();
        fs.unlink(path, () => {});
        res.writeHead(413);
        return res.end('File too large');
      }
    });

    req.pipe(stream);

    stream.on('finish', () => {
      files[id] = {
        path,
        createdAt: Date.now(),
        size
      };
      res.end(id);
    });

    stream.on('error', () => {
      fs.unlink(path, () => {});
      res.writeHead(500);
      res.end('Upload failed');
    });
  }

  /* ── DOWNLOAD (fallback) ── */
  else if (req.url.startsWith('/f/')) {
    const id = req.url.split('/f/')[1];
    const file = files[id];

    if (!file) return res.end();

    fs.createReadStream(file.path)
      .on('error', () => res.end())
      .pipe(res);
  }

  else res.end('stelno alive');
});

/* ─────────────────────────────────────────────
   WEBSOCKET
───────────────────────────────────────────── */

const wss = new WebSocketServer({ server });

wss.on('connection', ws => {

  let room;

  ws.on('message', msg => {
    const d = JSON.parse(msg);

    /* ── JOIN ── */
    if (d.join) {
      room = d.join;

      if (!rooms[room]) {
        rooms[room] = {
          peers: [],
          lastActive: Date.now()
        };
      }

      const r = rooms[room];

      /* enforce 2-peer P2P */
      if (r.peers.length >= MAX_PEERS_PER_ROOM) {
        if (ws.readyState === 1)
          ws.send(JSON.stringify({ error: 'room_full' }));
        return;
      }

      if (!r.peers.includes(ws)) r.peers.push(ws);

      r.lastActive = Date.now();

      if (r.peers.length > 1) {
        r.peers.forEach(c => {
          if (c !== ws && c.readyState === 1)
            c.send(JSON.stringify({ peerJoined: true }));
        });

        if (ws.readyState === 1)
          ws.send(JSON.stringify({ roomReady: true }));
      }
    }

    /* ── SIGNAL ── */
    if (d.signal && room) {
      const r = rooms[room];
      if (!r) return;

      r.lastActive = Date.now();

      r.peers.forEach(c => {
        if (c !== ws && c.readyState === 1)
          c.send(JSON.stringify({ signal: d.signal }));
      });
    }

    /* ── FALLBACK FILE NOTIFY ── */
    if (d.file && room) {
      const r = rooms[room];
      if (!r) return;

      r.lastActive = Date.now();

      r.peers.forEach(c => {
        if (c !== ws && c.readyState === 1)
          c.send(JSON.stringify({ file: d.file }));
      });
    }

    /* ── LATE PEER DISCOVERY ── */
    if (d.checkPeers && room) {
      const r = rooms[room];
      if (!r) return;

      r.lastActive = Date.now();

      r.peers.forEach(c => {
        if (c !== ws && c.readyState === 1)
          c.send(JSON.stringify({ checkPeers: true }));
      });
    }
  });

  /* ── DISCONNECT CLEANUP ── */
  ws.on('close', () => {
    if (room && rooms[room]) {
      const r = rooms[room];

      r.peers = r.peers.filter(c => c !== ws);

      if (!r.peers.length) {
        delete rooms[room];
      } else {
        r.lastActive = Date.now();
      }
    }
  });
});

/* ─────────────────────────────────────────────
   CLEANUP LOOPS
───────────────────────────────────────────── */

/* room cleanup */
setInterval(() => {
  const now = Date.now();

  for (const id in rooms) {
    const r = rooms[id];

    /* remove dead sockets */
    r.peers = r.peers.filter(c => c.readyState === 1);

    if (!r.peers.length || (now - r.lastActive > ROOM_TTL)) {
      delete rooms[id];
    }
  }
}, CLEANUP_INTERVAL);

/* file cleanup */
setInterval(() => {
  const now = Date.now();

  for (const id in files) {
    const f = files[id];

    if (now - f.createdAt > FILE_TTL) {
      fs.unlink(f.path, () => {});
      delete files[id];
    }
  }
}, CLEANUP_INTERVAL);

/* ───────────────────────────────────────────── */

server.listen(port, () => {
  console.log(`Stelno hybrid server listening on port ${port}`);
});
