/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';
import crypto from 'crypto';
import url from 'url';

/* ─────────────────────────────────────────────
   PORT CONFIG
───────────────────────────────────────────── */
let port = parseInt(process.env.PORT, 10);
if (isNaN(port) || port <= 0 || port > 65535) port = 3000;
const httpPort = port + 1 > 65535 ? 3001 : port + 1;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;     /* 3 */
const rooms = new Map();           /* roomId => { peers: Set(ws), lastActive: timestamp } */

/* TURN server config */
const TURN_SERVER = 'turn:your.turn.server:3478'; /* replace with your TURN server */
const TURN_SECRET = 'superSecretKey';             /* long-term shared secret */

/* ─────────────────────────────────────────────
   FUNCTIONS
───────────────────────────────────────────── */

/* Validate incoming WS messages */
function validateMessage(msg) {
  if (typeof msg !== 'object' || msg === null) return false;
  const keys = Object.keys(msg);
  return keys.every(k =>
	['join', 'signal', 'file', 'checkPeers'].includes(k)
  );
}

/* Cleanup stale rooms */
function cleanupRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
	if (now - room.lastActive > ROOM_TTL || room.peers.size === 0) {
	  rooms.delete(id);
	  console.log('Deleted stale room:', id);
	}
  }
}

/* Generate ephemeral TURN credentials */
function generateTurnCredentials() {
  const ttl = 3600; /* 1 hour */
  const expiry = Math.floor(Date.now() / 1000) + ttl;
  const username = expiry + ':' + crypto.randomBytes(4).toString('hex');
  const hmac = crypto.createHmac('sha1', TURN_SECRET);
  hmac.update(username);
  const password = hmac.digest('base64');
  return { username, credential: password, ttl, urls: [TURN_SERVER] };
}

/* ─────────────────────────────────────────────
   WEBSOCKET SERVER
───────────────────────────────────────────── */
const wss = new WebSocketServer({ port });

wss.on('connection', ws => {
  let roomId = null;

  ws.on('message', data => {
	let msg;
	try { msg = JSON.parse(data); } catch { return; }
	if (!validateMessage(msg)) return;

	if (msg.join) {
	  roomId = msg.join;
	  if (!rooms.has(roomId)) rooms.set(roomId, { peers: new Set(), lastActive: Date.now() });
	  const room = rooms.get(roomId);

	  if (room.peers.size >= MAX_PEERS_PER_ROOM) {
		ws.send(JSON.stringify({ error: 'Room full' }));
		ws.close();
		return;
	  }

	  room.peers.add(ws);
	  room.lastActive = Date.now();

	  /* notify others */
	  room.peers.forEach(peer => {
		if (peer !== ws && peer.readyState === 1) peer.send(JSON.stringify({ peerJoined: true }));
	  });
	}

	if (roomId && rooms.has(roomId)) {
	  const room = rooms.get(roomId);
	  room.lastActive = Date.now();

	  /* relay signals & files */
	  if (msg.signal || msg.file || msg.checkPeers) {
		room.peers.forEach(peer => {
		  if (peer !== ws && peer.readyState === 1) {
			peer.send(JSON.stringify(msg));
		  }
		});
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
});

setInterval(cleanupRooms, 60 * 1000); /* every minute */

console.log('WebSocket server running on port', port);

/* ─────────────────────────────────────────────
   HTTP SERVER FOR TURN CREDENTIALS
───────────────────────────────────────────── */
const httpServer = http.createServer((req, res) => {
  const pathname = url.parse(req.url).pathname;

  if (pathname === '/turn-cred') {
	const creds = generateTurnCredentials();
	res.writeHead(200, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify(creds));
	return;
  }

  res.writeHead(404);
  res.end();
});

httpServer.listen(httpPort, () => {
  console.log('TURN credential server running on port', httpPort);
});
