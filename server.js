/* hybrid server: signaling + temp file relay */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';

const port = process.env.PORT || 3000;
const rooms = {};
const files = {};

const server = http.createServer((req, res) => {
  /* fallback upload */
  if (req.method === 'POST') {
    const id = Math.random().toString(36).slice(2);
    const path = 'tmp_'+id;

    const stream = fs.createWriteStream(path);
    req.pipe(stream);

    stream.on('finish', () => {
      files[id] = path;
      res.end(id);
    });
  }

  /* fallback download */
  else if (req.url.startsWith('/f/')) {
    const id = req.url.split('/f/')[1];
    if (!files[id]) return res.end();

    fs.createReadStream(files[id]).pipe(res);
  }

  else res.end('stelno alive');
});

const wss = new WebSocketServer({ server });

wss.on('connection', ws => {
  let room;

  ws.on('message', msg => {
    const d = JSON.parse(msg);

    if (d.join) {
      room = d.join;
      rooms[room] = rooms[room] || [];
      rooms[room].push(ws);
    }

    if (d.signal && room) {
      rooms[room].forEach(c => {
        if (c !== ws && c.readyState === 1)
          c.send(JSON.stringify({ signal: d.signal }));
      });
    }

    /* fallback notify */
    if (d.file && room) {
      rooms[room].forEach(c => {
        if (c !== ws && c.readyState === 1)
          c.send(JSON.stringify({ file: d.file }));
      });
    }
  });

  ws.on('close', () => {
    if (room && rooms[room]) {
      rooms[room] = rooms[room].filter(c => c !== ws);
      if (!rooms[room].length) delete rooms[room];
    }
  });
});

server.listen(port);
