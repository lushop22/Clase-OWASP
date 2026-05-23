const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const SECURE = process.env.SECURE === 'true';

const USERS = {
  1: { id:1, username:'ana',    name:'Ana García',   email:'ana@corp.com',    role:'user',  balance:'$1.250,00',   card:'•••• 4821', phone:'+34 612 345 678' },
  2: { id:2, username:'carlos', name:'Carlos López',  email:'carlos@corp.com', role:'user',  balance:'$3.840,00',   card:'•••• 9034', phone:'+34 698 765 432' },
  3: { id:3, username:'admin',  name:'Root Admin',    email:'admin@corp.com',  role:'admin', balance:'$99.999,99',  card:'•••• 0001', phone:'+34 600 000 001' },
};

// token → userId
const sessions = new Map();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) => res.json({ secure: SECURE }));

app.post('/api/login', (req, res) => {
  const userId = parseInt(req.body.userId);
  if (!USERS[userId]) return res.status(400).json({ error: 'Usuario no encontrado' });
  const token = crypto.randomBytes(16).toString('hex');
  sessions.set(token, userId);
  const u = USERS[userId];
  res.json({ token, user: { id: u.id, name: u.name, role: u.role } });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  sessions.delete(token);
  res.json({ success: true });
});

app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const sessionUserId = sessions.get(token);
  if (!sessionUserId) return res.status(401).json({ error: 'No autenticado' });

  const requestedId = parseInt(req.query.id) || sessionUserId;

  if (SECURE) {
    // ✅ SECURE: only allow own profile unless admin
    const sessionUser = USERS[sessionUserId];
    if (requestedId !== sessionUserId && sessionUser.role !== 'admin') {
      return res.status(403).json({
        error: 'Acceso denegado: no puedes ver el perfil de otro usuario',
        your_id: sessionUserId,
        requested_id: requestedId,
      });
    }
  }
  // ❌ VULNERABLE: uses client-supplied ?id= without ownership check

  const user = USERS[requestedId];
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

  res.json({ user, session_owner: sessionUserId });
});

app.listen(3000, () => console.log(`IDOR Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`));
