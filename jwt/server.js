const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const SECURE = process.env.SECURE === 'true';

// ❌ VULNERABLE: hardcoded weak secret (crackable with hashcat/jwt-cracker)
// ✅ SECURE: strong random secret generated once at startup
const WEAK_SECRET = 'secret';
const STRONG_SECRET = crypto.randomBytes(32).toString('hex');
const SECRET = SECURE ? STRONG_SECRET : WEAK_SECRET;

const USERS = {
  alice: { id:1, username:'alice', password:'password123', role:'user',  name:'Alice García' },
  admin: { id:2, username:'admin', password:'admin123',    role:'admin', name:'Admin Root'   },
};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) =>
  res.json({ secure: SECURE, weak_secret: SECURE ? null : WEAK_SECRET })
);

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password)
    return res.status(401).json({ error: 'Credenciales inválidas' });

  const payload = { userId: user.id, username: user.username, role: user.role };
  const token = jwt.sign(payload, SECRET, { expiresIn: '1h' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.get('/api/admin', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  if (SECURE) {
    // ✅ SECURE: strict algorithm + verify signature + role from DB
    try {
      const payload = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
      const dbUser = Object.values(USERS).find(u => u.id === payload.userId);
      if (!dbUser || dbUser.role !== 'admin')
        return res.status(403).json({ error: 'Acceso denegado: se requiere rol admin (verificado en DB)' });
      return res.json({
        message: 'Panel admin — acceso correcto',
        users: Object.values(USERS).map(u => ({ ...u, password: '***' })),
        server_config: { db_host: 'db.internal', secret_key: '[REDACTED]' },
      });
    } catch (e) {
      return res.status(401).json({ error: 'Token inválido: ' + e.message });
    }
  }

  // ❌ VULNERABLE: manual parsing — accepts alg:none (no signature needed) + trusts token role
  try {
    const parts = token.split('.');
    if (parts.length < 2) throw new Error('Token malformado');

    const b64 = s => Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString();
    const header  = JSON.parse(b64(parts[0]));
    const payload = JSON.parse(b64(parts[1]));

    // Only verify signature when alg is NOT none — accepts unsigned tokens!
    if (header.alg !== 'none') {
      jwt.verify(token, SECRET); // Still uses weak secret anyway
    }

    // Trusts role claim from token without checking the database
    if (payload.role !== 'admin')
      return res.status(403).json({ error: 'Acceso denegado', token_payload: payload });

    return res.json({
      message: '¡PANEL ADMIN COMPROMETIDO!',
      users: Object.values(USERS),   // exposes plain-text passwords!
      server_config: { db_host: 'db.internal', secret_key: 'P@ssw0rd_DB_2024!' },
    });
  } catch (e) {
    return res.status(401).json({ error: 'Error de token: ' + e.message });
  }
});

app.listen(3000, () => console.log(`JWT Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`));
