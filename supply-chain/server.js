const express = require('express');
const path = require('path');

const app = express();
const SECURE = process.env.SECURE === 'true';

// ── In-memory users ──────────────────────────────────────────
const USERS = {
  alice: { id: 1, username: 'alice', role: 'user',  prefs: { theme: 'light' } },
  bob:   { id: 2, username: 'bob',   role: 'user',  prefs: { theme: 'dark'  } },
  admin: { id: 3, username: 'admin', role: 'admin', prefs: { theme: 'dark'  } },
};

// Session store: token → username
const sessions = new Map();

// ── VULNERABLE: for...in iterates __proto__ as a key ──────────
// Simulates CVE-2019-10744 (lodash < 4.17.12) and similar
// Supply chain risk: using an outdated/unpatched deep-merge library
function vulnerableMerge(target, source) {
  for (const key in source) {                 // ← iterates '__proto__'
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};     // target['__proto__'] = Object.prototype
      vulnerableMerge(target[key], source[key]); // merges into Object.prototype!
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ── SECURE: explicit key blocklist + Object.keys (no __proto__) ─
function safeMerge(target, source) {
  const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue;           // drop dangerous keys
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!Object.prototype.hasOwnProperty.call(target, key)) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) =>
  res.json({
    secure: SECURE,
    library: SECURE
      ? 'custom-merge v2.1.0 (patched — bloquea __proto__)'
      : 'custom-merge v1.0.0 (VULNERABLE — CVE-2019-XXXX)',
  })
);

// ── Login ────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  const user = USERS[username];
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  const token = `tok_${username}_${Date.now()}`;
  sessions.set(token, username);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  sessions.delete(token);
  res.json({ success: true });
});

// ── Merge user preferences (the vulnerable/secure endpoint) ──
app.post('/api/prefs', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const username = sessions.get(token);
  if (!username) return res.status(401).json({ error: 'No autenticado' });

  const user = USERS[username];
  const rawBody = req.body;

  if (SECURE) {
    safeMerge(user.prefs, rawBody);
    res.json({
      success: true,
      prefs: user.prefs,
      prototype_isAdmin: ({}).isAdmin,          // should remain undefined
      note: 'safeMerge bloqueó __proto__',
    });
  } else {
    vulnerableMerge(user.prefs, rawBody);
    res.json({
      success: true,
      prefs: user.prefs,
      prototype_isAdmin: ({}).isAdmin,           // true if polluted!
      note: 'vulnerableMerge ejecutado — revisa prototype_isAdmin',
    });
  }
});

// ── Admin check ───────────────────────────────────────────────
app.get('/api/admin-check', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const username = sessions.get(token);
  if (!username) return res.status(401).json({ error: 'No autenticado' });

  const user = USERS[username];

  if (SECURE) {
    // ✅ Check role from the DB object — not inherited from prototype
    const isAdmin = user.role === 'admin';
    return res.json({ isAdmin, reason: 'Rol verificado desde la base de datos' });
  }

  // ❌ user.isAdmin may come from polluted Object.prototype
  const isAdmin = user.isAdmin === true;
  res.json({
    isAdmin,
    prototype_polluted: ({}).isAdmin === true,
    reason: isAdmin
      ? '¡Object.prototype contaminado! user.isAdmin heredado del prototipo'
      : 'Prototipo aún no contaminado — prueba el ataque primero',
  });
});

// ── Admin panel ───────────────────────────────────────────────
app.get('/api/admin-panel', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const username = sessions.get(token);
  if (!username) return res.status(401).json({ error: 'No autenticado' });

  const user = USERS[username];
  const isAdmin = SECURE ? user.role === 'admin' : user.isAdmin === true;

  if (!isAdmin) return res.status(403).json({ error: 'Acceso denegado al panel admin' });

  res.json({
    message: SECURE ? 'Acceso legítimo al panel admin' : '¡PANEL ADMIN COMPROMETIDO VÍA PROTOTYPE POLLUTION!',
    all_users: Object.values(USERS),
    server_info: { node: process.version, uptime: process.uptime() },
  });
});

// ── Reset prototype (demo utility) ───────────────────────────
app.post('/api/reset', (_, res) => {
  delete Object.prototype.isAdmin;
  res.json({ success: true, prototype_isAdmin: ({}).isAdmin });
});

app.listen(3000, () =>
  console.log(`Supply Chain Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`)
);
