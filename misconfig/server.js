const express = require('express');
const path = require('path');

const app = express();
const SECURE = process.env.SECURE === 'true';

const SERVER_CONFIG = {
  db_password: 'mysql_r00t_P@ss!',
  api_key: 'sk-prod-1234567890abcdef',
  jwt_secret: 'weak_jwt_secret',
  internal_ip: '10.0.0.50',
  admin_user: 'sysadmin',
  admin_password: 'admin123',
};

const USERS = [
  { id:1, username:'alice', password:'alice_pass',  email:'alice@corp.com',  role:'user'  },
  { id:2, username:'bob',   password:'bob_pass',    email:'bob@corp.com',    role:'user'  },
  { id:3, username:'admin', password:'admin123',    email:'admin@corp.com',  role:'admin', api_key:'sk-admin-secret-xyz' },
];

const sessions = new Map();

app.use(express.json());

if (!SECURE) {
  // ❌ Wildcard CORS — any origin can make credentialed requests
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    next();
  });
}

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) => res.json({ secure: SECURE }));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
  // Predictable token (another misconfiguration shown for context)
  const token = Buffer.from(`${user.id}:${user.role}:${Date.now()}`).toString('base64');
  sessions.set(token, user.id);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// ── Exposed debug endpoint ────────────────────────────────────
app.get('/debug', (req, res) => {
  if (SECURE) return res.status(404).json({ error: 'Not Found' }); // disabled in prod

  // ❌ Dumps everything: env vars, config, sessions, users with passwords
  res.json({
    environment: process.env,
    server_config: SERVER_CONFIG,
    active_sessions: Object.fromEntries(sessions),
    all_users: USERS,
    node_version: process.version,
    uptime_seconds: process.uptime(),
    memory: process.memoryUsage(),
    cwd: process.cwd(),
  });
});

// ── User list — no auth required in vuln mode ─────────────────
app.get('/api/users', (req, res) => {
  if (SECURE) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const userId = sessions.get(token);
    const user = USERS.find(u => u.id === userId);
    if (!user || user.role !== 'admin')
      return res.status(403).json({ error: 'Acceso denegado: requiere rol admin' });
    return res.json({ users: USERS.map(u => ({ ...u, password: '[REDACTED]' })) });
  }
  // ❌ Returns all users including plain-text passwords, no auth
  res.json({ users: USERS });
});

// ── Verbose error with stack trace ───────────────────────────
app.get('/api/trigger-error', (req, res) => {
  try {
    // Simulate a DB connection error
    const err = new Error(
      `DB connection failed at ${SERVER_CONFIG.internal_ip}:3306 — Access denied for user "${SERVER_CONFIG.admin_user}"@"localhost" (using password: "${SERVER_CONFIG.admin_password}")`
    );
    err.config = SERVER_CONFIG;
    throw err;
  } catch (e) {
    if (SECURE) {
      return res.status(500).json({ error: 'Error interno del servidor. Contacte al administrador.' });
    }
    // ❌ Full error details, stack trace, internal config
    res.status(500).json({ error: e.message, stack: e.stack, config: SERVER_CONFIG, path: __dirname });
  }
});

// ── Admin panel — no auth in vuln mode ───────────────────────
app.get('/api/admin/dashboard', (req, res) => {
  if (SECURE) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const userId = sessions.get(token);
    const user = USERS.find(u => u.id === userId);
    if (!user || user.role !== 'admin')
      return res.status(403).json({ error: 'Acceso denegado' });
  }
  // ❌ Accessible without authentication in vulnerable mode
  res.json({
    message: SECURE ? 'Panel admin — acceso correcto' : '¡Panel admin accedido sin autenticación!',
    server_config: SERVER_CONFIG,
    all_users: SECURE ? USERS.map(u => ({ ...u, password: '[REDACTED]' })) : USERS,
  });
});

app.listen(3000, () => console.log(`Misconfig Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`));
