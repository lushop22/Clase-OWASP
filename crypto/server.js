const express = require('express');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const path    = require('path');

const app  = express();
const SECURE = process.env.SECURE === 'true';

// ── Hash utilities ────────────────────────────────────────────
const md5 = s => crypto.createHash('md5').update(s).digest('hex');

// Rainbow table — simula herramientas como hashcat / CrackStation
const RAINBOW = {
  '482c811da5d5b4bc6d497ffa98491e38': 'password123',
  'd8578edf8458ce06fbc5bb76a58c5ca4': 'qwerty',
  '21232f297a57a5a743894a0e4a801fc3': 'admin',
  '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
  'e10adc3949ba59abbe56e057f20f883e': '123456',
  '25d55ad283aa400af464c76d713c07ad': '12345678',
  '827ccb0eea8a706c4c34a16891f84e7b': '12345',
  '098f6bcd4621d373cade4e832627b4f6': 'test',
  'fcea920f7412b5da7be0cf42b8c93759': '1234',
  '1a1dc91c907325c69271ddf0c944bc72': 'pass',
  'ab56b4d92b40713acc5af89985d4b786': 'pass123',
  'b59c67bf196a4758191e42f76670ceba': 'changeme',
};

// ── Users — initialized at startup ───────────────────────────
// In vulnerable mode: MD5 (fast, no salt, reversible with rainbow tables)
// In secure mode: bcrypt (adaptive, salted, computationally expensive)
const SEED = [
  { username: 'alice', plain: 'password123', role: 'user',  email: 'alice@corp.com' },
  { username: 'bob',   plain: 'qwerty',      role: 'user',  email: 'bob@corp.com'   },
  { username: 'admin', plain: 'admin',        role: 'admin', email: 'admin@corp.com' },
];

let USERS = [];

async function initUsers() {
  if (SECURE) {
    USERS = await Promise.all(SEED.map(async u => ({
      ...u,
      hash: await bcrypt.hash(u.plain, 12),
      hashType: 'bcrypt ($2b$12$…)',
    })));
  } else {
    USERS = SEED.map(u => ({
      ...u,
      hash: md5(u.plain),
      hashType: 'MD5 (sin sal)',
    }));
  }
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) => res.json({
  secure: SECURE,
  algorithm: SECURE ? 'bcrypt (cost=12)' : 'MD5 (sin sal, deprecated)',
}));

// ── Simulated DB breach — returns all hashes ─────────────────
app.get('/api/dump-hashes', (_, res) => {
  res.json({
    warning: 'Simulación de brecha de base de datos',
    users: USERS.map(u => ({
      username: u.username,
      email: u.email,
      role: u.role,
      hash: u.hash,
      hashType: u.hashType,
    })),
  });
});

// ── Login ─────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

  let match;
  if (SECURE) {
    match = await bcrypt.compare(password, user.hash);
  } else {
    match = md5(password) === user.hash;
  }

  if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });
  res.json({ success: true, user: { username: user.username, role: user.role } });
});

// ── Register (shows how new passwords are stored) ─────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  if (USERS.find(u => u.username === username))
    return res.status(409).json({ error: 'Usuario ya existe' });

  let hash, hashType;
  if (SECURE) {
    hash = await bcrypt.hash(password, 12);
    hashType = 'bcrypt ($2b$12$…)';
  } else {
    hash = md5(password);
    hashType = 'MD5 (sin sal)';
  }

  const user = { username, plain: password, role: 'user', email: `${username}@demo.com`, hash, hashType };
  USERS.push(user);
  res.json({ success: true, stored_hash: hash, hashType });
});

// ── Crack attempt (rainbow table lookup) ─────────────────────
app.post('/api/crack', (req, res) => {
  const { hash } = req.body;
  if (!hash) return res.status(400).json({ error: 'Falta el hash' });

  if (SECURE) {
    return res.json({
      cracked: false,
      message: 'bcrypt no puede crackearse con rainbow tables — cada hash tiene sal única',
      time_estimate: 'Miles de años con hardware moderno',
      hash_type: 'bcrypt',
    });
  }

  const found = RAINBOW[hash.toLowerCase()];
  res.json({
    cracked: !!found,
    password: found || null,
    message: found
      ? `✓ Hash MD5 revertido en < 1ms usando rainbow table`
      : 'No está en la rainbow table — pero hashcat puede crackearlo con GPU',
    hash_type: 'MD5',
    rainbow_table_size: Object.keys(RAINBOW).length,
  });
});

initUsers().then(() =>
  app.listen(3000, () =>
    console.log(`Crypto Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`)
  )
);
