const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const SECURE = process.env.SECURE === 'true';

// ── Seed in-memory database ──────────────────────────────────
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    credit_card TEXT,
    role TEXT DEFAULT 'user'
  );
  INSERT INTO users VALUES (1,'alice','alice_pass_2024','alice@corp.com','4532-1111-2222-3333','user');
  INSERT INTO users VALUES (2,'bob','bob_xyz_789','bob@corp.com','4111-4444-5555-6666','user');
  INSERT INTO users VALUES (3,'admin','P@$$w0rd_Admin!','admin@corp.com','4916-7777-8888-9999','admin');
`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) => res.json({ secure: SECURE }));

app.post('/api/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  if (SECURE) {
    // ✅ SECURE: parameterized query — input never alters SQL structure
    try {
      const stmt = db.prepare(
        `SELECT id, username, email, role FROM users WHERE username = ? AND password = ?`
      );
      const user = stmt.get(username, password);
      return res.json({
        success: !!user,
        user: user || null,
        query: `SELECT id, username, email, role FROM users\nWHERE username = [?] AND password = [?]`,
        params: ['<username>', '<password>'],
        note: 'Los parámetros viajan separados del SQL. La DB los trata siempre como datos, nunca como código.'
      });
    } catch (e) {
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }

  // ❌ VULNERABLE: string concatenation — user controls the SQL
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const user = db.prepare(query).get();
    return res.json({ success: !!user, user: user || null, query, note: 'La entrada se insertó directamente en la consulta SQL.' });
  } catch (e) {
    return res.status(500).json({ success: false, query, error: e.message });
  }
});

app.listen(3000, () => console.log(`SQLi Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`));
