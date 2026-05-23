const express = require('express');
const path = require('path');

const app = express();
const SECURE = process.env.SECURE === 'true';

const escape = s =>
  String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
           .replace(/"/g,'&quot;').replace(/'/g,'&#x27;');

let messages = [
  { id: 1, author: 'Sistema', text: '¡Bienvenidos al foro! Publiquen sus comentarios.', ts: '09:00' },
];
let nextId = 2;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (_, res) => res.json({ secure: SECURE }));

app.get('/api/messages', (_, res) => res.json({ messages }));

app.post('/api/message', (req, res) => {
  const { author = 'Anónimo', text = '' } = req.body;
  if (!text.trim()) return res.status(400).json({ error: 'Texto requerido' });

  const ts = new Date().toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });

  if (SECURE) {
    // ✅ SECURE: sanitize — HTML entities neutralize any script tags
    messages.push({
      id: nextId++,
      author: escape(author.slice(0, 50)),
      text: escape(text.slice(0, 500)),
      ts,
    });
  } else {
    // ❌ VULNERABLE: raw storage → client renders as innerHTML
    messages.push({ id: nextId++, author: author.slice(0, 50), text: text.slice(0, 500), ts });
  }
  res.json({ success: true, sanitized: SECURE });
});

app.delete('/api/messages', (_, res) => {
  messages = [{ id: 1, author: 'Sistema', text: 'Foro reiniciado.', ts: '00:00' }];
  nextId = 2;
  res.json({ success: true });
});

app.listen(3000, () => console.log(`XSS Lab [${SECURE ? 'SECURE' : 'VULNERABLE'}] :3000`));
