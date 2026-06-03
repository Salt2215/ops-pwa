const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth middleware ──────────────────────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE token=$1', [token]);
    if (!rows[0]) return res.status(401).json({ error: 'Invalid token' });
    req.user = rows[0];
    next();
  } catch (e) {
    next();
  }
}

// ─── Init DB ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pwa_users (
      id SERIAL PRIMARY KEY,
      uid BIGINT UNIQUE,
      name TEXT,
      role TEXT DEFAULT 'worker',
      token TEXT UNIQUE,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_objects (
      id TEXT PRIMARY KEY,
      name TEXT,
      address TEXT DEFAULT '',
      customer TEXT DEFAULT '',
      status TEXT DEFAULT 'active',
      plan_cable INT DEFAULT 0,
      plan_devices INT DEFAULT 0,
      owner_uid BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_entries (
      id TEXT PRIMARY KEY,
      object_id TEXT,
      uid BIGINT,
      text TEXT,
      cable INT DEFAULT 0,
      devices INT DEFAULT 0,
      problem TEXT DEFAULT '',
      ts BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('DB initialized');
}

// ─── API Routes ───────────────────────────────────────────────────────────────

// Sync — get all data for user
app.get('/api/sync', auth, async (req, res) => {
  try {
    const uid = req.user?.uid;
    let objects, entries;

    if (req.user?.role === 'admin') {
      objects = (await pool.query('SELECT * FROM pwa_objects ORDER BY created_at DESC')).rows;
    } else {
      objects = (await pool.query('SELECT * FROM pwa_objects WHERE owner_uid=$1 ORDER BY created_at DESC', [uid])).rows;
    }

    const objIds = objects.map(o => o.id);
    entries = objIds.length > 0
      ? (await pool.query('SELECT * FROM pwa_entries WHERE object_id = ANY($1) ORDER BY ts DESC LIMIT 200', [objIds])).rows
      : [];

    // Normalize keys
    const normObj = objects.map(o => ({
      id: o.id, name: o.name, address: o.address, customer: o.customer,
      status: o.status, planCable: o.plan_cable, planDevices: o.plan_devices, ts: o.created_at
    }));
    const normEnt = entries.map(e => ({
      id: e.id, objectId: e.object_id, text: e.text,
      cable: e.cable, devices: e.devices, problem: e.problem, ts: e.ts, synced: true
    }));

    res.json({ objects: normObj, entries: normEnt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Save entry
app.post('/api/entries', auth, async (req, res) => {
  try {
    const { id, objectId, text, cable, devices, problem, ts } = req.body;
    await pool.query(
      'INSERT INTO pwa_entries (id,object_id,uid,text,cable,devices,problem,ts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING',
      [id, objectId, req.user?.uid, text, cable||0, devices||0, problem||'', ts]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Sync objects
app.post('/api/objects/sync', auth, async (req, res) => {
  try {
    const { objects } = req.body;
    for (const o of objects) {
      await pool.query(
        `INSERT INTO pwa_objects (id,name,address,customer,status,plan_cable,plan_devices,owner_uid)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (id) DO UPDATE SET name=$2,address=$3,customer=$4,status=$5,plan_cable=$6,plan_devices=$7`,
        [o.id, o.name, o.address||'', o.customer||'', o.status||'active', o.planCable||0, o.planDevices||0, req.user?.uid]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Token login (from Telegram bot)
app.post('/api/auth', async (req, res) => {
  try {
    const { uid, name, role, secret } = req.body;
    if (secret !== process.env.PWA_SECRET) return res.status(403).json({ error: 'Forbidden' });
    const token = require('crypto').randomBytes(32).toString('hex');
    await pool.query(
      'INSERT INTO pwa_users (uid,name,role,token) VALUES ($1,$2,$3,$4) ON CONFLICT (uid) DO UPDATE SET name=$2,role=$3,token=$4',
      [uid, name, role, token]
    );
    res.json({ token, name, role });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve PWA for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`PWA server running on port ${PORT}`));
});
