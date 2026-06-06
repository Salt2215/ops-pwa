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
    const { rows } = await pool.query('SELECT * FROM pwa_users WHERE token=$1', [token]);
    if (!rows[0]) return res.status(401).json({ error: 'Invalid token' });
    req.user = rows[0];
    next();
  } catch (e) {
    console.error('auth error:', e.message);
    res.status(500).json({ error: 'auth check failed' });
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
    CREATE TABLE IF NOT EXISTS pwa_team (
      id TEXT PRIMARY KEY,
      name TEXT,
      role TEXT DEFAULT 'worker',
      owner_uid BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE pwa_objects ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT '';
  `);
  console.log('DB initialized');
}

// ─── API Routes ───────────────────────────────────────────────────────────────

// Sync — get all data for user
app.get('/api/sync', auth, async (req, res) => {
  try {
    const safeArr = s => { try { return s ? JSON.parse(s) : []; } catch { return []; } };
    const objects = (await pool.query('SELECT * FROM pwa_objects ORDER BY created_at DESC')).rows;
    const team = (await pool.query('SELECT * FROM pwa_team ORDER BY created_at DESC')).rows;
    const objIds = objects.map(o => o.id);
    const entries = objIds.length > 0
      ? (await pool.query(
          `SELECT e.*, u.name AS author FROM pwa_entries e
           LEFT JOIN pwa_users u ON u.uid = e.uid
           WHERE e.object_id = ANY($1) ORDER BY e.ts DESC LIMIT 500`, [objIds])).rows
      : [];

    const normObj = objects.map(o => ({
      id: o.id, name: o.name, address: o.address, customer: o.customer,
      status: o.status, planCable: o.plan_cable, planDevices: o.plan_devices,
      assignedTo: safeArr(o.assigned_to), ts: o.created_at
    }));
    const normTeam = team.map(t => ({ id: t.id, name: t.name, role: t.role }));
    const normEnt = entries.map(e => ({
      id: e.id, objectId: e.object_id, text: e.text, userName: e.author || '',
      cable: e.cable, devices: e.devices, problem: e.problem, ts: e.ts, synced: true
    }));

    res.json({ objects: normObj, team: normTeam, entries: normEnt });
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
        `INSERT INTO pwa_objects (id,name,address,customer,status,plan_cable,plan_devices,assigned_to,owner_uid)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO UPDATE SET name=$2,address=$3,customer=$4,status=$5,plan_cable=$6,plan_devices=$7,assigned_to=$8`,
        [o.id, o.name, o.address||'', o.customer||'', o.status||'active', o.planCable||0, o.planDevices||0, JSON.stringify(o.assignedTo||[]), req.user?.uid]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Sync team roster (engineer only) — full replace so removals propagate
app.post('/api/team/sync', auth, async (req, res) => {
  try {
    if (!['admin','engineer'].includes(req.user?.role)) return res.json({ ok: true });
    const team = req.body.team || [];
    await pool.query('DELETE FROM pwa_team');
    for (const t of team) {
      await pool.query(
        'INSERT INTO pwa_team (id,name,role,owner_uid) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO UPDATE SET name=$2,role=$3',
        [t.id, t.name, t.role||'worker', req.user?.uid]
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
