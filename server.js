const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const ENGINEER_CODE = (process.env.ENGINEER_CODE || '').trim(); // задаётся в Railway

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const safeArr = s => { try { return s ? JSON.parse(s) : []; } catch { return []; } };
const isEngineer = u => !!u && (u.role === 'engineer' || u.role === 'admin');

// ─── Auth middleware (по сессии) ───────────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const { rows } = await pool.query('SELECT * FROM pwa_sessions WHERE token=$1', [token]);
    if (!rows[0]) return res.status(401).json({ error: 'Invalid token' });
    req.user = { uid: rows[0].uid, name: rows[0].name, role: rows[0].role, teamId: rows[0].team_id };
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
    CREATE TABLE IF NOT EXISTS pwa_sessions (
      token TEXT PRIMARY KEY,
      uid BIGINT,
      name TEXT,
      role TEXT,
      team_id TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE pwa_objects ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT '';
    ALTER TABLE pwa_team    ADD COLUMN IF NOT EXISTS login_code TEXT;
    ALTER TABLE pwa_entries ADD COLUMN IF NOT EXISTS user_name TEXT;
  `);
  console.log('DB initialized');
}

// ─── API Routes ───────────────────────────────────────────────────────────────

// Вход по коду (инженер — по ENGINEER_CODE, монтажник — по личному коду)
app.post('/api/login', async (req, res) => {
  try {
    const code = (req.body.code || '').trim();
    if (!code) return res.status(400).json({ error: 'Введите код' });
    const token = crypto.randomBytes(32).toString('hex');

    if (ENGINEER_CODE && code === ENGINEER_CODE) {
      await pool.query(
        'INSERT INTO pwa_sessions (token,uid,name,role,team_id) VALUES ($1,$2,$3,$4,$5)',
        [token, null, 'Инженер', 'engineer', null]
      );
      return res.json({ token, name: 'Инженер', role: 'engineer', teamId: null });
    }

    const { rows } = await pool.query('SELECT * FROM pwa_team WHERE login_code=$1', [code]);
    if (rows[0]) {
      const m = rows[0];
      await pool.query(
        'INSERT INTO pwa_sessions (token,uid,name,role,team_id) VALUES ($1,$2,$3,$4,$5)',
        [token, null, m.name, 'worker', m.id]
      );
      return res.json({ token, name: m.name, role: 'worker', teamId: m.id });
    }

    return res.status(403).json({ error: 'Неверный код' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Выход — гасим сессию
app.post('/api/logout', auth, async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    await pool.query('DELETE FROM pwa_sessions WHERE token=$1', [token]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: true }); }
});

// Синхронизация — данные по роли
app.get('/api/sync', auth, async (req, res) => {
  try {
    const eng = isEngineer(req.user);
    const allObjects = (await pool.query('SELECT * FROM pwa_objects ORDER BY created_at DESC')).rows;

    // Инженер видит все объекты, монтажник — только назначенные ему
    const objects = eng
      ? allObjects
      : allObjects.filter(o => safeArr(o.assigned_to).includes(req.user.teamId));

    const objIds = objects.map(o => o.id);
    const entries = objIds.length > 0
      ? (await pool.query(
          `SELECT * FROM pwa_entries WHERE object_id = ANY($1) ORDER BY ts DESC LIMIT 500`, [objIds])).rows
      : [];

    // Команду (и коды) отдаём только инженеру
    const team = eng
      ? (await pool.query('SELECT * FROM pwa_team ORDER BY created_at DESC')).rows
      : [];

    const normObj = objects.map(o => ({
      id: o.id, name: o.name, address: o.address, customer: o.customer,
      status: o.status, planCable: o.plan_cable, planDevices: o.plan_devices,
      assignedTo: safeArr(o.assigned_to), ts: o.created_at
    }));
    const normTeam = team.map(t => ({ id: t.id, name: t.name, role: t.role, code: t.login_code || '' }));
    const normEnt = entries.map(e => ({
      id: e.id, objectId: e.object_id, text: e.text, userName: e.user_name || '',
      cable: e.cable, devices: e.devices, problem: e.problem, ts: e.ts, synced: true
    }));

    res.json({ objects: normObj, team: normTeam, entries: normEnt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Запись в журнал
app.post('/api/entries', auth, async (req, res) => {
  try {
    const { id, objectId, text, cable, devices, problem, ts } = req.body;
    // Монтажник может писать только в назначенный ему объект
    if (!isEngineer(req.user)) {
      const { rows } = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [objectId]);
      const allowed = rows[0] && safeArr(rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'Объект вам не назначен' });
    }
    await pool.query(
      'INSERT INTO pwa_entries (id,object_id,uid,user_name,text,cable,devices,problem,ts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING',
      [id, objectId, req.user.uid, req.user.name, text, cable || 0, devices || 0, problem || '', ts]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Объекты — менять может только инженер
app.post('/api/objects/sync', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.json({ ok: true }); // монтажникам молча отказываем
    const { objects } = req.body;
    for (const o of objects) {
      await pool.query(
        `INSERT INTO pwa_objects (id,name,address,customer,status,plan_cable,plan_devices,assigned_to,owner_uid)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO UPDATE SET name=$2,address=$3,customer=$4,status=$5,plan_cable=$6,plan_devices=$7,assigned_to=$8`,
        [o.id, o.name, o.address || '', o.customer || '', o.status || 'active', o.planCable || 0, o.planDevices || 0, JSON.stringify(o.assignedTo || []), req.user.uid]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Команда — только инженер; сохраняем личные коды, удаляем выбывших
app.post('/api/team/sync', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.json({ ok: true });
    const team = req.body.team || [];
    const ids = team.map(t => t.id);
    if (ids.length > 0) await pool.query('DELETE FROM pwa_team WHERE id <> ALL($1)', [ids]);
    else await pool.query('DELETE FROM pwa_team');
    for (const t of team) {
      await pool.query(
        `INSERT INTO pwa_team (id,name,role,owner_uid,login_code) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE SET name=$2, role=$3, login_code=COALESCE($5, pwa_team.login_code)`,
        [t.id, t.name, t.role || 'worker', req.user.uid, t.code || null]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Вход от Telegram-бота (на будущее) — тоже создаёт сессию
app.post('/api/auth', async (req, res) => {
  try {
    const { uid, name, role, secret } = req.body;
    if (secret !== process.env.PWA_SECRET) return res.status(403).json({ error: 'Forbidden' });
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      'INSERT INTO pwa_users (uid,name,role,token) VALUES ($1,$2,$3,$4) ON CONFLICT (uid) DO UPDATE SET name=$2,role=$3,token=$4',
      [uid, name, role, token]
    );
    await pool.query(
      'INSERT INTO pwa_sessions (token,uid,name,role,team_id) VALUES ($1,$2,$3,$4,$5)',
      [token, uid, name, role, null]
    );
    res.json({ token, name, role });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Отдаём PWA на все прочие маршруты
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`PWA server running on port ${PORT}`));
});
