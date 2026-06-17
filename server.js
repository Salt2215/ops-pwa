const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const ENGINEER_CODE = (process.env.ENGINEER_CODE || '').trim(); // задаётся в Railway

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(express.json({ limit: '8mb' }));
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
    CREATE TABLE IF NOT EXISTS pwa_projects (
      id TEXT PRIMARY KEY,
      object_id TEXT,
      type TEXT DEFAULT '',
      plan_cable INT DEFAULT 0,
      cable_type TEXT DEFAULT '',
      plan_devices INT DEFAULT 0,
      device_type TEXT DEFAULT '',
      drawing_url TEXT DEFAULT '',
      drawing_name TEXT DEFAULT '',
      owner_uid BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_messages (
      id TEXT PRIMARY KEY,
      uid BIGINT,
      user_name TEXT,
      role TEXT,
      text TEXT,
      ts BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_shleyfy (
      id TEXT PRIMARY KEY,
      object_id TEXT,
      name TEXT DEFAULT '',
      system TEXT DEFAULT '',
      plan_cable INT DEFAULT 0,
      plan_devices INT DEFAULT 0,
      done_cable INT DEFAULT 0,
      done_devices INT DEFAULT 0,
      status TEXT DEFAULT 'todo',
      assigned_to TEXT DEFAULT '',
      owner_uid BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_shleyf_log (
      id TEXT PRIMARY KEY,
      shleyf_id TEXT,
      author_name TEXT,
      text TEXT,
      is_problem BOOLEAN DEFAULT false,
      ts BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_plans (
      object_id TEXT PRIMARY KEY,
      image TEXT DEFAULT '',
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_segments (
      id TEXT PRIMARY KEY,
      object_id TEXT,
      x1 REAL, y1 REAL, x2 REAL, y2 REAL,
      status TEXT DEFAULT 'done',
      note TEXT DEFAULT '',
      author_name TEXT,
      ts BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pwa_devices (
      id TEXT PRIMARY KEY,
      object_id TEXT,
      shleyf_id TEXT,
      num INTEGER,
      x REAL, y REAL,
      status TEXT DEFAULT 'todo',
      note TEXT DEFAULT '',
      author_name TEXT,
      ts BIGINT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE pwa_objects ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT '';
    ALTER TABLE pwa_team    ADD COLUMN IF NOT EXISTS login_code TEXT;
    ALTER TABLE pwa_entries ADD COLUMN IF NOT EXISTS user_name TEXT;
    ALTER TABLE pwa_shleyfy ADD COLUMN IF NOT EXISTS pin_x REAL;
    ALTER TABLE pwa_shleyfy ADD COLUMN IF NOT EXISTS pin_y REAL;
    ALTER TABLE pwa_segments ADD COLUMN IF NOT EXISTS points TEXT;
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
    const planIds = new Set((await pool.query('SELECT object_id FROM pwa_plans')).rows.map(r => r.object_id));

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

    // Проекты — по тем объектам, что доступны пользователю
    const projRows = objIds.length > 0
      ? (await pool.query(`SELECT * FROM pwa_projects WHERE object_id = ANY($1) ORDER BY created_at DESC`, [objIds])).rows
      : [];

    // Шлейфы — по доступным объектам; и их история
    const shRows = objIds.length > 0
      ? (await pool.query(`SELECT * FROM pwa_shleyfy WHERE object_id = ANY($1) ORDER BY created_at DESC`, [objIds])).rows
      : [];
    const shIds = shRows.map(s => s.id);
    const logRows = shIds.length > 0
      ? (await pool.query(`SELECT * FROM pwa_shleyf_log WHERE shleyf_id = ANY($1) ORDER BY ts ASC`, [shIds])).rows
      : [];

    const segRows = objIds.length > 0
      ? (await pool.query(`SELECT * FROM pwa_segments WHERE object_id = ANY($1) ORDER BY created_at ASC`, [objIds])).rows
      : [];

    const devRows = objIds.length > 0
      ? (await pool.query(`SELECT * FROM pwa_devices WHERE object_id = ANY($1) ORDER BY created_at ASC`, [objIds])).rows
      : [];

    const normObj = objects.map(o => ({
      id: o.id, name: o.name, address: o.address, customer: o.customer,
      status: o.status, planCable: o.plan_cable, planDevices: o.plan_devices,
      assignedTo: safeArr(o.assigned_to), hasPlan: planIds.has(o.id), ts: o.created_at
    }));
    const normTeam = team.map(t => ({ id: t.id, name: t.name, role: t.role, code: t.login_code || '' }));
    const normEnt = entries.map(e => ({
      id: e.id, objectId: e.object_id, text: e.text, userName: e.user_name || '',
      cable: e.cable, devices: e.devices, problem: e.problem, ts: e.ts, synced: true
    }));
    const normProj = projRows.map(p => ({
      id: p.id, objectId: p.object_id, type: p.type,
      planCable: p.plan_cable, cableType: p.cable_type,
      planDevices: p.plan_devices, deviceType: p.device_type,
      drawingUrl: p.drawing_url, drawingName: p.drawing_name, ts: p.created_at
    }));
    const normSh = shRows.map(s => ({
      id: s.id, objectId: s.object_id, name: s.name, system: s.system,
      planCable: s.plan_cable, planDevices: s.plan_devices,
      doneCable: s.done_cable, doneDevices: s.done_devices,
      status: s.status, assignedTo: s.assigned_to || '',
      pinX: s.pin_x, pinY: s.pin_y, ts: s.created_at
    }));
    const normLog = logRows.map(l => ({
      id: l.id, shleyfId: l.shleyf_id, author: l.author_name,
      text: l.text, isProblem: l.is_problem, ts: l.ts
    }));
    const normSeg = segRows.map(s => ({
      id: s.id, objectId: s.object_id,
      x1: s.x1, y1: s.y1, x2: s.x2, y2: s.y2,
      points: safeArr(s.points),
      status: s.status, note: s.note || '', author: s.author_name || '', ts: s.ts
    }));
    const normDev = devRows.map(d => ({
      id: d.id, objectId: d.object_id, shleyfId: d.shleyf_id,
      num: d.num, x: d.x, y: d.y,
      status: d.status, note: d.note || '', author: d.author_name || '', ts: d.ts
    }));

    res.json({ objects: normObj, team: normTeam, entries: normEnt, projects: normProj, shleyfy: normSh, shleyfLog: normLog, segments: normSeg, devices: normDev });
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

// Проекты — сохранять может только инженер (upsert)
app.post('/api/projects/sync', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.json({ ok: true });
    const projects = req.body.projects || [];
    for (const p of projects) {
      await pool.query(
        `INSERT INTO pwa_projects (id,object_id,type,plan_cable,cable_type,plan_devices,device_type,drawing_url,drawing_name,owner_uid)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET object_id=$2,type=$3,plan_cable=$4,cable_type=$5,plan_devices=$6,device_type=$7,drawing_url=$8,drawing_name=$9`,
        [p.id, p.objectId, p.type || '', p.planCable || 0, p.cableType || '', p.planDevices || 0, p.deviceType || '', p.drawingUrl || '', p.drawingName || '', req.user.uid]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Удаление проекта — только инженер
app.post('/api/projects/delete', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.status(403).json({ error: 'forbidden' });
    await pool.query('DELETE FROM pwa_projects WHERE id=$1', [req.body.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Шлейфы ─────────────────────────────────────────────────────────────────
// Создавать/редактировать шлейф (название, система, план) — только инженер.
// Прогресс (done_*) при этом НЕ трогаем — его ставит монтажник.
app.post('/api/shleyfy/sync', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.json({ ok: true });
    const list = req.body.shleyfy || [];
    for (const s of list) {
      await pool.query(
        `INSERT INTO pwa_shleyfy (id,object_id,name,system,plan_cable,plan_devices,assigned_to,pin_x,pin_y,owner_uid)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET object_id=$2,name=$3,system=$4,plan_cable=$5,plan_devices=$6,assigned_to=$7,pin_x=$8,pin_y=$9`,
        [s.id, s.objectId, s.name || '', s.system || '', s.planCable || 0, s.planDevices || 0, s.assignedTo || '',
         (typeof s.pinX === 'number' ? s.pinX : null), (typeof s.pinY === 'number' ? s.pinY : null), req.user.uid]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Прогресс по шлейфу — монтажник по своему объекту (или инженер)
app.post('/api/shleyfy/progress', auth, async (req, res) => {
  try {
    const { id, doneCable, doneDevices, status } = req.body;
    const { rows } = await pool.query('SELECT object_id FROM pwa_shleyfy WHERE id=$1', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'Шлейф не найден' });
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [rows[0].object_id]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'Объект вам не назначен' });
    }
    const st = ['todo', 'wip', 'done'].includes(status) ? status : 'todo';
    await pool.query(
      'UPDATE pwa_shleyfy SET done_cable=$2, done_devices=$3, status=$4 WHERE id=$1',
      [id, doneCable || 0, doneDevices || 0, st]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// История по шлейфу — добавить запись (монтажник по своему объекту / инженер)
app.post('/api/shleyfy/log', auth, async (req, res) => {
  try {
    const { id, logId, text, isProblem, ts } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'empty' });
    const { rows } = await pool.query('SELECT object_id FROM pwa_shleyfy WHERE id=$1', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'Шлейф не найден' });
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [rows[0].object_id]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'Объект вам не назначен' });
    }
    await pool.query(
      'INSERT INTO pwa_shleyf_log (id,shleyf_id,author_name,text,is_problem,ts) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING',
      [logId, id, req.user.name, text.trim().slice(0, 1000), !!isProblem, ts || Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Удаление шлейфа — только инженер (вместе с его историей)
app.post('/api/shleyfy/delete', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.status(403).json({ error: 'forbidden' });
    await pool.query('DELETE FROM pwa_shleyf_log WHERE shleyf_id=$1', [req.body.id]);
    await pool.query('DELETE FROM pwa_shleyfy WHERE id=$1', [req.body.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ─── План объекта (картинка) ─────────────────────────────────────────────────
// Сохранить план — только инженер
app.post('/api/plan/save', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.status(403).json({ error: 'forbidden' });
    const { objectId, image } = req.body;
    if (!objectId || !image) return res.status(400).json({ error: 'no data' });
    await pool.query(
      `INSERT INTO pwa_plans (object_id, image, updated_at) VALUES ($1,$2,NOW())
       ON CONFLICT (object_id) DO UPDATE SET image=$2, updated_at=NOW()`,
      [objectId, image]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Получить план — инженер или назначенный на объект монтажник
app.get('/api/plan/:objectId', auth, async (req, res) => {
  try {
    const objectId = req.params.objectId;
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [objectId]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'forbidden' });
    }
    const { rows } = await pool.query('SELECT image FROM pwa_plans WHERE object_id=$1', [objectId]);
    res.json({ objectId, image: rows[0] ? rows[0].image : '' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Удалить план — только инженер
app.post('/api/plan/delete', auth, async (req, res) => {
  try {
    if (!isEngineer(req.user)) return res.status(403).json({ error: 'forbidden' });
    await pool.query('DELETE FROM pwa_plans WHERE object_id=$1', [req.body.objectId]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Участки на плане (рисует инженер или назначенный монтажник) ──────────────
app.post('/api/segments/save', auth, async (req, res) => {
  try {
    const { id, objectId, points, x1, y1, x2, y2, status, note, ts } = req.body;
    if (!id || !objectId) return res.status(400).json({ error: 'no data' });
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [objectId]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'Объект вам не назначен' });
    }
    const st = ['done', 'wip', 'problem'].includes(status) ? status : 'done';
    // points: массив точек [{x,y},...] кривой. Чистим и ограничиваем; крайние точки дублируем в x1..y2.
    let pts = null;
    if (Array.isArray(points) && points.length >= 2) {
      pts = points.slice(0, 500).map(p => ({
        x: Math.max(0, Math.min(100, +p.x || 0)),
        y: Math.max(0, Math.min(100, +p.y || 0)),
      }));
    }
    const ax1 = pts ? pts[0].x : x1, ay1 = pts ? pts[0].y : y1;
    const ax2 = pts ? pts[pts.length - 1].x : x2, ay2 = pts ? pts[pts.length - 1].y : y2;
    const ptsJson = pts ? JSON.stringify(pts) : null;
    await pool.query(
      `INSERT INTO pwa_segments (id,object_id,x1,y1,x2,y2,status,note,author_name,ts,points)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE SET x1=$3,y1=$4,x2=$5,y2=$6,status=$7,note=$8,points=$11`,
      [id, objectId, ax1, ay1, ax2, ay2, st, note || '', req.user.name, ts || Date.now(), ptsJson]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/segments/delete', auth, async (req, res) => {
  try {
    const { id } = req.body;
    const r = await pool.query('SELECT object_id FROM pwa_segments WHERE id=$1', [id]);
    if (!r.rows[0]) return res.json({ ok: true });
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [r.rows[0].object_id]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'forbidden' });
    }
    await pool.query('DELETE FROM pwa_segments WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/devices/save', auth, async (req, res) => {
  try {
    const { id, objectId, shleyfId, num, x, y, status, note, ts } = req.body;
    if (!id || !objectId) return res.status(400).json({ error: 'no data' });
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [objectId]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'Объект вам не назначен' });
    }
    const st = ['done', 'todo', 'problem'].includes(status) ? status : 'todo';
    const px = Math.max(0, Math.min(100, +x || 0));
    const py = Math.max(0, Math.min(100, +y || 0));
    await pool.query(
      `INSERT INTO pwa_devices (id,object_id,shleyf_id,num,x,y,status,note,author_name,ts)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (id) DO UPDATE SET shleyf_id=$3,num=$4,x=$5,y=$6,status=$7,note=$8`,
      [id, objectId, shleyfId || null, parseInt(num) || 0, px, py, st, note || '', req.user.name, ts || Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/devices/delete', auth, async (req, res) => {
  try {
    const { id } = req.body;
    const r = await pool.query('SELECT object_id FROM pwa_devices WHERE id=$1', [id]);
    if (!r.rows[0]) return res.json({ ok: true });
    if (!isEngineer(req.user)) {
      const o = await pool.query('SELECT assigned_to FROM pwa_objects WHERE id=$1', [r.rows[0].object_id]);
      const allowed = o.rows[0] && safeArr(o.rows[0].assigned_to).includes(req.user.teamId);
      if (!allowed) return res.status(403).json({ error: 'forbidden' });
    }
    await pool.query('DELETE FROM pwa_devices WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Чат — общий канал для всех вошедших
app.get('/api/messages', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM (SELECT * FROM pwa_messages ORDER BY ts DESC LIMIT 200) m ORDER BY ts ASC');
    res.json({ messages: rows.map(m => ({ id: m.id, userName: m.user_name, role: m.role, text: m.text, ts: m.ts })) });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { id, text, ts } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'empty' });
    await pool.query(
      'INSERT INTO pwa_messages (id,uid,user_name,role,text,ts) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING',
      [id, req.user.uid, req.user.name, req.user.role, text.trim().slice(0, 2000), ts || Date.now()]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
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
