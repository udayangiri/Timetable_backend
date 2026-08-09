'use strict';
// ═══════════════════════════════════════════════════
//  Smart Timetable Scheduler — Backend Server (v2)
//  All 18 audit bugs fixed
// ═══════════════════════════════════════════════════
require('dotenv').config();
const express     = require('express');
const Database    = require('better-sqlite3');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const rateLimit   = require('express-rate-limit');
const path        = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';

// FIX 6: Refuse to start with default/missing JWT secret
if(!JWT_SECRET || JWT_SECRET.length < 32){
  console.error('\n❌ FATAL: JWT_SECRET must be set in .env and be at least 32 characters.');
  console.error('   Run: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  console.error('   Copy the output into your .env file as JWT_SECRET=<value>\n');
  process.exit(1);
}

// ── Middleware ──────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// FIX 5: Rate limiting on auth endpoints (10 req / 15 min per IP)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── SQLite Database ─────────────────────────────────
const db = new Database(path.join(__dirname, 'timetable.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ──────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
    pwd_hash      TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    tab_perms     TEXT NOT NULL DEFAULT '["none","none","none","none","none","none"]',
    pwd_changed_at TEXT DEFAULT NULL,
    created_at    TEXT DEFAULT (datetime('now')),
    updated_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS instances (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT UNIQUE NOT NULL,
    data_version  INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS faculty (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    faculty_id    TEXT NOT NULL,
    name          TEXT NOT NULL,
    load_periods  INTEGER NOT NULL DEFAULT 0,
    day_schedule  TEXT NOT NULL DEFAULT '{}',
    UNIQUE(instance_id, faculty_id)
  );
  CREATE TABLE IF NOT EXISTS subjects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    subject_id    TEXT NOT NULL,
    name          TEXT NOT NULL,
    load_periods  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(instance_id, subject_id)
  );
  CREATE TABLE IF NOT EXISTS sections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    slot_start    TEXT NOT NULL,
    slot_end      TEXT NOT NULL,
    class_days    TEXT NOT NULL DEFAULT '[]'
  );
  CREATE TABLE IF NOT EXISTS assignments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    section_name  TEXT NOT NULL,
    faculty_id    TEXT NOT NULL,
    subject_id    TEXT NOT NULL,
    faculty_name  TEXT NOT NULL,
    subject_name  TEXT NOT NULL,
    weekly_load   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(instance_id, section_name, faculty_id, subject_id)
  );
  CREATE TABLE IF NOT EXISTS timetables (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    generated_at  TEXT DEFAULT (datetime('now')),
    generated_by  INTEGER REFERENCES users(id),
    tt_json       TEXT NOT NULL,
    sec_slots_json TEXT NOT NULL,
    UNIQUE(instance_id)
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER REFERENCES users(id),
    action        TEXT NOT NULL,
    detail        TEXT,
    ts            TEXT DEFAULT (datetime('now'))
  );
`);

// Add missing columns to existing DBs (migration)
const cols = db.prepare("PRAGMA table_info(users)").all().map(c=>c.name);
// SQLite ALTER TABLE does not support non-constant defaults — use a fixed timestamp string
if(!cols.includes('pwd_changed_at'))
  db.exec("ALTER TABLE users ADD COLUMN pwd_changed_at TEXT DEFAULT '2000-01-01 00:00:00'");
const icols = db.prepare("PRAGMA table_info(instances)").all().map(c=>c.name);
if(!icols.includes('data_version'))
  db.exec("ALTER TABLE instances ADD COLUMN data_version INTEGER NOT NULL DEFAULT 1");

// ── Seed ────────────────────────────────────────────
(function seed(){
  if(!db.prepare('SELECT COUNT(*) as n FROM users').get().n){
    db.prepare(`INSERT INTO users(email,name,role,pwd_hash,active,tab_perms)
                VALUES(?,?,?,?,1,?)`)
      .run('admin@school.edu','Administrator','admin',
           bcrypt.hashSync('admin123',10),
           JSON.stringify(['edit','edit','edit','edit','edit','edit']));
    console.log('✅ Default admin: admin@school.edu / admin123  ← CHANGE THIS NOW');
  }
  if(!db.prepare('SELECT COUNT(*) as n FROM instances').get().n){
    db.prepare('INSERT INTO instances(name) VALUES(?)').run('Default');
    console.log('✅ Default instance created');
  }
})();

// ── Helpers ─────────────────────────────────────────
function signToken(user){
  return jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'8h' });
}
function audit(userId, action, detail=''){
  try{ db.prepare('INSERT INTO audit_log(user_id,action,detail) VALUES(?,?,?)').run(userId||null,action,detail||''); }
  catch(e){ console.error('Audit log error:',e.message); }
}
// FIX 1: email validation helper
function validEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'')); }
// FIX 2: safe integer instance_id parser
// FIX: strict integer check — reject strings like "1;DROP TABLE" that parseInt accepts as 1
function parseInstId(v){ const s=String(v||'').trim(); if(!/^\d+$/.test(s)) return null; const n=parseInt(s,10); return n>0?n:null; }

// ── Auth Middleware ──────────────────────────────────
function requireAuth(req,res,next){
  const h=req.headers.authorization;
  if(!h||!h.startsWith('Bearer ')) return res.status(401).json({error:'Not authenticated'});
  try{
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(payload.id);
    if(!u||!u.active) return res.status(401).json({error:'Account revoked or not found'});
    // FIX 7: only invalidate tokens if pwd_changed_at is non-NULL
    // NULL means no post-creation password change — skip check so new users work immediately
    // When set: changedAt+1 ensures same-second tokens are also rejected
    if(u.pwd_changed_at){
      const changedAt = Math.floor(new Date(u.pwd_changed_at).getTime()/1000) + 1;
      if(payload.iat < changedAt) return res.status(401).json({error:'Token expired after password change — please log in again.'});
    }
    req.user=payload; req.dbUser=u; next();
  }catch(e){ return res.status(401).json({error:'Invalid or expired token'}); }
}
function requireAdmin(req,res,next){
  if(req.dbUser.role!=='admin') return res.status(403).json({error:'Admin access required'});
  next();
}
function requireTabPerm(tabIdx,minPerm='view'){
  return (req,res,next)=>{
    if(req.dbUser.role==='admin') return next();
    const perms=JSON.parse(req.dbUser.tab_perms||'[]');
    const p=perms[tabIdx]||'none';
    const order=['none','view','edit'];
    if(order.indexOf(p)<order.indexOf(minPerm))
      return res.status(403).json({error:`Requires ${minPerm} permission on Tab ${tabIdx+1}`});
    next();
  };
}
// FIX 9: check if user has edit on ANY data tab (for sync)
function requireAnyEditPerm(req,res,next){
  if(req.dbUser.role==='admin') return next();
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  if(perms.slice(0,4).some(p=>p==='edit')) return next();
  return res.status(403).json({error:'Edit permission required on at least one data tab'});
}

// ════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════
// FIX 4+5: async bcrypt + rate limiting
app.post('/api/auth/login', authLimiter, async (req,res)=>{
  try{
    const {email,password}=req.body;
    if(!email||!password) return res.status(400).json({error:'Email and password required'});
    const u=db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase().trim());
    if(!u)         return res.status(401).json({error:'No account found for this email'});
    if(!u.active)  return res.status(401).json({error:'Account has been revoked'});
    // FIX 4: async bcrypt — non-blocking
    const ok = await bcrypt.compare(password, u.pwd_hash);
    if(!ok)        return res.status(401).json({error:'Incorrect password'});
    audit(u.id,'LOGIN');
    res.json({token:signToken(u), user:{id:u.id,email:u.email,name:u.name,role:u.role,tabPerms:JSON.parse(u.tab_perms)}});
  }catch(e){ res.status(500).json({error:'Login failed'}); }
});

app.post('/api/auth/change-password', requireAuth, async (req,res)=>{
  try{
    const {currentPassword,newPassword}=req.body;
    if(!currentPassword||!newPassword) return res.status(400).json({error:'Both passwords required'});
    if(newPassword.length<6)           return res.status(400).json({error:'New password must be at least 6 characters'});
    // FIX 4: async bcrypt
    const ok = await bcrypt.compare(currentPassword, req.dbUser.pwd_hash);
    if(!ok) return res.status(401).json({error:'Current password is incorrect'});
    const hash = await bcrypt.hash(newPassword,10);
    // FIX 7: update pwd_changed_at so old tokens are invalidated; NULL→non-NULL triggers check
    db.prepare("UPDATE users SET pwd_hash=?, pwd_changed_at=datetime('now'), updated_at=datetime('now') WHERE id=?")
      .run(hash, req.dbUser.id);
    // Audit AFTER the update so it's only logged on success
    audit(req.user.id,'CHANGE_PASSWORD');
    res.json({ok:true});
  }catch(e){ console.error('change-password error:',e); res.status(500).json({error:'Password change failed'}); }
});

app.get('/api/auth/me', requireAuth, (req,res)=>{
  const u=req.dbUser;
  res.json({id:u.id,email:u.email,name:u.name,role:u.role,tabPerms:JSON.parse(u.tab_perms)});
});

// ════════════════════════════════════════════════════
//  ADMIN — USER MANAGEMENT
// ════════════════════════════════════════════════════
app.get('/api/admin/users', requireAuth, requireAdmin, (req,res)=>{
  const users=db.prepare('SELECT id,email,name,role,active,tab_perms,created_at FROM users ORDER BY id').all();
  res.json(users.map(u=>({...u,tabPerms:JSON.parse(u.tab_perms)})));
});

app.post('/api/admin/users', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const {email,name,role,password,tabPerms}=req.body;
    if(!email||!name||!password) return res.status(400).json({error:'Email, name and password required'});
    // FIX 1: validate email format
    if(!validEmail(email)) return res.status(400).json({error:'Invalid email address format'});
    if(password.length<6)  return res.status(400).json({error:'Password must be at least 6 characters'});
    if(!['admin','user'].includes(role||'user')) return res.status(400).json({error:'Invalid role'});
    const perms=role==='admin'
      ? JSON.stringify(['edit','edit','edit','edit','edit','edit'])
      : JSON.stringify((tabPerms||[]).slice(0,6).map(p=>['none','view','edit'].includes(p)?p:'none'));
    // FIX 4: async hash
    const hash=await bcrypt.hash(password,10);
    const info=db.prepare('INSERT INTO users(email,name,role,pwd_hash,active,tab_perms) VALUES(?,?,?,?,1,?)')
      .run(email.toLowerCase().trim(),name,role||'user',hash,perms);
    audit(req.user.id,'ADD_USER',email);
    res.json({ok:true,id:info.lastInsertRowid});
  }catch(e){
    if(e.message.includes('UNIQUE')) return res.status(409).json({error:'Email already exists'});
    res.status(500).json({error:e.message});
  }
});

app.patch('/api/admin/users/:id/permissions', requireAuth, requireAdmin, (req,res)=>{
  const {tabPerms,role}=req.body;
  const uid=parseInt(req.params.id);
  const target=db.prepare('SELECT * FROM users WHERE id=?').get(uid);
  if(!target) return res.status(404).json({error:'User not found'});
  const newRole=role||target.role;
  const perms=newRole==='admin'
    ? JSON.stringify(['edit','edit','edit','edit','edit','edit'])
    : JSON.stringify((tabPerms||JSON.parse(target.tab_perms)).slice(0,6).map(p=>['none','view','edit'].includes(p)?p:'none'));
  db.prepare("UPDATE users SET tab_perms=?, role=?, updated_at=datetime('now') WHERE id=?").run(perms,newRole,uid);
  audit(req.user.id,'EDIT_PERMS',`uid=${uid}`);
  res.json({ok:true});
});

app.patch('/api/admin/users/:id/revoke', requireAuth, requireAdmin, (req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot revoke your own account'});
  db.prepare("UPDATE users SET active=0, updated_at=datetime('now') WHERE id=?").run(uid);
  audit(req.user.id,'REVOKE_USER',`uid=${uid}`);
  res.json({ok:true});
});

app.patch('/api/admin/users/:id/restore', requireAuth, requireAdmin, (req,res)=>{
  db.prepare("UPDATE users SET active=1, updated_at=datetime('now') WHERE id=?").run(parseInt(req.params.id));
  audit(req.user.id,'RESTORE_USER',`uid=${req.params.id}`);
  res.json({ok:true});
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot delete your own account'});
  db.prepare('DELETE FROM users WHERE id=?').run(uid);
  audit(req.user.id,'DELETE_USER',`uid=${uid}`);
  res.json({ok:true});
});

app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const {newPassword}=req.body;
    if(!newPassword||newPassword.length<6) return res.status(400).json({error:'Min 6 characters'});
    const hash=await bcrypt.hash(newPassword,10);
    // FIX 7: reset pwd_changed_at so old tokens of that user are invalidated
    db.prepare("UPDATE users SET pwd_hash=?, pwd_changed_at=datetime('now'), updated_at=datetime('now') WHERE id=?")
      .run(hash,parseInt(req.params.id));
    audit(req.user.id,'RESET_PASSWORD',`uid=${req.params.id}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/admin/audit-log', requireAuth, requireAdmin, (req,res)=>{
  const rows=db.prepare('SELECT a.*,u.email FROM audit_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.ts DESC LIMIT 200').all();
  res.json(rows);
});

// ════════════════════════════════════════════════════
//  INSTANCES
// ════════════════════════════════════════════════════
app.get('/api/instances', requireAuth, (req,res)=>{
  res.json(db.prepare('SELECT * FROM instances ORDER BY name').all());
});

app.post('/api/instances', requireAuth, requireAdmin, (req,res)=>{
  const {name}=req.body;
  if(!name||!name.trim()) return res.status(400).json({error:'Instance name required'});
  try{
    const info=db.prepare('INSERT INTO instances(name) VALUES(?)').run(name.trim());
    audit(req.user.id,'CREATE_INSTANCE',name);
    res.json({ok:true,id:info.lastInsertRowid});
  }catch(e){
    if(e.message.includes('UNIQUE')) return res.status(409).json({error:'Instance name already exists'});
    throw e;
  }
});

app.delete('/api/instances/:id', requireAuth, requireAdmin, (req,res)=>{
  db.prepare('DELETE FROM instances WHERE id=?').run(parseInt(req.params.id));
  audit(req.user.id,'DELETE_INSTANCE',`id=${req.params.id}`);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════
//  DATA ENDPOINTS
// ════════════════════════════════════════════════════
app.get('/api/faculty', requireAuth, requireTabPerm(0,'view'), (req,res)=>{
  // FIX 3: validate instance_id
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const rows=db.prepare('SELECT * FROM faculty WHERE instance_id=? ORDER BY faculty_id').all(iid);
  // FIX 16: null-safe day_schedule parsing
  res.json(rows.map(r=>({...r,daySchedule:JSON.parse(r.day_schedule||'{}')})));
});

app.post('/api/faculty', requireAuth, requireTabPerm(0,'edit'), (req,res)=>{
  const {instance_id,faculty_id,name,load_periods,daySchedule}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!faculty_id||!name) return res.status(400).json({error:'instance_id, faculty_id, name required'});
  try{
    db.prepare(`INSERT INTO faculty(instance_id,faculty_id,name,load_periods,day_schedule) VALUES(?,?,?,?,?)
      ON CONFLICT(instance_id,faculty_id) DO UPDATE SET name=excluded.name,load_periods=excluded.load_periods,day_schedule=excluded.day_schedule`)
      .run(iid,faculty_id,name,load_periods||0,JSON.stringify(daySchedule||{}));
    audit(req.user.id,'UPSERT_FACULTY',faculty_id);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// FIX 3: guard instance_id on DELETE
app.delete('/api/faculty/:faculty_id', requireAuth, requireTabPerm(0,'edit'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  db.prepare('DELETE FROM faculty WHERE instance_id=? AND faculty_id=?').run(iid,req.params.faculty_id);
  db.prepare('DELETE FROM assignments WHERE instance_id=? AND faculty_id=?').run(iid,req.params.faculty_id);
  audit(req.user.id,'DELETE_FACULTY',req.params.faculty_id);
  res.json({ok:true});
});

app.get('/api/subjects', requireAuth, requireTabPerm(1,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  res.json(db.prepare('SELECT * FROM subjects WHERE instance_id=? ORDER BY subject_id').all(iid));
});

app.post('/api/subjects', requireAuth, requireTabPerm(1,'edit'), (req,res)=>{
  const {instance_id,subject_id,name,load_periods}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!subject_id||!name) return res.status(400).json({error:'instance_id, subject_id, name required'});
  try{
    db.prepare(`INSERT INTO subjects(instance_id,subject_id,name,load_periods) VALUES(?,?,?,?)
      ON CONFLICT(instance_id,subject_id) DO UPDATE SET name=excluded.name,load_periods=excluded.load_periods`)
      .run(iid,subject_id,name,load_periods||0);
    audit(req.user.id,'UPSERT_SUBJECT',subject_id);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/subjects/:subject_id', requireAuth, requireTabPerm(1,'edit'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  db.prepare('DELETE FROM subjects WHERE instance_id=? AND subject_id=?').run(iid,req.params.subject_id);
  db.prepare('DELETE FROM assignments WHERE instance_id=? AND subject_id=?').run(iid,req.params.subject_id);
  audit(req.user.id,'DELETE_SUBJECT',req.params.subject_id);
  res.json({ok:true});
});

app.get('/api/sections', requireAuth, requireTabPerm(2,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const rows=db.prepare('SELECT * FROM sections WHERE instance_id=? ORDER BY name,slot_start').all(iid);
  res.json(rows.map(r=>({...r,days:JSON.parse(r.class_days||'[]')})));
});

app.post('/api/sections', requireAuth, requireTabPerm(2,'edit'), (req,res)=>{
  const {instance_id,name,slot_start,slot_end,days}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!name||!slot_start||!slot_end) return res.status(400).json({error:'All section fields required'});
  const info=db.prepare('INSERT INTO sections(instance_id,name,slot_start,slot_end,class_days) VALUES(?,?,?,?,?)')
    .run(iid,name,slot_start,slot_end,JSON.stringify(days||[]));
  audit(req.user.id,'ADD_SECTION',`${name} ${slot_start}-${slot_end}`);
  res.json({ok:true,id:info.lastInsertRowid});
});

app.delete('/api/sections/:id', requireAuth, requireTabPerm(2,'edit'), (req,res)=>{
  db.prepare('DELETE FROM sections WHERE id=?').run(parseInt(req.params.id));
  audit(req.user.id,'DELETE_SECTION',`id=${req.params.id}`);
  res.json({ok:true});
});

app.get('/api/assignments', requireAuth, requireTabPerm(3,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  res.json(db.prepare('SELECT * FROM assignments WHERE instance_id=? ORDER BY section_name').all(iid));
});

app.post('/api/assignments', requireAuth, requireTabPerm(3,'edit'), (req,res)=>{
  const {instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!section_name||!faculty_id||!subject_id) return res.status(400).json({error:'Required fields missing'});
  try{
    db.prepare(`INSERT INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load)
      VALUES(?,?,?,?,?,?,?) ON CONFLICT(instance_id,section_name,faculty_id,subject_id)
      DO UPDATE SET faculty_name=excluded.faculty_name,subject_name=excluded.subject_name,weekly_load=excluded.weekly_load`)
      .run(iid,section_name,faculty_id,subject_id,faculty_name||'',subject_name||'',weekly_load||0);
    audit(req.user.id,'UPSERT_ASSIGNMENT',`${section_name}/${faculty_id}/${subject_id}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// FIX 11: DELETE by row id OR by composite key
app.delete('/api/assignments/:id', requireAuth, requireTabPerm(3,'edit'), (req,res)=>{
  db.prepare('DELETE FROM assignments WHERE id=?').run(parseInt(req.params.id));
  audit(req.user.id,'DELETE_ASSIGNMENT',`id=${req.params.id}`);
  res.json({ok:true});
});
// FIX 11: additional route — delete by composite key (what frontend uses)
app.delete('/api/assignments', requireAuth, requireTabPerm(3,'edit'), (req,res)=>{
  const {instance_id,section_name,faculty_id,subject_id}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!section_name||!faculty_id||!subject_id) return res.status(400).json({error:'instance_id, section_name, faculty_id, subject_id required'});
  db.prepare('DELETE FROM assignments WHERE instance_id=? AND section_name=? AND faculty_id=? AND subject_id=?')
    .run(iid,section_name,faculty_id,subject_id);
  audit(req.user.id,'DELETE_ASSIGNMENT',`${section_name}/${faculty_id}/${subject_id}`);
  res.json({ok:true});
});

// FIX 2+8+9: BULK SYNC — validate instance_id, check per-entity perms, clear stale timetable
app.post('/api/sync', requireAuth, requireAnyEditPerm, (req,res)=>{
  const {instance_id,data}=req.body;
  // FIX 2: validate instance_id is a real integer
  const iid=parseInstId(instance_id);
  if(!iid||!data) return res.status(400).json({error:'Valid instance_id and data required'});
  const isAdmin=req.dbUser.role==='admin';
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  const canEdit=(i)=>isAdmin||perms[i]==='edit';

  const syncTx=db.transaction(()=>{
    // Only clear/sync tables the user has edit access to
    if(canEdit(0)){
      db.prepare('DELETE FROM faculty WHERE instance_id=?').run(iid);
      const ins=db.prepare('INSERT INTO faculty(instance_id,faculty_id,name,load_periods,day_schedule) VALUES(?,?,?,?,?)');
      (data.faculty||[]).forEach(f=>ins.run(iid,f.id,f.name,f.load||0,JSON.stringify(f.daySchedule||{})));
    }
    if(canEdit(1)){
      db.prepare('DELETE FROM subjects WHERE instance_id=?').run(iid);
      const ins=db.prepare('INSERT INTO subjects(instance_id,subject_id,name,load_periods) VALUES(?,?,?,?)');
      (data.subjects||[]).forEach(s=>ins.run(iid,s.id,s.name,s.load||0));
    }
    if(canEdit(2)){
      db.prepare('DELETE FROM sections WHERE instance_id=?').run(iid);
      const ins=db.prepare('INSERT INTO sections(instance_id,name,slot_start,slot_end,class_days) VALUES(?,?,?,?,?)');
      (data.sections||[]).forEach(s=>ins.run(iid,s.name,s.start,s.end,JSON.stringify(s.days||[])));
    }
    if(canEdit(3)){
      db.prepare('DELETE FROM assignments WHERE instance_id=?').run(iid);
      const ins=db.prepare(`INSERT INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load) VALUES(?,?,?,?,?,?,?)`);
      (data.assignments||[]).forEach(a=>ins.run(iid,a.sectionName,a.facultyId,a.subjectId,a.facultyName||'',a.subjectName||'',a.weeklyLoad||0));
    }
    // FIX 8: if faculty or sections changed, the stored timetable is stale — delete it
    if(canEdit(0)||canEdit(2)){
      db.prepare('DELETE FROM timetables WHERE instance_id=?').run(iid);
    }
    // FIX 18: bump data_version for optimistic concurrency
    db.prepare('UPDATE instances SET data_version=data_version+1 WHERE id=?').run(iid);
  });

  try{
    syncTx();
    const ver=db.prepare('SELECT data_version FROM instances WHERE id=?').get(iid)?.data_version;
    audit(req.user.id,'BULK_SYNC',`instance=${iid}`);
    res.json({ok:true,data_version:ver});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// LOAD instance data
app.get('/api/sync/:instance_id', requireAuth, (req,res)=>{
  const iid=parseInstId(req.params.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const isAdmin=req.dbUser.role==='admin';
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  const canView=(i)=>isAdmin||(perms[i]||'none')!=='none';

  const faculty=canView(0)?db.prepare('SELECT * FROM faculty WHERE instance_id=? ORDER BY faculty_id').all(iid)
    .map(r=>{
      // FIX 16: null-safe; days always an array even if daySchedule is empty
      const ds = JSON.parse(r.day_schedule||'{}');
      const dayKeys = Object.keys(ds);
      const firstDay = dayKeys.length > 0 ? ds[dayKeys[0]] : null;
      return {
        id: r.faculty_id, name: r.name, load: r.load_periods,
        daySchedule: ds,
        days: dayKeys,
        start: firstDay?.start || '',
        end:   firstDay?.end   || ''
      };
    }):[];
  const subjects=canView(1)?db.prepare('SELECT * FROM subjects WHERE instance_id=?').all(iid)
    .map(r=>({id:r.subject_id,name:r.name,load:r.load_periods})):[];
  const sections=canView(2)?db.prepare('SELECT * FROM sections WHERE instance_id=?').all(iid)
    .map(r=>({name:r.name,start:r.slot_start,end:r.slot_end,days:JSON.parse(r.class_days||'[]')})):[];
  const assignments=canView(3)?db.prepare('SELECT * FROM assignments WHERE instance_id=?').all(iid)
    .map(r=>({sectionName:r.section_name,facultyId:r.faculty_id,subjectId:r.subject_id,
      facultyName:r.faculty_name,subjectName:r.subject_name,weeklyLoad:r.weekly_load})):[];
  const inst=db.prepare('SELECT data_version FROM instances WHERE id=?').get(iid);
  res.json({faculty,subjects,sections,assignments,data_version:inst?.data_version||1});
});

// TIMETABLE
app.get('/api/timetable/:instance_id', requireAuth, requireTabPerm(4,'view'), (req,res)=>{
  const iid=parseInstId(req.params.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const row=db.prepare('SELECT * FROM timetables WHERE instance_id=?').get(iid);
  if(!row) return res.status(404).json({error:'No timetable generated yet'});
  res.json({tt:JSON.parse(row.tt_json),secSlots:JSON.parse(row.sec_slots_json),generatedAt:row.generated_at});
});

app.post('/api/timetable/:instance_id', requireAuth, requireTabPerm(4,'edit'), (req,res)=>{
  const {tt,secSlots}=req.body;
  const iid=parseInstId(req.params.instance_id);
  if(!iid||!tt||!secSlots) return res.status(400).json({error:'tt and secSlots required'});
  db.prepare(`INSERT INTO timetables(instance_id,generated_by,tt_json,sec_slots_json) VALUES(?,?,?,?)
    ON CONFLICT(instance_id) DO UPDATE SET generated_at=datetime('now'),generated_by=excluded.generated_by,
    tt_json=excluded.tt_json,sec_slots_json=excluded.sec_slots_json`)
    .run(iid,req.user.id,JSON.stringify(tt),JSON.stringify(secSlots));
  audit(req.user.id,'SAVE_TIMETABLE',`instance=${iid}`);
  res.json({ok:true});
});

app.get('/api/health',(req,res)=>res.json({status:'ok',time:new Date().toISOString()}));

app.use((err,req,res,next)=>{
  console.error(err.stack||err);
  res.status(500).json({error:'Internal server error'});
});

app.listen(PORT,()=>console.log(`\n🚀 Timetable backend running at http://localhost:${PORT}\n`));
