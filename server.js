'use strict';
// ═══════════════════════════════════════════════════
//  Smart Timetable Scheduler — Backend Server (v3)
//  PostgreSQL version — persistent cloud database
// ═══════════════════════════════════════════════════
require('dotenv').config();
const express     = require('express');
const { Pool }    = require('pg');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const rateLimit   = require('express-rate-limit');
const path        = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';

// Refuse to start with weak JWT secret
if(!JWT_SECRET || JWT_SECRET.length < 32){
  console.error('\n❌ FATAL: JWT_SECRET must be set and be at least 32 characters.');
  process.exit(1);
}

// ── PostgreSQL Pool ─────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper — run a query
async function q(sql, params=[]){
  const client = await pool.connect();
  try{ return await client.query(sql, params); }
  finally{ client.release(); }
}

// ── Middleware ──────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting on auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Schema ──────────────────────────────────────────
async function initSchema(){
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL,
      name          TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
      pwd_hash      TEXT NOT NULL,
      active        BOOLEAN NOT NULL DEFAULT TRUE,
      tab_perms     TEXT NOT NULL DEFAULT '["none","none","none","none","none","none"]',
      pwd_changed_at TIMESTAMPTZ DEFAULT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS instances (
      id            SERIAL PRIMARY KEY,
      name          TEXT UNIQUE NOT NULL,
      data_version  INTEGER NOT NULL DEFAULT 1,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS faculty (
      id            SERIAL PRIMARY KEY,
      instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
      faculty_id    TEXT NOT NULL,
      name          TEXT NOT NULL,
      load_periods  INTEGER NOT NULL DEFAULT 0,
      day_schedule  TEXT NOT NULL DEFAULT '{}',
      UNIQUE(instance_id, faculty_id)
    );
    CREATE TABLE IF NOT EXISTS subjects (
      id            SERIAL PRIMARY KEY,
      instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
      subject_id    TEXT NOT NULL,
      name          TEXT NOT NULL,
      load_periods  INTEGER NOT NULL DEFAULT 0,
      UNIQUE(instance_id, subject_id)
    );
    CREATE TABLE IF NOT EXISTS sections (
      id            SERIAL PRIMARY KEY,
      instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
      name          TEXT NOT NULL,
      slot_start    TEXT NOT NULL,
      slot_end      TEXT NOT NULL,
      class_days    TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS assignments (
      id            SERIAL PRIMARY KEY,
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
      id            SERIAL PRIMARY KEY,
      instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
      generated_at  TIMESTAMPTZ DEFAULT NOW(),
      generated_by  INTEGER REFERENCES users(id),
      tt_json       TEXT NOT NULL,
      sec_slots_json TEXT NOT NULL,
      UNIQUE(instance_id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER REFERENCES users(id),
      action        TEXT NOT NULL,
      detail        TEXT,
      ts            TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Seed default admin if no users exist
  const { rows } = await q('SELECT COUNT(*) as n FROM users');
  if(parseInt(rows[0].n) === 0){
    const hash = await bcrypt.hash('admin123', 10);
    await q(
      `INSERT INTO users(email,name,role,pwd_hash,active,tab_perms) VALUES($1,$2,$3,$4,TRUE,$5)`,
      ['admin@school.edu','Administrator','admin', hash,
       JSON.stringify(['edit','edit','edit','edit','edit','edit'])]
    );
    console.log('✅ Default admin: admin@school.edu / admin123  ← CHANGE THIS NOW');
  }

  // Seed default instance if none exists
  const inst = await q('SELECT COUNT(*) as n FROM instances');
  if(parseInt(inst.rows[0].n) === 0){
    await q(`INSERT INTO instances(name) VALUES($1)`, ['Default']);
    console.log('✅ Default instance created');
  }

  console.log('✅ Database schema ready');
}

// ── Helpers ─────────────────────────────────────────
function signToken(user){
  return jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:'8h' });
}
async function audit(userId, action, detail=''){
  try{ await q('INSERT INTO audit_log(user_id,action,detail) VALUES($1,$2,$3)', [userId||null,action,detail||'']); }
  catch(e){ console.error('Audit log error:',e.message); }
}
function validEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'')); }
function parseInstId(v){ const s=String(v||'').trim(); if(!/^\d+$/.test(s)) return null; const n=parseInt(s,10); return n>0?n:null; }

// ── Auth Middleware ──────────────────────────────────
async function requireAuth(req,res,next){
  const h=req.headers.authorization;
  if(!h||!h.startsWith('Bearer ')) return res.status(401).json({error:'Not authenticated'});
  try{
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const { rows } = await q('SELECT * FROM users WHERE id=$1', [payload.id]);
    const u = rows[0];
    if(!u||!u.active) return res.status(401).json({error:'Account revoked or not found'});
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
function requireAnyEditPerm(req,res,next){
  if(req.dbUser.role==='admin') return next();
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  if(perms.slice(0,4).some(p=>p==='edit')) return next();
  return res.status(403).json({error:'Edit permission required on at least one data tab'});
}

// ════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════
app.post('/api/auth/login', authLimiter, async (req,res)=>{
  try{
    const {email,password}=req.body;
    if(!email||!password) return res.status(400).json({error:'Email and password required'});
    const { rows } = await q('SELECT * FROM users WHERE LOWER(email)=$1', [(email||'').toLowerCase().trim()]);
    const u = rows[0];
    if(!u)        return res.status(401).json({error:'No account found for this email'});
    if(!u.active) return res.status(401).json({error:'Account has been revoked'});
    const ok = await bcrypt.compare(password, u.pwd_hash);
    if(!ok)       return res.status(401).json({error:'Incorrect password'});
    await audit(u.id,'LOGIN');
    res.json({token:signToken(u), user:{id:u.id,email:u.email,name:u.name,role:u.role,tabPerms:JSON.parse(u.tab_perms)}});
  }catch(e){ console.error(e); res.status(500).json({error:'Login failed'}); }
});

app.post('/api/auth/change-password', requireAuth, async (req,res)=>{
  try{
    const {currentPassword,newPassword}=req.body;
    if(!currentPassword||!newPassword) return res.status(400).json({error:'Both passwords required'});
    if(newPassword.length<6)           return res.status(400).json({error:'New password must be at least 6 characters'});
    const ok = await bcrypt.compare(currentPassword, req.dbUser.pwd_hash);
    if(!ok) return res.status(401).json({error:'Current password is incorrect'});
    const hash = await bcrypt.hash(newPassword,10);
    await q("UPDATE users SET pwd_hash=$1, pwd_changed_at=NOW(), updated_at=NOW() WHERE id=$2", [hash, req.dbUser.id]);
    await audit(req.user.id,'CHANGE_PASSWORD');
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'Password change failed'}); }
});

app.get('/api/auth/me', requireAuth, (req,res)=>{
  const u=req.dbUser;
  res.json({id:u.id,email:u.email,name:u.name,role:u.role,tabPerms:JSON.parse(u.tab_perms)});
});

// ════════════════════════════════════════════════════
//  ADMIN — USER MANAGEMENT
// ════════════════════════════════════════════════════
app.get('/api/admin/users', requireAuth, requireAdmin, async (req,res)=>{
  const { rows } = await q('SELECT id,email,name,role,active,tab_perms,created_at FROM users ORDER BY id');
  res.json(rows.map(u=>({...u,tabPerms:JSON.parse(u.tab_perms)})));
});

app.post('/api/admin/users', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const {email,name,role,password,tabPerms}=req.body;
    if(!email||!name||!password) return res.status(400).json({error:'Email, name and password required'});
    if(!validEmail(email)) return res.status(400).json({error:'Invalid email address format'});
    if(password.length<6)  return res.status(400).json({error:'Password must be at least 6 characters'});
    if(!['admin','user'].includes(role||'user')) return res.status(400).json({error:'Invalid role'});
    const perms=role==='admin'
      ? JSON.stringify(['edit','edit','edit','edit','edit','edit'])
      : JSON.stringify((tabPerms||[]).slice(0,6).map(p=>['none','view','edit'].includes(p)?p:'none'));
    const hash=await bcrypt.hash(password,10);
    const { rows } = await q(
      'INSERT INTO users(email,name,role,pwd_hash,active,tab_perms) VALUES($1,$2,$3,$4,TRUE,$5) RETURNING id',
      [email.toLowerCase().trim(), name, role||'user', hash, perms]
    );
    await audit(req.user.id,'ADD_USER',email);
    res.json({ok:true,id:rows[0].id});
  }catch(e){
    if(e.message.includes('unique') || e.message.includes('duplicate')) return res.status(409).json({error:'Email already exists'});
    res.status(500).json({error:e.message});
  }
});

app.patch('/api/admin/users/:id/permissions', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const {tabPerms,role}=req.body;
    const uid=parseInt(req.params.id);
    const { rows } = await q('SELECT * FROM users WHERE id=$1', [uid]);
    const target = rows[0];
    if(!target) return res.status(404).json({error:'User not found'});
    const newRole=role||target.role;
    const perms=newRole==='admin'
      ? JSON.stringify(['edit','edit','edit','edit','edit','edit'])
      : JSON.stringify((tabPerms||JSON.parse(target.tab_perms)).slice(0,6).map(p=>['none','view','edit'].includes(p)?p:'none'));
    await q("UPDATE users SET tab_perms=$1, role=$2, updated_at=NOW() WHERE id=$3", [perms,newRole,uid]);
    await audit(req.user.id,'EDIT_PERMS',`uid=${uid}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/admin/users/:id/revoke', requireAuth, requireAdmin, async (req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot revoke your own account'});
  await q("UPDATE users SET active=FALSE, updated_at=NOW() WHERE id=$1", [uid]);
  await audit(req.user.id,'REVOKE_USER',`uid=${uid}`);
  res.json({ok:true});
});

app.patch('/api/admin/users/:id/restore', requireAuth, requireAdmin, async (req,res)=>{
  await q("UPDATE users SET active=TRUE, updated_at=NOW() WHERE id=$1", [parseInt(req.params.id)]);
  await audit(req.user.id,'RESTORE_USER',`uid=${req.params.id}`);
  res.json({ok:true});
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot delete your own account'});
  await q('DELETE FROM users WHERE id=$1', [uid]);
  await audit(req.user.id,'DELETE_USER',`uid=${uid}`);
  res.json({ok:true});
});

app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const {new_password}=req.body;
    if(!new_password||new_password.length<6) return res.status(400).json({error:'Password must be at least 6 characters'});
    const hash=await bcrypt.hash(new_password,10);
    await q("UPDATE users SET pwd_hash=$1, pwd_changed_at=NOW(), updated_at=NOW() WHERE id=$2", [hash,parseInt(req.params.id)]);
    await audit(req.user.id,'RESET_PASSWORD',`uid=${req.params.id}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/admin/audit-log', requireAuth, requireAdmin, async (req,res)=>{
  const { rows } = await q(`
    SELECT a.id,a.action,a.detail,a.ts,u.email,u.name
    FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
    ORDER BY a.ts DESC LIMIT 200
  `);
  res.json(rows);
});

// ════════════════════════════════════════════════════
//  INSTANCES
// ════════════════════════════════════════════════════
app.get('/api/instances', requireAuth, async (req,res)=>{
  const { rows } = await q('SELECT * FROM instances ORDER BY id');
  res.json(rows);
});

app.post('/api/instances', requireAuth, requireAdmin, async (req,res)=>{
  try{
    const {name}=req.body;
    if(!name) return res.status(400).json({error:'Instance name required'});
    const { rows } = await q('INSERT INTO instances(name) VALUES($1) RETURNING id', [name]);
    await audit(req.user.id,'CREATE_INSTANCE',name);
    res.json({ok:true,id:rows[0].id});
  }catch(e){
    if(e.message.includes('unique')||e.message.includes('duplicate')) return res.status(409).json({error:'Instance name already exists'});
    res.status(500).json({error:e.message});
  }
});

// ════════════════════════════════════════════════════
//  FACULTY
// ════════════════════════════════════════════════════
app.get('/api/faculty', requireAuth, requireTabPerm(0,'view'), async (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const { rows } = await q('SELECT * FROM faculty WHERE instance_id=$1 ORDER BY faculty_id', [iid]);
  res.json(rows.map(r=>{
    const ds=JSON.parse(r.day_schedule||'{}');
    const dayKeys=Object.keys(ds);
    const firstDay=dayKeys.length>0?ds[dayKeys[0]]:null;
    return {id:r.faculty_id,name:r.name,load:r.load_periods,daySchedule:ds,days:dayKeys,
      start:firstDay?.start||'',end:firstDay?.end||''};
  }));
});

app.post('/api/faculty', requireAuth, requireTabPerm(0,'edit'), async (req,res)=>{
  const {instance_id,faculty_id,name,load,daySchedule}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!faculty_id||!name) return res.status(400).json({error:'instance_id, faculty_id and name required'});
  try{
    await q(`INSERT INTO faculty(instance_id,faculty_id,name,load_periods,day_schedule) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(instance_id,faculty_id) DO UPDATE SET name=EXCLUDED.name,load_periods=EXCLUDED.load_periods,day_schedule=EXCLUDED.day_schedule`,
      [iid,faculty_id,name,load||0,JSON.stringify(daySchedule||{})]);
    await audit(req.user.id,'UPSERT_FACULTY',`${faculty_id}/${name}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/faculty/:id', requireAuth, requireTabPerm(0,'edit'), async (req,res)=>{
  await q('DELETE FROM faculty WHERE id=$1', [parseInt(req.params.id)]);
  await audit(req.user.id,'DELETE_FACULTY',`id=${req.params.id}`);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════
//  SUBJECTS
// ════════════════════════════════════════════════════
app.get('/api/subjects', requireAuth, requireTabPerm(1,'view'), async (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const { rows } = await q('SELECT * FROM subjects WHERE instance_id=$1', [iid]);
  res.json(rows.map(r=>({id:r.subject_id,name:r.name,load:r.load_periods})));
});

app.post('/api/subjects', requireAuth, requireTabPerm(1,'edit'), async (req,res)=>{
  const {instance_id,subject_id,name,load}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!subject_id||!name) return res.status(400).json({error:'instance_id, subject_id and name required'});
  try{
    await q(`INSERT INTO subjects(instance_id,subject_id,name,load_periods) VALUES($1,$2,$3,$4)
      ON CONFLICT(instance_id,subject_id) DO UPDATE SET name=EXCLUDED.name,load_periods=EXCLUDED.load_periods`,
      [iid,subject_id,name,load||0]);
    await audit(req.user.id,'UPSERT_SUBJECT',`${subject_id}/${name}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/subjects/:id', requireAuth, requireTabPerm(1,'edit'), async (req,res)=>{
  await q('DELETE FROM subjects WHERE id=$1', [parseInt(req.params.id)]);
  await audit(req.user.id,'DELETE_SUBJECT',`id=${req.params.id}`);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════
//  SECTIONS
// ════════════════════════════════════════════════════
app.get('/api/sections', requireAuth, requireTabPerm(2,'view'), async (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const { rows } = await q('SELECT * FROM sections WHERE instance_id=$1', [iid]);
  res.json(rows.map(r=>({id:r.id,name:r.name,start:r.slot_start,end:r.slot_end,days:JSON.parse(r.class_days||'[]')})));
});

app.post('/api/sections', requireAuth, requireTabPerm(2,'edit'), async (req,res)=>{
  const {instance_id,name,slot_start,slot_end,days}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!name||!slot_start||!slot_end) return res.status(400).json({error:'All section fields required'});
  const { rows } = await q(
    'INSERT INTO sections(instance_id,name,slot_start,slot_end,class_days) VALUES($1,$2,$3,$4,$5) RETURNING id',
    [iid,name,slot_start,slot_end,JSON.stringify(days||[])]);
  await audit(req.user.id,'ADD_SECTION',`${name} ${slot_start}-${slot_end}`);
  res.json({ok:true,id:rows[0].id});
});

app.delete('/api/sections/:id', requireAuth, requireTabPerm(2,'edit'), async (req,res)=>{
  await q('DELETE FROM sections WHERE id=$1', [parseInt(req.params.id)]);
  await audit(req.user.id,'DELETE_SECTION',`id=${req.params.id}`);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════
//  ASSIGNMENTS
// ════════════════════════════════════════════════════
app.get('/api/assignments', requireAuth, requireTabPerm(3,'view'), async (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const { rows } = await q('SELECT * FROM assignments WHERE instance_id=$1 ORDER BY section_name', [iid]);
  res.json(rows);
});

app.post('/api/assignments', requireAuth, requireTabPerm(3,'edit'), async (req,res)=>{
  const {instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!section_name||!faculty_id||!subject_id) return res.status(400).json({error:'Required fields missing'});
  try{
    await q(`INSERT INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(instance_id,section_name,faculty_id,subject_id)
      DO UPDATE SET faculty_name=EXCLUDED.faculty_name,subject_name=EXCLUDED.subject_name,weekly_load=EXCLUDED.weekly_load`,
      [iid,section_name,faculty_id,subject_id,faculty_name||'',subject_name||'',weekly_load||0]);
    await audit(req.user.id,'UPSERT_ASSIGNMENT',`${section_name}/${faculty_id}/${subject_id}`);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/assignments/:id', requireAuth, requireTabPerm(3,'edit'), async (req,res)=>{
  await q('DELETE FROM assignments WHERE id=$1', [parseInt(req.params.id)]);
  await audit(req.user.id,'DELETE_ASSIGNMENT',`id=${req.params.id}`);
  res.json({ok:true});
});

app.delete('/api/assignments', requireAuth, requireTabPerm(3,'edit'), async (req,res)=>{
  const {instance_id,section_name,faculty_id,subject_id}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!section_name||!faculty_id||!subject_id) return res.status(400).json({error:'instance_id, section_name, faculty_id, subject_id required'});
  await q('DELETE FROM assignments WHERE instance_id=$1 AND section_name=$2 AND faculty_id=$3 AND subject_id=$4',
    [iid,section_name,faculty_id,subject_id]);
  await audit(req.user.id,'DELETE_ASSIGNMENT',`${section_name}/${faculty_id}/${subject_id}`);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════
//  BULK SYNC
// ════════════════════════════════════════════════════
app.post('/api/sync', requireAuth, requireAnyEditPerm, async (req,res)=>{
  const {instance_id,data}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!data) return res.status(400).json({error:'Valid instance_id and data required'});
  const isAdmin=req.dbUser.role==='admin';
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  const canEdit=(i)=>isAdmin||perms[i]==='edit';
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    if(canEdit(0)){
      await client.query('DELETE FROM faculty WHERE instance_id=$1',[iid]);
      for(const f of (data.faculty||[])){
        await client.query('INSERT INTO faculty(instance_id,faculty_id,name,load_periods,day_schedule) VALUES($1,$2,$3,$4,$5)',
          [iid,f.id,f.name,f.load||0,JSON.stringify(f.daySchedule||{})]);
      }
    }
    if(canEdit(1)){
      await client.query('DELETE FROM subjects WHERE instance_id=$1',[iid]);
      for(const s of (data.subjects||[])){
        await client.query('INSERT INTO subjects(instance_id,subject_id,name,load_periods) VALUES($1,$2,$3,$4)',
          [iid,s.id,s.name,s.load||0]);
      }
    }
    if(canEdit(2)){
      await client.query('DELETE FROM sections WHERE instance_id=$1',[iid]);
      for(const s of (data.sections||[])){
        await client.query('INSERT INTO sections(instance_id,name,slot_start,slot_end,class_days) VALUES($1,$2,$3,$4,$5)',
          [iid,s.name,s.start,s.end,JSON.stringify(s.days||[])]);
      }
    }
    if(canEdit(3)){
      await client.query('DELETE FROM assignments WHERE instance_id=$1',[iid]);
      for(const a of (data.assignments||[])){
        await client.query(`INSERT INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load)
          VALUES($1,$2,$3,$4,$5,$6,$7)`,
          [iid,a.sectionName,a.facultyId,a.subjectId,a.facultyName||'',a.subjectName||'',a.weeklyLoad||0]);
      }
    }
    if(canEdit(0)||canEdit(2)){
      await client.query('DELETE FROM timetables WHERE instance_id=$1',[iid]);
    }
    await client.query('UPDATE instances SET data_version=data_version+1 WHERE id=$1',[iid]);
    await client.query('COMMIT');
    const ver=await client.query('SELECT data_version FROM instances WHERE id=$1',[iid]);
    await audit(req.user.id,'BULK_SYNC',`instance=${iid}`);
    res.json({ok:true,data_version:ver.rows[0]?.data_version||1});
  }catch(e){
    await client.query('ROLLBACK');
    res.status(500).json({error:e.message});
  }finally{ client.release(); }
});

// LOAD instance data
app.get('/api/sync/:instance_id', requireAuth, async (req,res)=>{
  const iid=parseInstId(req.params.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const isAdmin=req.dbUser.role==='admin';
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  const canView=(i)=>isAdmin||(perms[i]||'none')!=='none';

  const faculty=canView(0)?(await q('SELECT * FROM faculty WHERE instance_id=$1 ORDER BY faculty_id',[iid])).rows
    .map(r=>{
      const ds=JSON.parse(r.day_schedule||'{}');
      const dayKeys=Object.keys(ds);
      const firstDay=dayKeys.length>0?ds[dayKeys[0]]:null;
      return {id:r.faculty_id,name:r.name,load:r.load_periods,daySchedule:ds,days:dayKeys,
        start:firstDay?.start||'',end:firstDay?.end||''};
    }):[];
  const subjects=canView(1)?(await q('SELECT * FROM subjects WHERE instance_id=$1',[iid])).rows
    .map(r=>({id:r.subject_id,name:r.name,load:r.load_periods})):[];
  const sections=canView(2)?(await q('SELECT * FROM sections WHERE instance_id=$1',[iid])).rows
    .map(r=>({name:r.name,start:r.slot_start,end:r.slot_end,days:JSON.parse(r.class_days||'[]')})):[];
  const assignments=canView(3)?(await q('SELECT * FROM assignments WHERE instance_id=$1',[iid])).rows
    .map(r=>({sectionName:r.section_name,facultyId:r.faculty_id,subjectId:r.subject_id,
      facultyName:r.faculty_name,subjectName:r.subject_name,weeklyLoad:r.weekly_load})):[];
  const inst=(await q('SELECT data_version FROM instances WHERE id=$1',[iid])).rows[0];
  res.json({faculty,subjects,sections,assignments,data_version:inst?.data_version||1});
});

// ════════════════════════════════════════════════════
//  TIMETABLE
// ════════════════════════════════════════════════════
app.get('/api/timetable/:instance_id', requireAuth, requireTabPerm(4,'view'), async (req,res)=>{
  const iid=parseInstId(req.params.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const { rows } = await q('SELECT * FROM timetables WHERE instance_id=$1',[iid]);
  if(!rows[0]) return res.status(404).json({error:'No timetable generated yet'});
  const row=rows[0];
  res.json({tt:JSON.parse(row.tt_json),secSlots:JSON.parse(row.sec_slots_json),generatedAt:row.generated_at});
});

app.post('/api/timetable/:instance_id', requireAuth, requireTabPerm(4,'edit'), async (req,res)=>{
  const {tt,secSlots}=req.body;
  const iid=parseInstId(req.params.instance_id);
  if(!iid||!tt||!secSlots) return res.status(400).json({error:'tt and secSlots required'});
  await q(`INSERT INTO timetables(instance_id,generated_by,tt_json,sec_slots_json) VALUES($1,$2,$3,$4)
    ON CONFLICT(instance_id) DO UPDATE SET generated_at=NOW(),generated_by=EXCLUDED.generated_by,
    tt_json=EXCLUDED.tt_json,sec_slots_json=EXCLUDED.sec_slots_json`,
    [iid,req.user.id,JSON.stringify(tt),JSON.stringify(secSlots)]);
  await audit(req.user.id,'SAVE_TIMETABLE',`instance=${iid}`);
  res.json({ok:true});
});

// ════════════════════════════════════════════════════
//  HEALTH + ERROR HANDLER
// ════════════════════════════════════════════════════
app.get('/api/health',(req,res)=>res.json({status:'ok',time:new Date().toISOString()}));

app.use((err,req,res,next)=>{
  console.error(err.stack||err);
  res.status(500).json({error:'Internal server error'});
});

// ════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════
initSchema().then(()=>{
  app.listen(PORT,()=>console.log(`\n🚀 Timetable backend (PostgreSQL) running at http://localhost:${PORT}\n`));
}).catch(e=>{
  console.error('❌ Failed to initialize database:',e.message);
  process.exit(1);
});
