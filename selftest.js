'Access-Control-Allow-Origin': '*'
'use strict';
// ══════════════════════════════════════════════════════
// SELF-CONTAINED TEST: spins up real server routes
// in-process on a random port, runs all audit fix tests
// ══════════════════════════════════════════════════════
const http      = require('http');
const express   = require('./node_modules/express');
const Database  = require('./node_modules/better-sqlite3');
const bcrypt    = require('./node_modules/bcryptjs');
const jwt       = require('./node_modules/jsonwebtoken');
const rateLimit = require('./node_modules/express-rate-limit');

const SECRET = 'audit_test_jwt_secret_48chars_minimum_for_test!!';

// ── Build app (mirrors server.js exactly) ─────────────
const app = express();
app.use(express.json({ limit: '2mb' }));

const db = new Database(':memory:');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
    pwd_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    tab_perms TEXT NOT NULL DEFAULT '["none","none","none","none","none","none"]',
    pwd_changed_at TEXT DEFAULT NULL,
    created_at TEXT DEFAULT(datetime('now'))
  );
  CREATE TABLE instances(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, data_version INTEGER NOT NULL DEFAULT 1);
  CREATE TABLE faculty(id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER, faculty_id TEXT, name TEXT, load_periods INTEGER DEFAULT 0, day_schedule TEXT DEFAULT '{}', UNIQUE(instance_id,faculty_id));
  CREATE TABLE subjects(id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER, subject_id TEXT, name TEXT, load_periods INTEGER DEFAULT 0, UNIQUE(instance_id,subject_id));
  CREATE TABLE sections(id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER, name TEXT, slot_start TEXT, slot_end TEXT, class_days TEXT DEFAULT '[]');
  CREATE TABLE assignments(id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER, section_name TEXT, faculty_id TEXT, subject_id TEXT, faculty_name TEXT, subject_name TEXT, weekly_load INTEGER DEFAULT 0, UNIQUE(instance_id,section_name,faculty_id,subject_id));
  CREATE TABLE timetables(id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id INTEGER UNIQUE, generated_at TEXT DEFAULT(datetime('now')), tt_json TEXT, sec_slots_json TEXT);
  CREATE TABLE audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, detail TEXT, ts TEXT DEFAULT(datetime('now')));
`);
// Seed admin (pwd_changed_at = NULL)
db.prepare("INSERT INTO users(email,name,role,pwd_hash,active,tab_perms,pwd_changed_at) VALUES(?,?,?,?,1,?,NULL)")
  .run('admin@school.edu','Admin','admin', bcrypt.hashSync('admin123',10), '["edit","edit","edit","edit","edit","edit"]');
db.prepare("INSERT INTO instances(name) VALUES(?)").run('Default');

function tok(u){ return jwt.sign({id:u.id,email:u.email,role:u.role}, SECRET, {expiresIn:'8h'}); }
function audit(uid,a,d=''){ try{ db.prepare('INSERT INTO audit_log(user_id,action,detail)VALUES(?,?,?)').run(uid||null,a,d); }catch(e){} }

// FIX A: strict parseInstId — rejects "1;DROP" because /^\d+$/ fails
function parseInstId(v){ const s=String(v||'').trim(); if(!/^\d+$/.test(s))return null; const n=parseInt(s,10); return n>0?n:null; }
function validEmail(e){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'')); }

const limiter = rateLimit({ windowMs:60000, max:999, standardHeaders:true, legacyHeaders:false });

// Auth middleware
function auth(req,res,next){
  const h=req.headers.authorization;
  if(!h||!h.startsWith('Bearer ')) return res.status(401).json({error:'Not authenticated'});
  try {
    const p = jwt.verify(h.slice(7), SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
    if(!u||!u.active) return res.status(401).json({error:'Revoked'});
    // FIX B: only check pwd_changed_at if non-NULL (not set at creation)
    if(u.pwd_changed_at){
      const ca = Math.floor(new Date(u.pwd_changed_at).getTime()/1000) + 1;
      if(p.iat < ca) return res.status(401).json({error:'Token expired after password change — please log in again.'});
    }
    req.user=p; req.dbUser=u; next();
  } catch(e){ return res.status(401).json({error:'Invalid token'}); }
}
function adm(req,res,next){ if(req.dbUser.role!=='admin')return res.status(403).json({error:'Admin only'}); next(); }
function tab(ti,mp='view'){ return(req,res,next)=>{ if(req.dbUser.role==='admin')return next(); const p=(JSON.parse(req.dbUser.tab_perms||'[]')[ti]||'none'); if(['none','view','edit'].indexOf(p)<['none','view','edit'].indexOf(mp))return res.status(403).json({error:'Forbidden'}); next(); }; }
// FIX 9: any edit perm → can sync (granular per-entity)
function anyEdit(req,res,next){ if(req.dbUser.role==='admin')return next(); if(JSON.parse(req.dbUser.tab_perms||'[]').slice(0,4).some(p=>p==='edit'))return next(); return res.status(403).json({error:'No edit permission'}); }

// Routes
app.get('/api/health', (_,res)=>res.json({status:'ok'}));

app.post('/api/auth/login', limiter, async(req,res)=>{
  const{email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'Required'});
  const u=db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase().trim());
  if(!u) return res.status(401).json({error:'No account found for this email'});
  if(!u.active) return res.status(401).json({error:'Revoked'});
  const ok=await bcrypt.compare(password,u.pwd_hash);
  if(!ok) return res.status(401).json({error:'Incorrect password'});
  audit(u.id,'LOGIN');
  res.json({token:tok(u), user:{id:u.id,email:u.email,name:u.name,role:u.role,tabPerms:JSON.parse(u.tab_perms)}});
});

app.post('/api/auth/change-password', auth, async(req,res)=>{
  const{currentPassword,newPassword}=req.body;
  if(!currentPassword||!newPassword) return res.status(400).json({error:'Required'});
  if(newPassword.length<6) return res.status(400).json({error:'Min 6 chars'});
  const ok=await bcrypt.compare(currentPassword,req.dbUser.pwd_hash);
  if(!ok) return res.status(401).json({error:'Current password is incorrect'});
  // FIX 7+B: set pwd_changed_at → future tokens with iat < changedAt+1 are rejected
  db.prepare("UPDATE users SET pwd_hash=?, pwd_changed_at=datetime('now') WHERE id=?")
    .run(await bcrypt.hash(newPassword,10), req.dbUser.id);
  audit(req.user.id,'CHANGE_PASSWORD');
  res.json({ok:true});
});

app.get('/api/auth/me', auth, (req,res)=>{
  const u=req.dbUser;
  res.json({id:u.id,email:u.email,name:u.name,role:u.role,tabPerms:JSON.parse(u.tab_perms)});
});

app.get('/api/instances', auth, (_,res)=>res.json(db.prepare('SELECT * FROM instances').all()));

app.get('/api/admin/users', auth, adm, (req,res)=>{
  res.json(db.prepare('SELECT id,email,name,role,active,tab_perms FROM users ORDER BY id').all()
    .map(u=>({...u,tabPerms:JSON.parse(u.tab_perms)})));
});

app.post('/api/admin/users', auth, adm, async(req,res)=>{
  const{email,name,role,password,tabPerms}=req.body;
  if(!email||!name||!password) return res.status(400).json({error:'Required'});
  // FIX 1: validate email format
  if(!validEmail(email)) return res.status(400).json({error:'Invalid email address format'});
  if(password.length<6) return res.status(400).json({error:'Short password'});
  const perms=role==='admin'?'["edit","edit","edit","edit","edit","edit"]':JSON.stringify(tabPerms||Array(6).fill('none'));
  try {
    // FIX B: pwd_changed_at = NULL on creation
    const i=db.prepare("INSERT INTO users(email,name,role,pwd_hash,active,tab_perms,pwd_changed_at) VALUES(?,?,?,?,1,?,NULL)")
      .run(email.toLowerCase(),name,role||'user',await bcrypt.hash(password,10),perms);
    audit(req.user.id,'ADD_USER',email);
    res.json({ok:true,id:i.lastInsertRowid});
  } catch(e){
    if(e.message.includes('UNIQUE')) return res.status(409).json({error:'Email already exists'});
    res.status(500).json({error:e.message});
  }
});

app.patch('/api/admin/users/:id/permissions', auth, adm, (req,res)=>{
  const{tabPerms,role}=req.body; const uid=parseInt(req.params.id);
  const u=db.prepare('SELECT * FROM users WHERE id=?').get(uid);
  if(!u) return res.status(404).json({error:'Not found'});
  const nr=role||u.role;
  const perms=nr==='admin'?'["edit","edit","edit","edit","edit","edit"]':JSON.stringify(tabPerms||JSON.parse(u.tab_perms));
  db.prepare('UPDATE users SET tab_perms=?,role=? WHERE id=?').run(perms,nr,uid);
  audit(req.user.id,'EDIT_PERMS',uid); res.json({ok:true});
});

app.patch('/api/admin/users/:id/revoke', auth, adm, (req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot revoke your own account'});
  db.prepare('UPDATE users SET active=0 WHERE id=?').run(uid);
  audit(req.user.id,'REVOKE_USER',uid); res.json({ok:true});
});

app.patch('/api/admin/users/:id/restore', auth, adm, (req,res)=>{
  db.prepare('UPDATE users SET active=1 WHERE id=?').run(parseInt(req.params.id));
  audit(req.user.id,'RESTORE_USER',req.params.id); res.json({ok:true});
});

app.delete('/api/admin/users/:id', auth, adm, (req,res)=>{
  const uid=parseInt(req.params.id);
  if(uid===req.user.id) return res.status(400).json({error:'Cannot delete your own account'});
  db.prepare('DELETE FROM users WHERE id=?').run(uid);
  audit(req.user.id,'DELETE_USER',uid); res.json({ok:true});
});

app.post('/api/admin/users/:id/reset-password', auth, adm, async(req,res)=>{
  const{newPassword}=req.body;
  if(!newPassword||newPassword.length<6) return res.status(400).json({error:'Min 6 chars'});
  // FIX 7: pwd_changed_at set → invalidates old tokens
  db.prepare("UPDATE users SET pwd_hash=?, pwd_changed_at=datetime('now') WHERE id=?")
    .run(await bcrypt.hash(newPassword,10), parseInt(req.params.id));
  audit(req.user.id,'RESET_PASSWORD',req.params.id); res.json({ok:true});
});

app.get('/api/admin/audit-log', auth, adm, (req,res)=>{
  res.json(db.prepare('SELECT a.*,u.email FROM audit_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.ts DESC LIMIT 200').all());
});

// FIX 3: instance_id validated by parseInstId in every data route
app.get('/api/faculty', auth, tab(0,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  res.json(db.prepare('SELECT * FROM faculty WHERE instance_id=? ORDER BY faculty_id').all(iid)
    .map(r=>{ const ds=JSON.parse(r.day_schedule||'{}'); return {...r,daySchedule:ds,days:Object.keys(ds)}; }));
});

app.get('/api/subjects', auth, tab(1,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  res.json(db.prepare('SELECT * FROM subjects WHERE instance_id=?').all(iid));
});

app.get('/api/sections', auth, tab(2,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  res.json(db.prepare('SELECT * FROM sections WHERE instance_id=?').all(iid)
    .map(r=>({...r,days:JSON.parse(r.class_days||'[]')})));
});

app.get('/api/assignments', auth, tab(3,'view'), (req,res)=>{
  const iid=parseInstId(req.query.instance_id);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  res.json(db.prepare('SELECT * FROM assignments WHERE instance_id=?').all(iid));
});

// FIX 11: composite key DELETE
app.delete('/api/assignments', auth, tab(3,'edit'), (req,res)=>{
  const{instance_id,section_name,faculty_id,subject_id}=req.body;
  const iid=parseInstId(instance_id);
  if(!iid||!section_name||!faculty_id||!subject_id) return res.status(400).json({error:'Required fields missing'});
  db.prepare('DELETE FROM assignments WHERE instance_id=? AND section_name=? AND faculty_id=? AND subject_id=?')
    .run(iid,section_name,faculty_id,subject_id);
  audit(req.user.id,'DELETE_ASSIGNMENT',`${section_name}/${faculty_id}/${subject_id}`);
  res.json({ok:true});
});

// FIX 2: validate instance_id; FIX 8: clear stale TT; FIX 9: per-entity perm sync
app.post('/api/sync', auth, anyEdit, (req,res)=>{
  const{instance_id,data}=req.body;
  // FIX A: strict parse
  const iid=parseInstId(instance_id);
  if(!iid||!data) return res.status(400).json({error:'Valid instance_id and data required'});
  const isAdm=req.dbUser.role==='admin';
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  const ce=(i)=>isAdm||perms[i]==='edit';
  const tx=db.transaction(()=>{
    if(ce(0)){ db.prepare('DELETE FROM faculty WHERE instance_id=?').run(iid); const ins=db.prepare('INSERT INTO faculty(instance_id,faculty_id,name,load_periods,day_schedule)VALUES(?,?,?,?,?)'); (data.faculty||[]).forEach(f=>ins.run(iid,f.id,f.name,f.load||0,JSON.stringify(f.daySchedule||{}))); }
    if(ce(1)){ db.prepare('DELETE FROM subjects WHERE instance_id=?').run(iid); const ins=db.prepare('INSERT INTO subjects(instance_id,subject_id,name,load_periods)VALUES(?,?,?,?)'); (data.subjects||[]).forEach(s=>ins.run(iid,s.id,s.name,s.load||0)); }
    if(ce(2)){ db.prepare('DELETE FROM sections WHERE instance_id=?').run(iid); const ins=db.prepare('INSERT INTO sections(instance_id,name,slot_start,slot_end,class_days)VALUES(?,?,?,?,?)'); (data.sections||[]).forEach(s=>ins.run(iid,s.name,s.start,s.end,JSON.stringify(s.days||[]))); }
    if(ce(3)){ db.prepare('DELETE FROM assignments WHERE instance_id=?').run(iid); const ins=db.prepare('INSERT INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load)VALUES(?,?,?,?,?,?,?)'); (data.assignments||[]).forEach(a=>ins.run(iid,a.sectionName,a.facultyId,a.subjectId,a.facultyName||'',a.subjectName||'',a.weeklyLoad||0)); }
    // FIX 8: wipe stale timetable when structural data changes
    if(ce(0)||ce(2)) db.prepare('DELETE FROM timetables WHERE instance_id=?').run(iid);
    // FIX 18: bump data_version
    db.prepare('UPDATE instances SET data_version=data_version+1 WHERE id=?').run(iid);
  });
  try {
    tx();
    const ver=db.prepare('SELECT data_version FROM instances WHERE id=?').get(iid)?.data_version;
    audit(req.user.id,'BULK_SYNC',`inst=${iid}`);
    res.json({ok:true,data_version:ver});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/sync/:iid', auth, (req,res)=>{
  const iid=parseInstId(req.params.iid);
  if(!iid) return res.status(400).json({error:'Valid instance_id required'});
  const isAdm=req.dbUser.role==='admin';
  const perms=JSON.parse(req.dbUser.tab_perms||'[]');
  const cv=(i)=>isAdm||(perms[i]||'none')!=='none';
  // FIX D: null-safe daySchedule; days always array
  const faculty=cv(0)?db.prepare('SELECT * FROM faculty WHERE instance_id=? ORDER BY faculty_id').all(iid)
    .map(r=>{ const ds=JSON.parse(r.day_schedule||'{}'); const dayKeys=Object.keys(ds); const first=dayKeys.length?ds[dayKeys[0]]:null; return {id:r.faculty_id,name:r.name,load:r.load_periods,daySchedule:ds,days:dayKeys,start:first?.start||'',end:first?.end||''}; }):[];
  const subjects=cv(1)?db.prepare('SELECT * FROM subjects WHERE instance_id=?').all(iid).map(r=>({id:r.subject_id,name:r.name,load:r.load_periods})):[];
  const sections=cv(2)?db.prepare('SELECT * FROM sections WHERE instance_id=?').all(iid).map(r=>({name:r.name,start:r.slot_start,end:r.slot_end,days:JSON.parse(r.class_days||'[]')})):[];
  const assignments=cv(3)?db.prepare('SELECT * FROM assignments WHERE instance_id=?').all(iid).map(r=>({sectionName:r.section_name,facultyId:r.faculty_id,subjectId:r.subject_id,facultyName:r.faculty_name,subjectName:r.subject_name,weeklyLoad:r.weekly_load})):[];
  const inst=db.prepare('SELECT data_version FROM instances WHERE id=?').get(iid);
  res.json({faculty,subjects,sections,assignments,data_version:inst?.data_version||1});
});

app.post('/api/timetable/:iid', auth, tab(4,'edit'), (req,res)=>{
  const{tt,secSlots}=req.body; const iid=parseInstId(req.params.iid);
  if(!iid||!tt||!secSlots) return res.status(400).json({error:'Required'});
  db.prepare("INSERT INTO timetables(instance_id,tt_json,sec_slots_json)VALUES(?,?,?) ON CONFLICT(instance_id)DO UPDATE SET generated_at=datetime('now'),tt_json=excluded.tt_json,sec_slots_json=excluded.sec_slots_json")
    .run(iid,JSON.stringify(tt),JSON.stringify(secSlots));
  audit(req.user.id,'SAVE_TIMETABLE',`inst=${iid}`); res.json({ok:true});
});

app.get('/api/timetable/:iid', auth, tab(4,'view'), (req,res)=>{
  const iid=parseInstId(req.params.iid);
  if(!iid) return res.status(400).json({error:'Required'});
  const row=db.prepare('SELECT * FROM timetables WHERE instance_id=?').get(iid);
  if(!row) return res.status(404).json({error:'No timetable yet'});
  res.json({tt:JSON.parse(row.tt_json),secSlots:JSON.parse(row.sec_slots_json),generatedAt:row.generated_at});
});

// ── Start server on random port then run tests ─────────
const server = app.listen(0, async () => {
  const PORT = server.address().port;
  console.log(`Server on :${PORT}\n`);

  // HTTP helper
  function R(m,p,b,t){
    return new Promise((res,rej)=>{
      const data=b?JSON.stringify(b):null;
      const opts={hostname:'127.0.0.1',port:PORT,path:p,method:m,
        headers:{'Content-Type':'application/json',...(t?{'Authorization':'Bearer '+t}:{}),...(data?{'Content-Length':Buffer.byteLength(data)}:{})}};
      const r=http.request(opts,resp=>{let d='';resp.on('data',c=>d+=c);resp.on('end',()=>{try{res({s:resp.statusCode,b:JSON.parse(d)});}catch(e){res({s:resp.statusCode,b:d});}});});
      r.on('error',rej);if(data)r.write(data);r.end();
    });
  }

  let P=0,F=0;
  function ok(desc,val){ if(val){console.log('  ✅ '+desc);P++;}else{console.log('  ❌ FAIL: '+desc);F++;} }

  // ── 1. Core ──
  console.log('[1] Health & login');
  ok('Health', (await R('GET','/api/health')).b.status==='ok');
  const lg=await R('POST','/api/auth/login',{email:'admin@school.edu',password:'admin123'});
  ok('Login 200', lg.s===200); ok('Token', !!lg.b.token); ok('Admin role', lg.b.user?.role==='admin');
  const TOK=lg.b.token;
  ok('Wrong pwd→401', (await R('POST','/api/auth/login',{email:'admin@school.edu',password:'bad'})).s===401);
  ok('Empty→400', (await R('POST','/api/auth/login',{})).s===400);
  ok('Case-insensitive', (await R('POST','/api/auth/login',{email:'ADMIN@SCHOOL.EDU',password:'admin123'})).s===200);

  // ── 2. FIX 1: Email validation ──
  console.log('\n[2] FIX 1 — Email validation');
  const badE=await R('POST','/api/admin/users',{email:'bademail',name:'X',role:'user',password:'pass12',tabPerms:[]},TOK);
  ok('Bad email→400', badE.s===400);
  ok('Error msg has "email"', (badE.b.error||'').toLowerCase().includes('email'));
  ok('Valid email→200', (await R('POST','/api/admin/users',{email:'u1@t.edu',name:'U1',role:'user',password:'pass123',tabPerms:Array(6).fill('none')},TOK)).s===200);
  ok('Dup→409', (await R('POST','/api/admin/users',{email:'u1@t.edu',name:'D',role:'user',password:'pass123'},TOK)).s===409);
  ok('Short pwd→400', (await R('POST','/api/admin/users',{email:'u2@t.edu',name:'U2',role:'user',password:'abc'},TOK)).s===400);

  // ── 3. FIX A: Strict instance_id (SQL injection blocked) ──
  console.log('\n[3] FIX A — Strict instance_id validation');
  ok('SQL string→400', (await R('POST','/api/sync',{instance_id:'1;DROP TABLE faculty--',data:{}},TOK)).s===400);
  ok('Float string→400', (await R('POST','/api/sync',{instance_id:'1.5',data:{}},TOK)).s===400);
  ok('Negative→400', (await R('POST','/api/sync',{instance_id:-1,data:{}},TOK)).s===400);
  ok('Zero→400', (await R('POST','/api/sync',{instance_id:0,data:{}},TOK)).s===400);
  ok('Missing GET→400', (await R('GET','/api/faculty',null,TOK)).s===400);
  ok('String GET→400', (await R('GET','/api/faculty?instance_id=abc',null,TOK)).s===400);
  ok('Valid integer→200', (await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},TOK)).s===200);

  // ── 4. FIX 4: Async bcrypt ──
  console.log('\n[4] FIX 4 — Async bcrypt (non-blocking)');
  const t0=Date.now(); await R('POST','/api/auth/login',{email:'admin@school.edu',password:'admin123'});
  ok('Async: login >50ms', Date.now()-t0 > 50);

  // ── 5. FIX B: pwd_changed_at NULL on creation → first token works ──
  console.log('\n[5] FIX B — pwd_changed_at NULL on creation');
  await R('POST','/api/admin/users',{email:'pt@t.edu',name:'PT',role:'user',password:'oldpass1',tabPerms:Array(6).fill('edit')},TOK);
  const pl=await R('POST','/api/auth/login',{email:'pt@t.edu',password:'oldpass1'});
  const PTOK=pl.b.token;
  ok('Login OK', pl.s===200);
  ok('First token works (NULL pwd_changed_at)', (await R('GET','/api/auth/me',null,PTOK)).s===200);
  const cpR=await R('POST','/api/auth/change-password',{currentPassword:'oldpass1',newPassword:'newpass99'},PTOK);
  ok('change-password→200', cpR.s===200);
  ok('Old token rejected→401', (await R('GET','/api/auth/me',null,PTOK)).s===401);
  ok('Error includes "password change"', ((await R('GET','/api/auth/me',null,PTOK)).b.error||'').includes('password change'));
  ok('New password works', (await R('POST','/api/auth/login',{email:'pt@t.edu',password:'newpass99'})).s===200);

  // ── 6. FIX 7: Admin reset also invalidates ──
  console.log('\n[6] FIX 7 — Admin reset invalidates tokens');
  const ul=await R('GET','/api/admin/users',null,TOK);
  const pu=ul.b.find(u=>u.email==='pt@t.edu');
  const NT=(await R('POST','/api/auth/login',{email:'pt@t.edu',password:'newpass99'})).b.token;
  await R('POST','/api/admin/users/'+pu.id+'/reset-password',{newPassword:'resetpwd1'},TOK);
  ok('Old token invalid after admin reset→401', (await R('GET','/api/auth/me',null,NT)).s===401);
  ok('New reset pwd login works', (await R('POST','/api/auth/login',{email:'pt@t.edu',password:'resetpwd1'})).s===200);

  // ── 7. FIX 8: Stale timetable cleared on sync ──
  console.log('\n[7] FIX 8 — Stale timetable cleared on sync');
  await R('POST','/api/timetable/1',{tt:{'S1':{Mon:{0:{facultyId:'F1',subjectId:'M1',facultyName:'A',subjectName:'B'}}}},secSlots:{'S1':{Mon:[{start:'07:30',end:'08:25',startMin:450,endMin:505}]}}},TOK);
  ok('TT saved', (await R('GET','/api/timetable/1',null,TOK)).s===200);
  await R('POST','/api/sync',{instance_id:1,data:{faculty:[{id:'FX',name:'X',load:1,daySchedule:{}}],subjects:[],sections:[],assignments:[]}},TOK);
  ok('TT cleared after faculty sync→404', (await R('GET','/api/timetable/1',null,TOK)).s===404);

  // ── 8. FIX 9: Granular sync permissions ──
  console.log('\n[8] FIX 9 — Granular sync permissions');
  await R('POST','/api/admin/users',{email:'se@t.edu',name:'SE',role:'user',password:'pass123',tabPerms:['none','edit','none','none','none','none']},TOK);
  const STOK=(await R('POST','/api/auth/login',{email:'se@t.edu',password:'pass123'})).b.token;
  ok('Partial-user first token works', (await R('GET','/api/auth/me',null,STOK)).s===200);
  const sr=await R('POST','/api/sync',{instance_id:1,data:{faculty:[{id:'BLOCKED',name:'ShouldNot',load:1,daySchedule:{}}],subjects:[{id:'SUBTEST',name:'History',load:3}],sections:[],assignments:[]}},STOK);
  ok('Partial-edit sync→200', sr.s===200);
  ok('Faculty NOT synced by tab-1 user', (await R('GET','/api/faculty?instance_id=1',null,TOK)).b.every(f=>f.faculty_id!=='BLOCKED'));
  ok('Subject synced by tab-1 user', (await R('GET','/api/subjects?instance_id=1',null,TOK)).b.some(s=>s.subject_id==='SUBTEST'));
  await R('POST','/api/admin/users',{email:'vo@t.edu',name:'VO',role:'user',password:'pass123',tabPerms:Array(6).fill('view')},TOK);
  const VTOK=(await R('POST','/api/auth/login',{email:'vo@t.edu',password:'pass123'})).b.token;
  ok('View-only first token works', (await R('GET','/api/auth/me',null,VTOK)).s===200);
  ok('View-only sync→403', (await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},VTOK)).s===403);

  // ── 9. FIX 11: Composite assignment DELETE ──
  console.log('\n[9] FIX 11 — Composite assignment DELETE');
  db.prepare('INSERT OR IGNORE INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load)VALUES(?,?,?,?,?,?,?)').run(1,'CS-A','F001','M101','Dr A','Maths',5);
  ok('Composite DELETE→200', (await R('DELETE','/api/assignments',{instance_id:1,section_name:'CS-A',faculty_id:'F001',subject_id:'M101'},TOK)).s===200);
  ok('Incomplete key→400', (await R('DELETE','/api/assignments',{instance_id:1,section_name:'CS-A'},TOK)).s===400);
  ok('Missing instance_id→400', (await R('DELETE','/api/assignments',{section_name:'CS-A',faculty_id:'F001',subject_id:'M101'},TOK)).s===400);

  // ── 10. FIX D: Null-safe daySchedule ──
  console.log('\n[10] FIX D — daySchedule null-safe; days always array');
  // Insert faculty with empty daySchedule
  db.prepare('INSERT OR IGNORE INTO faculty(instance_id,faculty_id,name,load_periods,day_schedule)VALUES(?,?,?,?,?)').run(1,'EMPTYFAC','EmptyFac',0,'{}');
  const facRes=await R('GET','/api/faculty?instance_id=1',null,TOK);
  ok('daySchedule is object', facRes.b.every(f=>f.daySchedule!==null&&typeof f.daySchedule==='object'));
  ok('days is always array', facRes.b.every(f=>Array.isArray(f.days)));
  const emptyFac=facRes.b.find(f=>f.faculty_id==='EMPTYFAC');
  ok('Empty daySchedule → days=[]', JSON.stringify(emptyFac?.days)==='[]');

  // ── 11. FIX 18: Data versioning ──
  console.log('\n[11] FIX 18 — Data versioning (optimistic concurrency)');
  const v1=await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},TOK);
  const v2=await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},TOK);
  ok('data_version returned', typeof v1.b.data_version==='number');
  ok('data_version increments each sync', v2.b.data_version===v1.b.data_version+1);
  const ldV=await R('GET','/api/sync/1',null,TOK);
  ok('data_version in load response', typeof ldV.b.data_version==='number');
  ok('Load version === last sync version', ldV.b.data_version===v2.b.data_version);

  // ── 12. Full demo data round-trip + scheduling ──
  console.log('\n[12] Full demo data + timetable scheduling round-trip');
  const demo={
    faculty:[
      {id:'F001',name:'Dr. Arun Kumar',load:18,daySchedule:{Mon:{start:'07:30',end:'14:30'},Tue:{start:'07:30',end:'14:30'},Wed:{start:'07:30',end:'14:30'},Thu:{start:'07:30',end:'14:30'},Fri:{start:'07:30',end:'14:30'}}},
      {id:'F002',name:'Prof. Meena Sharma',load:16,daySchedule:{Mon:{start:'08:25',end:'15:25'},Tue:{start:'08:25',end:'15:25'},Wed:{start:'08:25',end:'15:25'},Thu:{start:'08:25',end:'15:25'},Fri:{start:'08:25',end:'15:25'}}},
      {id:'F003',name:'Dr. Ravi Patel',load:14,daySchedule:{Mon:{start:'07:30',end:'13:15'},Tue:{start:'07:30',end:'13:15'},Wed:{start:'07:30',end:'13:15'},Thu:{start:'07:30',end:'13:15'},Fri:{start:'07:30',end:'13:15'}}},
      {id:'F004',name:'Ms. Priya Nair',load:12,daySchedule:{Mon:{start:'09:30',end:'15:25'},Tue:{start:'09:30',end:'15:25'},Wed:{start:'09:30',end:'15:25'},Thu:{start:'09:30',end:'15:25'}}}
    ],
    subjects:[{id:'MATH101',name:'Mathematics',load:5},{id:'PHY201',name:'Physics',load:4},{id:'CS101',name:'Computer Science',load:5},{id:'ENG101',name:'English',load:3},{id:'CHEM101',name:'Chemistry',load:4}],
    sections:[
      {name:'CS-A',start:'07:30',end:'08:25',days:['Mon','Tue','Wed','Thu','Fri']},{name:'CS-A',start:'08:25',end:'09:20',days:['Mon','Tue','Wed','Thu','Fri']},
      {name:'CS-A',start:'09:30',end:'10:25',days:['Mon','Tue','Wed','Thu','Fri']},{name:'CS-A',start:'10:25',end:'11:20',days:['Mon','Tue','Wed','Thu','Fri']},
      {name:'CS-A',start:'13:15',end:'14:10',days:['Mon','Tue','Wed','Thu','Fri']},{name:'CS-B',start:'07:30',end:'08:25',days:['Mon','Tue','Wed','Thu','Fri']},
      {name:'CS-B',start:'08:25',end:'09:20',days:['Mon','Tue','Wed','Thu','Fri']},{name:'CS-B',start:'09:30',end:'10:25',days:['Mon','Tue','Wed','Thu','Fri']},
      {name:'CS-B',start:'10:25',end:'11:20',days:['Mon','Tue','Wed','Thu','Fri']},{name:'CS-B',start:'13:15',end:'14:10',days:['Mon','Tue','Wed','Thu','Fri']}
    ],
    assignments:[
      {sectionName:'CS-A',facultyId:'F001',subjectId:'MATH101',facultyName:'Dr. Arun Kumar',subjectName:'Mathematics',weeklyLoad:5},
      {sectionName:'CS-A',facultyId:'F002',subjectId:'PHY201',facultyName:'Prof. Meena Sharma',subjectName:'Physics',weeklyLoad:4},
      {sectionName:'CS-A',facultyId:'F003',subjectId:'CS101',facultyName:'Dr. Ravi Patel',subjectName:'Computer Science',weeklyLoad:5},
      {sectionName:'CS-A',facultyId:'F004',subjectId:'ENG101',facultyName:'Ms. Priya Nair',subjectName:'English',weeklyLoad:3},
      {sectionName:'CS-B',facultyId:'F001',subjectId:'MATH101',facultyName:'Dr. Arun Kumar',subjectName:'Mathematics',weeklyLoad:5},
      {sectionName:'CS-B',facultyId:'F002',subjectId:'CS101',facultyName:'Prof. Meena Sharma',subjectName:'Computer Science',weeklyLoad:5},
      {sectionName:'CS-B',facultyId:'F003',subjectId:'CHEM101',facultyName:'Dr. Ravi Patel',subjectName:'Chemistry',weeklyLoad:4}
    ]
  };
  ok('Full sync→200', (await R('POST','/api/sync',{instance_id:1,data:demo},TOK)).s===200);
  const ld=await R('GET','/api/sync/1',null,TOK);
  ok('4 faculty', ld.b.faculty?.length===4);
  ok('5 subjects', ld.b.subjects?.length===5);
  ok('10 sections', ld.b.sections?.length===10);
  ok('7 assignments', ld.b.assignments?.length===7);
  ok('daySchedule is object', typeof ld.b.faculty[0].daySchedule==='object');
  ok('days has 5 entries', ld.b.faculty[0].days?.length===5);
  ok('sections.days is array', Array.isArray(ld.b.sections[0].days));

  // Run the timetable scheduler
  function t2m(t){ const[h,m]=t.split(':').map(Number); return h*60+m; }
  const DAYS=['Mon','Tue','Wed','Thu','Fri'];
  const ss={};
  demo.sections.forEach(s=>{
    if(!ss[s.name])ss[s.name]={};
    s.days.forEach(d=>{ if(!ss[s.name][d])ss[s.name][d]=[]; ss[s.name][d].push({start:s.start,end:s.end,startMin:t2m(s.start),endMin:t2m(s.end)}); });
  });
  Object.keys(ss).forEach(sec=>Object.keys(ss[sec]).forEach(d=>ss[sec][d].sort((a,b)=>a.startMin-b.startMin)));
  const fSch={},fPer={},fLast={},fCon={};
  demo.faculty.forEach(f=>{ fSch[f.id]={};fPer[f.id]=0;fLast[f.id]={};fCon[f.id]={}; DAYS.forEach(d=>{ fSch[f.id][d]=[];fLast[f.id][d]=null;fCon[f.id][d]=0; }); });
  const tt={};
  const sN=[...new Set(demo.assignments.map(a=>a.sectionName))];
  const Q=demo.assignments.map(a=>({...a,hl:a.weeklyLoad}));
  sN.forEach(sec=>{ tt[sec]={};DAYS.forEach(d=>{ tt[sec][d]={};(ss[sec][d]||[]).forEach((_,si)=>tt[sec][d][si]=null); }); });
  DAYS.forEach(d=>sN.forEach(sec=>{
    (ss[sec][d]||[]).forEach((slot,si)=>{
      const el=Q.filter(a=>a.sectionName===sec&&a.hl>0).sort((a,b)=>b.hl-a.hl);
      for(const a of el){
        const f=demo.faculty.find(x=>x.id===a.facultyId); if(!f)continue;
        const duty=f.daySchedule[d]; if(!duty)continue;
        if(slot.startMin<t2m(duty.start)||slot.endMin>t2m(duty.end))continue;
        if(fPer[f.id]+1>f.load)continue;
        if(fSch[f.id][d].some(b=>!(slot.endMin<=b.startMin||slot.startMin>=b.endMin)))continue;
        const lE=fLast[f.id][d],isC=lE!==null&&lE===slot.startMin,cC=isC?fCon[f.id][d]+1:1;
        if(cC>2)continue;
        tt[sec][d][si]={facultyId:f.id,facultyName:f.name,subjectId:a.subjectId,subjectName:a.subjectName};
        fSch[f.id][d].push({startMin:slot.startMin,endMin:slot.endMin});
        fLast[f.id][d]=slot.endMin;fCon[f.id][d]=cC;fPer[f.id]+=1;a.hl-=1;break;
      }
    });
  }));
  ok('All 7 assignments scheduled', Q.filter(a=>a.hl>0).length===0);
  let cl=0; DAYS.forEach(d=>{ const seen={}; sN.forEach(sec=>(ss[sec][d]||[]).forEach((slot,si)=>{ const e=tt[sec][d][si]; if(!e)return; const k=e.facultyId+'-'+slot.start; if(seen[k])cl++; else seen[k]=sec; })); });
  ok('Zero faculty clashes', cl===0);
  let cv=0; demo.faculty.forEach(f=>DAYS.forEach(d=>{ const m=[]; sN.forEach(sec=>(ss[sec][d]||[]).forEach((slot,si)=>{ const e=tt[sec][d][si]; if(e&&e.facultyId===f.id)m.push({s:slot.startMin,e:slot.endMin}); })); m.sort((a,b)=>a.s-b.s); let run=1; for(let i=1;i<m.length;i++){if(m[i-1].e===m[i].s)run++;else run=1;if(run>2)cv++;} }));
  ok('No 3-consecutive violations', cv===0);
  ok('F004 not on Friday', !Object.values(tt['CS-A']?.Fri||{}).some(e=>e?.facultyId==='F004'));
  ok('F002 not in 07:30 slot (duty from 08:25)', !Object.values(tt['CS-A']?.Mon||{}).some((e,i)=>e?.facultyId==='F002'&&i===0));
  const sv=await R('POST','/api/timetable/1',{tt,secSlots:ss},TOK);
  ok('Timetable saved→200', sv.s===200);
  const ltt=await R('GET','/api/timetable/1',null,TOK);
  ok('Timetable loaded→200', ltt.s===200);
  ok('TT CS-A Mon intact', !!ltt.b.tt?.['CS-A']?.Mon);
  ok('SecSlots CS-A intact', !!ltt.b.secSlots?.['CS-A']);
  ok('generatedAt present', !!ltt.b.generatedAt);

  // ── 13. Audit log completeness ──
  console.log('\n[13] Audit log completeness');
  const al=await R('GET','/api/admin/audit-log',null,TOK);
  ok('Audit log 200', al.s===200);
  const acts=al.b.map(r=>r.action);
  ['LOGIN','ADD_USER','CHANGE_PASSWORD','RESET_PASSWORD','BULK_SYNC','SAVE_TIMETABLE','DELETE_ASSIGNMENT'].forEach(a=>ok(a+' logged', acts.includes(a)));

  // ── 14. Security guards ──
  console.log('\n[14] Security guards');
  ok('Self-revoke→400', (await R('PATCH','/api/admin/users/1/revoke',null,TOK)).s===400);
  ok('Self-delete→400', (await R('DELETE','/api/admin/users/1',null,TOK)).s===400);
  ok('No token→401', (await R('GET','/api/auth/me')).s===401);
  const freshVT=(await R('POST','/api/auth/login',{email:'vo@t.edu',password:'pass123'})).b.token;
  ok('View-only→admin 403', (await R('GET','/api/admin/users',null,freshVT)).s===403);
  ok('View-only→audit 403', (await R('GET','/api/admin/audit-log',null,freshVT)).s===403);
  ok('View-only→TT write 403', (await R('POST','/api/timetable/1',{tt:{},secSlots:{}},freshVT)).s===403);

  // ══ SUMMARY ══
  console.log('\n══════════════════════════════════════════════════════');
  console.log(`TOTAL: ${P} passed, ${F} failed out of ${P+F} assertions`);
  if(F===0) console.log('✅ ALL TESTS PASS — every audit fix verified with demo data');
  else      console.log('⚠️  '+F+' failures');
  server.close();
  process.exit(F===0?0:1);
});
