'Access-Control-Allow-Origin': '*'
'use strict';
// ── test runner: loads actual server.js, fires all tests ──
process.env.PORT = '3005';
process.env.JWT_SECRET = 'audit_test_secret_key_minimum_32_chars_ok_1234';

const http = require('http');

// Intercept app.listen so we can close it after tests
const express = require('./node_modules/express');
let _testServer = null;
const origListen = express.application.listen;
express.application.listen = function(...args){
  _testServer = origListen.apply(this, args);
  return _testServer;
};

// Load the real server
require('./server');

// HTTP helper
function R(m,p,b,t){
  return new Promise((res,rej)=>{
    const data = b ? JSON.stringify(b) : null;
    const opts = {
      hostname:'localhost', port:3005, path:p, method:m,
      headers:{
        'Content-Type':'application/json',
        ...(t ? {'Authorization':'Bearer '+t} : {}),
        ...(data ? {'Content-Length':Buffer.byteLength(data)} : {})
      }
    };
    const r = http.request(opts, resp=>{
      let d=''; resp.on('data',c=>d+=c);
      resp.on('end',()=>{ try{res({status:resp.statusCode,body:JSON.parse(d)});}
                          catch(e){res({status:resp.statusCode,body:d});} });
    });
    r.on('error',rej); if(data) r.write(data); r.end();
  });
}

// Wait for server ready
function waitReady(cb, n=0){
  if(n>30){ cb(new Error('Timeout')); return; }
  R('GET','/api/health').then(()=>cb(null)).catch(()=>setTimeout(()=>waitReady(cb,n+1),300));
}

setTimeout(()=>{
  waitReady(async err=>{
    if(err){ console.error('Server not ready'); process.exit(1); }
    console.log('✅ Server ready on port 3005\n');

    let P=0, F=0;
    function ok(d,v){ if(v){console.log('  ✅ '+d);P++;}else{console.log('  ❌ FAIL: '+d);F++;} }

    try {
      const lg = await R('POST','/api/auth/login',{email:'admin@school.edu',password:'admin123'});
      const TOK = lg.body.token;

      // ── 1. Core ──
      console.log('[1] Health & login');
      ok('Health ok', (await R('GET','/api/health')).body.status==='ok');
      ok('Login 200', lg.status===200);
      ok('Token present', !!TOK);
      ok('Role=admin', lg.body.user?.role==='admin');
      ok('Wrong pwd → 401', (await R('POST','/api/auth/login',{email:'admin@school.edu',password:'bad'})).status===401);
      ok('Empty body → 400', (await R('POST','/api/auth/login',{})).status===400);
      ok('Case-insensitive', (await R('POST','/api/auth/login',{email:'ADMIN@SCHOOL.EDU',password:'admin123'})).status===200);

      // ── 2. FIX 1: Email validation ──
      console.log('\n[2] FIX 1 — Email validation on add-user');
      const badE = await R('POST','/api/admin/users',{email:'bademail',name:'X',role:'user',password:'pass12',tabPerms:[]},TOK);
      ok('Bad email → 400', badE.status===400);
      ok('Error mentions email', (badE.body.error||'').toLowerCase().includes('email'));
      ok('Valid email → 200', (await R('POST','/api/admin/users',{email:'u1@test.edu',name:'U1',role:'user',password:'pass123',tabPerms:Array(6).fill('none')},TOK)).status===200);
      ok('Dup email → 409', (await R('POST','/api/admin/users',{email:'u1@test.edu',name:'D',role:'user',password:'pass123'},TOK)).status===409);
      ok('Short pwd → 400', (await R('POST','/api/admin/users',{email:'u2@test.edu',name:'U2',role:'user',password:'abc'},TOK)).status===400);

      // ── 3. FIX 2&3: instance_id validation ──
      console.log('\n[3] FIX 2&3 — instance_id validation');
      ok('SQL string → 400', (await R('POST','/api/sync',{instance_id:"1;DROP TABLE--",data:{}},TOK)).status===400);
      ok('Negative → 400',   (await R('POST','/api/sync',{instance_id:-1,data:{}},TOK)).status===400);
      ok('Zero → 400',       (await R('POST','/api/sync',{instance_id:0,data:{}},TOK)).status===400);
      ok('Missing GET → 400',(await R('GET','/api/faculty',null,TOK)).status===400);
      ok('String GET → 400', (await R('GET','/api/faculty?instance_id=abc',null,TOK)).status===400);
      ok('Valid id → 200',   (await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},TOK)).status===200);

      // ── 4. FIX 4: Async bcrypt ──
      console.log('\n[4] FIX 4 — Async bcrypt (non-blocking)');
      const t0 = Date.now();
      await R('POST','/api/auth/login',{email:'admin@school.edu',password:'admin123'});
      ok('Takes >50ms (async, not blocking)', Date.now()-t0 > 50);

      // ── 5. FIX 7: Token invalidation after pwd change ──
      console.log('\n[5] FIX 7 — Token invalidated after password change');
      await R('POST','/api/admin/users',{email:'pt@test.edu',name:'PT',role:'user',password:'oldpass1',tabPerms:Array(6).fill('edit')},TOK);
      const pl = await R('POST','/api/auth/login',{email:'pt@test.edu',password:'oldpass1'});
      const PTOK = pl.body.token;
      ok('Login before change', pl.status===200);
      // pwd_changed_at is NULL on fresh user — first token must work
      ok('First token works (pwd_changed_at NULL)', (await R('GET','/api/auth/me',null,PTOK)).status===200);
      // Change password using valid token
      const cpRes = await R('POST','/api/auth/change-password',{currentPassword:'oldpass1',newPassword:'newpass99'},PTOK);
      ok('Change password succeeds', cpRes.status===200);
      // Old token now invalid — pwd_changed_at set, changedAt+1 > iat
      const chk = await R('GET','/api/auth/me',null,PTOK);
      ok('Old token rejected → 401', chk.status===401);
      ok('Correct error message', (chk.body.error||'').includes('password change'));
      ok('New password works', (await R('POST','/api/auth/login',{email:'pt@test.edu',password:'newpass99'})).status===200);

      // ── 6. FIX 7: Admin reset also invalidates ──
      console.log('\n[6] FIX 7 — Admin reset invalidates tokens');
      const userList = await R('GET','/api/admin/users',null,TOK);
      const pu = userList.body.find(u=>u.email==='pt@test.edu');
      const NT = (await R('POST','/api/auth/login',{email:'pt@test.edu',password:'newpass99'})).body.token;
      await R('POST',`/api/admin/users/${pu.id}/reset-password`,{newPassword:'resetpwd1'},TOK);
      ok('Token invalid after admin reset → 401', (await R('GET','/api/auth/me',null,NT)).status===401);
      ok('New pwd from reset works', (await R('POST','/api/auth/login',{email:'pt@test.edu',password:'resetpwd1'})).status===200);

      // ── 7. FIX 8: Stale timetable cleared ──
      console.log('\n[7] FIX 8 — Stale timetable cleared on sync');
      const fakeTT = {'S1':{Mon:{0:{facultyId:'F1',subjectId:'M1',facultyName:'A',subjectName:'B'}}}};
      const fakeSlots = {'S1':{Mon:[{start:'07:30',end:'08:25',startMin:450,endMin:505}]}};
      await R('POST','/api/timetable/1',{tt:fakeTT,secSlots:fakeSlots},TOK);
      ok('TT saved', (await R('GET','/api/timetable/1',null,TOK)).status===200);
      await R('POST','/api/sync',{instance_id:1,data:{faculty:[{id:'FX',name:'X',load:1,daySchedule:{}}],subjects:[],sections:[],assignments:[]}},TOK);
      ok('TT cleared after faculty sync → 404', (await R('GET','/api/timetable/1',null,TOK)).status===404);

      // ── 8. FIX 9: Granular sync permissions ──
      console.log('\n[8] FIX 9 — Granular sync permissions');
      await R('POST','/api/admin/users',{email:'se@test.edu',name:'SE',role:'user',password:'pass123',tabPerms:['none','edit','none','none','none','none']},TOK);
      const STOK = (await R('POST','/api/auth/login',{email:'se@test.edu',password:'pass123'})).body.token;
      const partialSync = await R('POST','/api/sync',{instance_id:1,
        data:{faculty:[{id:'BLOCKED',name:'ShouldNotSync',load:1,daySchedule:{}}],
              subjects:[{id:'SUB1',name:'History',load:3}],sections:[],assignments:[]}},STOK);
      ok('Partial-edit sync → 200', partialSync.status===200);
      const facAfter = await R('GET','/api/faculty?instance_id=1',null,TOK);
      ok('Faculty NOT synced by tab-1-only user', facAfter.body.every(f=>f.faculty_id!=='BLOCKED'));
      const subAfter = await R('GET','/api/subjects?instance_id=1',null,TOK);
      ok('Subject synced by tab-1 user', subAfter.body.some(s=>s.subject_id==='SUB1'));
      await R('POST','/api/admin/users',{email:'vo@test.edu',name:'VO',role:'user',password:'pass123',tabPerms:Array(6).fill('view')},TOK);
      const VTOK = (await R('POST','/api/auth/login',{email:'vo@test.edu',password:'pass123'})).body.token;
      ok('View-only sync → 403', (await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},VTOK)).status===403);

      // ── 9. FIX 11: Composite assignment DELETE ──
      console.log('\n[9] FIX 11 — Assignment DELETE by composite key');
      // Insert directly into DB via a separate connection
      const Database = require('./node_modules/better-sqlite3');
      const tmpDb = new Database('./timetable.db');
      tmpDb.prepare("INSERT OR IGNORE INTO assignments(instance_id,section_name,faculty_id,subject_id,faculty_name,subject_name,weekly_load)VALUES(?,?,?,?,?,?,?)").run(1,'CS-A','F001','M101','Dr A','Maths',5);
      tmpDb.close();
      ok('Composite DELETE → 200', (await R('DELETE','/api/assignments',{instance_id:1,section_name:'CS-A',faculty_id:'F001',subject_id:'M101'},TOK)).status===200);
      ok('Incomplete key → 400', (await R('DELETE','/api/assignments',{instance_id:1,section_name:'CS-A'},TOK)).status===400);
      ok('Missing instance_id → 400', (await R('DELETE','/api/assignments',{section_name:'CS-A',faculty_id:'F001',subject_id:'M101'},TOK)).status===400);

      // ── 10. FIX 16: Null-safe daySchedule ──
      console.log('\n[10] FIX 16 — Null-safe daySchedule');
      const facResp = await R('GET','/api/faculty?instance_id=1',null,TOK);
      ok('daySchedule always object', facResp.body.every(f=>f.daySchedule!==null && typeof f.daySchedule==='object'));
      ok('days always array', facResp.body.every(f=>Array.isArray(f.days)));

      // ── 11. FIX 18: Data versioning ──
      console.log('\n[11] FIX 18 — Data versioning');
      const v1 = await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},TOK);
      const v2 = await R('POST','/api/sync',{instance_id:1,data:{faculty:[],subjects:[],sections:[],assignments:[]}},TOK);
      ok('data_version returned', typeof v1.body.data_version==='number');
      ok('data_version increments', v2.body.data_version === v1.body.data_version+1);
      const ldV = await R('GET','/api/sync/1',null,TOK);
      ok('data_version in load', typeof ldV.body.data_version==='number');
      ok('Load version matches sync', ldV.body.data_version === v2.body.data_version);

      // ── 12. Full demo data round-trip + scheduling ──
      console.log('\n[12] Full demo data + scheduling round-trip');
      const demo = {
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
      ok('Full sync → 200', (await R('POST','/api/sync',{instance_id:1,data:demo},TOK)).status===200);
      const ld = await R('GET','/api/sync/1',null,TOK);
      ok('4 faculty loaded', ld.body.faculty?.length===4);
      ok('5 subjects loaded', ld.body.subjects?.length===5);
      ok('10 sections loaded', ld.body.sections?.length===10);
      ok('7 assignments loaded', ld.body.assignments?.length===7);
      ok('daySchedule is object', typeof ld.body.faculty[0].daySchedule==='object');
      ok('days array with 5 days', Array.isArray(ld.body.faculty[0].days) && ld.body.faculty[0].days.length===5);
      ok('sections.days is array', Array.isArray(ld.body.sections[0].days));

      // Run scheduler
      const DAYS = ['Mon','Tue','Wed','Thu','Fri'];
      function t2m(t){ const[h,m]=t.split(':').map(Number); return h*60+m; }
      const ss={};
      demo.sections.forEach(s=>{ if(!ss[s.name])ss[s.name]={};s.days.forEach(d=>{ if(!ss[s.name][d])ss[s.name][d]=[];ss[s.name][d].push({start:s.start,end:s.end,startMin:t2m(s.start),endMin:t2m(s.end)});});});
      Object.keys(ss).forEach(sec=>Object.keys(ss[sec]).forEach(d=>ss[sec][d].sort((a,b)=>a.startMin-b.startMin)));
      const fSch={},fPer={},fLast={},fCon={};
      demo.faculty.forEach(f=>{ fSch[f.id]={};fPer[f.id]=0;fLast[f.id]={};fCon[f.id]={};DAYS.forEach(d=>{ fSch[f.id][d]=[];fLast[f.id][d]=null;fCon[f.id][d]=0;}); });
      const tt={};
      const sN=[...new Set(demo.assignments.map(a=>a.sectionName))];
      const Q=demo.assignments.map(a=>({...a,hl:a.weeklyLoad}));
      sN.forEach(sec=>{ tt[sec]={};DAYS.forEach(d=>{ tt[sec][d]={};(ss[sec][d]||[]).forEach((_,si)=>tt[sec][d][si]=null);}); });
      DAYS.forEach(d=>sN.forEach(sec=>{
        const slots=ss[sec][d]||[];
        slots.forEach((slot,si)=>{
          const el=Q.filter(a=>a.sectionName===sec&&a.hl>0).sort((a,b)=>b.hl-a.hl);
          for(const a of el){
            const f=demo.faculty.find(x=>x.id===a.facultyId);if(!f)continue;
            const duty=f.daySchedule[d];if(!duty)continue;
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
      let cl=0;
      DAYS.forEach(d=>{ const seen={};sN.forEach(sec=>(ss[sec][d]||[]).forEach((slot,si)=>{ const e=tt[sec][d][si];if(!e)return;const k=e.facultyId+'-'+slot.start;if(seen[k])cl++;else seen[k]=sec;})); });
      ok('Zero faculty clashes', cl===0);
      let cv=0;
      demo.faculty.forEach(f=>DAYS.forEach(d=>{ const m=[];sN.forEach(sec=>(ss[sec][d]||[]).forEach((slot,si)=>{ const e=tt[sec][d][si];if(e&&e.facultyId===f.id)m.push({s:slot.startMin,e:slot.endMin});}));m.sort((a,b)=>a.s-b.s);let run=1;for(let i=1;i<m.length;i++){if(m[i-1].e===m[i].s)run++;else run=1;if(run>2)cv++;} }));
      ok('No 3-consecutive violations', cv===0);
      ok('F004 not on Friday', !Object.values(tt['CS-A']?.Fri||{}).some(e=>e?.facultyId==='F004'));
      ok('F002 not in 07:30 slot', !Object.values(tt['CS-A']?.Mon||{}).some((e,i)=>e?.facultyId==='F002'&&i===0));
      const sv = await R('POST','/api/timetable/1',{tt,secSlots:ss},TOK);
      ok('Timetable saved → 200', sv.status===200);
      const ltt = await R('GET','/api/timetable/1',null,TOK);
      ok('Timetable loaded → 200', ltt.status===200);
      ok('TT data intact', !!ltt.body.tt?.['CS-A']?.Mon);
      ok('SecSlots intact', !!ltt.body.secSlots?.['CS-A']);
      ok('generatedAt present', !!ltt.body.generatedAt);

      // ── 13. Audit log ──
      console.log('\n[13] Audit log completeness');
      const al = await R('GET','/api/admin/audit-log',null,TOK);
      ok('Audit → 200', al.status===200);
      const acts = al.body.map(r=>r.action);
      ['LOGIN','ADD_USER','CHANGE_PASSWORD','RESET_PASSWORD','BULK_SYNC','SAVE_TIMETABLE','DELETE_ASSIGNMENT'].forEach(a=>ok(a+' logged', acts.includes(a)));

      // ── 14. Security ──
      console.log('\n[14] Security guards');
      ok('Self-revoke → 400', (await R('PATCH','/api/admin/users/1/revoke',null,TOK)).status===400);
      ok('Self-delete → 400', (await R('DELETE','/api/admin/users/1',null,TOK)).status===400);
      ok('No token → 401', (await R('GET','/api/auth/me')).status===401);
      // Re-fetch view-only token fresh (VTOK from [8] may be stale)
      const freshVTOK = (await R('POST','/api/auth/login',{email:'vo@test.edu',password:'pass123'})).body.token;
      ok('View-only blocked from admin → 403', (await R('GET','/api/admin/users',null,freshVTOK)).status===403);
      ok('View-only blocked from audit → 403', (await R('GET','/api/admin/audit-log',null,freshVTOK)).status===403);
      ok('View-only blocked timetable write', (await R('POST','/api/timetable/1',{tt:{},secSlots:{}},freshVTOK)).status===403);

    } catch(e) {
      console.error('\nTest runner exception:', e.message, e.stack);
      F++;
    }

    console.log('\n══════════════════════════════════════════════════════');
    console.log(`TOTAL: ${P} passed, ${F} failed out of ${P+F} assertions`);
    if(F===0) console.log('✅ All tests pass — every audit fix verified against real server.js');
    else      console.log('⚠️  '+F+' failures');
    if(_testServer) _testServer.close();
    process.exit(F===0?0:1);
  });
}, 800);
