/**
 * Field Ops Platform -- Server v2
 * Node.js, zero npm dependencies.
 * Supabase (database) + Cloudinary (files/photos)
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'wh-' + crypto.randomBytes(16).toString('hex');
const SESSION_HOURS = 24;
const SB_URL = process.env.SUPABASE_URL || 'https://htkvgfmbcoozmkiairvt.supabase.co';
const SB_ANON = process.env.SUPABASE_KEY || 'sb_publishable_1U37N6iZ8Is4mF_aR9kThg_DS7wExWO';
const SB_SERVICE = process.env.SUPABASE_SERVICE_KEY || '';
const CL_CLOUD = process.env.CLOUDINARY_CLOUD || 'disyczlam';
const CL_KEY = process.env.CLOUDINARY_KEY || '641369166864517';
const CL_SECRET = process.env.CLOUDINARY_SECRET || '';
const CL_PRESET = process.env.CLOUDINARY_PRESET || 'btgbch6a';

// ── SUPABASE ──────────────────────────────────────────────────────────────────
function sbReq(method, table, body, params, svc) {
  return new Promise((resolve, reject) => {
    const key = svc ? SB_SERVICE : SB_ANON;
    let qs = '';
    if (params) qs = '?' + Object.entries(params).map(([k,v])=>k+'='+encodeURIComponent(v)).join('&');
    const u = new URL(SB_URL + '/rest/v1/' + table + qs);
    const opts = {
      hostname: u.hostname, path: u.pathname + u.search, method,
      headers: { 'apikey': key, 'Authorization': 'Bearer '+key, 'Content-Type': 'application/json', 'Prefer': 'return=representation' }
    };
    const req = https.request(opts, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const p = d ? JSON.parse(d) : null;
          if (res.statusCode >= 400) reject(new Error(p?.message || p?.error || 'DB error ' + res.statusCode));
          else resolve(p);
        } catch(e) { resolve(d); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}
async function dbGet(t, p) { return await sbReq('GET', t, null, p) || []; }
async function dbInsert(t, b) { return await sbReq('POST', t, b, null, true); }
async function dbUpdate(t, b, p) { return await sbReq('PATCH', t, b, p, true); }
async function dbDelete(t, p) { return await sbReq('DELETE', t, null, p, true); }
async function dbUpsert(t, b) {
  const u = new URL(SB_URL);
  const opts = { hostname: u.hostname, path: '/rest/v1/'+t, method:'POST',
    headers:{'apikey':SB_SERVICE,'Authorization':'Bearer '+SB_SERVICE,'Content-Type':'application/json','Prefer':'resolution=merge-duplicates,return=representation'}};
  return new Promise((res,rej)=>{
    const req=https.request(opts,r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{try{res(d?JSON.parse(d):null);}catch(e){res(d);}});});
    req.on('error',rej);req.write(JSON.stringify(b));req.end();
  });
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
function hashPwd(p){const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.pbkdf2Sync(p,s,100000,64,'sha512').toString('hex');}
function verifyPwd(p,stored){const[s,h]=stored.split(':');return crypto.pbkdf2Sync(p,s,100000,64,'sha512').toString('hex')===h;}
function makeToken(uid){const d=Buffer.from(JSON.stringify({uid,exp:Date.now()+SESSION_HOURS*3600000})).toString('base64');return d+'.'+crypto.createHmac('sha256',JWT_SECRET).update(d).digest('hex');}
function verifyToken(t){if(!t)return null;const[d,s]=t.split('.');if(!d||!s)return null;if(crypto.createHmac('sha256',JWT_SECRET).update(d).digest('hex')!==s)return null;try{const p=JSON.parse(Buffer.from(d,'base64').toString());return p.exp>Date.now()?p:null;}catch(e){return null;}}
function nowISO(){return new Date().toISOString();}
function nowDisplay(){return new Date().toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})+' '+new Date().toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',hour12:true});}
async function getUser(req){
  const t=(req.headers['authorization']||'').replace('Bearer ','');
  if(!t)return null;const p=verifyToken(t);if(!p)return null;
  try{const r=await dbGet('users',{id:'eq.'+p.uid,active:'eq.true',select:'*'});return r[0]||null;}catch(e){return null;}
}
function requireAuth(res,u){if(!u){json(res,401,{error:'Not authenticated'});return false;}return true;}
function requireRole(res,u,...roles){if(!requireAuth(res,u))return false;if(!roles.includes(u.role)){json(res,403,{error:'Permission denied'});return false;}return true;}
function safeUser(u){if(!u)return null;const{password_hash,...s}=u;return s;}

// ── HTTP ──────────────────────────────────────────────────────────────────────
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET, POST, PUT, DELETE, PATCH, OPTIONS'};
function json(res,status,data){res.writeHead(status,{'Content-Type':'application/json',...CORS});res.end(JSON.stringify(data));}
function readBody(req){return new Promise(r=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{try{r(JSON.parse(b));}catch(e){r({});}});});}
function serveFile(res,fp,ct){try{const d=fs.readFileSync(fp);res.writeHead(200,{'Content-Type':ct});res.end(d);}catch(e){res.writeHead(404);res.end('Not found');}}
function cloudinarySign(params){return crypto.createHash('sha1').update(Object.keys(params).sort().map(k=>k+'='+params[k]).join('&')+CL_SECRET).digest('hex');}

async function addAuditLog(type,jobId,partId,partName,username,extra){
  try{await dbInsert('audit_log',{id:'al'+Date.now()+Math.random().toString(36).slice(2),type,job_id:jobId,part_id:partId,part_name:partName,username,extra:extra||'',created_at:nowISO()});}catch(e){}
}
async function addNotif(type,title,message,meta){
  try{await dbInsert('notifications',{id:'n'+Date.now()+Math.random().toString(36).slice(2),type,title,message,meta:JSON.stringify(meta||{}),read:false,created_at:nowISO()});}catch(e){}
}

// Auto-add to manifest when staging
async function autoAddToManifest(jobId, partId, partName, qty, stagedBy) {
  try {
    const existing = await dbGet('job_manifest', {job_id:'eq.'+jobId, part_id:'eq.'+partId, select:'id'});
    if (!existing[0]) {
      await dbInsert('job_manifest', {id:'mf'+Date.now()+Math.random().toString(36).slice(2), job_id:jobId, part_id:partId, part_name:partName, expected_qty:qty, notes:'', added_by:stagedBy, added_at:nowDisplay()});
    }
  } catch(e) {}
}

// ── SETUP DB ──────────────────────────────────────────────────────────────────
async function setupDB() {
  try {
    const users = await dbGet('users', {select:'id', limit:'1'});
    if (!users || users.length === 0) {
      await dbInsert('users', {id:'u1', username:'admin', password_hash:hashPwd('admin123'), name:'Administrator', role:'admin', active:true, created_at:nowISO()});
      console.log('Default admin created: username=admin password=admin123');
    }
  } catch(e) { console.log('DB setup note:', e.message); }
}

// ── ROUTER ────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const p = parsed.pathname;
  const method = req.method;

  if (method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  if (method === 'GET' && (p === '/' || p === '/index.html'))
    return serveFile(res, path.join(__dirname, 'public', 'index.html'), 'text/html');

  // Auth
  if (p === '/api/login' && method === 'POST') {
    const {username, password} = await readBody(req);
    try {
      const rows = await dbGet('users', {username:'eq.'+username, active:'eq.true', select:'*'});
      const user = rows[0];
      if (!user || !verifyPwd(password, user.password_hash)) return json(res, 401, {error:'Invalid username or password'});
      return json(res, 200, {token:makeToken(user.id), user:safeUser(user)});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/me' && method === 'GET') {
    const u = await getUser(req); if (!u) return json(res, 401, {error:'Not authenticated'});
    return json(res, 200, safeUser(u));
  }

  // Upload sign
  if (p === '/api/upload-sign' && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {folder} = await readBody(req);
    const timestamp = Math.round(Date.now()/1000);
    const params = {folder:folder||'warehouse', timestamp, upload_preset:CL_PRESET};
    return json(res, 200, {signature:cloudinarySign(params), timestamp, api_key:CL_KEY, cloud_name:CL_CLOUD, upload_preset:CL_PRESET, folder:folder||'warehouse'});
  }

  // Users
  if (p === '/api/users' && method === 'GET') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { return json(res, 200, (await dbGet('users', {select:'*', order:'created_at.asc'})).map(safeUser)); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/users' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    const {username, password, name, role} = await readBody(req);
    if (!username||!password||!name||!role) return json(res, 400, {error:'All fields required'});
    if (!['admin','stager','signout','requestor','technician','foreman'].includes(role)) return json(res, 400, {error:'Invalid role'});
    try {
      const rows = await dbInsert('users', {id:'u'+Date.now(), username, password_hash:hashPwd(password), name, role, active:true, created_at:nowISO()});
      return json(res, 201, safeUser(rows[0]));
    } catch(e) { return json(res, 400, {error:e.message.includes('unique')?'Username taken':e.message}); }
  }
  const uM = p.match(/^\/api\/users\/([^/]+)$/);
  if (uM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    const b = await readBody(req); const upd = {};
    if (b.name) upd.name = b.name;
    if (b.role && ['admin','stager','signout','requestor','technician','foreman'].includes(b.role)) upd.role = b.role;
    if (b.active !== undefined) upd.active = !!b.active;
    if (b.password && b.password.length >= 6) upd.password_hash = hashPwd(b.password);
    try { return json(res, 200, safeUser((await dbUpdate('users', upd, {id:'eq.'+uM[1]}))[0])); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (uM && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    if (uM[1] === u.id) return json(res, 400, {error:"Can't delete yourself"});
    try { await dbDelete('users', {id:'eq.'+uM[1]}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Jobs
  if (p === '/api/jobs' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const showArch = parsed.query.archived === 'true';
      const params = {select:'*', order:'created_at.desc'};
      if (!showArch) params['archived'] = 'eq.false';
      return json(res, 200, await dbGet('jobs', params));
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/jobs' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const b = await readBody(req);
    if (!b.id) return json(res, 400, {error:'Job ID required'});
    try {
      const job = {
        id:b.id, name:b.name||b.id, description:b.description||'', address:b.address||'',
        gc_company:b.gc_company||'', gc_contact:b.gc_contact||'', gc_phone:b.gc_phone||'', gc_email:b.gc_email||'',
        super_name:b.super_name||'', super_phone:b.super_phone||'', super_email:b.super_email||'',
        scope:b.scope||'', notes:b.notes||'', install_notes:b.install_notes||'',
        job_walk_by:b.job_walk_by||'', job_walk_date:b.job_walk_date||null, job_walk_notes:b.job_walk_notes||'',
        phase:'not_started', pct_complete:0, archived:false, created_by:u.name, created_at:nowISO(), updated_at:nowISO(),
        date_contract:b.date_contract||null, date_permit:b.date_permit||null, date_start:b.date_start||null,
        date_roughin:b.date_roughin||null, date_trimout:b.date_trimout||null, date_inspection:b.date_inspection||null,
        date_next_visit:b.date_next_visit||null, date_closeout:b.date_closeout||null, date_co:b.date_co||null
      };
      const rows = await dbInsert('jobs', job);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 400, {error:e.message.includes('unique')?'Job ID already exists':e.message}); }
  }
  const jM = p.match(/^\/api\/jobs\/([^/]+)$/);
  if (jM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const rows = await dbGet('jobs', {id:'eq.'+jM[1], select:'*'});
      if (!rows[0]) return json(res, 404, {error:'Job not found'});
      return json(res, 200, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (jM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman','technician')) return;
    const b = await readBody(req);
    const allowed = ['name','description','address','gc_company','gc_contact','gc_phone','gc_email',
      'super_name','super_phone','super_email','scope','notes','install_notes',
      'job_walk_by','job_walk_date','job_walk_notes',
      'phase','pct_complete','archived',
      'date_contract','date_permit','date_start','date_roughin','date_trimout','date_inspection',
      'date_next_visit','date_closeout','date_co',
      'contract_value','labor_budget','material_budget','labor_rate'];
    const upd = {updated_at:nowISO()};
    allowed.forEach(k=>{ if(b[k]!==undefined) upd[k]=b[k]; });
    try { return json(res, 200, (await dbUpdate('jobs', upd, {id:'eq.'+jM[1]}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Job CSV import
  if (p === '/api/jobs/import' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const {jobs: jobList} = await readBody(req);
    if (!Array.isArray(jobList)) return json(res, 400, {error:'jobs array required'});
    const results = {created:[], skipped:[], errors:[]};
    for (const b of jobList) {
      if (!b.id) { results.errors.push('Missing ID'); continue; }
      try {
        const job = {
          id:b.id, name:b.name||b.id, description:b.description||'', address:b.address||'',
          gc_company:b.gc_company||'', gc_contact:b.gc_contact||'', gc_phone:b.gc_phone||'', gc_email:b.gc_email||'',
          super_name:b.super_name||'', super_phone:b.super_phone||'', super_email:b.super_email||'',
          scope:b.scope||'', notes:b.notes||'', install_notes:b.install_notes||'',
          job_walk_by:b.job_walk_by||'', job_walk_date:b.job_walk_date||null, job_walk_notes:b.job_walk_notes||'',
          phase:'not_started', pct_complete:0, archived:false, created_by:u.name, created_at:nowISO(), updated_at:nowISO(),
          date_contract:b.date_contract||null, date_permit:b.date_permit||null, date_start:b.date_start||null,
          date_roughin:b.date_roughin||null, date_trimout:b.date_trimout||null, date_inspection:b.date_inspection||null,
          date_next_visit:b.date_next_visit||null, date_closeout:b.date_closeout||null, date_co:b.date_co||null
        };
        await dbInsert('jobs', job);
        results.created.push(b.id);
      } catch(e) {
        if (e.message.includes('unique') || e.message.includes('duplicate')) results.skipped.push(b.id+' (already exists)');
        else results.errors.push(b.id+': '+e.message);
      }
    }
    return json(res, 200, results);
  }

  // Job Parts
  const jpListM = p.match(/^\/api\/jobs\/([^/]+)\/parts$/);
  if (jpListM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('job_parts', {job_id:'eq.'+jpListM[1], select:'*', order:'created_at.asc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (jpListM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const jobId = jpListM[1];
    const {partId, part_name, assignedQty} = await readBody(req);
    if (!partId) return json(res, 400, {error:'partId required'});
    try {
      const catRows = await dbGet('catalog', {barcode:'eq.'+partId, select:'name'});
      const nm = part_name || catRows[0]?.name || partId;
      const part = {id:'jp'+Date.now()+Math.random().toString(36).slice(2), job_id:jobId, part_id:partId, part_name:nm,
        status:'staged', assigned_qty:assignedQty||1, taken_qty:0, installed_qty:0, over:false,
        staged_by:u.name, staged_at:nowDisplay(), created_at:nowISO()};
      try {
        const inv = await dbGet('inventory', {id:'eq.'+partId, select:'qty'});
        if (inv[0] && inv[0].qty > 0) await dbUpdate('inventory', {qty:Math.max(0, inv[0].qty-(assignedQty||1)), updated_at:nowISO()}, {id:'eq.'+partId});
      } catch(e) {}
      // Auto-add to manifest
      await autoAddToManifest(jobId, partId, nm, assignedQty||1, u.name);
      await addAuditLog('staged', jobId, partId, nm, u.name, 'qty:'+(assignedQty||1));
      const rows = await dbInsert('job_parts', part);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 400, {error:e.message}); }
  }

  // Sign out
  const soM = p.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/signout$/);
  if (soM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {qty} = await readBody(req);
    try {
      const rows = await dbGet('job_parts', {id:'eq.'+soM[2], select:'*'});
      const part = rows[0]; if (!part) return json(res, 404, {error:'Part not found'});
      const newTaken = (part.taken_qty||0) + (qty||1);
      const isOver = part.assigned_qty && newTaken > part.assigned_qty;
      await dbUpdate('job_parts', {status:'signed_out', signed_out_by:u.name, signed_out_at:nowDisplay(), taken_qty:newTaken, over:isOver}, {id:'eq.'+soM[2]});
      if (isOver) await addNotif('overage','Overage: '+part.part_name, part.part_name+' taken '+newTaken+' vs '+part.assigned_qty+' on job '+soM[1], {job_id:soM[1]});
      await addAuditLog(isOver?'over':'signed_out', soM[1], part.part_id, part.part_name, u.name, 'qty:'+(qty||1));
      return json(res, 200, {ok:true, over:isOver});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Install
  const instM = p.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/install$/);
  if (instM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'technician','foreman','admin')) return;
    const {qty} = await readBody(req);
    try {
      const rows = await dbGet('job_parts', {id:'eq.'+instM[2], select:'*'});
      const part = rows[0]; if (!part) return json(res, 404, {error:'Not found'});
      const newInst = (part.installed_qty||0) + (qty||1);
      await dbUpdate('job_parts', {installed_qty:newInst, installed_by:u.name, installed_at:nowDisplay(), status:newInst >= part.assigned_qty ? 'installed' : 'partial_install'}, {id:'eq.'+instM[2]});
      await addAuditLog('installed', instM[1], part.part_id, part.part_name, u.name, 'qty:'+(qty||1));
      return json(res, 200, {ok:true});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Return part
  const retM = p.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/return$/);
  if (retM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    try {
      const rows = await dbGet('job_parts', {id:'eq.'+retM[2], select:'*'});
      const part = rows[0]; if (!part) return json(res, 404, {error:'Not found'});
      const inv = await dbGet('inventory', {id:'eq.'+part.part_id, select:'qty'});
      if (inv[0]) await dbUpdate('inventory', {qty:(inv[0].qty||0)+(part.assigned_qty||1), updated_at:nowISO()}, {id:'eq.'+part.part_id});
      await dbDelete('job_parts', {id:'eq.'+retM[2]});
      await addAuditLog('returned', retM[1], part.part_id, part.part_name, u.name, '');
      return json(res, 200, {ok:true});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Manifest
  const mnM = p.match(/^\/api\/jobs\/([^/]+)\/manifest$/);
  if (mnM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const mf = await dbGet('job_manifest', {job_id:'eq.'+mnM[1], select:'*', order:'added_at.asc'});
      const parts = await dbGet('job_parts', {job_id:'eq.'+mnM[1], select:'*'});
      const pm = {}; parts.forEach(p => pm[p.part_id] = p);
      return json(res, 200, mf.map(m => {
        const sp = pm[m.part_id];
        return {...m, staged_status:sp?sp.status:'not_staged', staged_by:sp?.staged_by||null, staged_at:sp?.staged_at||null,
          signed_out_by:sp?.signed_out_by||null, signed_out_at:sp?.signed_out_at||null,
          installed_by:sp?.installed_by||null, installed_at:sp?.installed_at||null,
          over:sp?.over||false, taken_qty:sp?.taken_qty||0, installed_qty:sp?.installed_qty||0};
      }));
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (mnM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const {partId, part_name, expectedQty, notes} = await readBody(req);
    if (!partId) return json(res, 400, {error:'partId required'});
    try {
      const cat = await dbGet('catalog', {barcode:'eq.'+partId, select:'name'});
      const nm = part_name || cat[0]?.name || partId;
      const item = {id:'mf'+Date.now(), job_id:mnM[1], part_id:partId, part_name:nm, expected_qty:expectedQty||1, notes:notes||'', added_by:u.name, added_at:nowDisplay()};
      return json(res, 201, (await dbInsert('job_manifest', item))[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const mnIM = p.match(/^\/api\/jobs\/([^/]+)\/manifest\/([^/]+)$/);
  if (mnIM && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    try { await dbDelete('job_manifest', {id:'eq.'+mnIM[2]}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Daily Logs
  const dlM = p.match(/^\/api\/jobs\/([^/]+)\/logs$/);
  if (dlM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('daily_logs', {job_id:'eq.'+dlM[1], select:'*', order:'created_at.desc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (dlM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {content, type} = await readBody(req);
    if (!content) return json(res, 400, {error:'Content required'});
    try { return json(res, 201, (await dbInsert('daily_logs', {id:'dl'+Date.now(), job_id:dlM[1], type:type||'note', content, author:u.name, created_at:nowISO()}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // GC Alerts
  const gcM = p.match(/^\/api\/jobs\/([^/]+)\/alerts$/);
  if (gcM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('gc_alerts', {job_id:'eq.'+gcM[1], select:'*', order:'created_at.desc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (gcM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {title, description, priority} = await readBody(req);
    if (!title) return json(res, 400, {error:'Title required'});
    try {
      const alert = {id:'gc'+Date.now(), job_id:gcM[1], title, description:description||'', priority:priority||'normal', status:'open', created_by:u.name, created_at:nowISO()};
      await addNotif('gc_alert','GC Alert: '+title, 'Job '+gcM[1]+' by '+u.name, {job_id:gcM[1]});
      return json(res, 201, (await dbInsert('gc_alerts', alert))[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const gcIM = p.match(/^\/api\/jobs\/([^/]+)\/alerts\/([^/]+)$/);
  if (gcIM && method === 'PUT') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, (await dbUpdate('gc_alerts', await readBody(req), {id:'eq.'+gcIM[2]}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Part Requests
  const prM = p.match(/^\/api\/jobs\/([^/]+)\/requests$/);
  if (prM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('part_requests', {job_id:'eq.'+prM[1], select:'*', order:'created_at.desc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (prM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {part_id, part_name, qty, reason} = await readBody(req);
    try {
      const r = {id:'pr'+Date.now(), job_id:prM[1], part_id:part_id||'', part_name:part_name||'', qty:qty||1, reason:reason||'', status:'pending', created_by:u.name, created_at:nowISO()};
      await addNotif('part_request','Part Request', u.name+' requested '+part_name+' for job '+prM[1], {job_id:prM[1]});
      return json(res, 201, (await dbInsert('part_requests', r))[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const prIM = p.match(/^\/api\/jobs\/([^/]+)\/requests\/([^/]+)$/);
  if (prIM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','foreman','stager')) return;
    const b = await readBody(req);
    if (b.status === 'approved') { b.approved_by = u.name; b.approved_at = nowDisplay(); }
    try { return json(res, 200, (await dbUpdate('part_requests', b, {id:'eq.'+prIM[2]}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Photos
  const phM = p.match(/^\/api\/jobs\/([^/]+)\/photos$/);
  if (phM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('job_photos', {job_id:'eq.'+phM[1], select:'*', order:'created_at.desc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (phM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {url:photoUrl, public_id, caption, type} = await readBody(req);
    if (!photoUrl) return json(res, 400, {error:'url required'});
    try { return json(res, 201, (await dbInsert('job_photos', {id:'ph'+Date.now(), job_id:phM[1], url:photoUrl, public_id:public_id||'', caption:caption||'', type:type||'photo', uploaded_by:u.name, created_at:nowISO()}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const phIM = p.match(/^\/api\/jobs\/([^/]+)\/photos\/([^/]+)$/);
  if (phIM && method === 'DELETE') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbDelete('job_photos', {id:'eq.'+phIM[2]}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Plans
  const plM = p.match(/^\/api\/jobs\/([^/]+)\/plans$/);
  if (plM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('job_plans', {job_id:'eq.'+plM[1], select:'*', order:'created_at.desc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (plM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {url:planUrl, public_id, name, thumb_url, plan_type} = await readBody(req);
    if (!planUrl) return json(res, 400, {error:'url required'});
    try { return json(res, 201, (await dbInsert('job_plans', {id:'pl'+Date.now(), job_id:plM[1], name:name||'Plan', url:planUrl, public_id:public_id||'', thumb_url:thumb_url||'', plan_type:plan_type||'plans', notes:'', uploaded_by:u.name, created_at:nowISO()}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const plIM = p.match(/^\/api\/jobs\/([^/]+)\/plans\/([^/]+)$/);
  if (plIM && method === 'PUT') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, (await dbUpdate('job_plans', await readBody(req), {id:'eq.'+plIM[2]}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (plIM && method === 'DELETE') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbDelete('job_plans', {id:'eq.'+plIM[2]}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── ATTENDANCE ────────────────────────────────────────────────────────────
  const attM = p.match(/^\/api\/jobs\/([^/]+)\/attendance$/);
  if (attM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('job_attendance', {job_id:'eq.'+attM[1], select:'*', order:'sign_in_at.desc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (attM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {action} = await readBody(req);
    try {
      if (action === 'signin') {
        // Check not already signed in to this job
        const existing = await dbGet('job_attendance', {job_id:'eq.'+attM[1], user_id:'eq.'+u.id, sign_out_at:'is.null', select:'id'});
        if (existing[0]) return json(res, 400, {error:'Already signed in to this job'});
        const rec = {id:'att'+Date.now(), job_id:attM[1], user_id:u.id, user_name:u.name, user_role:u.role, sign_in_at:nowISO(), sign_out_at:null, hours:null, created_at:nowISO()};
        return json(res, 201, (await dbInsert('job_attendance', rec))[0]);
      } else if (action === 'signout') {
        const recs = await dbGet('job_attendance', {job_id:'eq.'+attM[1], user_id:'eq.'+u.id, sign_out_at:'is.null', select:'*', order:'sign_in_at.desc'});
        if (!recs[0]) return json(res, 400, {error:'Not signed in to this job'});
        const rec = recs[0];
        const signInTime = new Date(rec.sign_in_at);
        const signOutTime = new Date();
        const hours = Math.round((signOutTime - signInTime) / 36000) / 100; // 2 decimal places
        await dbUpdate('job_attendance', {sign_out_at:nowISO(), hours}, {id:'eq.'+rec.id});
        return json(res, 200, {ok:true, hours});
      }
      return json(res, 400, {error:'action must be signin or signout'});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Check if user is currently signed in to a job
  if (p === '/api/attendance/status' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const recs = await dbGet('job_attendance', {user_id:'eq.'+u.id, sign_out_at:'is.null', select:'*'});
      return json(res, 200, recs);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Hours report
  if (p === '/api/attendance/report' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const all = await dbGet('job_attendance', {select:'*', order:'sign_in_at.desc'});
      // By technician
      const byTech = {};
      all.forEach(r => {
        if (!byTech[r.user_name]) byTech[r.user_name] = {name:r.user_name, role:r.user_role, total_hours:0, jobs:{}};
        const hrs = r.hours || 0;
        byTech[r.user_name].total_hours = Math.round((byTech[r.user_name].total_hours + hrs) * 100) / 100;
        if (!byTech[r.user_name].jobs[r.job_id]) byTech[r.user_name].jobs[r.job_id] = 0;
        byTech[r.user_name].jobs[r.job_id] = Math.round((byTech[r.user_name].jobs[r.job_id] + hrs) * 100) / 100;
      });
      // By job
      const byJob = {};
      all.forEach(r => {
        if (!byJob[r.job_id]) byJob[r.job_id] = {job_id:r.job_id, total_hours:0, techs:{}};
        const hrs = r.hours || 0;
        byJob[r.job_id].total_hours = Math.round((byJob[r.job_id].total_hours + hrs) * 100) / 100;
        if (!byJob[r.job_id].techs[r.user_name]) byJob[r.job_id].techs[r.user_name] = 0;
        byJob[r.job_id].techs[r.user_name] = Math.round((byJob[r.job_id].techs[r.user_name] + hrs) * 100) / 100;
      });
      return json(res, 200, {by_tech:Object.values(byTech), by_job:Object.values(byJob), raw:all});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Catalog
  if (p === '/api/catalog' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('catalog', {select:'*', order:'name.asc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/catalog' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const {barcode, name, part_number, category, description, alt_barcodes, unit_cost} = await readBody(req);
    if (!barcode||!name) return json(res, 400, {error:'barcode and name required'});
    try { return json(res, 201, (await dbUpsert('catalog', {barcode, name, part_number:part_number||'', category:category||'', description:description||'', alt_barcodes:alt_barcodes||[], unit_cost:parseFloat(unit_cost)||0}))[0] || {barcode,name}); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const cM = p.match(/^\/api\/catalog\/([^/]+)$/);
  if (cM && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { await dbDelete('catalog', {barcode:'eq.'+decodeURIComponent(cM[1])}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Inventory
  if (p === '/api/inventory' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('inventory', {select:'*', order:'name.asc'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/inventory' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const {id, name, description, qty, min_qty} = await readBody(req);
    if (!id) return json(res, 400, {error:'id required'});
    try {
      const existing = await dbGet('inventory', {id:'eq.'+id, select:'qty,min_qty'});
      const currentQty = existing[0]?.qty || 0;
      const item = {id, name:name||id, description:description||'', qty:Math.max(0, currentQty+(qty||0)), min_qty:min_qty||existing[0]?.min_qty||0, updated_at:nowISO()};
      const rows = await dbUpsert('inventory', item);
      if (item.min_qty > 0 && item.qty <= item.min_qty) await addNotif('low_stock','Low stock: '+name, name+' is at '+item.qty+' (min: '+item.min_qty+')', {part_id:id});
      return json(res, 200, rows[0]||item);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const invM = p.match(/^\/api\/inventory\/([^/]+)$/);
  if (invM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    try { return json(res, 200, (await dbUpdate('inventory', {...await readBody(req), updated_at:nowISO()}, {id:'eq.'+decodeURIComponent(invM[1])}))[0]); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Schedule
  if (p === '/api/schedule' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const rows = await dbGet('jobs', {archived:'eq.false', select:'id,name,address,phase,date_contract,date_permit,date_start,date_roughin,date_trimout,date_inspection,date_next_visit,date_closeout,date_co'});
      const today = new Date(); today.setHours(0,0,0,0);
      const upcoming = [];
      const dateFields = [{key:'date_next_visit',label:'Next Visit'},{key:'date_start',label:'On-Site Start'},{key:'date_roughin',label:'Rough-in Complete'},{key:'date_trimout',label:'Trim-out Complete'},{key:'date_inspection',label:'Inspection'},{key:'date_closeout',label:'Closeout'},{key:'date_co',label:'CO Date'},{key:'date_contract',label:'Contract Signed'},{key:'date_permit',label:'Permit Date'}];
      rows.forEach(job => {
        dateFields.forEach(df => {
          if (!job[df.key]) return;
          const d = new Date(job[df.key]); if (isNaN(d.getTime())) return;
          const daysAway = Math.round((d-today)/(864e5));
          upcoming.push({job_id:job.id, job_name:job.name||job.id, address:job.address||'', phase:job.phase, date_type:df.label, date:job[df.key], days_away:daysAway});
        });
      });
      upcoming.sort((a,b)=>new Date(a.date)-new Date(b.date));
      return json(res, 200, upcoming);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Notifications
  if (p === '/api/notifications' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { return json(res, 200, await dbGet('notifications', {select:'*', order:'created_at.desc', limit:'100'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/notifications/read-all' && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbUpdate('notifications', {read:true}, {'read':'eq.false'}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/notifications' && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { await dbDelete('notifications', {'read':'eq.true'}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const nRM = p.match(/^\/api\/notifications\/([^/]+)\/read$/);
  if (nRM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbUpdate('notifications', {read:true}, {id:'eq.'+nRM[1]}); return json(res, 200, {ok:true}); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Orders
  if (p === '/api/orders' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const params = {select:'*', order:'created_at.desc'};
      if (u.role === 'requestor') params['created_by'] = 'eq.'+u.name;
      return json(res, 200, await dbGet('orders', params));
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/orders' && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {job_id, notes, items} = await readBody(req);
    if (!job_id || !items?.length) return json(res, 400, {error:'job_id and items required'});
    try {
      const order = {id:'ord'+Date.now(), job_id, notes:notes||'', items:JSON.stringify(items), status:'pending', created_by:u.name, created_at:nowISO()};
      await addNotif('new_order','New Order', u.name+' requested '+items.length+' part type(s) for job '+job_id, {job_id});
      return json(res, 201, (await dbInsert('orders', order))[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const ordM = p.match(/^\/api\/orders\/([^/]+)\/(approve|reject|stage)$/);
  if (ordM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const order = (await dbGet('orders', {id:'eq.'+ordM[1], select:'*'}))[0];
    if (!order) return json(res, 404, {error:'Not found'});
    const items = typeof order.items === 'string' ? JSON.parse(order.items) : order.items;
    try {
      if (ordM[2] === 'approve') {
        await dbUpdate('orders', {status:'approved', approved_by:u.name, approved_at:nowISO()}, {id:'eq.'+ordM[1]});
        await addNotif('order_approved','Order Approved','Order for job '+order.job_id+' approved', {job_id:order.job_id});
      } else if (ordM[2] === 'reject') {
        const {note} = await readBody(req);
        await dbUpdate('orders', {status:'rejected', rejected_by:u.name, rejected_at:nowISO(), rejection_note:note||''}, {id:'eq.'+ordM[1]});
        await addNotif('order_rejected','Order Rejected','Order for job '+order.job_id+' rejected', {job_id:order.job_id});
      } else if (ordM[2] === 'stage') {
        const jobRows = await dbGet('jobs', {id:'eq.'+order.job_id, select:'id'});
        if (!jobRows[0]) await dbInsert('jobs', {id:order.job_id, name:order.job_id, phase:'not_started', pct_complete:0, archived:false, created_by:u.name, created_at:nowISO(), updated_at:nowISO()});
        for (const item of items) {
          const cat = await dbGet('catalog', {barcode:'eq.'+item.partId, select:'name'});
          const nm = item.name || cat[0]?.name || item.partId;
          const existing = await dbGet('job_parts', {job_id:'eq.'+order.job_id, part_id:'eq.'+item.partId, select:'id'});
          if (!existing[0]) {
            await dbInsert('job_parts', {id:'jp'+Date.now()+Math.random().toString(36).slice(2), job_id:order.job_id, part_id:item.partId, part_name:nm, status:'staged', assigned_qty:item.qty||1, taken_qty:0, installed_qty:0, over:false, staged_by:u.name, staged_at:nowDisplay(), created_at:nowISO()});
            await autoAddToManifest(order.job_id, item.partId, nm, item.qty||1, u.name);
            const inv = await dbGet('inventory', {id:'eq.'+item.partId, select:'qty'});
            if (inv[0]) await dbUpdate('inventory', {qty:Math.max(0,(inv[0].qty||0)-(item.qty||1)), updated_at:nowISO()}, {id:'eq.'+item.partId});
            await addAuditLog('staged', order.job_id, item.partId, nm, u.name, 'from order '+ordM[1]);
          }
        }
        await dbUpdate('orders', {status:'staged', staged_by:u.name, staged_at:nowISO()}, {id:'eq.'+ordM[1]});
        await addNotif('order_staged','Order Staged',items.length+' parts staged for job '+order.job_id, {job_id:order.job_id});
      }
      return json(res, 200, {ok:true});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Report
  if (p === '/api/report' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const fj = parsed.query.job || '';
    try {
      const jobParams = {archived:'eq.false', select:'id,name,phase,pct_complete'};
      if (fj) jobParams['id'] = 'like.*'+fj+'*';
      const jobs = await dbGet('jobs', jobParams);
      const partParams = {select:'*'};
      if (fj) partParams['job_id'] = 'eq.'+fj;
      const parts = await dbGet('job_parts', partParams);
      const staged=[], signedOut=[], installed=[], overages=[];
      parts.forEach(pt => {
        if (pt.over) overages.push(pt);
        else if (pt.status==='installed'||pt.status==='partial_install') installed.push(pt);
        else if (pt.status==='signed_out') signedOut.push(pt);
        else staged.push(pt);
      });
      const lowStock = (await dbGet('inventory', {select:'*'})).filter(i=>i.min_qty>0&&i.qty<=i.min_qty);
      return json(res, 200, {jobs:jobs.length, staged, signedOut, installed, overages, lowStock});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Audit Log
  if (p === '/api/log' && method === 'GET') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { return json(res, 200, await dbGet('audit_log', {select:'*', order:'created_at.desc', limit:'500'})); } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── FINANCIALS / PROFITABILITY ────────────────────────────────────────────
  // GET /api/jobs/:id/financials  — returns contract, budget, costs, profit calc
  const finM = p.match(/^\/api\/jobs\/([^/]+)\/financials$/);
  if (finM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const job = (await dbGet('jobs', {id:'eq.'+finM[1], select:'*'}))[0];
      if (!job) return json(res, 404, {error:'Job not found'});
      // Get all parts staged to the job with unit costs from catalog
      const parts = await dbGet('job_parts', {job_id:'eq.'+finM[1], select:'*'});
      let materialCost = 0;
      const partCosts = [];
      for (const part of parts) {
        const cat = await dbGet('catalog', {barcode:'eq.'+part.part_id, select:'unit_cost'}).catch(()=>[]);
        const unitCost = parseFloat(cat[0]?.unit_cost || 0);
        const lineTotal = unitCost * (part.assigned_qty || 1);
        materialCost += lineTotal;
        partCosts.push({...part, unit_cost: unitCost, line_total: lineTotal});
      }
      // Get labor hours from attendance
      const att = await dbGet('job_attendance', {job_id:'eq.'+finM[1], sign_out_at:'not.is.null', select:'hours'}).catch(()=>[]);
      const totalHours = att.reduce((sum, a) => sum + (parseFloat(a.hours) || 0), 0);
      const laborRate = parseFloat(job.labor_rate || 0);
      const laborCost = Math.round(totalHours * laborRate * 100) / 100;
      const contractValue = parseFloat(job.contract_value || 0);
      const laborBudget = parseFloat(job.labor_budget || 0);
      const materialBudget = parseFloat(job.material_budget || 0);
      const totalCost = Math.round((materialCost + laborCost) * 100) / 100;
      const grossProfit = Math.round((contractValue - totalCost) * 100) / 100;
      const profitMargin = contractValue > 0 ? Math.round(grossProfit / contractValue * 10000) / 100 : null;
      return json(res, 200, {
        contract_value: contractValue,
        labor_budget: laborBudget,
        material_budget: materialBudget,
        labor_rate: laborRate,
        total_hours: Math.round(totalHours * 100) / 100,
        labor_cost: laborCost,
        material_cost: Math.round(materialCost * 100) / 100,
        total_cost: totalCost,
        gross_profit: grossProfit,
        profit_margin: profitMargin,
        part_costs: partCosts
      });
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // PUT /api/jobs/:id/financials — save contract/budget fields
  if (finM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','foreman')) return;
    const b = await readBody(req);
    const allowed = ['contract_value','labor_budget','material_budget','labor_rate'];
    const upd = {updated_at: nowISO()};
    allowed.forEach(k => { if (b[k] !== undefined) upd[k] = parseFloat(b[k]) || 0; });
    try { return json(res, 200, (await dbUpdate('jobs', upd, {id:'eq.'+finM[1]}))[0]); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // GET /api/financials/overview — all jobs profitability summary
  if (p === '/api/financials/overview' && method === 'GET') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','foreman')) return;
    try {
      const jobs2 = await dbGet('jobs', {archived:'eq.false', select:'id,name,contract_value,labor_budget,material_budget,labor_rate,phase,pct_complete'});
      const parts = await dbGet('job_parts', {select:'job_id,part_id,assigned_qty'});
      const catRows = await dbGet('catalog', {select:'barcode,unit_cost'});
      const catCosts = {}; catRows.forEach(c => catCosts[c.barcode] = parseFloat(c.unit_cost || 0));
      const att = await dbGet('job_attendance', {sign_out_at:'not.is.null', select:'job_id,hours'}).catch(()=>[]);
      const attByJob = {}; att.forEach(a => { if (!attByJob[a.job_id]) attByJob[a.job_id] = 0; attByJob[a.job_id] += parseFloat(a.hours || 0); });
      const summary = jobs2.map(job => {
        const jobParts = parts.filter(p2 => p2.job_id === job.id);
        const materialCost = jobParts.reduce((sum, p2) => sum + (catCosts[p2.part_id] || 0) * (p2.assigned_qty || 1), 0);
        const hrs = attByJob[job.id] || 0;
        const laborCost = hrs * (parseFloat(job.labor_rate) || 0);
        const contractValue = parseFloat(job.contract_value || 0);
        const totalCost = materialCost + laborCost;
        const grossProfit = contractValue - totalCost;
        return {
          job_id: job.id, job_name: job.name, phase: job.phase, pct_complete: job.pct_complete,
          contract_value: Math.round(contractValue * 100) / 100,
          material_cost: Math.round(materialCost * 100) / 100,
          labor_cost: Math.round(laborCost * 100) / 100,
          total_cost: Math.round(totalCost * 100) / 100,
          gross_profit: Math.round(grossProfit * 100) / 100,
          profit_margin: contractValue > 0 ? Math.round(grossProfit / contractValue * 10000) / 100 : null,
          total_hours: Math.round(hrs * 100) / 100,
          labor_budget: parseFloat(job.labor_budget || 0),
          material_budget: parseFloat(job.material_budget || 0)
        };
      });
      const totals = summary.reduce((acc, j) => ({
        contract: acc.contract + j.contract_value,
        cost: acc.cost + j.total_cost,
        profit: acc.profit + j.gross_profit
      }), {contract:0, cost:0, profit:0});
      return json(res, 200, {jobs: summary, totals});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // GET /api/jobs/:id/po — generate purchase order data
  const poM = p.match(/^\/api\/jobs\/([^/]+)\/po$/);
  if (poM && method === 'GET') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','foreman','stager')) return;
    try {
      const job = (await dbGet('jobs', {id:'eq.'+poM[1], select:'*'}))[0];
      if (!job) return json(res, 404, {error:'Job not found'});
      const parts = await dbGet('job_parts', {job_id:'eq.'+poM[1], select:'*'});
      const lineItems = [];
      for (const part of parts) {
        const cat = await dbGet('catalog', {barcode:'eq.'+part.part_id, select:'name,part_number,unit_cost,description'}).catch(()=>[]);
        const unitCost = parseFloat(cat[0]?.unit_cost || 0);
        lineItems.push({
          part_id: part.part_id,
          part_number: cat[0]?.part_number || '',
          description: cat[0]?.description || part.part_name,
          name: part.part_name,
          qty: part.assigned_qty || 1,
          unit_cost: unitCost,
          line_total: Math.round(unitCost * (part.assigned_qty || 1) * 100) / 100,
          status: part.status
        });
      }
      const total = lineItems.reduce((sum, i) => sum + i.line_total, 0);
      return json(res, 200, {
        po_number: 'PO-' + poM[1] + '-' + Date.now().toString().slice(-6),
        job_id: job.id,
        job_name: job.name,
        address: job.address,
        gc_company: job.gc_company,
        generated_by: u.name,
        generated_at: nowDisplay(),
        line_items: lineItems,
        total: Math.round(total * 100) / 100
      });
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  json(res, 404, {error:'Not found'});
});

server.listen(PORT, '0.0.0.0', async () => {
  console.log('\nField Ops Platform starting on port ' + PORT);
  await setupDB();
  console.log('Ready.');
  if (process.env.RENDER) console.log('Running on Render');
});
