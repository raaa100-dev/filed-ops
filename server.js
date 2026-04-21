/**
 * Warehouse & Field Service Platform -- Server
 * Node.js, zero npm dependencies beyond built-ins.
 * Uses Supabase (database) + Cloudinary (files/photos)
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

// Supabase config
const SB_URL = process.env.SUPABASE_URL || 'https://htkvgfmbcoozmkiairvt.supabase.co';
const SB_ANON = process.env.SUPABASE_KEY || 'sb_publishable_1U37N6iZ8Is4mF_aR9kThg_DS7wExWO';
const SB_SERVICE = process.env.SUPABASE_SERVICE_KEY || '';

// Cloudinary config
const CL_CLOUD = process.env.CLOUDINARY_CLOUD || 'disyczlam';
const CL_KEY = process.env.CLOUDINARY_KEY || '641369166864517';
const CL_SECRET = process.env.CLOUDINARY_SECRET || '';
const CL_PRESET = process.env.CLOUDINARY_PRESET || 'btgbch6a';

// ── SUPABASE HTTP CLIENT ──────────────────────────────────────────────────────
function sbRequest(method, table, body, params, useService) {
  return new Promise((resolve, reject) => {
    const key = useService ? SB_SERVICE : SB_ANON;
    let queryStr = '';
    if (params) {
      const q = Object.entries(params).map(([k,v]) => k + '=' + encodeURIComponent(v)).join('&');
      queryStr = '?' + q;
    }
    const urlParsed = new URL(SB_URL + '/rest/v1/' + table + queryStr);
    const opts = {
      hostname: urlParsed.hostname,
      path: urlParsed.pathname + urlParsed.search,
      method,
      headers: {
        'apikey': key,
        'Authorization': 'Bearer ' + key,
        'Content-Type': 'application/json',
        'Prefer': method === 'POST' ? 'return=representation' : 'return=representation'
      }
    };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = data ? JSON.parse(data) : null;
          if (res.statusCode >= 400) reject(new Error(parsed?.message || parsed?.error || 'DB error ' + res.statusCode));
          else resolve(parsed);
        } catch(e) { resolve(data); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}
async function dbGet(table, params) { return await sbRequest('GET', table, null, params) || []; }
async function dbInsert(table, body) { return await sbRequest('POST', table, body, null, true); }
async function dbUpdate(table, body, params) { return await sbRequest('PATCH', table, body, params, true); }
async function dbDelete(table, params) { return await sbRequest('DELETE', table, null, params, true); }
async function dbUpsert(table, body) {
  const opts = {hostname: new URL(SB_URL).hostname, path: '/rest/v1/'+table, method:'POST', headers:{'apikey':SB_SERVICE,'Authorization':'Bearer '+SB_SERVICE,'Content-Type':'application/json','Prefer':'resolution=merge-duplicates,return=representation'}};
  return new Promise((resolve,reject)=>{
    const req = https.request(opts, res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(d?JSON.parse(d):null);}catch(e){resolve(d);}});});
    req.on('error',reject);req.write(JSON.stringify(body));req.end();
  });
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
function hashPwd(p) { const s=crypto.randomBytes(16).toString('hex'); return s+':'+crypto.pbkdf2Sync(p,s,100000,64,'sha512').toString('hex'); }
function verifyPwd(p,stored) { const[s,h]=stored.split(':'); return crypto.pbkdf2Sync(p,s,100000,64,'sha512').toString('hex')===h; }
function makeToken(uid) { const d=Buffer.from(JSON.stringify({uid,exp:Date.now()+SESSION_HOURS*3600000})).toString('base64'); return d+'.'+crypto.createHmac('sha256',JWT_SECRET).update(d).digest('hex'); }
function verifyToken(t) { if(!t)return null; const[d,s]=t.split('.'); if(!d||!s)return null; if(crypto.createHmac('sha256',JWT_SECRET).update(d).digest('hex')!==s)return null; try{const p=JSON.parse(Buffer.from(d,'base64').toString());return p.exp>Date.now()?p:null;}catch(e){return null;} }
function nowISO() { return new Date().toISOString(); }
function nowDisplay() { return new Date().toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})+' '+new Date().toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit',hour12:true}); }

async function getUser(req) {
  const auth = req.headers['authorization']||'';
  const t = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!t) return null;
  const p = verifyToken(t); if (!p) return null;
  try {
    const rows = await dbGet('users', {'id': 'eq.'+p.uid, 'active': 'eq.true', 'select': '*'});
    return rows[0] || null;
  } catch(e) { return null; }
}
function requireAuth(res, user) { if(!user){json(res,401,{error:'Not authenticated'});return false;}return true; }
function requireRole(res, user, ...roles) { if(!requireAuth(res,user))return false; if(!roles.includes(user.role)){json(res,403,{error:'Permission denied'});return false;}return true; }
function safeUser(u) { if(!u)return null; const{password_hash,...s}=u; return s; }

// ── HTTP HELPERS ──────────────────────────────────────────────────────────────
const CORS = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET, POST, PUT, DELETE, PATCH, OPTIONS'};
function json(res, status, data) { res.writeHead(status,{'Content-Type':'application/json',...CORS}); res.end(JSON.stringify(data)); }
function readBody(req) { return new Promise(r=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{try{r(JSON.parse(b));}catch(e){r({});}});}); }
function serveFile(res, fp, ct) { try{const d=fs.readFileSync(fp);res.writeHead(200,{'Content-Type':ct});res.end(d);}catch(e){res.writeHead(404);res.end('Not found');} }

// ── CLOUDINARY SIGNATURE ──────────────────────────────────────────────────────
function cloudinarySign(params) {
  const sorted = Object.keys(params).sort().map(k=>k+'='+params[k]).join('&');
  return crypto.createHash('sha1').update(sorted + CL_SECRET).digest('hex');
}

// ── SETUP DATABASE TABLES ─────────────────────────────────────────────────────
async function setupDB() {
  // Create tables via Supabase SQL API if they don't exist
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT, role TEXT DEFAULT 'stager', active BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, name TEXT, description TEXT, address TEXT, gc_company TEXT, gc_contact TEXT, gc_phone TEXT, gc_email TEXT, super_name TEXT, super_phone TEXT, super_email TEXT, scope TEXT, notes TEXT, phase TEXT DEFAULT 'not_started', pct_complete INTEGER DEFAULT 0, archived BOOLEAN DEFAULT false, created_by TEXT, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(), date_contract TEXT, date_permit TEXT, date_start TEXT, date_roughin TEXT, date_trimout TEXT, date_inspection TEXT, date_next_visit TEXT, date_closeout TEXT, date_co TEXT)`,
    `CREATE TABLE IF NOT EXISTS job_parts (id TEXT PRIMARY KEY, job_id TEXT, part_id TEXT, part_name TEXT, status TEXT DEFAULT 'staged', assigned_qty INTEGER DEFAULT 1, taken_qty INTEGER DEFAULT 0, installed_qty INTEGER DEFAULT 0, over BOOLEAN DEFAULT false, staged_by TEXT, staged_at TEXT, signed_out_by TEXT, signed_out_at TEXT, installed_by TEXT, installed_at TEXT, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS job_manifest (id TEXT PRIMARY KEY, job_id TEXT, part_id TEXT, part_name TEXT, expected_qty INTEGER DEFAULT 1, notes TEXT, added_by TEXT, added_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS catalog (barcode TEXT PRIMARY KEY, name TEXT NOT NULL, part_number TEXT, category TEXT, description TEXT, alt_barcodes TEXT[], created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS inventory (id TEXT PRIMARY KEY, name TEXT, description TEXT, qty INTEGER DEFAULT 0, min_qty INTEGER DEFAULT 0, updated_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS daily_logs (id TEXT PRIMARY KEY, job_id TEXT, type TEXT DEFAULT 'note', content TEXT, author TEXT, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS gc_alerts (id TEXT PRIMARY KEY, job_id TEXT, title TEXT, description TEXT, priority TEXT DEFAULT 'normal', status TEXT DEFAULT 'open', created_by TEXT, created_at TIMESTAMPTZ DEFAULT now(), resolved_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS part_requests (id TEXT PRIMARY KEY, job_id TEXT, part_id TEXT, part_name TEXT, qty INTEGER DEFAULT 1, reason TEXT, status TEXT DEFAULT 'pending', created_by TEXT, created_at TIMESTAMPTZ DEFAULT now(), approved_by TEXT, approved_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS job_photos (id TEXT PRIMARY KEY, job_id TEXT, url TEXT, public_id TEXT, caption TEXT, type TEXT DEFAULT 'photo', uploaded_by TEXT, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS job_plans (id TEXT PRIMARY KEY, job_id TEXT, name TEXT, url TEXT, public_id TEXT, markup_url TEXT, markup_public_id TEXT, notes TEXT, uploaded_by TEXT, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, job_id TEXT, notes TEXT, items JSONB, status TEXT DEFAULT 'pending', created_by TEXT, created_at TIMESTAMPTZ DEFAULT now(), approved_by TEXT, approved_at TEXT, staged_by TEXT, staged_at TEXT, rejected_by TEXT, rejected_at TEXT, rejection_note TEXT)`,
    `CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, type TEXT, title TEXT, message TEXT, meta JSONB, read BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT now())`,
    `CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, type TEXT, job_id TEXT, part_id TEXT, part_name TEXT, username TEXT, extra TEXT, created_at TIMESTAMPTZ DEFAULT now())`
  ];

  for (const sql of tables) {
    try {
      await new Promise((resolve, reject) => {
        const u = new URL(SB_URL + '/rest/v1/rpc/exec_sql');
        // Use Supabase SQL endpoint
        const opts = { hostname: u.hostname, path: '/rest/v1/rpc/exec_sql', method: 'POST',
          headers: { 'apikey': SB_SERVICE, 'Authorization': 'Bearer ' + SB_SERVICE, 'Content-Type': 'application/json' }};
        const req = https.request(opts, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve(d)); });
        req.on('error', resolve); // ignore errors, tables may already exist
        req.write(JSON.stringify({query: sql}));
        req.end();
      });
    } catch(e) { /* table may already exist */ }
  }

  // Seed admin user if none exists
  try {
    const users = await dbGet('users', {select:'id', limit:'1'});
    if (!users || users.length === 0) {
      await dbInsert('users', {id:'u1', username:'admin', password_hash:hashPwd('admin123'), name:'Administrator', role:'admin', active:true});
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

  // ── Auth ──
  if (p === '/api/login' && method === 'POST') {
    const {username, password} = await readBody(req);
    try {
      const rows = await dbGet('users', {username: 'eq.'+username, active: 'eq.true', select: '*'});
      const user = rows[0];
      if (!user || !verifyPwd(password, user.password_hash)) return json(res, 401, {error:'Invalid username or password'});
      return json(res, 200, {token: makeToken(user.id), user: safeUser(user)});
    } catch(e) { return json(res, 500, {error: e.message}); }
  }
  if (p === '/api/me' && method === 'GET') {
    const u = await getUser(req); if (!u) return json(res, 401, {error:'Not authenticated'});
    return json(res, 200, safeUser(u));
  }

  // ── Cloudinary signed upload ──
  if (p === '/api/upload-sign' && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res, u)) return;
    const {folder} = await readBody(req);
    const timestamp = Math.round(Date.now()/1000);
    const params = {folder: folder||'warehouse', timestamp, upload_preset: CL_PRESET};
    const signature = cloudinarySign(params);
    return json(res, 200, {signature, timestamp, api_key: CL_KEY, cloud_name: CL_CLOUD, upload_preset: CL_PRESET, folder: folder||'warehouse'});
  }

  // ── Users ──
  if (p === '/api/users' && method === 'GET') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { const rows = await dbGet('users', {select:'*', order:'created_at.asc'}); return json(res, 200, rows.map(safeUser)); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/users' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    const {username, password, name, role} = await readBody(req);
    if (!username||!password||!name||!role) return json(res, 400, {error:'All fields required'});
    if (!['admin','stager','signout','requestor','technician','foreman'].includes(role)) return json(res, 400, {error:'Invalid role'});
    try {
      const nu = {id:'u'+Date.now(), username, password_hash:hashPwd(password), name, role, active:true};
      const rows = await dbInsert('users', nu);
      return json(res, 201, safeUser(rows[0]));
    } catch(e) { return json(res, 400, {error: e.message.includes('unique')? 'Username already taken' : e.message}); }
  }
  const uM = p.match(/^\/api\/users\/([^/]+)$/);
  if (uM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    const b = await readBody(req);
    const upd = {};
    if (b.name) upd.name = b.name;
    if (b.role && ['admin','stager','signout','requestor','technician','foreman'].includes(b.role)) upd.role = b.role;
    if (b.active !== undefined) upd.active = !!b.active;
    if (b.password && b.password.length >= 6) upd.password_hash = hashPwd(b.password);
    try { const rows = await dbUpdate('users', upd, {id:'eq.'+uM[1]}); return json(res, 200, safeUser(rows[0])); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (uM && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    if (uM[1] === u.id) return json(res, 400, {error:"Can't delete yourself"});
    try { await dbDelete('users', {id:'eq.'+uM[1]}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Jobs ──
  if (p === '/api/jobs' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const showArch = parsed.query.archived === 'true';
      const params = {select:'*', order:'created_at.desc'};
      if (!showArch) params['archived'] = 'eq.false';
      const rows = await dbGet('jobs', params);
      return json(res, 200, rows);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/jobs' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const b = await readBody(req);
    if (!b.id) return json(res, 400, {error:'Job ID required'});
    try {
      const job = {id:b.id, name:b.name||b.id, description:b.description||'', address:b.address||'',
        gc_company:b.gc_company||'', gc_contact:b.gc_contact||'', gc_phone:b.gc_phone||'', gc_email:b.gc_email||'',
        super_name:b.super_name||'', super_phone:b.super_phone||'', super_email:b.super_email||'',
        scope:b.scope||'', notes:b.notes||'', phase:'not_started', pct_complete:0, archived:false,
        created_by:u.name, created_at:nowISO(),
        date_contract:b.date_contract||null, date_permit:b.date_permit||null, date_start:b.date_start||null,
        date_roughin:b.date_roughin||null, date_trimout:b.date_trimout||null, date_inspection:b.date_inspection||null,
        date_next_visit:b.date_next_visit||null, date_closeout:b.date_closeout||null, date_co:b.date_co||null};
      const rows = await dbInsert('jobs', job);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 400, {error: e.message.includes('unique')? 'Job ID already exists' : e.message}); }
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
      'super_name','super_phone','super_email','scope','notes','phase','pct_complete','archived',
      'date_contract','date_permit','date_start','date_roughin','date_trimout','date_inspection',
      'date_next_visit','date_closeout','date_co'];
    const upd = {updated_at: nowISO()};
    allowed.forEach(k=>{ if(b[k]!==undefined) upd[k]=b[k]; });
    try { const rows = await dbUpdate('jobs', upd, {id:'eq.'+jM[1]}); return json(res, 200, rows[0]); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Job Parts ──
  if (p.match(/^\/api\/jobs\/([^/]+)\/parts$/) && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const jobId = p.match(/^\/api\/jobs\/([^/]+)\/parts$/)[1];
    try { const rows = await dbGet('job_parts', {job_id:'eq.'+jobId, select:'*', order:'created_at.asc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p.match(/^\/api\/jobs\/([^/]+)\/parts$/) && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const jobId = p.match(/^\/api\/jobs\/([^/]+)\/parts$/)[1];
    const {partId, part_name, assignedQty} = await readBody(req);
    if (!partId) return json(res, 400, {error:'partId required'});
    try {
      const catRows = await dbGet('catalog', {barcode:'eq.'+partId, select:'name'});
      const nm = part_name || catRows[0]?.name || partId;
      const part = {id:'jp'+Date.now(), job_id:jobId, part_id:partId, part_name:nm, status:'staged',
        assigned_qty:assignedQty||1, taken_qty:0, installed_qty:0, over:false,
        staged_by:u.name, staged_at:nowDisplay()};
      // Deduct from inventory
      try {
        const inv = await dbGet('inventory', {id:'eq.'+partId, select:'qty'});
        if (inv[0] && inv[0].qty > 0) await dbUpdate('inventory', {qty: Math.max(0, inv[0].qty-(assignedQty||1)), updated_at:nowISO()}, {id:'eq.'+partId});
      } catch(e){}
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
      const upd = {status:'signed_out', signed_out_by:u.name, signed_out_at:nowDisplay(), taken_qty:newTaken, over:isOver};
      await dbUpdate('job_parts', upd, {id:'eq.'+soM[2]});
      if (isOver) await addNotification('overage','Overage: '+part.part_name, part.part_name+' taken '+newTaken+' vs '+part.assigned_qty+' on job '+soM[1], {job_id:soM[1]});
      await addAuditLog(isOver?'over':'signed_out', soM[1], part.part_id, part.part_name, u.name, 'qty:'+(qty||1));
      return json(res, 200, {ok:true, over:isOver});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // Mark installed
  const instM = p.match(/^\/api\/jobs\/([^/]+)\/parts\/([^/]+)\/install$/);
  if (instM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'technician','foreman','admin')) return;
    const {qty} = await readBody(req);
    try {
      const rows = await dbGet('job_parts', {id:'eq.'+instM[2], select:'*'});
      const part = rows[0]; if (!part) return json(res, 404, {error:'Not found'});
      const newInst = (part.installed_qty||0) + (qty||1);
      await dbUpdate('job_parts', {installed_qty:newInst, installed_by:u.name, installed_at:nowDisplay(), status: newInst >= part.assigned_qty ? 'installed' : 'partial_install'}, {id:'eq.'+instM[2]});
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

  // ── Job Manifest ──
  const mnM = p.match(/^\/api\/jobs\/([^/]+)\/manifest$/);
  if (mnM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const mf = await dbGet('job_manifest', {job_id:'eq.'+mnM[1], select:'*', order:'added_at.asc'});
      const parts = await dbGet('job_parts', {job_id:'eq.'+mnM[1], select:'*'});
      const partsMap = {}; parts.forEach(p => partsMap[p.part_id] = p);
      const enriched = mf.map(m => {
        const sp = partsMap[m.part_id];
        return {...m, staged_status: sp ? sp.status : 'not_staged', staged_by: sp?.staged_by||null, staged_at: sp?.staged_at||null, signed_out_by: sp?.signed_out_by||null, signed_out_at: sp?.signed_out_at||null, installed_by: sp?.installed_by||null, installed_at: sp?.installed_at||null, over: sp?.over||false, taken_qty: sp?.taken_qty||0, installed_qty: sp?.installed_qty||0};
      });
      return json(res, 200, enriched);
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
      const rows = await dbInsert('job_manifest', item);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const mnIM = p.match(/^\/api\/jobs\/([^/]+)\/manifest\/([^/]+)$/);
  if (mnIM && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    try { await dbDelete('job_manifest', {id:'eq.'+mnIM[2]}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Daily Logs ──
  const dlM = p.match(/^\/api\/jobs\/([^/]+)\/logs$/);
  if (dlM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('daily_logs', {job_id:'eq.'+dlM[1], select:'*', order:'created_at.desc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (dlM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {content, type} = await readBody(req);
    if (!content) return json(res, 400, {error:'Content required'});
    try {
      const log = {id:'dl'+Date.now(), job_id:dlM[1], type:type||'note', content, author:u.name, created_at:nowISO()};
      const rows = await dbInsert('daily_logs', log);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── GC Alerts ──
  const gcM = p.match(/^\/api\/jobs\/([^/]+)\/alerts$/);
  if (gcM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('gc_alerts', {job_id:'eq.'+gcM[1], select:'*', order:'created_at.desc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (gcM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {title, description, priority} = await readBody(req);
    if (!title) return json(res, 400, {error:'Title required'});
    try {
      const alert = {id:'gc'+Date.now(), job_id:gcM[1], title, description:description||'', priority:priority||'normal', status:'open', created_by:u.name, created_at:nowISO()};
      const rows = await dbInsert('gc_alerts', alert);
      await addNotification('gc_alert','GC Alert: '+title, 'On job '+gcM[1]+' by '+u.name, {job_id:gcM[1]});
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const gcIM = p.match(/^\/api\/jobs\/([^/]+)\/alerts\/([^/]+)$/);
  if (gcIM && method === 'PUT') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const b = await readBody(req);
    try { const rows = await dbUpdate('gc_alerts', b, {id:'eq.'+gcIM[2]}); return json(res, 200, rows[0]); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Part Requests ──
  const prM = p.match(/^\/api\/jobs\/([^/]+)\/requests$/);
  if (prM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('part_requests', {job_id:'eq.'+prM[1], select:'*', order:'created_at.desc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (prM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {part_id, part_name, qty, reason} = await readBody(req);
    try {
      const req2 = {id:'pr'+Date.now(), job_id:prM[1], part_id:part_id||'', part_name:part_name||'', qty:qty||1, reason:reason||'', status:'pending', created_by:u.name, created_at:nowISO()};
      const rows = await dbInsert('part_requests', req2);
      await addNotification('part_request','Part Request', u.name+' requested '+part_name+' for job '+prM[1], {job_id:prM[1]});
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const prIM = p.match(/^\/api\/jobs\/([^/]+)\/requests\/([^/]+)$/);
  if (prIM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','foreman','stager')) return;
    const b = await readBody(req);
    const upd = {...b};
    if (b.status === 'approved') { upd.approved_by = u.name; upd.approved_at = nowDisplay(); }
    try { const rows = await dbUpdate('part_requests', upd, {id:'eq.'+prIM[2]}); return json(res, 200, rows[0]); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Photos ──
  const phM = p.match(/^\/api\/jobs\/([^/]+)\/photos$/);
  if (phM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('job_photos', {job_id:'eq.'+phM[1], select:'*', order:'created_at.desc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (phM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {url:photoUrl, public_id, caption, type} = await readBody(req);
    if (!photoUrl) return json(res, 400, {error:'url required'});
    try {
      const photo = {id:'ph'+Date.now(), job_id:phM[1], url:photoUrl, public_id:public_id||'', caption:caption||'', type:type||'photo', uploaded_by:u.name, created_at:nowISO()};
      const rows = await dbInsert('job_photos', photo);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const phIM = p.match(/^\/api\/jobs\/([^/]+)\/photos\/([^/]+)$/);
  if (phIM && method === 'DELETE') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbDelete('job_photos', {id:'eq.'+phIM[2]}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Plans ──
  const plM = p.match(/^\/api\/jobs\/([^/]+)\/plans$/);
  if (plM && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('job_plans', {job_id:'eq.'+plM[1], select:'*', order:'created_at.desc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (plM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {url:planUrl, public_id, name} = await readBody(req);
    if (!planUrl) return json(res, 400, {error:'url required'});
    try {
      const plan = {id:'pl'+Date.now(), job_id:plM[1], name:name||'Plan', url:planUrl, public_id:public_id||'', notes:'', uploaded_by:u.name, created_at:nowISO()};
      const rows = await dbInsert('job_plans', plan);
      return json(res, 201, rows[0]);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const plIM = p.match(/^\/api\/jobs\/([^/]+)\/plans\/([^/]+)$/);
  if (plIM && method === 'PUT') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const b = await readBody(req);
    try { const rows = await dbUpdate('job_plans', b, {id:'eq.'+plIM[2]}); return json(res, 200, rows[0]); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (plIM && method === 'DELETE') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbDelete('job_plans', {id:'eq.'+plIM[2]}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Catalog ──
  if (p === '/api/catalog' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('catalog', {select:'*', order:'name.asc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/catalog' && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const {barcode, name, part_number, category, description, alt_barcodes} = await readBody(req);
    if (!barcode||!name) return json(res, 400, {error:'barcode and name required'});
    try {
      const item = {barcode, name, part_number:part_number||'', category:category||'', description:description||'', alt_barcodes:alt_barcodes||[]};
      const rows = await dbUpsert('catalog', item);
      return json(res, 201, rows[0]||item);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const cM = p.match(/^\/api\/catalog\/([^/]+)$/);
  if (cM && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { await dbDelete('catalog', {barcode:'eq.'+decodeURIComponent(cM[1])}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Inventory ──
  if (p === '/api/inventory' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('inventory', {select:'*', order:'name.asc'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
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
      if (item.min_qty > 0 && item.qty <= item.min_qty) {
        await addNotification('low_stock','Low stock: '+name, name+' is at '+item.qty+' (min: '+item.min_qty+')', {part_id:id});
      }
      return json(res, 200, rows[0]||item);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const invM = p.match(/^\/api\/inventory\/([^/]+)$/);
  if (invM && method === 'PUT') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const b = await readBody(req); const id = decodeURIComponent(invM[1]);
    try { const rows = await dbUpdate('inventory', {...b, updated_at:nowISO()}, {id:'eq.'+id}); return json(res, 200, rows[0]); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Schedule (upcoming dates across all jobs) ──
  if (p === '/api/schedule' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const rows = await dbGet('jobs', {archived:'eq.false', select:'id,name,address,phase,date_contract,date_permit,date_start,date_roughin,date_trimout,date_inspection,date_next_visit,date_closeout,date_co'});
      const today = new Date(); today.setHours(0,0,0,0);
      const in14 = new Date(today); in14.setDate(in14.getDate()+14);
      const upcoming = [];
      const dateFields = [{key:'date_next_visit',label:'Next Visit'},{key:'date_start',label:'On-Site Start'},{key:'date_roughin',label:'Rough-in Complete'},{key:'date_trimout',label:'Trim-out Complete'},{key:'date_inspection',label:'Inspection'},{key:'date_closeout',label:'Closeout'},{key:'date_co',label:'CO Date'},{key:'date_contract',label:'Contract Signed'},{key:'date_permit',label:'Permit Date'}];
      rows.forEach(job => {
        dateFields.forEach(df => {
          if (!job[df.key]) return;
          const d = new Date(job[df.key]); if (isNaN(d.getTime())) return;
          const daysAway = Math.round((d-today)/(1000*60*60*24));
          upcoming.push({job_id:job.id, job_name:job.name||job.id, address:job.address||'', phase:job.phase, date_type:df.label, date:job[df.key], days_away:daysAway, urgent: daysAway >= 0 && daysAway <= 14, overdue: daysAway < 0});
        });
      });
      upcoming.sort((a,b)=>{const da=new Date(a.date),db=new Date(b.date);return da-db;});
      return json(res, 200, upcoming);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Notifications ──
  if (p === '/api/notifications' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { const rows = await dbGet('notifications', {select:'*', order:'created_at.desc', limit:'100'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/notifications/read-all' && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbUpdate('notifications', {read:true}, {'read':'eq.false'}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/notifications' && method === 'DELETE') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { await dbDelete('notifications', {'read':'eq.true'}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }
  const nRM = p.match(/^\/api\/notifications\/([^/]+)\/read$/);
  if (nRM && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try { await dbUpdate('notifications', {read:true}, {id:'eq.'+nRM[1]}); return json(res, 200, {ok:true}); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Orders ──
  if (p === '/api/orders' && method === 'GET') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    try {
      const params = {select:'*', order:'created_at.desc'};
      if (u.role === 'requestor') params['created_by'] = 'eq.'+u.name;
      const rows = await dbGet('orders', params);
      return json(res, 200, rows);
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  if (p === '/api/orders' && method === 'POST') {
    const u = await getUser(req); if (!requireAuth(res,u)) return;
    const {job_id, notes, items} = await readBody(req);
    if (!job_id || !items?.length) return json(res, 400, {error:'job_id and items required'});
    try {
      const order = {id:'ord'+Date.now(), job_id, notes:notes||'', items:JSON.stringify(items), status:'pending', created_by:u.name, created_at:nowISO()};
      const rows = await dbInsert('orders', order);
      await addNotification('new_order','New Order', u.name+' requested '+items.length+' part type(s) for job '+job_id, {job_id});
      return json(res, 201, {...rows[0], items});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }
  const ordM = p.match(/^\/api\/orders\/([^/]+)\/(approve|reject|stage)$/);
  if (ordM && method === 'POST') {
    const u = await getUser(req); if (!requireRole(res,u,'admin','stager','foreman')) return;
    const order_rows = await dbGet('orders', {id:'eq.'+ordM[1], select:'*'});
    const order = order_rows[0]; if (!order) return json(res, 404, {error:'Not found'});
    const items = typeof order.items === 'string' ? JSON.parse(order.items) : order.items;
    try {
      if (ordM[2] === 'approve') {
        await dbUpdate('orders', {status:'approved', approved_by:u.name, approved_at:nowISO()}, {id:'eq.'+ordM[1]});
        await addNotification('order_approved','Order Approved','Order for job '+order.job_id+' approved',{job_id:order.job_id});
      } else if (ordM[2] === 'reject') {
        const {note} = await readBody(req);
        await dbUpdate('orders', {status:'rejected', rejected_by:u.name, rejected_at:nowISO(), rejection_note:note||''}, {id:'eq.'+ordM[1]});
        await addNotification('order_rejected','Order Rejected','Order for job '+order.job_id+' rejected',{job_id:order.job_id});
      } else if (ordM[2] === 'stage') {
        // Check job exists, create if not
        const jobRows = await dbGet('jobs', {id:'eq.'+order.job_id, select:'id'});
        if (!jobRows[0]) await dbInsert('jobs', {id:order.job_id, name:order.job_id, phase:'not_started', pct_complete:0, archived:false, created_by:u.name, created_at:nowISO()});
        for (const item of items) {
          const cat = await dbGet('catalog', {barcode:'eq.'+item.partId, select:'name'});
          const nm = item.name || cat[0]?.name || item.partId;
          const existing = await dbGet('job_parts', {job_id:'eq.'+order.job_id, part_id:'eq.'+item.partId, select:'id'});
          if (!existing[0]) {
            await dbInsert('job_parts', {id:'jp'+Date.now()+Math.random().toString(36).slice(2), job_id:order.job_id, part_id:item.partId, part_name:nm, status:'staged', assigned_qty:item.qty||1, taken_qty:0, installed_qty:0, over:false, staged_by:u.name, staged_at:nowDisplay()});
            const inv = await dbGet('inventory', {id:'eq.'+item.partId, select:'qty'});
            if (inv[0]) await dbUpdate('inventory', {qty:Math.max(0,(inv[0].qty||0)-(item.qty||1)), updated_at:nowISO()}, {id:'eq.'+item.partId});
            await addAuditLog('staged', order.job_id, item.partId, nm, u.name, 'from order '+ordM[1]);
          }
        }
        await dbUpdate('orders', {status:'staged', staged_by:u.name, staged_at:nowISO()}, {id:'eq.'+ordM[1]});
        await addNotification('order_staged','Order Staged',items.length+' parts staged for job '+order.job_id,{job_id:order.job_id});
      }
      return json(res, 200, {ok:true});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Reports ──
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
        const row = {...pt};
        if (pt.over) overages.push(row);
        else if (pt.status==='installed'||pt.status==='partial_install') installed.push(row);
        else if (pt.status==='signed_out') signedOut.push(row);
        else staged.push(row);
      });
      const lowStock = await dbGet('inventory', {select:'*'});
      return json(res, 200, {jobs:jobs.length, staged, signedOut, installed, overages, lowStock:lowStock.filter(i=>i.min_qty>0&&i.qty<=i.min_qty)});
    } catch(e) { return json(res, 500, {error:e.message}); }
  }

  // ── Audit Log ──
  if (p === '/api/log' && method === 'GET') {
    const u = await getUser(req); if (!requireRole(res,u,'admin')) return;
    try { const rows = await dbGet('audit_log', {select:'*', order:'created_at.desc', limit:'500'}); return json(res, 200, rows); }
    catch(e) { return json(res, 500, {error:e.message}); }
  }

  json(res, 404, {error:'Not found'});
});

async function addAuditLog(type, jobId, partId, partName, username, extra) {
  try { await dbInsert('audit_log', {id:'al'+Date.now()+Math.random().toString(36).slice(2), type, job_id:jobId, part_id:partId, part_name:partName, username, extra:extra||'', created_at:nowISO()}); } catch(e) {}
}
async function addNotification(type, title, message, meta) {
  try { await dbInsert('notifications', {id:'n'+Date.now()+Math.random().toString(36).slice(2), type, title, message, meta:JSON.stringify(meta||{}), read:false, created_at:nowISO()}); } catch(e) {}
}

server.listen(PORT, '0.0.0.0', async () => {
  console.log('\nWarehouse Platform starting on port ' + PORT);
  console.log('Setting up database tables...');
  await setupDB();
  console.log('Ready.');
  if (process.env.RENDER) console.log('Running on Render');
});
