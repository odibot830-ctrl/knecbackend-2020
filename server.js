'use strict';
const path = require('node:path');
require('dotenv').config({path:path.join(__dirname,'.env'),quiet:true});
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit').rateLimit;
const multer = require('multer');
const app = express();
app.disable('x-powered-by'); app.set('trust proxy',1);
const production=process.env.NODE_ENV==='production';
const adminPath=process.env.ADMIN_PATH || '/manage-kneck';
if(!/^\/[a-zA-Z0-9_-]{8,100}$/.test(adminPath)) throw new Error('ADMIN_PATH must be one non-reserved path segment of 8–100 letters, numbers, hyphens or underscores.');
if(['/api','/healthz','/public','/admin-assets'].includes(adminPath)) throw new Error('Reserved ADMIN_PATH');
const password=process.env.ADMIN_PASSWORD || '';
const secret=process.env.SESSION_SECRET || '';
if(password.length<16 || secret.length<48) throw new Error('Set ADMIN_PASSWORD (at least 16 characters) and SESSION_SECRET (at least 48 characters). See the private generated environment file.');
const adminUser=process.env.ADMIN_USER || 'admin';
const passwordSalt=crypto.randomBytes(32);
const passwordHash=crypto.scryptSync(password,passwordSalt,64);
const seedDir=path.join(__dirname,'seed');
const dataDir=path.resolve(process.env.DATA_DIR || path.join(__dirname,'data'));
try { fs.mkdirSync(dataDir,{recursive:true}); fs.accessSync(dataDir,fs.constants.W_OK); }
catch(e) { throw new Error('DATA_DIR is not writable. Mount a Render persistent disk at /var/data and set DATA_DIR=/var/data, or use ./data locally. '+e.message); }
if(production && !process.env.DATA_DIR) throw new Error('Production requires an explicit persistent DATA_DIR. Use the supplied Render Blueprint or configure durable storage.');
for(const folder of ['papers','logos'])fs.mkdirSync(path.join(dataDir,folder),{recursive:true});
const subjects=JSON.parse(fs.readFileSync(path.join(seedDir,'catalog.json'),'utf8'));
const databaseFile=path.join(dataDir,'database.json');
let db;
if(fs.existsSync(databaseFile)){
  try {db=JSON.parse(fs.readFileSync(databaseFile,'utf8')); if(!Array.isArray(db.exams)||!db.settings)throw new Error('Invalid database shape');}
  catch(e){throw new Error('Cannot read database.json. Restore a valid backup; existing data was NOT overwritten. '+e.message);}
}else{
  db={version:1,settings:{brandName:'Kneck Official',instructions:'Click Browse exams. Choose a subject, select its paper, then click Download PDF. The marking guidance is included after the questions.',logo:null},exams:JSON.parse(fs.readFileSync(path.join(seedDir,'exams.json'),'utf8')).map(e=>({...e,source:'seed'}))};
}
function persist(){const temp=databaseFile+'.tmp';fs.writeFileSync(temp,JSON.stringify(db,null,2),{mode:0o600});fs.renameSync(temp,databaseFile);}
persist();
const sessions=new Map();
const allowedOrigins=(process.env.FRONTEND_ORIGINS||'http://localhost:4173,http://127.0.0.1:4173').split(',').map(s=>s.trim()).filter(Boolean);
app.use(helmet({crossOriginResourcePolicy:{policy:'cross-origin'},contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'",'data:','blob:'],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"],upgradeInsecureRequests:production?[]:null}}}));
app.use(express.json({limit:'32kb'}));
app.get('/healthz',(req,res)=>res.json({ok:true,service:'kneck-official-api',version:'1.0.0'}));
app.use('/api',rateLimit({windowMs:15*60*1000,limit:1000,standardHeaders:'draft-8',legacyHeaders:false}));
const publicCors=cors({origin(origin,cb){if(!origin||allowedOrigins.includes(origin))return cb(null,true);const error=new Error('Origin is not in FRONTEND_ORIGINS.');error.status=403;cb(error);},methods:['GET','HEAD','OPTIONS'],credentials:false});
app.use(['/api/catalog','/api/settings','/api/exams','/api/downloads','/api/logo'],publicCors);
function publicExam(e){const {filename,source,...view}=e;return {...view,bytes:fs.statSync(examFile(e)).size};}
function examFile(e){return path.join(e.source==='seed'?path.join(seedDir,'papers'):path.join(dataDir,'papers'),path.basename(e.filename));}
app.get('/api/catalog',(req,res)=>res.json({subjects,independent:true,reference:'https://www.knec.ac.ke/wp-content/uploads/2026/02/2026-KCSE-Timetable.pdf'}));
app.get('/api/settings',(req,res)=>res.json({...db.settings,logoUrl:db.settings.logo?'/api/logo':null,logo:undefined}));
app.get('/api/logo',(req,res)=>{if(!db.settings.logo)return res.sendStatus(404);res.set('Cache-Control','no-cache');res.sendFile(path.join(dataDir,'logos',path.basename(db.settings.logo)));});
app.get('/api/exams',(req,res)=>{
  let exams=db.exams.filter(e=>e.published);
  if(req.query.subject)exams=exams.filter(e=>e.subjectId===req.query.subject);
  if(req.query.paper)exams=exams.filter(e=>e.paper===Number(req.query.paper));
  res.set('Cache-Control','no-cache');res.json({exams:exams.map(publicExam)});
});
app.get('/api/downloads/:id',(req,res,next)=>{
  const exam=db.exams.find(e=>e.id===req.params.id&&e.published);
  if(!exam)return res.status(404).json({error:'Paper not found or unpublished.'});
  res.set('Cache-Control','private, no-store');
  const safeTitle=exam.title.replace(/[^a-zA-Z0-9 -]/g,'').slice(0,70)||'Revision';
  res.download(examFile(exam),`${exam.subjectId}-paper-${exam.paper}-${safeTitle}.pdf`,err=>{
    if(err){if(!res.headersSent)next(err);return;}
    if(req.method!=='HEAD'){exam.downloads=(exam.downloads||0)+1;try{persist();}catch(e){console.error('Could not save download count:',e.message);}}
  });
});
function sameOrigin(req,res,next){
  const origin=req.get('origin');
  if(origin){let host;try{host=new URL(origin).host;}catch{return res.status(403).json({error:'Invalid origin.'});}if(host!==req.get('host'))return res.status(403).json({error:'Open the admin panel directly on the backend domain.'});}
  next();
}
app.use('/api/admin',sameOrigin);
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=')).filter(x=>x.length===2));}
function sign(payload){const body=Buffer.from(JSON.stringify(payload)).toString('base64url');return body+'.'+crypto.createHmac('sha256',secret).update(body).digest('base64url');}
function readSession(req){
  try{
    const token=cookies(req).kneck_session; if(!token)return null;const parts=token.split('.');if(parts.length!==2)return null;
    const expected=crypto.createHmac('sha256',secret).update(parts[0]).digest();const got=Buffer.from(parts[1],'base64url');if(got.length!==expected.length||!crypto.timingSafeEqual(got,expected))return null;
    const data=JSON.parse(Buffer.from(parts[0],'base64url').toString());
    if(data.exp<Date.now()||!sessions.has(data.jti)){sessions.delete(data.jti);return null;}return data;
  }catch{return null;}
}
const cookieOptions={httpOnly:true,secure:production,sameSite:'strict',path:'/api/admin',maxAge:8*60*60*1000};
app.post('/api/admin/login',rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:'draft-8',legacyHeaders:false}),async(req,res,next)=>{
  try{
    const supplied=String(req.body.password||'').slice(0,1024);
    const hash=await new Promise((resolve,reject)=>crypto.scrypt(supplied,passwordSalt,64,(e,r)=>e?reject(e):resolve(r)));
    if(req.body.username!==adminUser||!crypto.timingSafeEqual(hash,passwordHash))return res.status(401).json({error:'Incorrect username or password.'});
    for(const [id,exp] of sessions)if(exp<Date.now())sessions.delete(id);
    if(sessions.size>=20)sessions.delete(sessions.keys().next().value);
    const session={jti:crypto.randomUUID(),csrf:crypto.randomBytes(24).toString('hex'),exp:Date.now()+cookieOptions.maxAge};sessions.set(session.jti,session.exp);
    res.cookie('kneck_session',sign(session),cookieOptions);res.json({ok:true,csrf:session.csrf});
  }catch(e){next(e);}
});
app.use('/api/admin',(req,res,next)=>{const session=readSession(req);if(!session)return res.status(401).json({error:'Please sign in to the admin panel.'});req.session=session;if(!['GET','HEAD','OPTIONS'].includes(req.method)&&req.get('x-csrf-token')!==session.csrf)return res.status(403).json({error:'Security token missing or expired. Refresh and sign in again.'});next();});
app.get('/api/admin/me',(req,res)=>res.json({username:adminUser,csrf:req.session.csrf}));
app.post('/api/admin/logout',(req,res)=>{sessions.delete(req.session.jti);res.clearCookie('kneck_session',{path:'/api/admin',httpOnly:true,secure:production,sameSite:'strict'});res.json({ok:true});});
app.get('/api/admin/dashboard',(req,res)=>res.json({subjects,settings:db.settings,exams:db.exams.map(publicExam),stats:{papers:db.exams.length,published:db.exams.filter(e=>e.published).length,downloads:db.exams.reduce((n,e)=>n+(e.downloads||0),0)}}));
app.put('/api/admin/settings',(req,res)=>{
  const {brandName,instructions}=req.body;
  if(typeof brandName!=='string'||!brandName.trim()||brandName.length>60||typeof instructions!=='string'||!instructions.trim()||instructions.length>1500)return res.status(400).json({error:'Provide a brand name (1–60 characters) and instructions (1–1500 characters).'});
  db.settings={...db.settings,brandName:brandName.trim(),instructions:instructions.trim()};persist();res.json({ok:true});
});
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:20*1024*1024,files:1,fields:10,fieldSize:4000}});
app.post('/api/admin/exams',upload.single('file'),(req,res)=>{
  const {subjectId,title}=req.body;const paper=Number(req.body.paper);const year=Number(req.body.year);
  const subject=subjects.find(s=>s.id===subjectId);
  if(!subject||!subject.papers.some(p=>p.number===paper))return res.status(400).json({error:'Invalid subject or paper. Paper 3 is not available for every subject.'});
  if(typeof title!=='string'||!title.trim()||title.length>120||!Number.isInteger(year)||year<2000||year>2100)return res.status(400).json({error:'Title required (up to 120 characters); year must be 2000–2100.'});
  if(!req.file||req.file.buffer.subarray(0,5).toString()!=='%PDF-')return res.status(400).json({error:'Upload a valid PDF file, up to 20 MB.'});
  const id=crypto.randomUUID();const filename=id+'.pdf';fs.writeFileSync(path.join(dataDir,'papers',filename),req.file.buffer,{mode:0o600});
  const exam={id,subjectId,paper,title:title.trim(),year,kind:'Uploaded revision',filename,source:'upload',published:req.body.published!=='false',createdAt:new Date().toISOString(),downloads:0};
  db.exams.unshift(exam);persist();res.status(201).json({exam:publicExam(exam)});
});
app.patch('/api/admin/exams/:id',(req,res)=>{const exam=db.exams.find(e=>e.id===req.params.id);if(!exam)return res.sendStatus(404);if(typeof req.body.published!=='boolean')return res.status(400).json({error:'published must be true or false.'});exam.published=req.body.published;persist();res.json({ok:true});});
app.delete('/api/admin/exams/:id',(req,res)=>{const exam=db.exams.find(e=>e.id===req.params.id);if(!exam)return res.sendStatus(404);db.exams=db.exams.filter(e=>e.id!==exam.id);persist();if(exam.source==='upload')fs.rmSync(examFile(exam),{force:true});res.json({ok:true});});
function imageExtension(b){if(b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))return'png';if(b[0]===255&&b[1]===216&&b[2]===255)return'jpg';if(['GIF87a','GIF89a'].includes(b.subarray(0,6).toString()))return'gif';if(b.subarray(0,4).toString()==='RIFF'&&b.subarray(8,12).toString()==='WEBP')return'webp';return null;}
app.post('/api/admin/logo',upload.single('file'),(req,res)=>{if(!req.file||req.file.size>8*1024*1024)return res.status(400).json({error:'Use a PNG, JPG, GIF or WebP image up to 8 MB.'});const ext=imageExtension(req.file.buffer);if(!ext)return res.status(400).json({error:'Unsupported image. Use PNG, JPG, GIF or WebP. SVG is disabled for security.'});const filename=crypto.randomUUID()+'.'+ext;const old=db.settings.logo;fs.writeFileSync(path.join(dataDir,'logos',filename),req.file.buffer);db.settings.logo=filename;persist();if(old)fs.rmSync(path.join(dataDir,'logos',path.basename(old)),{force:true});res.json({ok:true});});
app.delete('/api/admin/logo',(req,res)=>{const old=db.settings.logo;db.settings.logo=null;persist();if(old)fs.rmSync(path.join(dataDir,'logos',path.basename(old)),{force:true});res.json({ok:true});});
app.get('/api/admin/backup',(req,res)=>{res.set('Content-Disposition','attachment; filename="kneck-metadata-backup.json"');res.json({...db,backupNotice:'Metadata only. Back up the complete DATA_DIR for uploaded PDF and logo bytes. Seed PDFs remain in the repository.'});});
// Admin HTML is physically in public/, but is served ONLY at the environment-selected path.
app.get(adminPath,(req,res)=>{res.set('Cache-Control','no-store');res.sendFile(path.join(__dirname,'public','admin.html'));});
app.use('/admin-assets',express.static(path.join(__dirname,'public','assets'),{dotfiles:'deny',index:false}));
app.use((req,res)=>res.status(404).json({error:'Not found.'}));
app.use((err,req,res,next)=>{console.error(err.message);if(res.headersSent)return next(err);const status=err instanceof multer.MulterError?400:err.status||500;res.status(status).json({error:status===500?'The server could not complete the request. Check server logs.':err.message});});
const port=Number(process.env.PORT||3001);
const server=app.listen(port,'0.0.0.0',()=>console.log(`Kneck API listening on ${port}. Storage writable. ${db.exams.length} papers loaded.`));
process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
