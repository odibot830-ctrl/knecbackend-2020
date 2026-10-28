'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {Pool} = require('pg');
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
function validate(db) {
  if (!db || !Array.isArray(db.exams) || !db.settings || typeof db.settings.brandName !== 'string') throw new Error('Invalid library metadata');
  const ids = new Set();
  for (const e of db.exams) {
    if (!e.id || ids.has(e.id) || !['seed','upload'].includes(e.source) || typeof e.filename !== 'string' || path.basename(e.filename) !== e.filename || !e.filename.endsWith('.pdf')) throw new Error('Invalid paper metadata');
    ids.add(e.id);
  }
  if (db.settings.logo && (typeof db.settings.logo !== 'string' || path.basename(db.settings.logo) !== db.settings.logo || !/\.(png|jpg|gif|webp)$/.test(db.settings.logo))) throw new Error('Invalid logo metadata');
  return db;
}
function assets(db) {
  return [...new Set([...db.exams.filter(e=>e.source==='upload').map(e=>'papers/'+e.filename), ...(db.settings.logo?['logos/'+db.settings.logo]:[])])];
}
function atomic(file, bytes) {
  fs.mkdirSync(path.dirname(file),{recursive:true});
  const temp=file+'.'+crypto.randomUUID()+'.tmp';
  fs.writeFileSync(temp,bytes,{mode:0o600});fs.renameSync(temp,file);
}
class NeonStorage {
  constructor({connectionString, dataDir, namespace='knec-library', backupMs=240000, recoveryMs=120000}) {
    this.dir=dataDir;this.namespace=namespace;this.backupMs=backupMs;this.recoveryMs=recoveryMs;this.timers=[];this.fileCache=new Map();
    this.status={enabled:!!connectionString,backupIntervalSeconds:backupMs/1000,recoveryIntervalSeconds:recoveryMs/1000,lastBackupAt:null,lastRecoveryAt:null,lastError:null};
    if(connectionString){
      // Verify certificates (including Neon sslmode=require URLs). Never disable TLS validation.
      const url=new URL(connectionString);
      if(!['postgres:','postgresql:'].includes(url.protocol))throw new Error('DATABASE_URL must be a PostgreSQL connection URL');
      for(const name of ['sslmode','sslcert','sslkey','sslrootcert','channel_binding'])url.searchParams.delete(name);
      this.pool=new Pool({connectionString:url.toString(),ssl:{rejectUnauthorized:true},enableChannelBinding:true,max:3,connectionTimeoutMillis:15000,idleTimeoutMillis:10000,query_timeout:30000,application_name:'knec-library-backup'});
      this.pool.on('error',()=>this.fail('Database connection interrupted; retrying on next scheduled check.'));
    }
  }
  fail(message){this.status.lastError=message;console.error('Neon storage:',message);}
  async init(){
    if(!this.pool||this.ready)return;
    await this.pool.query(`CREATE TABLE IF NOT EXISTS knec_backup_snapshots (
      id BIGSERIAL PRIMARY KEY, namespace TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), metadata JSONB NOT NULL,
      manifest JSONB NOT NULL, digest TEXT NOT NULL)`);
    await this.pool.query('CREATE INDEX IF NOT EXISTS knec_backup_namespace_idx ON knec_backup_snapshots(namespace,id DESC)');
    await this.pool.query(`CREATE TABLE IF NOT EXISTS knec_backup_files (
      snapshot_id BIGINT NOT NULL REFERENCES knec_backup_snapshots(id) ON DELETE CASCADE,
      file_path TEXT NOT NULL, content BYTEA NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(snapshot_id,file_path))`);
    this.ready=true;
  }
  async latest(){
    if(!this.pool)return null;
    const {rows}=await this.pool.query('SELECT id,metadata,manifest,digest,created_at FROM knec_backup_snapshots WHERE namespace=$1 ORDER BY id DESC LIMIT 1',[this.namespace]);
    return rows[0]||null;
  }
  async readSnapshot(){
    if(!this.pool)return null;
    await this.init();
    // One consistent transaction protects against retention cleanup by another instance.
    const client=await this.pool.connect();
    try{
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const {rows}=await client.query('SELECT id,metadata,manifest,digest,created_at FROM knec_backup_snapshots WHERE namespace=$1 ORDER BY id DESC LIMIT 1',[this.namespace]);
      if(!rows.length){await client.query('COMMIT');return null;}
      const s=rows[0];validate(s.metadata);
      // JSONB canonicalizes object ordering: digest is over metadata normalized below.
      if(hash(canonical(s.metadata))!==s.digest)throw new Error('Neon metadata checksum mismatch');
      const files=(await client.query('SELECT file_path,content,digest FROM knec_backup_files WHERE snapshot_id=$1',[s.id])).rows;
      const byPath=new Map(files.map(f=>[f.file_path,f]));
      for(const name of assets(s.metadata)){
        const f=byPath.get(name);
        if(!f||s.manifest[name]!==f.digest||hash(f.content)!==f.digest)throw new Error('Neon file checksum mismatch');
      }
      await client.query('COMMIT');return {...s,files:byPath};
    }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
  }
  async bootstrap(local){
    if(!this.pool)return local;
    await this.init();
    if(local)return local;
    const s=await this.readSnapshot();if(!s)return null;
    for(const name of assets(s.metadata))atomic(path.join(this.dir,name),s.files.get(name).content);
    atomic(path.join(this.dir,'database.json'),JSON.stringify(s.metadata,null,2));
    this.status.lastRecoveryAt=new Date().toISOString();this.status.lastError=null;
    return s.metadata;
  }
  fileValid(db,name){
    try{
      const file=path.join(this.dir,name);const stat=fs.statSync(file);
      const expected=name.startsWith('papers/')?db.exams.find(e=>'papers/'+e.filename===name)?.fileHash:db.settings.logoHash;
      const key=[expected||'',stat.size,stat.mtimeMs,stat.ctimeMs].join(':');
      if(this.fileCache.get(name)===key)return true;
      const content=fs.readFileSync(file);
      const valid=expected?hash(content)===expected:(name.endsWith('.pdf')?content.subarray(0,5).toString()==='%PDF-':content.length>0);
      if(valid)this.fileCache.set(name,key);else this.fileCache.delete(name);
      return valid;
    }catch{return false;}
  }
  async recover(getDB){
    if(this.recoveryJob)return this.recoveryJob;
    this.recoveryJob=this.doRecover(getDB).finally(()=>{this.recoveryJob=null;});return this.recoveryJob;
  }
  async doRecover(getDB){
    const db=validate(getDB());
    const file=path.join(this.dir,'database.json');
    // In-memory metadata is authoritative until restart. Never roll back intentional
    // deletions/settings or newer unsynchronized changes to an older snapshot.
    let broken=false;
    try{broken=canonical(validate(JSON.parse(fs.readFileSync(file,'utf8'))))!==canonical(db);}catch{broken=true;}
    const missing=assets(db).filter(name=>!this.fileValid(db,name));
    if(!broken&&!missing.length)return false;
    let s=null;
    if(missing.length&&this.pool)s=await this.readSnapshot();
    // Recheck current state after asynchronous I/O: admin may have changed it.
    const current=validate(getDB());const needed=assets(current);
    for(const name of missing){
      if(!needed.includes(name)||this.fileValid(current,name))continue;
      const f=s&&s.files.get(name);
      if(!f)throw new Error('An uploaded file has no Neon backup yet; restore it from your own copy.');
      atomic(path.join(this.dir,name),f.content);
    }
    if(broken)atomic(file,JSON.stringify(current,null,2));
    this.status.lastRecoveryAt=new Date().toISOString();this.status.lastError=null;return true;
  }
  async backup(getDB){
    if(!this.pool)return false;
    if(this.backupJob)return this.backupJob;
    this.backupJob=this.doBackup(getDB).finally(()=>{this.backupJob=null;});return this.backupJob;
  }
  async doBackup(getDB){
    await this.init();
    await this.recover(getDB);
    // Capture metadata and bytes synchronously before any network await.
    const db=validate(structuredClone(getDB()));const manifest={};const files=[];
    for(const name of assets(db)){
      const content=fs.readFileSync(path.join(this.dir,name));const digest=hash(content);manifest[name]=digest;files.push({name,content,digest});
    }
    const digest=hash(canonical(db));const client=await this.pool.connect();
    try{
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',['knec-backup:'+this.namespace]);
      const old=(await client.query('SELECT digest,manifest FROM knec_backup_snapshots WHERE namespace=$1 ORDER BY id DESC LIMIT 1',[this.namespace])).rows[0];
      if(!old||old.digest!==digest||canonical(old.manifest)!==canonical(manifest)){
        const r=await client.query('INSERT INTO knec_backup_snapshots(namespace,metadata,manifest,digest) VALUES($1,$2,$3,$4) RETURNING id',[this.namespace,db,manifest,digest]);
        for(const f of files)await client.query('INSERT INTO knec_backup_files(snapshot_id,file_path,content,digest) VALUES($1,$2,$3,$4)',[r.rows[0].id,f.name,f.content,f.digest]);
        await client.query('DELETE FROM knec_backup_snapshots WHERE namespace=$1 AND id NOT IN (SELECT id FROM knec_backup_snapshots WHERE namespace=$1 ORDER BY id DESC LIMIT 3)',[this.namespace]);
      }
      await client.query('COMMIT');this.status.lastBackupAt=new Date().toISOString();this.status.lastError=null;return true;
    }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
  }
  start(getDB){
    if(!this.pool)return;
    const run=(job,label)=>job.call(this,getDB).catch(()=>this.fail(label+' failed. Local data was not replaced; check database connectivity and uploaded files.'));
    this.timers.push(setInterval(()=>run(this.backup,'Scheduled backup'),this.backupMs));
    this.timers.push(setInterval(()=>run(this.recover,'Recovery check'),this.recoveryMs));
    for(const t of this.timers)t.unref();
  }
  async close(getDB){for(const t of this.timers)clearInterval(t);if(this.pool){await this.backup(getDB);await this.pool.end();}}
}
function canonical(value){
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
module.exports={NeonStorage,validate,assets,atomic,canonical};
