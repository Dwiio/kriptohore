import express from 'express';
import mysql from 'mysql2/promise';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import argon2 from 'argon2';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const app = express();
app.disable('x-powered-by');
app.use(express.json({limit:'20mb'}));
app.use(express.static(path.join(root,'public'), {extensions:['html']}));
const PORT = Number(process.env.PORT || 4177);
const EXPECTED_DONGLE_SHA256 = (process.env.DONGLE_SHA256 || fs.readFileSync(path.join(root,'provisioning/DONGLE_SHA256.txt'),'utf8').trim()).toLowerCase();
const pool = mysql.createPool({
  host:process.env.DB_HOST || '127.0.0.1',
  port:Number(process.env.DB_PORT || 3306),
  user:process.env.DB_USER || 'root',
  password:process.env.DB_PASSWORD || '',
  database:process.env.DB_NAME || 'cryptovault',
  waitForConnections:true, connectionLimit:5, queueLimit:0,
  charset:'utf8mb4'
});
let dongle = {valid:false, volume:null, checkedAt:null};
const hashFile = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function scanVolumes(){
  const roots = process.platform==='darwin' ? ['/Volumes'] : process.platform==='win32' ? (process.env.DRIVE_SCAN_ROOTS||'D:\\\\,E:\\\\,F:\\\\,G:\\\\').split(',') : ['/media/'+os.userInfo().username,'/run/media/'+os.userInfo().username];
  let found = null;
  for(const vol of roots){
    try{
      const candidates = process.platform==='win32' ? [path.join(vol,'MEMORY_CAMERA_DONGLE.key')] :
        fs.readdirSync(vol,{withFileTypes:true}).filter(x=>x.isDirectory()).map(x=>path.join(vol,x.name,'MEMORY_CAMERA_DONGLE.key'));
      for(const f of candidates){
        try{if(fs.existsSync(f) && hashFile(f)===EXPECTED_DONGLE_SHA256){found=f;break;}}catch{}
      }
    }catch{}
    if(found)break;
  }
  dongle={valid:!!found,volume:found?path.dirname(found):null,checkedAt:new Date().toISOString()};
}
scanVolumes(); setInterval(scanVolumes,500).unref();
function sid(req){return req.cookies?.['cv.sid'] || req.headers.cookie?.split(';').map(x=>x.trim()).find(x=>x.startsWith('cv.sid='))?.slice(7);}
async function setSession(res,user='demo'){
  const token=crypto.randomBytes(32).toString('hex');
  const sessionId=crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt=new Date(Date.now()+30*60*1000);
  await pool.execute('INSERT INTO user_sessions (session_id,user_id,expires_at) SELECT ?,id,? FROM users WHERE username=?', [sessionId,expiresAt,user]);
  res.cookie('cv.sid',token,{httpOnly:true,sameSite:'strict',secure:false,path:'/',maxAge:30*60*1000});
}
async function auth(req,res,next){
  const token=sid(req);
  if(!token || !/^[a-f0-9]{64}$/i.test(token))return res.status(401).json({error:'Sesi tidak valid. Silakan login kembali.'});
  const sessionId=crypto.createHash('sha256').update(token).digest('hex');
  try {
    const [rows]=await pool.execute('SELECT s.user_id,s.expires_at,u.username FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.session_id=? LIMIT 1',[sessionId]);
    if(!rows.length || new Date(rows[0].expires_at).getTime()<=Date.now()){
      await pool.execute('DELETE FROM user_sessions WHERE session_id=?',[sessionId]);
      return res.status(401).json({error:'Sesi tidak valid. Silakan login kembali.'});
    }
    if(!dongle.valid){await pool.execute('DELETE FROM user_sessions WHERE session_id=?',[sessionId]);return res.status(423).json({error:'Memory Camera Dongle tidak terpasang atau tidak valid.'});}
    req.session={user:rows[0].username,userId:rows[0].user_id}; next();
  } catch(e) { return res.status(503).json({error:'Tidak dapat memverifikasi sesi melalui MySQL.'}); }
}
function requireDongle(req,res,next){if(!dongle.valid)return res.status(423).json({error:'Pasang Memory Camera Dongle yang valid terlebih dahulu.'});next();}
// Password authentication is server-side only. Argon2id hashes are stored in MySQL.
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32
};
async function initializeAuth() {
  // Keep existing databases compatible; this is safe to run on every startup.
  const [columns] = await pool.query("SHOW COLUMNS FROM users LIKE 'password_hash'");
  if (!columns.length) {
    await pool.query('ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NULL AFTER display_name');
  }
  await pool.execute(
    "INSERT IGNORE INTO users (username, display_name) VALUES ('demo', 'KRIPTOHORE Demo User')"
  );
  const [rows] = await pool.execute('SELECT id, password_hash FROM users WHERE username=? LIMIT 1', ['demo']);
  if (!rows.length) throw new Error('Akun demo tidak dapat dibuat.');
  // Bootstrap only an empty password field; never overwrite a password already set in DB.
  if (!rows[0].password_hash) {
    const initialPassword = process.env.DEMO_INITIAL_PASSWORD || 'kriptohore';
    const passwordHash = await argon2.hash(initialPassword, ARGON2_OPTIONS);
    await pool.execute('UPDATE users SET password_hash=? WHERE id=? AND password_hash IS NULL', [passwordHash, rows[0].id]);
    console.log('Password demo awal berhasil dibuat menggunakan Argon2id dan disimpan ke MySQL.');
  }
}
async function verifyPassword(pass, encodedHash) {
  if (typeof pass !== 'string' || !pass || typeof encodedHash !== 'string' || !encodedHash) return false;
  try { return await argon2.verify(encodedHash, pass, { type: argon2.argon2id }); }
  catch { return false; }
}
const blockHash=b=>crypto.createHash('sha256').update(`${b.index}|${b.timestamp}|${JSON.stringify(b.data)}|${b.previous_hash}|${b.nonce}`).digest('hex');
async function mine(b){do{b.hash=blockHash(b);if(b.hash.startsWith('000'))return b;b.nonce++;}while(true);}
app.get('/api/health',async(_req,res)=>{
  let database=false;try{await pool.query('SELECT 1');database=true;}catch{}
  res.json({ok:true,service:'Kriptohore Local Server',database,dongle:dongle.valid});
});
app.get('/api/dongle/status',(_req,res)=>res.json(dongle));
app.post('/api/password/login',requireDongle,async(req,res)=>{
  try {
    const username=String(req.body?.username || '').trim();
    const password=req.body?.password;
    if (!username || typeof password !== 'string' || !password) {
      return res.status(400).json({error:'Nama akun dan password wajib diisi.'});
    }
    const [rows] = await pool.execute('SELECT id, username, password_hash FROM users WHERE username=? LIMIT 1', [username]);
    if (!rows.length || !await verifyPassword(password, rows[0].password_hash)) {
      return res.status(401).json({error:'Nama akun atau password tidak valid.'});
    }
    await setSession(res, rows[0].username);
    res.json({authenticated:true,method:'password'});
  } catch (e) {
    console.error('Password login error:', e.message);
    res.status(503).json({error:'Autentikasi tidak dapat dilakukan. Pastikan MySQL aktif dan database sudah disiapkan.'});
  }
});
app.post('/api/fingerprint/login',requireDongle,async(req,res)=>{
  if(req.body?.username!=='demo')return res.status(401).json({error:'Nama akun tidak dikenal.'});
  // Existing local Touch ID verification flow is intentionally unchanged.
  try { await setSession(res);res.json({authenticated:true,method:'platform-authenticator-demo'}); }
  catch { res.status(503).json({error:'Gagal membuat sesi login di MySQL.'}); }
});
app.post('/api/logout',async(req,res)=>{const token=sid(req);if(token && /^[a-f0-9]{64}$/i.test(token)){const id=crypto.createHash('sha256').update(token).digest('hex');try{await pool.execute('DELETE FROM user_sessions WHERE session_id=?',[id]);}catch{}}res.clearCookie('cv.sid',{path:'/'});res.json({ok:true});});
app.get('/api/vault',auth,async(_req,res)=>{
  try{const [rows]=await pool.query('SELECT id,ciphertext,created_at FROM vault_messages ORDER BY id DESC');res.json({items:rows.map(r=>({...r,ciphertext:typeof r.ciphertext==='string'?JSON.parse(r.ciphertext):r.ciphertext}))});}
  catch(e){res.status(503).json({error:'MySQL belum tersedia. Jalankan XAMPP dan import database/schema.sql.',detail:e.message});}
});
app.post('/api/vault',auth,async(req,res)=>{
  try{const [r]=await pool.execute('INSERT INTO vault_messages (user_id,ciphertext) VALUES (1,?)',[JSON.stringify(req.body.ciphertext)]);res.json({id:r.insertId});}
  catch(e){res.status(503).json({error:'Gagal menyimpan ke MySQL. Pastikan schema sudah di-import.',detail:e.message});}
});
app.delete('/api/vault/:id',auth,async(req,res)=>{
  try{await pool.execute('DELETE FROM vault_messages WHERE id=?',[req.params.id]);res.json({ok:true});}
  catch(e){res.status(503).json({error:'Gagal menghapus data dari MySQL.',detail:e.message});}
});
app.get('/api/chain',auth,async(_req,res)=>{
  try{const [rows]=await pool.query('SELECT block_index AS `index`,block_timestamp AS timestamp,block_data,previous_hash,nonce,block_hash AS hash FROM chain_blocks ORDER BY block_index');res.json({chain:rows.map(r=>({...r,data:JSON.parse(r.block_data)}))});}
  catch(e){res.status(503).json({error:'MySQL belum tersedia.',detail:e.message});}
});
app.post('/api/chain',auth,async(req,res)=>{
  try{
    const asset=String(req.body.asset||'').slice(0,180),details=String(req.body.details||'').slice(0,1000);
    if(!asset)return res.status(400).json({error:'Nama aset wajib diisi.'});
    const [rows]=await pool.query('SELECT block_index AS `index`,block_timestamp AS timestamp,block_data,previous_hash,nonce,block_hash AS hash FROM chain_blocks ORDER BY block_index DESC LIMIT 1');
    let previous='0',index=0;
    if(rows.length){previous=rows[0].hash;index=Number(rows[0].index)+1;}
    else {const genesis=await mine({index:0,timestamp:new Date().toISOString(),data:{event:'Genesis'},previous_hash:'0',nonce:0});await pool.execute('INSERT INTO chain_blocks (block_index,block_timestamp,block_data,previous_hash,nonce,block_hash) VALUES (?,?,?,?,?,?)',[0,genesis.timestamp,JSON.stringify(genesis.data),'0',genesis.nonce,genesis.hash]);previous=genesis.hash;index=1;}
    const block=await mine({index,timestamp:new Date().toISOString(),data:{asset,details},previous_hash:previous,nonce:0});
    await pool.execute('INSERT INTO chain_blocks (block_index,block_timestamp,block_data,previous_hash,nonce,block_hash) VALUES (?,?,?,?,?,?)',[block.index,block.timestamp,JSON.stringify(block.data),block.previous_hash,block.nonce,block.hash]);
    res.json({block});
  }catch(e){res.status(503).json({error:'Gagal membuat blok. Pastikan MySQL aktif dan schema terpasang.',detail:e.message});}
});
app.get('/api/chain/verify',auth,async(_req,res)=>{
  try{
    const [rows]=await pool.query('SELECT block_index AS `index`,block_timestamp AS timestamp,block_data,previous_hash,nonce,block_hash AS hash FROM chain_blocks ORDER BY block_index');
    const chain=rows.map(r=>({...r,data:JSON.parse(r.block_data)}));
    for(let i=0;i<chain.length;i++){const b=chain[i];if(blockHash(b)!==b.hash)return res.json({valid:false,count:chain.length,reason:`Hash blok #${i} tidak cocok.`});if(i&&b.previous_hash!==chain[i-1].hash)return res.json({valid:false,count:chain.length,reason:`Rantai putus pada blok #${i}.`});if(!b.hash.startsWith('000'))return res.json({valid:false,count:chain.length,reason:`Proof-of-work blok #${i} tidak valid.`});}
    res.json({valid:true,count:chain.length,reason:'Hash, previous_hash, dan proof-of-work valid.'});
  }catch(e){res.status(503).json({error:'Tidak dapat memverifikasi blockchain.',detail:e.message});}
});
app.delete('/api/chain',auth,async(_req,res)=>{try{await pool.query('DELETE FROM chain_blocks');res.json({ok:true});}catch(e){res.status(503).json({error:'Gagal reset blockchain.'});}});
app.get('*',(req,res)=>res.sendFile(path.join(root,'public/index.html')));
async function start() {
  try {
    await initializeAuth();
    app.listen(PORT,'127.0.0.1',()=>console.log(`KRIPTOHORE aktif: http://localhost:${PORT}`));
  } catch (e) {
    console.error('Gagal menyiapkan autentikasi/database:', e.message);
    console.error('Pastikan MySQL XAMPP aktif dan database cryptovault sudah di-import.');
    process.exit(1);
  }
}
start();
