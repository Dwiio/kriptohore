/* CryptoVault: educational browser prototype. Requires HTTPS or localhost for WebCrypto/WebAuthn. */
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const hex = buf => [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,'0')).join('');
function say(id,msg){$(id).textContent=msg}
function download(name,blob){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1500)}
async function deriveKey(pass,salt,usage=['encrypt','decrypt']) {
  if(!pass) throw new Error('Kunci/frasa sandi wajib diisi.');
  const material=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,usage);
}
async function aesEncryptBytes(bytes,pass){
  const salt=rand(16),iv=rand(12),key=await deriveKey(pass,salt);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,bytes);
  return {v:1,alg:'AES-256-GCM',kdf:'PBKDF2-SHA256-250000',salt:toB64(salt),iv:toB64(iv),data:toB64(ciphertext)};
}
async function aesDecryptBytes(obj,pass){
  if(obj.alg!=='AES-256-GCM'||!obj.salt||!obj.iv||!obj.data)throw new Error('Format ciphertext tidak valid.');
  const key=await deriveKey(pass,fromB64(obj.salt));
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(obj.iv)},key,fromB64(obj.data)));
}
/* File encryption is intentionally different from text: AES-256-CTR + HMAC-SHA-256 (encrypt-then-MAC). */
async function deriveFileKeys(pass,salt){
 if(!pass) throw new Error('Kunci file wajib diisi.');
 const material=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveBits']);
 const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:300000,hash:'SHA-256'},material,512);
 const raw=new Uint8Array(bits);
 const aes=await crypto.subtle.importKey('raw',raw.slice(0,32),{name:'AES-CTR'},false,['encrypt','decrypt']);
 const mac=await crypto.subtle.importKey('raw',raw.slice(32),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
 return {aes,mac};
}
async function fileEncryptBytes(bytes,pass){
 const salt=rand(16),counter=rand(16),keys=await deriveFileKeys(pass,salt);
 const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter,length:64},keys.aes,bytes));
 const header={v:1,alg:'AES-256-CTR-HMAC-SHA256',kdf:'PBKDF2-SHA256-300000',salt:toB64(salt),counter:toB64(counter)};
 const signed=enc.encode(JSON.stringify(header));
 const macInput=new Uint8Array(signed.length+ciphertext.length);macInput.set(signed);macInput.set(ciphertext,signed.length);
 const tag=await crypto.subtle.sign('HMAC',keys.mac,macInput);
 return {...header,data:toB64(ciphertext),tag:toB64(tag)};
}
async function fileDecryptBytes(obj,pass){
 if(obj.alg!=='AES-256-CTR-HMAC-SHA256'||!obj.salt||!obj.counter||!obj.data||!obj.tag) throw new Error('Format file CryptoVault tidak valid.');
 const keys=await deriveFileKeys(pass,fromB64(obj.salt));
 const header={v:obj.v,alg:obj.alg,kdf:obj.kdf,salt:obj.salt,counter:obj.counter};
 const signed=enc.encode(JSON.stringify(header)),ciphertext=fromB64(obj.data);
 const macInput=new Uint8Array(signed.length+ciphertext.length);macInput.set(signed);macInput.set(ciphertext,signed.length);
 const valid=await crypto.subtle.verify('HMAC',keys.mac,fromB64(obj.tag),macInput);
 if(!valid) throw new Error('Autentikasi file gagal. Password salah atau file telah diubah.');
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:fromB64(obj.counter),length:64},keys.aes,ciphertext));
}

function vig(text,key,decodeMode=false){
  const k=key.toUpperCase().replace(/[^A-Z]/g,'');if(!k)throw new Error('Kunci Vigenère harus memiliki huruf A-Z.');
  let j=0;return [...text].map(ch=>{if(/[a-z]/i.test(ch)){const base=ch===ch.toUpperCase()?65:97;const shift=k.charCodeAt(j++%k.length)-65;return String.fromCharCode((ch.charCodeAt(0)-base+(decodeMode?-shift:shift)+26)%26+base)}return ch}).join('');
}
async function sha256(data){return hex(await crypto.subtle.digest('SHA-256',typeof data==='string'?enc.encode(data):data))}
function b64json(obj){return JSON.stringify(obj,null,2)}
function parseJson(s){try{return JSON.parse(s)}catch{throw new Error('Output bukan JSON valid. Enkripsi terlebih dahulu atau periksa formatnya.')}}

/* Sidebar navigation */
document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));
  document.querySelectorAll('.module').forEach(x=>x.classList.toggle('hidden',x.id!==b.dataset.tab));
}));

/* Server-verified WebAuthn authentication. No password or USB-dongle bypass. */
function b64url(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function fromB64url(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function publicKeyOptions(options){
 const o={...options,challenge:fromB64url(options.challenge)};
 if(options.user)o.user={...options.user,id:fromB64url(options.user.id)};
 if(options.excludeCredentials)o.excludeCredentials=options.excludeCredentials.map(c=>({...c,id:fromB64url(c.id)}));
 if(options.allowCredentials)o.allowCredentials=options.allowCredentials.map(c=>({...c,id:fromB64url(c.id)}));
 return o;
}
function credentialJSON(cred){
 const response={clientDataJSON:b64url(cred.response.clientDataJSON)};
 if(cred.response.attestationObject)response.attestationObject=b64url(cred.response.attestationObject);
 if(cred.response.authenticatorData)response.authenticatorData=b64url(cred.response.authenticatorData);
 if(cred.response.signature)response.signature=b64url(cred.response.signature);
 if(cred.response.userHandle)response.userHandle=b64url(cred.response.userHandle);
 if(cred.response.getTransports)response.transports=cred.response.getTransports();
 return {id:cred.id,rawId:b64url(cred.rawId),type:cred.type,response,clientExtensionResults:cred.getClientExtensionResults(),authenticatorAttachment:cred.authenticatorAttachment};
}
async function api(path,options={}){
 const response=await fetch(path,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(options.headers||{})},...options});
 const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data.error||`Permintaan gagal (${response.status})`);return data;
}
/* Local IndexedDB fallback keeps the academic demo usable without a configured remote MySQL. */
const LOCAL_DB='cryptovault_local_v1';
function openLocalDB(){return new Promise((resolve,reject)=>{const req=indexedDB.open(LOCAL_DB,1);req.onupgradeneeded=()=>{const db=req.result;if(!db.objectStoreNames.contains('vault'))db.createObjectStore('vault',{keyPath:'id',autoIncrement:true});if(!db.objectStoreNames.contains('chain'))db.createObjectStore('chain',{keyPath:'index'});};req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});}
async function localAll(store){const db=await openLocalDB();return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readonly'),r=tx.objectStore(store).getAll();r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);tx.oncomplete=()=>db.close();});}
async function localPut(store,value){const db=await openLocalDB();return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readwrite'),r=tx.objectStore(store).put(value);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);tx.oncomplete=()=>db.close();});}
async function localAdd(store,value){const db=await openLocalDB();return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readwrite'),r=tx.objectStore(store).add(value);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);tx.oncomplete=()=>db.close();});}
async function localDelete(store,key){const db=await openLocalDB();return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readwrite');tx.objectStore(store).delete(key);tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);});}
async function localClear(store){const db=await openLocalDB();return new Promise((resolve,reject)=>{const tx=db.transaction(store,'readwrite');tx.objectStore(store).clear();tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);});}

function setAuthenticated(ok){
 $('gateView').classList.toggle('hidden',ok);$('appView').classList.toggle('hidden',!ok);$('logoutBtn').classList.toggle('hidden',!ok);
 $('authState').textContent=ok?'Terverifikasi':'Belum diverifikasi';$('authState').style.color=ok?'#376c9e':'';
}
/* Password authentication is performed only by the backend using Argon2id + MySQL. */
$('passwordLogin').addEventListener('click',async()=>{
 const username=$('accountName').value.trim() || 'demo';
 const password=$('loginPassword').value;
 $('accountName').value=username;
 if(!password) { say('deviceStatus','Masukkan password terlebih dahulu.'); return; }
 const button=$('passwordLogin'); button.disabled=true;
 try {
   await api('/api/password/login',{method:'POST',body:JSON.stringify({username,password})});
   $('loginPassword').value=''; setAuthenticated(true);
   say('deviceStatus','Login berhasil. Password telah diverifikasi oleh server.');
 } catch(e) { say('deviceStatus','Login ditolak: '+e.message); }
 finally { button.disabled=false; }
});

/* Local WebAuthn demo for a platform authenticator (e.g. Mac Touch ID).
   First use creates a passkey; later uses request a fresh signed assertion.
   For production, the assertion must be verified by a trusted backend. */
const TOUCHID_CREDENTIAL_KEY='cryptovault_touchid_credential_demo_v1';
$('fingerprintLogin').addEventListener('click',async()=>{
 const button=$('fingerprintLogin');
 button.disabled=true;
 try{
  if(!window.isSecureContext) throw new Error('WebAuthn memerlukan secure context. Gunakan http://localhost:4177.');
  if(!window.PublicKeyCredential || !navigator.credentials) throw new Error('Browser tidak mendukung WebAuthn. Gunakan Safari terbaru.');
  const available=await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if(!available) throw new Error('Touch ID / platform authenticator tidak tersedia. Pastikan Touch ID sudah diatur di macOS.');
  const username=$('accountName').value.trim() || 'demo';
  $('accountName').value=username;
  if(username!=='demo') throw new Error('Nama akun tidak dikenal. Gunakan akun demo.');
  const rpId=location.hostname;
  const saved=localStorage.getItem(TOUCHID_CREDENTIAL_KEY);
  if(!saved){
    say('deviceStatus','Pendaftaran Touch ID pertama kali. Ikuti dialog keamanan macOS.');
    const created=await navigator.credentials.create({publicKey:{
      challenge:rand(32),
      rp:{name:'Kriptohore',id:rpId},
      user:{id:rand(16),name:username,displayName:'Kriptohore Demo'},
      pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
      authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'required',userVerification:'required'},
      timeout:60000,attestation:'none'
    }});
    if(!created) throw new Error('Pendaftaran Touch ID dibatalkan.');
    localStorage.setItem(TOUCHID_CREDENTIAL_KEY,b64url(created.rawId));
    await api('/api/fingerprint/login',{method:'POST',body:JSON.stringify({username})});
    setAuthenticated(true);
    say('deviceStatus','Touch ID berhasil didaftarkan dan login berhasil. Berikutnya gunakan Touch ID untuk masuk.');
    return;
  }
  say('deviceStatus','Menunggu verifikasi Touch ID dari macOS...');
  const assertion=await navigator.credentials.get({publicKey:{
    challenge:rand(32),
    rpId,
    allowCredentials:[{type:'public-key',id:fromB64url(saved)}],
    userVerification:'required',timeout:60000
  }});
  if(!assertion) throw new Error('Autentikasi Touch ID dibatalkan.');
  await api('/api/fingerprint/login',{method:'POST',body:JSON.stringify({username})});
  setAuthenticated(true);
  say('deviceStatus','Touch ID berhasil diverifikasi oleh perangkat. Selamat datang di Kriptohore.');
 }catch(e){
  say('deviceStatus','Login Touch ID gagal: '+(e.name==='NotAllowedError'?'Permintaan dibatalkan atau tidak disetujui.':e.message));
 }finally{button.disabled=false;}
});

$('logoutBtn').addEventListener('click',async()=>{try{await api('/api/logout',{method:'POST'});}catch{} setAuthenticated(false);say('deviceStatus','Sesi telah diakhiri. Silakan login kembali.')});
if(!$('accountName').value.trim()) $('accountName').value='demo';
setAuthenticated(false);

/* Super-encryption: Vigenere then AES-GCM */
$('encryptText').addEventListener('click',async()=>{
 try{const text=$('plainText').value;if(!text)throw new Error('Pesan masih kosong.');
  const v=vig(text,$('vigKey').value);const obj=await aesEncryptBytes(enc.encode(v),$('textKey').value);
  obj.pipeline='Vigenere-AZ then AES-256-GCM';$('textOutput').value=b64json(obj);say('textStatus','Berhasil dienkripsi. Simpan JSON untuk proses dekripsi.')}
 catch(e){say('textStatus',e.message)}
});
$('decryptText').addEventListener('click',async()=>{
 try{const obj=parseJson($('textOutput').value);const bytes=await aesDecryptBytes(obj,$('textKey').value);$('plainText').value=vig(dec.decode(bytes),$('vigKey').value,true);say('textStatus','Dekripsi berhasil.')}
 catch(e){say('textStatus','Dekripsi gagal: '+e.message)}
});

/* File encryption uses AES-CTR + HMAC, preserving filename metadata. */
$('encryptFile').addEventListener('click',async()=>{
 try{const f=$('fileInput').files[0];if(!f)throw new Error('Pilih file dahulu.');const bytes=new Uint8Array(await f.arrayBuffer());const obj=await fileEncryptBytes(bytes,$('fileKey').value);obj.filename=f.name;obj.mime=f.type||'application/octet-stream';obj.pipeline='file-AES-256-CTR-HMAC-SHA256';download(f.name+'.cvault',new Blob([JSON.stringify(obj)],{type:'application/json'}));say('fileStatus','File terenkripsi dengan AES-256-CTR + HMAC-SHA-256 dan diunduh sebagai .cvault.')}
 catch(e){say('fileStatus',e.message)}
});
$('decryptFile').addEventListener('click',async()=>{
 try{const f=$('fileInput').files[0];if(!f)throw new Error('Pilih file .cvault dahulu.');const obj=JSON.parse(await f.text());const bytes=await fileDecryptBytes(obj,$('fileKey').value);download(obj.filename||'decrypted.bin',new Blob([bytes],{type:obj.mime||'application/octet-stream'}));say('fileStatus','Autentikasi HMAC valid dan dekripsi file berhasil.')}
 catch(e){say('fileStatus','Dekripsi gagal: '+e.message)}
});

/* Client-side AES-GCM encryption; prefer remote MySQL, fall back to local IndexedDB for offline demo. */
$('saveVault').addEventListener('click',async()=>{
 try{const msg=$('vaultMessage').value;if(!msg)throw new Error('Pesan masih kosong.');const obj=await aesEncryptBytes(enc.encode(msg),$('vaultKey').value);
  try{const result=await api('/api/vault',{method:'POST',body:JSON.stringify({ciphertext:obj})});$('vaultOutput').textContent=`Ciphertext tersimpan di MySQL dengan ID ${result.id}.`;say('vaultStatus','Berhasil dienkripsi di browser dan disimpan ke MySQL.');}
  catch(remoteError){const id=await localAdd('vault',{ciphertext:obj,created_at:new Date().toISOString()});$('vaultOutput').textContent=`Ciphertext tersimpan pada database lokal browser dengan ID ${id}.`;say('vaultStatus','MySQL belum terhubung; ciphertext disimpan di IndexedDB browser untuk demonstrasi lokal.');}
 }catch(e){say('vaultStatus',e.message)}
});
$('loadVault').addEventListener('click',async()=>{
 try{let chosen;try{const data=await api('/api/vault');chosen=data.items[0];}catch{const items=(await localAll('vault')).sort((a,b)=>b.id-a.id);chosen=items[0];}
  if(!chosen)throw new Error('Belum ada pesan tersimpan.');const bytes=await aesDecryptBytes(chosen.ciphertext,$('vaultKey').value);$('vaultOutput').textContent=dec.decode(bytes);say('vaultStatus',`Pesan ID ${chosen.id} berhasil didekripsi.`);
 }catch(e){say('vaultStatus','Gagal membuka pesan: '+e.message)}
});
$('deleteVault').addEventListener('click',async()=>{
 try{try{const data=await api('/api/vault');if(!data.items.length)throw new Error('Tidak ada pesan untuk dihapus.');await api('/api/vault/'+data.items[0].id,{method:'DELETE'});$('vaultOutput').textContent='Pesan terbaru dihapus dari MySQL.';}
  catch(remoteError){const items=(await localAll('vault')).sort((a,b)=>b.id-a.id);if(!items.length)throw new Error('Tidak ada pesan untuk dihapus.');await localDelete('vault',items[0].id);$('vaultOutput').textContent='Pesan terbaru dihapus dari database lokal browser.';}say('vaultStatus','Pesan berhasil dihapus.');
 }catch(e){say('vaultStatus',e.message)}
});

/* LSB steganography: 32-bit length prefix followed by UTF-8 payload, RGB channels only. */
let stegoImg=null;
$('stegoImage').addEventListener('change',async()=>{
 const f=$('stegoImage').files[0];if(!f)return;
 try{stegoImg=await createImageBitmap(f);const c=$('stegoCanvas'),ctx=c.getContext('2d');c.width=stegoImg.width;c.height=stegoImg.height;ctx.drawImage(stegoImg,0,0);say('stegoStatus',`Gambar dimuat ${c.width}×${c.height}.`)}
 catch(e){say('stegoStatus','Gagal memuat gambar: '+e.message)}
});
function canvasPixels(){const c=$('stegoCanvas');if(!c.width)throw new Error('Pilih gambar terlebih dahulu.');return c.getContext('2d').getImageData(0,0,c.width,c.height)}
function writeBits(img,bytes){
 const bits=[];const length=bytes.length;for(let i=31;i>=0;i--)bits.push((length>>i)&1);for(const b of bytes)for(let i=7;i>=0;i--)bits.push((b>>i)&1);
 const capacity=img.data.length/4*3;if(bits.length>capacity)throw new Error('Pesan terlalu besar untuk gambar ini.');
 let j=0;for(let p=0;p<img.data.length&&j<bits.length;p+=4){for(let k=0;k<3&&j<bits.length;k++,j++)img.data[p+k]=(img.data[p+k]&254)|bits[j]}return img
}
function readBits(img){
 const channels=[];for(let p=0;p<img.data.length;p+=4)channels.push(img.data[p]&1,img.data[p+1]&1,img.data[p+2]&1);
 let len=0;for(let i=0;i<32;i++)len=(len<<1)|channels[i];if(!len||len>(channels.length-32)/8)throw new Error('Tidak menemukan pesan LSB valid pada gambar ini.');
 const out=new Uint8Array(len);let q=32;for(let i=0;i<len;i++){let b=0;for(let j=0;j<8;j++)b=(b<<1)|channels[q++];out[i]=b}return out
}
$('hideMessage').addEventListener('click',async()=>{
 try{const img=canvasPixels(),message=$('stegoMessage').value;if(!message)throw new Error('Pesan masih kosong.');const encrypted=await aesEncryptBytes(enc.encode(message),$('stegoKey').value);const bytes=enc.encode(JSON.stringify(encrypted));writeBits(img,bytes);const c=$('stegoCanvas');c.getContext('2d').putImageData(img,0,0);c.toBlob(b=>download('cryptovault-stego.png',b),'image/png');say('stegoStatus','Pesan dienkripsi AES-256-GCM, disisipkan dengan LSB, lalu PNG diunduh. Simpan kunci stego.')}
 catch(e){say('stegoStatus',e.message)}
});
$('extractMessage').addEventListener('click',async()=>{
 try{const packed=JSON.parse(dec.decode(readBits(canvasPixels())));$('stegoOutput').value=dec.decode(await aesDecryptBytes(packed,$('stegoKey').value));say('stegoStatus','Pesan berhasil diekstrak dan didekripsi.')}
 catch(e){say('stegoStatus','Ekstraksi/dekripsi gagal: '+e.message)}
});

/* SHA-256 proof-of-work chain. Remote MySQL is preferred; IndexedDB provides a local demo fallback. */
async function getChain(){try{const d=await api('/api/chain');return d.chain||[];}catch{return (await localAll('chain')).sort((a,b)=>a.index-b.index);}}
async function renderChain(){
 const chain=await getChain();$('chainList').innerHTML='';
 if(!chain.length){$('chainList').textContent='Belum ada blok. Tambahkan aset untuk membuat genesis block dan blok pertama.';return;}
 chain.slice().reverse().forEach(b=>{const el=document.createElement('div');el.className='block';el.innerHTML=`<strong>Block #${b.index}</strong> · ${new Date(b.timestamp).toLocaleString()}<br><span>${escapeHtml(JSON.stringify(b.data))}</span><br><code>hash: ${b.hash}<br>previous: ${b.previous_hash}<br>nonce: ${b.nonce}</code>`;$('chainList').appendChild(el)});
}
function escapeHtml(s){return s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function localBlockHash(b){return sha256(`${b.index}|${b.timestamp}|${JSON.stringify(b.data)}|${b.previous_hash}|${b.nonce}`)}
async function mineLocalBlock(b){do{b.hash=await localBlockHash(b);if(b.hash.startsWith('000'))return b;b.nonce++;}while(true);}
$('addBlock').addEventListener('click',async()=>{
 try{const name=$('assetName').value.trim(),details=$('assetDetails').value.trim();if(!name)throw new Error('Nama aset/event wajib diisi.');
  try{const result=await api('/api/chain',{method:'POST',body:JSON.stringify({asset:name,details})});await renderChain();say('chainStatus',`Blok #${result.block.index} tersimpan di MySQL (nonce ${result.block.nonce}).`);}
  catch(remoteError){let chain=await localAll('chain');chain.sort((a,b)=>a.index-b.index);let last=chain.at(-1);if(!last){const genesis=await mineLocalBlock({index:0,timestamp:new Date().toISOString(),data:{event:'Genesis'},previous_hash:'0',nonce:0});await localPut('chain',genesis);last=genesis;}
   const block=await mineLocalBlock({index:last.index+1,timestamp:new Date().toISOString(),data:{asset:name,details},previous_hash:last.hash,nonce:0});await localPut('chain',block);await renderChain();say('chainStatus',`Blok #${block.index} dibuat di IndexedDB browser (nonce ${block.nonce}).`);}
 }catch(e){say('chainStatus',e.message)}
});
$('verifyChain').addEventListener('click',async()=>{
 try{let chain,remote=true;try{const result=await api('/api/chain/verify');say('chainStatus',result.valid?`Valid: ${result.count} blok. ${result.reason}`:`Tidak valid: ${result.reason}`);return;}catch{remote=false;}
  chain=(await localAll('chain')).sort((a,b)=>a.index-b.index);if(!chain.length)throw new Error('Blockchain masih kosong.');
  for(let i=0;i<chain.length;i++){const b=chain[i];if(await localBlockHash(b)!==b.hash)throw new Error(`Hash blok #${i} tidak cocok.`);if(i&&b.previous_hash!==chain[i-1].hash)throw new Error(`Rantai putus pada blok #${i}.`);if(!b.hash.startsWith('000'))throw new Error(`Proof-of-work blok #${i} tidak valid.`);}
  say('chainStatus',`Valid: ${chain.length} blok. Hash, previous_hash, dan proof-of-work cocok (database lokal browser).`);
 }catch(e){say('chainStatus','Verifikasi gagal: '+e.message)}
});
$('resetChain').addEventListener('click',async()=>{if(confirm('Hapus seluruh blockchain demo?')){try{try{await api('/api/chain',{method:'DELETE'});}catch{await localClear('chain');}await renderChain();say('chainStatus','Blockchain demo direset.');}catch(e){say('chainStatus',e.message)}}});
renderChain().catch(()=>{});

$('loginPassword').addEventListener('keydown',e=>{if(e.key==='Enter')$('passwordLogin').click()});

/* Local device monitor: lock immediately when the Memory Camera dongle disappears. */
let lastDongleState = null;
async function refreshLocalStatus(){
  try{
    const d=await api('/api/dongle/status');
    const present=!!d.valid;
    $('dongleHeader').textContent=present?'Dongle: TERHUBUNG':'Dongle: TIDAK TERHUBUNG';
    $('dongleHeader').style.borderColor=present?'#16875c':'#8a3c50';
    $('dashDongle').textContent=present?'CONNECTED':'NOT FOUND';
    $('dashDongle').style.color=present?'#4ade80':'#fb7185';
    $('deviceDongleTitle').textContent=present?'Memory Camera Dongle terverifikasi':'Memory Camera Dongle tidak ditemukan';
    $('deviceDongleText').textContent=present?'Kunci perangkat cocok dengan fingerprint SHA-256 yang terdaftar.':'Pasang microSD berisi MEMORY_CAMERA_DONGLE.key yang sah.';
    $('helperStatus').textContent='ONLINE · http://127.0.0.1:4177';
    if(lastDongleState===true && !present){
      try{await api('/api/logout',{method:'POST'});}catch{}
      setAuthenticated(false);
      say('deviceStatus','Dongle dicabut. Aplikasi dikunci dan sesi lokal diakhiri.');
      alert('Memory Camera Dongle dicabut. Kriptohore dikunci.');
    }
    lastDongleState=present;
    const h=await api('/api/health');
    $('dashDatabase').textContent=h.database?'CONNECTED':'OFFLINE';
    $('dashDatabase').style.color=h.database?'#4ade80':'#fb7185';
    $('databaseStatus').textContent=h.database?'MySQL CONNECTED':'MySQL OFFLINE';
  }catch(e){
    $('dongleHeader').textContent='Helper: OFFLINE';
    $('dashDongle').textContent='HELPER OFFLINE';
    $('deviceDongleTitle').textContent='Local Security Helper tidak aktif';
    $('deviceDongleText').textContent='Jalankan npm start dari folder project.';
    $('helperStatus').textContent='OFFLINE';
    $('dashDatabase').textContent='UNKNOWN';
  }
}
refreshLocalStatus();
setInterval(refreshLocalStatus,500);
