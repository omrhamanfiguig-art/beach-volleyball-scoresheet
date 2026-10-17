(()=>{
const C=window.BV_CONFIG||{},L=localStorage,te=new TextEncoder();
const J=(k,d)=>{try{return JSON.parse(L.getItem(k))??d}catch(x){return d}},W=(k,v)=>L.setItem(k,JSON.stringify(v));
const d10=s=>String(s||'').replace(/\D/g,''),same=(a,b)=>d10(a).slice(-9)===d10(b).slice(-9);
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const ub=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const users=()=>J('bv-users',[]),me=()=>users().find(u=>u.email===J('bv-session','')),act=u=>!!u&&u.exp>Date.now();
const upd=u=>W('bv-users',users().map(x=>x.email===u.email?u:x));
const fmt=t=>new Date(t).toLocaleDateString('en-GB');
const pbk=async(pw,salt)=>{const k=await crypto.subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:ub(salt),iterations:120000},k,256))};
const $q=id=>document.getElementById(id);
function dlg(html,closable=true){document.getElementById('dlg')?.remove();const d=document.createElement('div');d.className='ov';d.id='dlg';
 d.innerHTML=`<section class="box" style="max-width:440px;width:100%;margin:auto">${html}${closable?'<p><button class="btn sm" id="dx">إغلاق</button></p>':''}</section>`;
 document.body.appendChild(d);if(closable)$q('dx').onclick=()=>d.remove();return d}
const msg=(t,ok)=>{const m=$q('dm');if(m){m.className=ok?'':'alert';m.textContent=t}};
const inp=(id,l,t='text',v='')=>`<label>${l}<input id="${id}" type="${t}" value="${e(v)}" autocomplete="off"></label>`;

function chip(){let b=$q('acc');if(!b){b=document.createElement('button');b.id='acc';b.className='btn sm';b.onclick=()=>me()?acct():gate('login');document.getElementById('thm').before(b)}
 const u=me();b.textContent=u?`${u.name} · ${act(u)?'✅':'⚠️'}`:'تسجيل الدخول'}

function gate(mode){const reg=mode==='reg';
 dlg(`<h2>${reg?'إنشاء حساب':'تسجيل الدخول'}</h2><div id="dm"></div><div class="grid" style="grid-template-columns:1fr">
 ${reg?inp('gn','الاسم الكامل')+inp('gp','رقم الهاتف (مع رمز الدولة، مثل 212600000000)','tel'):''}${inp('ge','البريد الإلكتروني','email')}${inp('gw','كلمة المرور (6 أحرف على الأقل)','password')}</div>
 <div class="row" style="margin-top:10px"><button class="btn pri" id="go">${reg?'إنشاء الحساب':'دخول'}</button><button class="btn" id="sw">${reg?'لدي حساب':'حساب جديد'}</button></div>
 <p style="font-size:.8rem;color:var(--mut)">الحسابات محفوظة على هذا الجهاز وتعمل بدون إنترنت.</p>`,false);
 $q('sw').onclick=()=>gate(reg?'login':'reg');
 $q('go').onclick=async()=>{const em=$q('ge').value.trim().toLowerCase(),pw=$q('gw').value;
  if(!/^\S+@\S+\.\S+$/.test(em))return msg('بريد إلكتروني غير صالح');if(pw.length<6)return msg('كلمة المرور أقصر من 6 أحرف');
  if(reg){const n=$q('gn').value.trim(),ph=d10($q('gp').value);if(n.length<2)return msg('أدخل الاسم');if(ph.length<8)return msg('رقم هاتف غير صالح');
   if(users().some(u=>u.email===em))return msg('هذا البريد مسجل مسبقاً، سجّل الدخول');
   const salt=b64(crypto.getRandomValues(new Uint8Array(16)));W('bv-users',[...users(),{name:n,email:em,phone:ph,salt,h:await pbk(pw,salt),exp:0}])}
  else{const u=users().find(x=>x.email===em);if(!u||u.h!==await pbk(pw,u.salt))return msg('البريد أو كلمة المرور غير صحيحة')}
  W('bv-session',em);$q('dlg').remove();chip();const m=/code=([\w.-]+)/.exec(location.hash);if(m)acct(m[1])}}

async function verify(code,u){const m=/^BV\.([\w-]+)\.([\w-]+)$/.exec((code||'').trim());if(!m)return'الرمز غير صالح';
 if(!C.ADMIN_PUBLIC_KEY)return'لم يُضبط مفتاح المسيّر في config.js';
 try{const k=await crypto.subtle.importKey('jwk',C.ADMIN_PUBLIC_KEY,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},k,ub(m[2]),te.encode(m[1])))return'الرمز غير صحيح أو مزوّر';
  const p=JSON.parse(new TextDecoder().decode(ub(m[1])));if(!same(p.p,u.phone))return'هذا الرمز مخصص لرقم هاتف آخر';
  if(p.e<Date.now())return'انتهت صلاحية الرمز';return p}catch(x){return'تعذر التحقق من الرمز'}}

function acct(code){const u=me();if(!u)return gate('login');const a=act(u),adm=J('bv-admin-key',null);
 dlg(`<h2>${e(u.name)}</h2><p>${e(u.email)} · ${e(u.phone)}<br>الاشتراك: <b>${a?'مفعّل حتى '+fmt(u.exp):'غير مفعّل'}</b></p><div id="dm"></div>
 ${a?'':'<p>لبدء المباريات تحتاج إلى رمز تفعيل من المسيّر.</p>'}
 ${inp('ac','رمز التفعيل','text',typeof code==='string'?code:'')}
 <div class="row" style="margin-top:8px"><button class="btn pri" id="av">تفعيل الاشتراك</button><button class="btn" id="rq">طلب التفعيل عبر واتساب</button></div>
 <div class="row" style="margin-top:8px"><button class="btn sm" id="ad">لوحة المسيّر</button><button class="btn sm" id="lo">تسجيل الخروج</button></div>`);
 $q('av').onclick=async()=>{const r=await verify($q('ac').value,u);if(typeof r==='string')return msg(r);u.exp=r.e;upd(u);chip();acct();setTimeout(()=>msg('تم التفعيل ✅',1))};
 $q('rq').onclick=()=>{if(!d10(C.ADMIN_PHONE))return msg('لم يُضبط رقم المسيّر في config.js');
  open(`https://wa.me/${d10(C.ADMIN_PHONE)}?text=`+encodeURIComponent(`مرحباً، أرغب بتفعيل اشتراكي.\nالاسم: ${u.name}\nالهاتف: ${u.phone}\nالبريد: ${u.email}`),'_blank')};
 $q('ad').onclick=admin;$q('lo').onclick=()=>{L.removeItem('bv-session');$q('dlg').remove();chip();gate('login')}}

async function admin(){let k=J('bv-admin-key',null);
 if(!k){dlg(`<h2>إنشاء مفتاح المسيّر</h2><p>يُنشأ مفتاح توقيع خاص يبقى على هذا الجهاز فقط. بعده تنسخ المفتاح العام إلى <b>config.js</b> وترفعه إلى GitHub.</p><p style="color:#b00">احتفظ بهذا الجهاز ونسخة احتياطية: بدون المفتاح الخاص لا يمكن إصدار رموز جديدة.</p><button class="btn pri" id="ck">إنشاء المفتاح</button>`);
  $q('ck').onclick=async()=>{const p=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);W('bv-admin-key',await crypto.subtle.exportKey('jwk',p.privateKey));admin()};return}
 const pub=JSON.stringify({kty:k.kty,crv:k.crv,x:k.x,y:k.y}),ok=C.ADMIN_PUBLIC_KEY&&C.ADMIN_PUBLIC_KEY.x===k.x;
 dlg(`<h2>لوحة المسيّر</h2><div id="dm"></div>${ok?'':`<div class="alert">المفتاح العام غير موجود في config.js. الصق السطر التالي في ADMIN_PUBLIC_KEY وارفع الملف، وإلا ستُرفض الرموز.<br><textarea readonly style="width:100%;direction:ltr" rows="4" onclick="this.select()">${e(pub)}</textarea></div>`}
 <div class="grid" style="grid-template-columns:1fr">${inp('an','اسم المنخرط')}${inp('ap','هاتف المنخرط (مع رمز الدولة)','tel')}
 <label>مدة الاشتراك<select id="am"><option value="1">شهر</option><option value="3">3 أشهر</option><option value="6">6 أشهر</option><option value="12">سنة</option></select></label></div>
 <div class="row" style="margin-top:8px"><button class="btn pri" id="ag">إنشاء الرمز وإرساله عبر واتساب</button></div><textarea id="ao" readonly rows="3" style="width:100%;direction:ltr;margin-top:8px" placeholder="الرمز يظهر هنا"></textarea>`);
 $q('ag').onclick=async()=>{const n=$q('an').value.trim(),ph=d10($q('ap').value),mo=+$q('am').value;if(!n||ph.length<8)return msg('أدخل اسم المنخرط ورقم هاتفه');
  const pb=b64(te.encode(JSON.stringify({n,p:ph,e:Math.round(Date.now()+mo*30.44*864e5)})));
  const key=await crypto.subtle.importKey('jwk',k,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const code=`BV.${pb}.${b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,te.encode(pb)))}`;$q('ao').value=code;
  const url=(C.APP_URL||location.origin+location.pathname)+'#code='+code;
  open(`https://wa.me/${ph}?text=`+encodeURIComponent(`مرحباً ${n} 👋\nتم تفعيل اشتراكك في تطبيق ورقة الكرة الطائرة الشاطئية لمدة ${mo} شهر.\n\nرمز التفعيل:\n${code}\n\nأو افتح الرابط مباشرة بعد تسجيل الدخول:\n${url}`),'_blank')}}

const o=window.startSet;window.startSet=function(s){if(act(me()))return o(s);me()?acct():gate('login')};
chip();if(!me())gate('reg');else{const m=/code=([\w.-]+)/.exec(location.hash);if(m)acct(m[1])}
if('serviceWorker' in navigator)addEventListener('load',()=>navigator.serviceWorker.register('sw.js').catch(()=>{}));
})();
