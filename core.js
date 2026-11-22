'use strict';
const Core = (() => {
  const normalize = s => String(s ?? '').replace(/[٠-٩]/g,c=>c.charCodeAt(0)-1632).replace(/[۰-۹]/g,c=>c.charCodeAt(0)-1776).replace(/[\u064B-\u065F\u0670ـ]/g,'').replace(/[أإآ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه').replace(/\s+/g,' ').trim().toLowerCase();
  const digits = s => String(s ?? '').replace(/[٠-٩]/g,c=>c.charCodeAt(0)-1632).replace(/[۰-۹]/g,c=>c.charCodeAt(0)-1776);
  const aliases = {ticket:['رقم التذكرة','رقم التذكره','رقم البلاغ'],name:['اسم العميل','العميل'],phone:['رقم التليفون','رقم الهاتف','التليفون','رقم الموبايل'],address:['العنوان'],status:['الحالة','حالة البلاغ'],problem:['المشكلة','العطل'],device:['نوع الجهاز','الجهاز'],notes:['ملاحظات'],contact:['حالة الاتصال']};
  function headerMap(row) { const out={}; row.forEach((v,i)=>{const n=normalize(v);for(const [k,names] of Object.entries(aliases))if(names.some(x=>normalize(x)===n))out[k]=i;});return out; }
  function phone(v) { let s=digits(v).trim().replace(/[\s()\-.]/g,''); if(/^1[0125]\d{8}$/.test(s))s='0'+s; return s; }
  function parseSheet(sheet) {
    const rows = XLSX.utils.sheet_to_json(sheet,{header:1,raw:false,defval:'',blankrows:false});
    const h = rows.findIndex(r=>{const m=headerMap(r);return ['ticket','name','phone','address','status','problem','device'].every(k=>k in m);});
    if(h<0)throw Error('مش لاقي أعمدة الشيت المطلوبة: رقم التذكرة، اسم العميل، رقم التليفون، العنوان، الحالة، المشكلة، نوع الجهاز.');
    const m=headerMap(rows[h]);let skipped=0;
    const items=[];
    for(const r of rows.slice(h+1)) { const get=k=>String(r[m[k]]??'').trim();const ticket=digits(get('ticket')).replace(/\.0$/,'');
      if(!/^\d{3,}$/.test(ticket)){if(r.some(x=>String(x).trim()))skipped++;continue;}
      const item={};for(const k of Object.keys(aliases))item[k]=get(k).slice(0,5000);item.ticket=ticket;item.phone=phone(item.phone);item.vip=/[★⭐🌟]/u.test(item.name)||/(?:\(\s*مهم\s*\)|\bVIP\b)/i.test(item.name+' '+item.notes);items.push(item);
    }
    if(!items.length)throw Error('الشيت فيه أعمدة صحيحة، بس مفيهوش بلاغات برقم تذكرة واضح.');
    if(items.length>10000)throw Error('الشيت أكبر من ١٠ آلاف بلاغ. قسّمه لملف أصغر.');
    return {items,skipped};
  }
  const enc=new TextEncoder(),dec=new TextDecoder();
  const b64 = a => {let s='';for(const x of new Uint8Array(a))s+=String.fromCharCode(x);return btoa(s);};
  const unb64 = s => Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  async function key(password,salt,uses){const k=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,uses);}
  async function encrypt(data,password){const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));const k=await key(password,salt,['encrypt']);const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,enc.encode(JSON.stringify(data)));return {version:1,algorithm:'AES-256-GCM',kdf:'PBKDF2-SHA256',iterations:600000,salt:b64(salt),iv:b64(iv),ciphertext:b64(ciphertext)};}
  async function decrypt(payload,password,raw=false){if(payload.version!==1||payload.algorithm!=='AES-256-GCM'||payload.kdf!=='PBKDF2-SHA256'||payload.iterations!==600000)throw Error('unsupported');const salt=unb64(payload.salt),iv=unb64(payload.iv);if(salt.length!==16||iv.length!==12||payload.ciphertext.length>30000000)throw Error('invalid');const k=await key(password,salt,['decrypt']);const parsed=JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv},k,unb64(payload.ciphertext))));return raw?parsed:validate(parsed);}
  function validate(data){if(!Array.isArray(data.items)||data.items.length>10000||!/^\d{4}-\d{2}-\d{2}$/.test(data.date))throw Error('invalid data');for(const item of data.items){for(const k of Object.keys(aliases)){if(typeof item[k]!=='string'||item[k].length>5000)throw Error('invalid row');}item.vip=!!item.vip;item.phone=phone(item.phone);}return data;}
  function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
  function card(item){const a=el('article','complaint'+(item.vip?' vip':''));const top=el('div','cardtop');top.append(el('span','','تذكرة #'+item.ticket));const badges=el('div','badges');if(item.vip)badges.append(el('span','badge vip','★ مهم'));badges.append(el('span','badge'+(/pending|استكمال/i.test(item.status)?' pending':''),item.status||'الحالة مش محددة'));top.append(badges);a.append(top,el('h3','',item.name||'بدون اسم'));const dl=el('dl');for(const [k,title]of [['device','الجهاز'],['problem','المشكلة'],['address','العنوان'],['notes','ملاحظات']]){if(!item[k])continue;const row=el('div','detail');row.append(el('dt','',title),el('dd','',item[k]));dl.append(row);}a.append(dl);const bottom=el('div','callrow');if(/^\+?\d{7,15}$/.test(item.phone)){const link=el('a','phone',item.phone+'  ↗');link.href='tel:'+item.phone;link.setAttribute('aria-label','اتصل بالعميل '+item.name+' على '+item.phone);bottom.append(link);}else bottom.append(el('span','small',item.phone?'رقم الهاتف محتاج مراجعة':'مفيش رقم تليفون'));bottom.append(el('span','callstate',item.contact||'لسه مفيش حالة اتصال'));a.append(bottom);return a;}
  function demo(){return {date:new Intl.DateTimeFormat('en-CA',{timeZone:'Africa/Cairo',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date()),items:[{ticket:'100001',name:'عميل تجريبي ١',phone:'00000000001',address:'عنوان تجريبي، مدينة افتراضية',status:'Open',problem:'الثلاجة مش بتبرد كويس. بيانات للتجربة فقط.',device:'ثلاجة',notes:'الاتصال قبل الزيارة بساعة',contact:'رد',vip:true},{ticket:'100002',name:'عميل تجريبي ٢',phone:'00000000002',address:'شارع افتراضي، عنوان غير حقيقي',status:'Pending (استكمال)',problem:'مراجعة السخان واستكمال الصيانة',device:'سخان',notes:'منتظر قطعة غيار',contact:'رنيت مرة',vip:false},{ticket:'100003',name:'عميل تجريبي ٣',phone:'',address:'عنوان تجريبي',status:'Open',problem:'شعلة البوتاجاز محتاجة فحص',device:'بوتاجاز',notes:'',contact:'',vip:false}]};}
  return {normalize,phone,parseSheet,encrypt,decrypt,validate,el,card,demo};
})();
