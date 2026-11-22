import {createClient} from 'npm:@supabase/supabase-js@2';
const URL=Deno.env.get('SUPABASE_URL')!;
const SERVICE=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ANON=Deno.env.get('SUPABASE_ANON_KEY')!;
const OWNER='ba5afd58-8b65-455b-acf0-97fcdaba0a5f';
const origin='https://moaz221.github.io';
const headers={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Headers':'authorization, x-client-info, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS','Content-Type':'application/json','Cache-Control':'no-store','Vary':'Origin'};
const out=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers});
Deno.serve(async req=>{
 if(req.method==='OPTIONS')return new Response('ok',{headers});
 if(req.method!=='POST')return out({error:'Method not allowed'},405);
 try{
  if(Number(req.headers.get('content-length')||0)>20000)return out({error:'Request too large'},413);
  const body=await req.json();
  const svc=createClient(URL,SERVICE,{auth:{persistSession:false,autoRefreshToken:false}});
  if(body.action==='login'){
   const username=String(body.username||'').trim().toLowerCase();
   if(!/^[a-z0-9._-]{3,40}$/.test(username)||typeof body.password!=='string'||body.password.length>256)return out({error:'Invalid credentials'},401);
   const throttle=await svc.rpc('allow_app_login',{p_username:username});
   if(throttle.error)return out({error:'Service unavailable'},503);
   if(!throttle.data)return out({error:'Too many attempts. Try again in 15 minutes.'},429);
   const profile=await svc.from('app_profiles').select('id,active').eq('username',username).maybeSingle();
   if(profile.error||!profile.data?.active)return out({error:'Invalid credentials'},401);
   const user=await svc.auth.admin.getUserById(profile.data.id);
   if(!user.data.user?.email)return out({error:'Invalid credentials'},401);
   const auth=createClient(URL,ANON,{auth:{persistSession:false,autoRefreshToken:false}});
   const login=await auth.auth.signInWithPassword({email:user.data.user.email,password:body.password});
   if(login.error||!login.data.session)return out({error:'Invalid credentials'},401);
   return out({session:login.data.session});
  }
  const bearer=(req.headers.get('Authorization')||'').replace(/^Bearer /,'');
  if(!bearer)return out({error:'Authentication required'},401);
  const verified=await svc.auth.getUser(bearer);
  if(verified.error||!verified.data.user)return out({error:'Authentication required'},401);
  const actor=await svc.from('app_profiles').select('role,active').eq('id',verified.data.user.id).single();
  if(actor.error||!actor.data.active||actor.data.role!=='admin')return out({error:'Admin access required'},403);
  if(body.action==='create'){
   const username=String(body.username||'').trim().toLowerCase();
   const name=String(body.display_name||'').trim();
   const role=body.role;const phone=String(body.phone||'').trim();
   if(!/^[a-z0-9._-]{3,40}$/.test(username)||!name||name.length>120||!['admin','technician'].includes(role)||typeof body.password!=='string'||body.password.length<8||body.password.length>128||!/^\+?[0-9 ()-]{0,30}$/.test(phone))return out({error:'Invalid account details. Password must be at least 8 characters.'},400);
   const exists=await svc.from('app_profiles').select('id').eq('username',username).maybeSingle();
   if(exists.error)return out({error:'Service unavailable'},503);
   if(exists.data)return out({error:'Username already used'},409);
   const created=await svc.auth.admin.createUser({email:crypto.randomUUID()+'@daily-complaints.invalid',password:body.password,email_confirm:true});
   if(created.error||!created.data.user)return out({error:'Account could not be created'},400);
   const saved=await svc.from('app_profiles').insert({id:created.data.user.id,username,display_name:name,role,phone}).select('id,username,display_name,role,phone,active').single();
   if(saved.error){await svc.auth.admin.deleteUser(created.data.user.id);return out({error:'Account could not be saved'},400);}
   return out({profile:saved.data},201);
  }
  if(body.action==='update'){
   const target=String(body.id||'');const name=String(body.display_name||'').trim();const role=body.role;const phone=String(body.phone||'').trim();
   if(!/^[a-f0-9-]{36}$/.test(target)||!name||name.length>120||!['admin','technician'].includes(role)||typeof body.active!=='boolean'||!/^\+?[0-9 ()-]{0,30}$/.test(phone))return out({error:'Invalid account details'},400);
   if(target===OWNER&&(role!=='admin'||!body.active))return out({error:'The owner must remain an active admin'},400);
   if(target===verified.data.user.id&&(!body.active||role!=='admin'))return out({error:'Cannot remove your own admin access'},400);
   const saved=await svc.from('app_profiles').update({display_name:name,role,phone,active:body.active}).eq('id',target).select('id,username,display_name,role,phone,active').single();
   if(saved.error)return out({error:'Account could not be updated'},400);
   return out({profile:saved.data});
  }
  return out({error:'Unknown action'},400);
 }catch{return out({error:'Request could not be processed'},400);}
});
