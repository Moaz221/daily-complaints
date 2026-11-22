-- V3 migration, not installed until verified. Customer data stays client-side encrypted.
create schema if not exists app_private;
revoke all on schema app_private from public, anon, authenticated;
create table public.app_profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 username text unique not null check(username ~ '^[a-z0-9._-]{3,40}$'),
 display_name text not null check(length(display_name) between 1 and 120),
 role text not null check(role in ('admin','technician')),
 phone text not null default '' check(length(phone)<=30),
 active boolean not null default true,
 created_at timestamptz not null default now()
);
alter table public.app_profiles enable row level security;
revoke all on public.app_profiles from anon, authenticated;
grant select on public.app_profiles to authenticated;
grant select,insert,update,delete on public.app_profiles to service_role;
insert into public.app_profiles(id,username,display_name,role) values('ba5afd58-8b65-455b-acf0-97fcdaba0a5f','moaz','معاذ','admin');
create function public.app_role() returns text language sql stable security definer set search_path='' as $$
 select role from public.app_profiles where id=(select auth.uid()) and active;
$$;
revoke all on function public.app_role() from public,anon;
grant execute on function public.app_role() to authenticated;
create policy profile_read on public.app_profiles for select to authenticated using(id=(select auth.uid()) or (select public.app_role())='admin');
create table app_private.encryption_keys(id boolean primary key default true check(id), secret text not null);
insert into app_private.encryption_keys(secret) values(encode(extensions.gen_random_bytes(48),'base64'));
create function public.complaint_key() returns text language plpgsql security definer set search_path='' as $$
begin
 if public.app_role() is null then raise insufficient_privilege using message='Active account required'; end if;
 return (select secret from app_private.encryption_keys where id);
end;
$$;
revoke all on function public.complaint_key() from public,anon;
grant execute on function public.complaint_key() to authenticated;
-- No anonymous record access in the account-based version.
drop policy read_latest_ciphertext on public.complaint_latest;
drop policy admin_insert_latest on public.complaint_latest;
drop policy admin_update_latest on public.complaint_latest;
drop policy admin_delete_latest on public.complaint_latest;
drop policy admin_archive on public.complaint_archive;
revoke all on public.complaint_latest,public.complaint_archive from anon,authenticated;
grant select on public.complaint_latest,public.complaint_archive to authenticated;
create policy account_read_latest on public.complaint_latest for select to authenticated using((select public.app_role()) is not null);
create policy admin_read_archive on public.complaint_archive for select to authenticated using((select public.app_role())='admin');
alter table public.complaint_latest add column revision bigint not null default 1;
alter table public.complaint_archive add column revision bigint not null default 1;
drop function public.publish_complaints(jsonb,date);
create function public.publish_complaints(p_payload jsonb,p_work_date date,p_expected_revision bigint default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare current_revision bigint; published_at timestamptz:=now();
begin
 if public.app_role() is distinct from 'admin' then raise insufficient_privilege using message='Admin access required'; end if;
 if p_payload->>'version' is distinct from '1' or p_payload->>'algorithm' is distinct from 'AES-256-GCM' or p_payload->>'kdf' is distinct from 'PBKDF2-SHA256' or p_payload->>'iterations' is distinct from '600000' or jsonb_typeof(p_payload->'ciphertext') is distinct from 'string' or length(p_payload::text)>20000000 then raise check_violation using message='Unsupported encrypted payload'; end if;
 perform pg_advisory_xact_lock(98276132);
 select coalesce((select revision from public.complaint_latest where id),0) into current_revision;
 if current_revision<>p_expected_revision then raise exception using errcode='P0001',message='REVISION_CONFLICT'; end if;
 current_revision:=current_revision+1;
 insert into public.complaint_archive(payload,work_date,revision) values(p_payload,p_work_date,current_revision);
 insert into public.complaint_latest(id,payload,work_date,updated_at,revision) values(true,p_payload,p_work_date,published_at,current_revision) on conflict(id) do update set payload=excluded.payload,work_date=excluded.work_date,updated_at=excluded.updated_at,revision=excluded.revision;
 return jsonb_build_object('revision',current_revision,'updated_at',published_at);
end;
$$;
revoke all on function public.publish_complaints(jsonb,date,bigint) from public,anon;
grant execute on function public.publish_complaints(jsonb,date,bigint) to authenticated;
create table public.technician_routes(user_id uuid not null references public.app_profiles(id) on delete cascade,work_date date not null,stop_ids uuid[] not null default '{}',updated_at timestamptz not null default now(),primary key(user_id,work_date),check(cardinality(stop_ids)<=1000));
alter table public.technician_routes enable row level security;
revoke all on public.technician_routes from anon,authenticated;
grant select,insert,update,delete on public.technician_routes to authenticated;
create policy own_route on public.technician_routes for all to authenticated using(user_id=(select auth.uid()) and (select public.app_role()) is not null) with check(user_id=(select auth.uid()) and (select public.app_role()) is not null);
-- Server-only login throttling, independent of the browser UI.
create table app_private.login_attempts(username text primary key,started_at timestamptz not null,attempts integer not null);
create function public.allow_app_login(p_username text) returns boolean language plpgsql security definer set search_path='' as $$
declare n integer;
begin
 delete from app_private.login_attempts where started_at<now()-interval '1 day';
 insert into app_private.login_attempts values(left(p_username,100),now(),1) on conflict(username) do update set attempts=case when app_private.login_attempts.started_at<now()-interval '15 minutes' then 1 else app_private.login_attempts.attempts+1 end,started_at=case when app_private.login_attempts.started_at<now()-interval '15 minutes' then now() else app_private.login_attempts.started_at end returning attempts into n;
 return n<=12;
end;
$$;
revoke all on function public.allow_app_login(text) from public,anon,authenticated;
grant execute on function public.allow_app_login(text) to service_role;
