-- Server-side permission rules. Ciphertext only. No service-role key belongs in frontend code.
create table public.complaint_latest (
  id boolean primary key default true check (id),
  payload jsonb not null check (coalesce(payload->>'algorithm' = 'AES-256-GCM' and payload->>'kdf' = 'PBKDF2-SHA256' and payload->>'iterations' = '600000' and jsonb_typeof(payload->'ciphertext') = 'string', false)),
  work_date date not null,
  updated_at timestamptz not null default now()
);
create table public.complaint_archive (
  id uuid primary key default gen_random_uuid(),
  payload jsonb not null check (coalesce(payload->>'algorithm' = 'AES-256-GCM' and payload->>'kdf' = 'PBKDF2-SHA256' and payload->>'iterations' = '600000' and jsonb_typeof(payload->'ciphertext') = 'string', false)),
  work_date date not null,
  created_at timestamptz not null default now()
);
alter table public.complaint_latest enable row level security;
alter table public.complaint_archive enable row level security;
revoke all on public.complaint_latest, public.complaint_archive from anon, authenticated;
grant select on public.complaint_latest to anon, authenticated;
grant insert, update, delete on public.complaint_latest to authenticated;
grant select, insert, delete on public.complaint_archive to authenticated;
create policy read_latest_ciphertext on public.complaint_latest for select to anon, authenticated using (true);
create policy admin_insert_latest on public.complaint_latest for insert to authenticated with check ((select auth.uid()) = 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid);
create policy admin_update_latest on public.complaint_latest for update to authenticated using ((select auth.uid()) = 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid) with check ((select auth.uid()) = 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid);
create policy admin_delete_latest on public.complaint_latest for delete to authenticated using ((select auth.uid()) = 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid);
create policy admin_archive on public.complaint_archive for all to authenticated using ((select auth.uid()) = 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid) with check ((select auth.uid()) = 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid);
create or replace function public.publish_complaints(p_payload jsonb, p_work_date date)
returns timestamptz language plpgsql security invoker set search_path = '' as $$
declare published_at timestamptz := now();
begin
 if auth.uid() is distinct from 'ba5afd58-8b65-455b-acf0-97fcdaba0a5f'::uuid then
  raise insufficient_privilege using message = 'Admin access required';
 end if;
 if p_payload->>'version' is distinct from '1' or length(p_payload::text)>20000000 then
  raise check_violation using message = 'Unsupported encrypted payload';
 end if;
 insert into public.complaint_archive(payload,work_date) values(p_payload,p_work_date);
 insert into public.complaint_latest(id,payload,work_date,updated_at) values(true,p_payload,p_work_date,published_at)
 on conflict(id) do update set payload=excluded.payload,work_date=excluded.work_date,updated_at=excluded.updated_at;
 return published_at;
end;
$$;
revoke all on function public.publish_complaints(jsonb,date) from public, anon;
grant execute on function public.publish_complaints(jsonb,date) to authenticated;
