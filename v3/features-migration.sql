-- V4 features: per-day history for all accounts, complaint closures with outcome + note,
-- and the persistent customer directory. Run once on the live project, after v3/migration.sql.

-- 1) Complaint closures: a technician (or admin) closes a complaint with an outcome and a note.
create table public.complaint_closures (
  id uuid primary key default gen_random_uuid(),
  complaint_id uuid not null unique,
  work_date date not null,
  closed_by uuid not null references public.app_profiles(id),
  closed_by_name text,
  outcome text not null check (outcome in ('إنهاء خدمة','استكمال قطعة غيار','تأجيل','رفض إصلاح','إلغاء البلاغ','استكمال شحن')),
  charge text check (charge in ('paid','free')),
  note text not null check (length(note) between 1 and 500),
  created_at timestamptz not null default now()
);
alter table public.complaint_closures enable row level security;
revoke all on public.complaint_closures from anon, authenticated;
grant select, insert on public.complaint_closures to authenticated;
create policy closures_read on public.complaint_closures for select to authenticated
  using ((select public.app_role()) is not null);
create policy closures_insert on public.complaint_closures for insert to authenticated
  with check (closed_by = (select auth.uid()) and (select public.app_role()) is not null);
create index complaint_closures_work_date on public.complaint_closures(work_date);

-- 2) Every active account may read the encrypted day archive (technicians need the day filter).
drop policy admin_read_archive on public.complaint_archive;
create policy account_read_archive on public.complaint_archive for select to authenticated
  using ((select public.app_role()) is not null);
create index complaint_archive_work_date on public.complaint_archive(work_date, revision desc);

-- 3) Persistent customer directory (بيانات العملاء): one encrypted payload, admin writes, active accounts read.
create table public.customer_directory (
  id boolean primary key default true check (id),
  payload jsonb not null check (coalesce(payload->>'version' = '1' and jsonb_typeof(payload->'ciphertext') = 'string', false)),
  revision bigint not null default 1,
  updated_at timestamptz not null default now()
);
alter table public.customer_directory enable row level security;
revoke all on public.customer_directory from anon, authenticated;
grant select on public.customer_directory to authenticated;
create policy directory_read on public.customer_directory for select to authenticated
  using ((select public.app_role()) is not null);
create function public.save_customer_directory(p_payload jsonb, p_expected_revision bigint default 0)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare current_revision bigint; saved_at timestamptz := now();
begin
  if public.app_role() is distinct from 'admin' then
    raise insufficient_privilege using message = 'Admin access required';
  end if;
  if p_payload->>'version' is distinct from '1' or p_payload->>'algorithm' is distinct from 'AES-256-GCM'
     or jsonb_typeof(p_payload->'ciphertext') is distinct from 'string' or length(p_payload::text) > 20000000 then
    raise check_violation using message = 'Unsupported encrypted payload';
  end if;
  perform pg_advisory_xact_lock(98276133);
  select coalesce((select revision from public.customer_directory where id), 0) into current_revision;
  if current_revision <> p_expected_revision then
    raise exception using errcode = 'P0001', message = 'REVISION_CONFLICT';
  end if;
  current_revision := current_revision + 1;
  insert into public.customer_directory(id, payload, revision, updated_at)
    values (true, p_payload, current_revision, saved_at)
    on conflict (id) do update set payload = excluded.payload, revision = excluded.revision, updated_at = excluded.updated_at;
  return jsonb_build_object('revision', current_revision, 'updated_at', saved_at);
end;
$$;
revoke all on function public.save_customer_directory(jsonb, bigint) from public, anon;
grant execute on function public.save_customer_directory(jsonb, bigint) to authenticated;

-- applied as a hotfix on 2026-11-22 after the initial migration:
-- alter table public.complaint_closures add column if not exists closed_by_name text;
