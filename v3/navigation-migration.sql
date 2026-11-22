-- V5: record the authenticated closer's name and role at the time of closure.
-- Existing closures keep their original name and an unknown historical role.
alter table public.complaint_closures add column if not exists closed_by_role text
  check (closed_by_role in ('admin','technician'));
create or replace function public.stamp_complaint_closer()
returns trigger language plpgsql security definer set search_path = '' as $$
declare p public.app_profiles;
begin
  select * into p from public.app_profiles where id = auth.uid() and active;
  if p.id is null or new.closed_by is distinct from p.id then
    raise insufficient_privilege using message = 'Active authenticated closer required';
  end if;
  new.closed_by_name := p.display_name;
  new.closed_by_role := p.role;
  return new;
end;
$$;
revoke all on function public.stamp_complaint_closer() from public, anon, authenticated;
create trigger stamp_complaint_closer before insert on public.complaint_closures
for each row execute function public.stamp_complaint_closer();
select (select revision from public.complaint_latest limit 1) as latest_revision,
       (select count(*) from public.complaint_archive) as archives,
       (select count(*) from public.complaint_closures) as closures;
