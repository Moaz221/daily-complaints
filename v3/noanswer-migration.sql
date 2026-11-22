-- No-answer outcome: adds 'العميل مردش' to the closure outcomes so a technician can log
-- that the customer did not answer. The complaint stays tracked (مردشوا screen + المتأخرات).
alter table public.complaint_closures drop constraint complaint_closures_outcome_check;
alter table public.complaint_closures add constraint complaint_closures_outcome_check
  check (outcome in ('إنهاء خدمة','استكمال قطعة غيار','تأجيل','رفض إصلاح','إلغاء البلاغ','استكمال شحن','العميل مردش'));

-- Allow repeated no-answer attempts plus one final outcome per complaint:
-- the blanket one-closure-per-complaint uniqueness becomes a partial unique index
-- over final (non no-answer) outcomes only. Attempt history is preserved.
do $$
declare c text;
begin
  select conname into c from pg_constraint
   where conrelid='public.complaint_closures'::regclass and contype='u';
  if c is not null then
    execute format('alter table public.complaint_closures drop constraint %I', c);
  end if;
end $$;
create unique index complaint_closures_one_final_outcome
  on public.complaint_closures (complaint_id) where outcome <> 'العميل مردش';
