-- No-answer outcome: adds 'العميل مردش' to the closure outcomes so a technician can log
-- that the customer did not answer. The complaint stays tracked (مردشوا screen + المتأخرات).
alter table public.complaint_closures drop constraint complaint_closures_outcome_check;
alter table public.complaint_closures add constraint complaint_closures_outcome_check
  check (outcome in ('إنهاء خدمة','استكمال قطعة غيار','تأجيل','رفض إصلاح','إلغاء البلاغ','استكمال شحن','العميل مردش'));
