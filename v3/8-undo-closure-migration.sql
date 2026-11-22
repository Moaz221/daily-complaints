-- V6: admin can undo a mistaken closure (e.g. wrong outcome or wrong complaint).
-- Deleting the closure reopens the complaint everywhere; damaged-part rows ride in the
-- closure note, so they leave the توالف الضمان screen with it. Run once on the live project.
grant delete on public.complaint_closures to authenticated;
create policy closures_admin_delete on public.complaint_closures for delete to authenticated
  using ((select public.app_role()) = 'admin');
