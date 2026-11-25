-- Kashi Growth Academy: secure student-teacher messaging
create table if not exists public.teacher_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  sender_role text not null check (sender_role in ('student','admin')),
  message text not null check (char_length(trim(message)) between 1 and 2000),
  created_at timestamptz not null default now()
);

create index if not exists teacher_messages_user_created_idx
  on public.teacher_messages (user_id, created_at);

alter table public.teacher_messages enable row level security;

-- SECURITY DEFINER avoids recursive profile RLS checks when verifying admin role.
create or replace function public.kga_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

revoke all on function public.kga_is_admin() from public;
grant execute on function public.kga_is_admin() to authenticated;
grant select, insert on public.teacher_messages to authenticated;

drop policy if exists "KGA read own messages or admin" on public.teacher_messages;
create policy "KGA read own messages or admin"
on public.teacher_messages for select to authenticated
using (user_id = auth.uid() or public.kga_is_admin());

drop policy if exists "KGA send own student message or admin reply" on public.teacher_messages;
create policy "KGA send own student message or admin reply"
on public.teacher_messages for insert to authenticated
with check (
  (user_id = auth.uid() and sender_role = 'student')
  or (sender_role = 'admin' and public.kga_is_admin())
);
