-- Kashi Growth Academy: certificate issuance and verification setup
-- Run this entire script once in Supabase SQL Editor.

create table if not exists public.certificates (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  certificate_id text not null unique,
  student_name text not null,
  issued_at timestamptz not null default now(),
  course_name text not null default 'Amazon Seller Training Course',
  lessons_completed integer not null check (lessons_completed = 20)
);

alter table public.certificates enable row level security;

drop policy if exists "Students can read own certificate" on public.certificates;
create policy "Students can read own certificate"
on public.certificates for select to authenticated
using (auth.uid() = user_id);

drop policy if exists "Students can issue own certificate" on public.certificates;
create policy "Students can issue own certificate"
on public.certificates for insert to authenticated
with check (auth.uid() = user_id and lessons_completed = 20);

drop policy if exists "Admins can read certificates" on public.certificates;
create policy "Admins can read certificates"
on public.certificates for select to authenticated
using (
  exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  )
);

create or replace function public.verify_kga_certificate(p_certificate_id text)
returns table (
  certificate_id text,
  student_name text,
  issued_at timestamptz,
  course_name text,
  lessons_completed integer
)
language sql
security definer
set search_path = public
stable
as $$
  select c.certificate_id, c.student_name, c.issued_at, c.course_name, c.lessons_completed
  from public.certificates c
  where upper(c.certificate_id) = upper(trim(p_certificate_id))
  limit 1;
$$;

revoke all on function public.verify_kga_certificate(text) from public;
grant execute on function public.verify_kga_certificate(text) to anon, authenticated;

grant select, insert on public.certificates to authenticated;
