-- =====================================================================
-- 탐구 문제풀이 · DB 스키마 v2: 학년별·과목별 문제은행
-- 실행: Supabase → SQL Editor → New query → 전체 붙여넣기 → Run
-- 기존 데이터(회원·풀이기록)는 유지되며, 여러 번 실행해도 안전합니다.
-- ※ v1(supabase_schema.sql)이 먼저 실행되어 있어야 합니다.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. v1에서 누락된 경우 대비: 건너뛴 문제 테이블
-- ---------------------------------------------------------------------
create table if not exists public.skipped_questions (
  user_id      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  question_id  text not null,
  skipped_at   timestamptz not null default now(),
  deleted      boolean not null default false,
  updated_at   timestamptz not null default now(),
  primary key (user_id, question_id)
);
alter table public.skipped_questions enable row level security;
drop policy if exists skipped_questions_own on public.skipped_questions;
create policy skipped_questions_own on public.skipped_questions for all to authenticated
  using (user_id = auth.uid() and public.is_member()) with check (user_id = auth.uid() and public.is_member());
drop policy if exists skipped_questions_admin_read on public.skipped_questions;
create policy skipped_questions_admin_read on public.skipped_questions for select to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- 1. 학년 코드
-- ---------------------------------------------------------------------
create table if not exists public.grades (
  code  text primary key,
  name  text not null,
  sort  integer not null
);
insert into public.grades (code, name, sort) values
  ('m1','중1',1), ('m2','중2',2), ('m3','중3',3), ('h1','고1',4), ('h2','고2',5), ('h3','고3/재수생',6)
on conflict (code) do update set name = excluded.name, sort = excluded.sort;

-- ---------------------------------------------------------------------
-- 2. 회원: 학년, 최초 연결 허용 여부
-- ---------------------------------------------------------------------
alter table public.members add column if not exists grade text references public.grades(code);
alter table public.members add column if not exists claimable boolean not null default false;
update public.members set grade = 'h3' where login_id = 'sjliu' and grade is null;        -- 기본 사용자 → 고3/재수생
update public.members set claimable = (user_id is null) where login_id = 'sjliu';          -- 아직 DB 계정 미연결 시에만 최초 연결 허용

-- ---------------------------------------------------------------------
-- 3. 문제은행 (학년 × 과목) 과 문항
-- ---------------------------------------------------------------------
create table if not exists public.question_banks (
  id              bigint generated always as identity primary key,
  grade           text not null references public.grades(code),
  subject         text not null,
  question_count  integer not null default 0,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  unique (grade, subject)
);
create table if not exists public.questions (
  question_id  text primary key,                       -- 문항ID: 전체 학년에서 고유 (풀이기록과 연결되는 키)
  bank_id      bigint not null references public.question_banks(id) on delete cascade,
  unit         text not null,
  subunit      text,
  q_type       text not null check (q_type in ('객관식','단답형','서술형')),
  difficulty   text check (difficulty in ('상','중','하')),
  text         text not null,
  image        text,
  choices      jsonb not null default '[]'::jsonb,
  answer       text not null,
  explanation  text,
  points       numeric(4,1),
  criteria     text,
  updated_at   timestamptz not null default now()
);
create index if not exists questions_bank on public.questions (bank_id);

-- 문항이 바뀌면 과목 문제은행의 문항 수·수정 시각 갱신 (사용자 기기는 바뀐 과목만 다시 받음)
create or replace function public.touch_bank() returns trigger
language plpgsql security definer set search_path = public as $$
declare b bigint;
begin
  foreach b in array array[case when tg_op <> 'INSERT' then old.bank_id end, case when tg_op <> 'DELETE' then new.bank_id end] loop
    if b is not null then
      update question_banks set updated_at = now(), question_count = (select count(*) from questions where bank_id = b) where id = b;
    end if;
  end loop;
  return null;
end $$;
drop trigger if exists questions_touch on public.questions;
create trigger questions_touch after insert or update or delete on public.questions
  for each row execute function public.touch_bank();

-- ---------------------------------------------------------------------
-- 4. 풀이기록에 학년 추가 (학년별 분석)
-- ---------------------------------------------------------------------
alter table public.attempts add column if not exists grade text references public.grades(code);
update public.attempts a set grade = 'h3' where grade is null;                       -- 기존 기록은 고3/재수생
create index if not exists attempts_user_grade on public.attempts (user_id, grade);

-- ---------------------------------------------------------------------
-- 5. 접근 권한 (RLS): 회원은 문제 조회, 관리자만 등록·수정·삭제
-- ---------------------------------------------------------------------
alter table public.grades         enable row level security;
alter table public.question_banks enable row level security;
alter table public.questions      enable row level security;
drop policy if exists grades_read on public.grades;
create policy grades_read on public.grades for select to authenticated using (true);
do $$
declare t text;
begin
  foreach t in array array['question_banks','questions'] loop
    execute format('drop policy if exists %1$s_read on public.%1$s', t);
    execute format('create policy %1$s_read on public.%1$s for select to authenticated using (public.is_member())', t);
    execute format('drop policy if exists %1$s_admin on public.%1$s', t);
    execute format('create policy %1$s_admin on public.%1$s for all to authenticated using (public.is_admin()) with check (public.is_admin())', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 6. 회원 함수
-- ---------------------------------------------------------------------
-- 6-1. 최초 연결: 관리자가 허용(claimable)한 기존 회원만, 1회
create or replace function public.claim_member() returns text
language plpgsql security definer set search_path = public as $$
declare v_login text; v_role text;
begin
  select split_part(email, '@', 1) into v_login from auth.users where id = auth.uid();
  if v_login is null then raise exception 'not authenticated'; end if;
  select role into v_role from members where login_id = v_login and user_id = auth.uid() and active;
  if v_role is not null then return v_role; end if;
  update members set user_id = auth.uid(), claimable = false
   where login_id = v_login and active and claimable and user_id is null
  returning role into v_role;
  if v_role is null then raise exception 'member not registered: %', v_login; end if;
  return v_role;
end $$;

-- 6-2. 내 학년 선택
create or replace function public.set_my_grade(p_grade text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from grades where code = p_grade) then raise exception 'invalid grade: %', p_grade; end if;
  update members set grade = p_grade where user_id = auth.uid() and active;
  if not found then raise exception 'not a member'; end if;
end $$;

-- 6-3. 회원 등록·권한·학년 변경 (관리자)
drop function if exists public.admin_upsert_member(text, text);
create or replace function public.admin_upsert_member(p_login text, p_role text default 'user', p_grade text default null) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if p_role not in ('admin','user') then raise exception 'invalid role'; end if;
  insert into members (login_id, role, grade) values (lower(p_login), p_role, p_grade)
  on conflict (login_id) do update set role = excluded.role, grade = coalesce(excluded.grade, members.grade), active = true;
end $$;

-- 6-4. 관리자가 만든 인증 계정을 회원과 연결
create or replace function public.admin_link_member(p_login text, p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if not exists (select 1 from auth.users where id = p_user and split_part(email,'@',1) = lower(p_login)) then
    raise exception 'account mismatch'; end if;
  update members set user_id = p_user, claimable = false
   where login_id = lower(p_login) and (user_id is null or user_id = p_user);
  if not found then raise exception 'member already linked to another account: %', p_login; end if;
end $$;

revoke all on function public.admin_upsert_member(text,text,text), public.set_my_grade(text) from public, anon;
grant execute on function public.claim_member(), public.set_my_grade(text), public.admin_upsert_member(text,text,text),
                          public.admin_link_member(text,uuid) to authenticated;

-- ---------------------------------------------------------------------
-- 7. 관리자용 사용자별 학습 현황 (권한·학년·상태 추가)
-- ---------------------------------------------------------------------
create or replace view public.v_user_summary with (security_invoker = true) as
select m.login_id,
       count(a.id)                                   as attempts,
       round(avg(a.score)::numeric, 3)               as accuracy,
       round(avg(a.time_sec)::numeric, 1)            as avg_time_sec,
       max(a.answered_at)                            as last_activity,
       m.role, m.grade, m.active
  from public.members m
  left join public.attempts a on a.user_id = m.user_id
 group by m.login_id, m.role, m.grade, m.active;

-- ---------------------------------------------------------------------
-- 8. 문제 이미지 저장소 (회원만 조회, 관리자만 업로드)
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public) values ('qimages', 'qimages', false)
on conflict (id) do nothing;
drop policy if exists qimages_read   on storage.objects;
drop policy if exists qimages_insert on storage.objects;
drop policy if exists qimages_update on storage.objects;
drop policy if exists qimages_delete on storage.objects;
create policy qimages_read   on storage.objects for select to authenticated using (bucket_id = 'qimages' and public.is_member());
create policy qimages_insert on storage.objects for insert to authenticated with check (bucket_id = 'qimages' and public.is_admin());
create policy qimages_update on storage.objects for update to authenticated using (bucket_id = 'qimages' and public.is_admin()) with check (bucket_id = 'qimages' and public.is_admin());
create policy qimages_delete on storage.objects for delete to authenticated using (bucket_id = 'qimages' and public.is_admin());

-- ---------------------------------------------------------------------
-- 9. API 스키마 새로고침 · 결과 확인
-- ---------------------------------------------------------------------
notify pgrst, 'reload schema';
select login_id, role, grade, active, (user_id is not null) as db_linked, claimable from public.members order by login_id;
