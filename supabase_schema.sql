-- =====================================================================
-- 탐구 문제풀이 · 학습기록 DB 스키마 (Supabase / PostgreSQL)
-- 실행: Supabase 대시보드 → SQL Editor → New query → 전체 붙여넣기 → Run
-- 여러 번 실행해도 안전하도록 작성됨 (if not exists / or replace)
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. 회원 (사이트 아이디 ↔ Supabase 인증 계정 연결, 권한)
--    · 관리자가 등록한 아이디만 기록을 저장할 수 있음 (임의 가입자 차단)
-- ---------------------------------------------------------------------
create table if not exists public.members (
  login_id    text primary key check (login_id ~ '^[a-z0-9._-]{3,30}$'),
  role        text not null default 'user' check (role in ('admin','user')),
  user_id     uuid unique references auth.users(id) on delete set null,
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 2. 풀이 기록 (1문항 풀이 = 1행)
-- ---------------------------------------------------------------------
create table if not exists public.attempts (
  id           bigint generated always as identity primary key,
  user_id      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  client_key   text not null,                      -- 기기에서 만든 고유키(문항ID|시각): 중복 저장 방지
  question_id  text not null,
  subject      text not null,
  unit         text not null,
  subunit      text,
  q_type       text not null check (q_type in ('객관식','단답형','서술형')),
  difficulty   text check (difficulty in ('상','중','하')),
  points       numeric(4,1),
  score        numeric(3,2) not null check (score between 0 and 1),   -- 1 정답, 0.5 부분, 0 오답
  answer       text,
  time_sec     integer check (time_sec >= 0),
  session_id   text,
  appealed     boolean not null default false,     -- '정답 인정' 처리 여부
  answered_at  timestamptz not null,
  updated_at   timestamptz not null default now(),
  unique (user_id, client_key)
);
create index if not exists attempts_user_time on public.attempts (user_id, answered_at desc);
create index if not exists attempts_user_unit on public.attempts (user_id, subject, unit);

-- ---------------------------------------------------------------------
-- 3. 오답노트
-- ---------------------------------------------------------------------
create table if not exists public.wrong_notes (
  user_id        uuid not null default auth.uid() references auth.users(id) on delete cascade,
  question_id    text not null,
  wrong_count    integer not null default 0,
  last_wrong_at  timestamptz,
  cleared        boolean not null default false,   -- 이후 정답으로 극복
  starred        boolean not null default false,   -- 직접 저장
  deleted        boolean not null default false,   -- 삭제 표시 (다른 기기에서 되살아나지 않도록)
  updated_at     timestamptz not null default now(),
  primary key (user_id, question_id)
);

-- ---------------------------------------------------------------------
-- 4. 사용자 설정 (출제 설정, 학습기록 초기화 시점)
-- ---------------------------------------------------------------------
create table if not exists public.user_settings (
  user_id              uuid primary key default auth.uid() references auth.users(id) on delete cascade,
  settings             jsonb,
  settings_updated_at  timestamptz,
  reset_at             timestamptz,
  updated_at           timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 5. 개인 문제 (사용자가 '내 기기에만' 올린 문제)
-- ---------------------------------------------------------------------
create table if not exists public.personal_questions (
  user_id      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  question_id  text not null,
  data         jsonb,
  deleted      boolean not null default false,
  updated_at   timestamptz not null default now(),
  primary key (user_id, question_id)
);

-- ---------------------------------------------------------------------
-- 5-1. 건너뛴 문제 ('건너뛴 문제 제외' 옵션용)
-- ---------------------------------------------------------------------
create table if not exists public.skipped_questions (
  user_id      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  question_id  text not null,
  skipped_at   timestamptz not null default now(),
  deleted      boolean not null default false,   -- 해제 표시 (다시 풀었거나 '모두 해제')
  updated_at   timestamptz not null default now(),
  primary key (user_id, question_id)
);

-- ---------------------------------------------------------------------
-- 6. 권한 확인 함수
-- ---------------------------------------------------------------------
create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where user_id = auth.uid() and active);
$$;
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where user_id = auth.uid() and active and role = 'admin');
$$;

-- ---------------------------------------------------------------------
-- 7. 행 수준 보안(RLS): 본인 기록만 읽기/쓰기, 관리자는 전체 조회
-- ---------------------------------------------------------------------
alter table public.members            enable row level security;
alter table public.attempts           enable row level security;
alter table public.wrong_notes        enable row level security;
alter table public.user_settings      enable row level security;
alter table public.personal_questions enable row level security;
alter table public.skipped_questions  enable row level security;

drop policy if exists members_select on public.members;
create policy members_select on public.members for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

do $$
declare t text;
begin
  foreach t in array array['attempts','wrong_notes','user_settings','personal_questions','skipped_questions'] loop
    execute format('drop policy if exists %1$s_own on public.%1$s', t);
    execute format('create policy %1$s_own on public.%1$s for all to authenticated
                    using (user_id = auth.uid() and public.is_member())
                    with check (user_id = auth.uid() and public.is_member())', t);
    execute format('drop policy if exists %1$s_admin_read on public.%1$s', t);
    execute format('create policy %1$s_admin_read on public.%1$s for select to authenticated
                    using (public.is_admin())', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 8. 회원 관리 함수 (화면에서 호출, 관리자만 실행 가능)
-- ---------------------------------------------------------------------
-- 8-1. 본인 계정 연결: 관리자가 미리 등록한 아이디와 내 인증 계정(이메일 앞부분)을 연결
create or replace function public.claim_member() returns text
language plpgsql security definer set search_path = public as $$
declare v_login text;
begin
  select split_part(email, '@', 1) into v_login from auth.users where id = auth.uid();
  if v_login is null then raise exception 'not authenticated'; end if;
  update members set user_id = auth.uid()
   where login_id = v_login and active and (user_id is null or user_id = auth.uid());
  if not found then raise exception 'member not registered: %', v_login; end if;
  return (select role from members where login_id = v_login);
end $$;

-- 8-2. 회원 등록/권한 변경 (관리자)
create or replace function public.admin_upsert_member(p_login text, p_role text default 'user') returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  insert into members (login_id, role) values (lower(p_login), p_role)
  on conflict (login_id) do update set role = excluded.role, active = true;
end $$;

-- 8-3. 신규 인증 계정 연결 (관리자가 방금 생성한 계정을 회원과 연결)
create or replace function public.admin_link_member(p_login text, p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if not exists (select 1 from auth.users where id = p_user and split_part(email,'@',1) = lower(p_login)) then
    raise exception 'account mismatch'; end if;
  update members set user_id = p_user where login_id = lower(p_login) and (user_id is null or user_id = p_user);
  if not found then raise exception 'member already linked to another account: %', p_login; end if;
end $$;

-- 8-4. 비밀번호 재설정 (관리자)
create or replace function public.admin_set_password(p_login text, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_user uuid;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if length(p_password) < 8 then raise exception 'password too short'; end if;
  select user_id into v_user from members where login_id = lower(p_login);
  if v_user is null then raise exception 'member has no account: %', p_login; end if;
  update auth.users set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')), updated_at = now()
   where id = v_user;
end $$;

-- 8-5. 회원 비활성화 (관리자) — 기록은 보존, 저장·조회만 차단
create or replace function public.admin_deactivate_member(p_login text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update members set active = false where login_id = lower(p_login) and user_id is distinct from auth.uid();
end $$;

revoke all on function public.admin_upsert_member(text,text), public.admin_link_member(text,uuid),
                       public.admin_set_password(text,text), public.admin_deactivate_member(text) from public, anon;
grant execute on function public.claim_member(), public.admin_upsert_member(text,text), public.admin_link_member(text,uuid),
                          public.admin_set_password(text,text), public.admin_deactivate_member(text),
                          public.is_member(), public.is_admin() to authenticated;

-- ---------------------------------------------------------------------
-- 9. 관리자용 학습 현황 뷰 (사용자별 요약)
-- ---------------------------------------------------------------------
create or replace view public.v_user_summary with (security_invoker = true) as
select m.login_id,
       count(a.id)                                   as attempts,
       round(avg(a.score)::numeric, 3)               as accuracy,
       round(avg(a.time_sec)::numeric, 1)            as avg_time_sec,
       max(a.answered_at)                            as last_activity
  from public.members m
  left join public.attempts a on a.user_id = m.user_id
 group by m.login_id;

-- ---------------------------------------------------------------------
-- 10. 최초 관리자 등록 (사이트 기본 계정)
--     → 사이트에서 sjliu로 처음 로그인하면 인증 계정이 자동 생성·연결됨
-- ---------------------------------------------------------------------
insert into public.members (login_id, role) values ('sjliu', 'admin')
on conflict (login_id) do nothing;

-- ---------------------------------------------------------------------
-- 11. API 스키마 캐시 새로고침 (새 테이블이 바로 보이도록)
-- ---------------------------------------------------------------------
notify pgrst, 'reload schema';
