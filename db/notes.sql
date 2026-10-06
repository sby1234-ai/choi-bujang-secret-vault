-- 방어전 2~5단계: 메모를 코드 밖(학습용 Supabase DB)에 두고, 서버 함수(service_role)만 이 테이블에 직접 접근하게 하는 SQL입니다.
-- Supabase 대시보드 > SQL Editor에 이 파일 전체를 붙여 넣고 Run 하세요. (여러 번 실행해도 됩니다.)
-- 학습용 자료만 다룹니다. 실제 키·개인정보는 넣지 않습니다.

create table if not exists public.notes (
  id         uuid primary key default gen_random_uuid(),
  -- 소유자(Supabase Auth 사용자 ID)입니다. auth.users 외래키는 일부러 걸지 않았습니다.
  owner_id   uuid,
  title      text not null,
  content    text not null,
  created_at timestamptz not null default now()
);

-- RLS를 켭니다. 5단계에서 직접 권한을 모두 회수하지만, 정책은 두 번째 방어선으로 남겨 둡니다.
alter table public.notes enable row level security;

-- 1) 기존 권한부터 모두 회수합니다. (service_role은 건드리지 않습니다.)
revoke all on table public.notes from public;
revoke all on table public.notes from anon;
revoke all on table public.notes from authenticated;

-- 2) 5단계: anon·authenticated(공개 키로 직접 부르는 길)에는 권한을 주지 않습니다.
--    4단계에서 authenticated에 주었던 네 가지 권한도 위 revoke로 회수됩니다. 자료는 서버 함수를 통해서만 오갑니다.

-- 3) 서버 함수가 쓰는 서버 전용 키(service_role)의 권한입니다.
--    새 테이블 자동 공개를 끈 프로젝트에서는 이 줄이 없으면 서버 함수가 읽거나 쓰지 못합니다.
grant select, insert, update, delete on table public.notes to service_role;

-- 4) 정책(직접 권한이 없어 지금은 쓰이지 않지만 두 번째 방어선으로 둡니다): 읽기·삭제는 기존 행(USING), 추가는 새 행(WITH CHECK),
--    수정은 기존 행(USING)과 새 행(WITH CHECK) 모두 auth.uid() = owner_id 일 때만 허용합니다.
drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

create policy notes_select_own on public.notes
  for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy notes_insert_own on public.notes
  for insert to authenticated
  with check ((select auth.uid()) = owner_id);

create policy notes_update_own on public.notes
  for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

create policy notes_delete_own on public.notes
  for delete to authenticated
  using ((select auth.uid()) = owner_id);

-- 가상 메모와 시험 메모는 SQL Editor에서 한 번 넣었고, 공개 저장소에는 메모 문장을 남기지 않기 위해
-- 이 파일에서는 넣는 문장을 뺐습니다. 새 프로젝트에서 다시 만들 때는 SQL Editor에서 직접 입력하세요.
-- 소유자 연결 예시: 먼저 Authentication > Users에서 시험 계정 둘을 만들고, 그 ID를 owner_id에 넣습니다.
--   insert into public.notes (owner_id, title, content)
--   select id, '제목', '내용' from auth.users where lower(email) = lower('<시험 계정 이메일>');

-- ===== 실행 뒤 확인용 (필요하면 하나씩 따로 실행) =====
-- 1) 두 역할의 실제 권한: anon·authenticated 모두 네 칸 전부 false 여야 함
--    select r.role,
--           has_table_privilege(r.role, 'public.notes', 'SELECT') as can_select,
--           has_table_privilege(r.role, 'public.notes', 'INSERT') as can_insert,
--           has_table_privilege(r.role, 'public.notes', 'UPDATE') as can_update,
--           has_table_privilege(r.role, 'public.notes', 'DELETE') as can_delete
--      from (values ('anon'), ('authenticated')) as r(role);
-- 2) 권한 목록: anon·authenticated 행이 없어야 함 (service_role만 남음)
--    select grantee, privilege_type from information_schema.role_table_grants
--     where table_schema = 'public' and table_name = 'notes'
--       and grantee in ('anon', 'authenticated', 'service_role') order by grantee, privilege_type;
-- 3) 정책 4개가 모두 authenticated 대상인지
--    select policyname, cmd, roles from pg_policies
--     where schemaname = 'public' and tablename = 'notes' order by cmd;
-- 4) RLS가 켜져 있는지 (rowsecurity = true)
--    select tablename, rowsecurity from pg_tables where schemaname = 'public' and tablename = 'notes';
-- 5) 주인 없는 메모가 없는지 (0 이어야 함)
--    select count(*) from public.notes where owner_id is null;
