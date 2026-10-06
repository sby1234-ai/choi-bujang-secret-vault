-- 방어전 2단계: 메모를 코드 밖(학습용 Supabase DB)에 둘 테이블을 만듭니다.
-- Supabase 대시보드 > SQL Editor에 이 파일 전체를 붙여 넣고 Run 하세요.
-- 학습용 자료만 다룹니다. 실제 키·개인정보는 넣지 않습니다.

create table if not exists public.notes (
  id         uuid primary key default gen_random_uuid(),
  -- 3단계 로그인에서 쓸 자리입니다. auth.users 외래키는 일부러 걸지 않았습니다.
  owner_id   uuid,
  title      text not null,
  content    text not null,
  created_at timestamptz not null default now()
);

-- RLS를 켭니다. 정책(policy)을 만들지 않으므로 anon·authenticated는 아무 행도 못 봅니다.
alter table public.notes enable row level security;

-- 테이블 권한도 회수합니다. 서버 전용 키(service role)는 RLS와 권한 회수와 상관없이 읽을 수 있습니다.
revoke all on table public.notes from public;
revoke all on table public.notes from anon;
revoke all on table public.notes from authenticated;

-- 가상 메모 네 건은 SQL Editor에서 한 번 넣었고, 공개 저장소에는 메모 문장을 남기지 않기 위해
-- 이 파일에서는 넣는 문장을 뺐습니다. 새 프로젝트에서 다시 만들 때는 SQL Editor에서 직접 입력하세요.
--   insert into public.notes (title, content) values ('제목', '내용');

-- ===== 실행 뒤 확인용 (필요하면 따로 실행) =====
-- 1) owner_id 칸이 있고 외래키가 없는지
--    select column_name, data_type from information_schema.columns
--     where table_schema = 'public' and table_name = 'notes' order by ordinal_position;
--    select count(*) as fk_count from information_schema.table_constraints
--     where table_schema = 'public' and table_name = 'notes' and constraint_type = 'FOREIGN KEY';   -- 0 이어야 함
-- 2) RLS가 켜져 있는지 (rowsecurity = true)
--    select tablename, rowsecurity from pg_tables where schemaname = 'public' and tablename = 'notes';
-- 3) anon·authenticated에 권한이 없는지 (결과 0행이어야 함)
--    select grantee, privilege_type from information_schema.role_table_grants
--     where table_schema = 'public' and table_name = 'notes' and grantee in ('anon', 'authenticated');
-- 4) 메모 네 건이 들어갔는지
--    select count(*) from public.notes;   -- 4
