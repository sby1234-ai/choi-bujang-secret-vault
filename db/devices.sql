-- 방어전 11단계: 기기 승인 표(devices)를 만드는 SQL입니다.
-- Supabase 대시보드 > SQL Editor에 이 파일 전체를 붙여 넣고 Run 하세요. (여러 번 실행해도 됩니다.)
-- 표에는 기기 증표의 SHA-256 지문과 확인 코드, 상태만 있고 증표 원문·개인키는 없습니다.
-- anon·authenticated(공개 키)에는 권한이 없습니다. 서버 함수(service_role)는 읽기와 "승인 대기" 등록만 할 수 있고, 상태를 바꿀 수 없습니다.

create table if not exists public.devices (
  id           uuid primary key default gen_random_uuid(),
  owner_id     uuid not null,
  token_sha256 text not null unique check (token_sha256 ~ '^[0-9a-f]{64}$'),
  code         text not null unique check (code ~ '^[0-9A-F]{4}-[0-9A-F]{4}$'),
  status       text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  approved_at  timestamptz
);

alter table public.devices enable row level security;
revoke all on table public.devices from public;
revoke all on table public.devices from anon;
revoke all on table public.devices from authenticated;
revoke all on table public.devices from service_role;
-- 서버 함수: 읽기 + 세 열(owner_id, token_sha256, code)만 넣기. status·approved_at은 기본값(pending, 비어 있음)으로만 들어갑니다.
grant select on table public.devices to service_role;
grant insert (owner_id, token_sha256, code) on table public.devices to service_role;

-- ===== 승인·회수 (관리자가 SQL Editor에서 직접 실행) =====
-- 1) 승인 대기 기기 보기:
--    select code, owner_id, status, requested_at from public.devices order by requested_at desc;
-- 2) 화면에 보인 확인 코드로 한 대만 승인:
--    update public.devices set status = 'approved', approved_at = now() where code = '<확인 코드>' and status = 'pending';
-- 3) 회수(잃어버린 기기 등):
--    update public.devices set status = 'revoked' where code = '<확인 코드>';
-- 4) 권한 확인(anon·authenticated는 모두 false. service_role은 select와 code 열 insert만 true, status 열 update·insert는 false):
--    select r.role, has_table_privilege(r.role, 'public.devices', 'SELECT') as can_select,
--           has_column_privilege(r.role, 'public.devices', 'code', 'INSERT') as can_insert_code,
--           has_column_privilege(r.role, 'public.devices', 'status', 'INSERT') as can_insert_status,
--           has_column_privilege(r.role, 'public.devices', 'status', 'UPDATE') as can_update_status,
--           has_table_privilege(r.role, 'public.devices', 'DELETE') as can_delete
--      from (values ('anon'), ('authenticated'), ('service_role')) as r(role);
