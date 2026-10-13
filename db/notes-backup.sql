-- 방어전 10단계: 비공개 가상 메모 사본(notes_backup)과 복원 감사 기록(notes_restore_audit)을 만드는 SQL입니다.
-- Supabase 대시보드 > SQL Editor에 이 파일 전체를 붙여 넣고 Run 하세요. (여러 번 실행해도 됩니다.)
-- 학습용 자료만 다룹니다. 이 파일에는 메모 문장이 없고, 사본은 이미 있는 notes 테이블에서 복사합니다.
-- 두 테이블 모두 anon·authenticated(공개 키)에는 권한이 없고, 서버 함수(service_role)만 접근합니다.

create table if not exists public.notes_backup (
  id             uuid primary key,
  owner_id       uuid not null,
  title          text not null,
  content        text not null,
  -- 내용 해시: sha256(제목 || 줄바꿈 || 내용) 의 16진수입니다. src/restore-note.mjs 의 contentHash 와 같은 계산입니다.
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at   timestamptz not null default now()
);

alter table public.notes_backup enable row level security;
revoke all on table public.notes_backup from public;
revoke all on table public.notes_backup from anon;
revoke all on table public.notes_backup from authenticated;
-- 사본은 읽기와 추가만 합니다. 수정·삭제 권한은 주지 않아, 서버 함수가 사본을 바꾸거나 지우지 못합니다.
grant select, insert on table public.notes_backup to service_role;

create table if not exists public.notes_restore_audit (
  id             bigint generated always as identity primary key,
  note_id        uuid not null,
  owner_id       uuid not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  outcome        text not null check (outcome in ('restored', 'created', 'unchanged')),
  at             timestamptz not null default now()
);

alter table public.notes_restore_audit enable row level security;
revoke all on table public.notes_restore_audit from public;
revoke all on table public.notes_restore_audit from anon;
revoke all on table public.notes_restore_audit from authenticated;
-- 감사 기록도 읽기와 추가만 됩니다. 기존 기록은 수정·삭제할 수 없습니다.
grant select, insert on table public.notes_restore_audit to service_role;

-- ===== 사본 만들기 (침해 전에, 자료가 정상일 때만 실행하세요) =====
-- 이미 사본이 있는 메모는 건너뜁니다(덮어쓰지 않음). 소유자 없는 메모는 복사하지 않습니다.
-- 침해 뒤에 이 문장을 실행하면 바뀐 자료가 사본이 되므로 실행하지 마세요.
insert into public.notes_backup (id, owner_id, title, content, content_sha256)
select n.id, n.owner_id, n.title, n.content,
       encode(sha256(convert_to(n.title || E'\n' || n.content, 'UTF8')), 'hex')
  from public.notes n
 where n.owner_id is not null
on conflict (id) do nothing;

-- ===== 실행 뒤 확인용 (필요하면 하나씩 따로 실행) =====
-- 1) 두 테이블의 권한: anon·authenticated 는 모두 false 여야 함
--    select t.tbl, r.role,
--           has_table_privilege(r.role, t.tbl, 'SELECT') as can_select,
--           has_table_privilege(r.role, t.tbl, 'INSERT') as can_insert,
--           has_table_privilege(r.role, t.tbl, 'UPDATE') as can_update,
--           has_table_privilege(r.role, t.tbl, 'DELETE') as can_delete
--      from (values ('public.notes_backup'), ('public.notes_restore_audit')) as t(tbl),
--           (values ('anon'), ('authenticated'), ('service_role')) as r(role);
-- 2) 사본의 해시가 내용과 맞는지 (0 이어야 함)
--    select count(*) from public.notes_backup
--     where content_sha256 <> encode(sha256(convert_to(title || E'\n' || content, 'UTF8')), 'hex');
-- 3) 복원 대상 한 건의 사본과 현재 값 비교 (<메모 번호>는 시험 계정 B의 메모 번호; 같은 줄이 true 여야 함)
--    select b.id = n.id as same_id, b.owner_id = n.owner_id as same_owner,
--           b.content_sha256 = encode(sha256(convert_to(n.title || E'\n' || n.content, 'UTF8')), 'hex') as same_hash
--      from public.notes_backup b join public.notes n on n.id = b.id where b.id = '<메모 번호>';
-- 4) 감사 기록: select id, note_id, outcome, at from public.notes_restore_audit order by id;
