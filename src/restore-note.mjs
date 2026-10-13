// 10단계: 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 판단 로직입니다.
// 저장소 접근은 repo(주입)에 맡겨서, 이 파일은 DB 없이 시험할 수 있습니다.
// 소유자는 서버가 검증한 로그인에서만 얻습니다. 본문의 owner_id·role은 믿지 않습니다.
// 다른 메모는 읽지도 쓰지도 않고, 감사 기록은 한 줄을 덧붙이기만 합니다.
import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const ROLE_KEYS = Object.freeze(['role', 'roles', 'isinstructor', 'instructor', 'permission', 'permissions', 'scope', 'zone']);
const OWNER_KEYS = Object.freeze(['owner_id', 'ownerid', 'userid']);
const ID_KEYS = Object.freeze(['id', 'noteid', 'note_id', 'memoid']);
const ALLOWED_KEYS = Object.freeze([...ID_KEYS, 'contentsha256', 'dryrun']);

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

// 내용 해시: 제목, 줄바꿈 한 개, 내용을 UTF-8로 이어 붙여 SHA-256 16진수로 만듭니다. (db/notes-backup.sql의 계산과 같습니다.)
export function contentHash({ title, content }) {
  return createHash('sha256').update(`${title}\n${content}`, 'utf8').digest('hex');
}

// 내용 해시: 메모 내용(content) 하나만 UTF-8로 SHA-256 한 16진수입니다. 응답에 돌려주고 기대 해시와 대조하는 값입니다.
export function bodySha256(content) {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

// 본문에서 복원할 메모 번호(id)와 선택 사항인 기대 내용 해시(contentSha256), 미리보기(dryRun)만 꺼냅니다.
export function readRestoreInput(body, userId) {
  let data = body;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return { error: 'INVALID_BODY' }; }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { error: 'INVALID_BODY' };
  const keys = Object.keys(data);
  if (keys.some(key => ROLE_KEYS.includes(key.toLowerCase()))) return { error: 'ROLE_NOT_TRUSTED' };
  for (const key of keys) {
    if (OWNER_KEYS.includes(key.toLowerCase()) && !same(String(data[key]), userId)) return { error: 'OWNER_FORBIDDEN' };
  }
  const extra = keys.filter(key => !OWNER_KEYS.includes(key.toLowerCase()) && !ALLOWED_KEYS.includes(key.toLowerCase()));
  if (extra.length) return { error: 'INVALID_BODY' };
  const idKeys = keys.filter(key => ID_KEYS.includes(key.toLowerCase()));
  if (idKeys.length !== 1) return { error: 'INVALID_ID' };
  const rawId = data[idKeys[0]];
  if (typeof rawId !== 'string' || !UUID.test(rawId)) return { error: 'INVALID_ID' };
  const input = { id: rawId.toLowerCase() };
  const dryKey = keys.find(key => key.toLowerCase() === 'dryrun');
  if (dryKey !== undefined) {
    if (typeof data[dryKey] !== 'boolean') return { error: 'INVALID_BODY' };
    input.dryRun = data[dryKey];
  }
  const hashKey = keys.find(key => key.toLowerCase() === 'contentsha256');
  if (hashKey !== undefined) {
    if (typeof data[hashKey] !== 'string' || !SHA256.test(data[hashKey])) return { error: 'INVALID_HASH' };
    input.contentSha256 = data[hashKey];
  }
  return { input };
}

const deny = (status, error) => ({ status, body: { error } });

// repo: readBackup(id), readNote(id), insertNote(row) -> { conflict }, updateNote(id, ownerId, fields) -> 바뀐 행 수, writeAudit(entry)
export async function restoreNote({ userId, input, repo, log = () => {} }) {
  const backup = await repo.readBackup(input.id);
  if (!backup) { log('backup_not_found'); return deny(404, 'NOT_FOUND'); }
  // 사본의 ID와 소유자가 요청·로그인과 같을 때만 진행합니다. 남의 사본은 없는 사본과 똑같이 404입니다.
  if (!same(backup.id, input.id) || !same(backup.owner_id, userId)) { log('owner_mismatch'); return deny(404, 'NOT_FOUND'); }
  const savedHash = contentHash(backup);
  if (backup.content_sha256 !== savedHash) { log('backup_hash_mismatch'); return deny(409, 'BACKUP_INVALID'); }
  if (input.contentSha256 !== undefined && input.contentSha256 !== bodySha256(backup.content)) { log('expected_hash_mismatch'); return deny(409, 'HASH_MISMATCH'); }

  // 사본을 다시 읽어 검증한 결과(버전·무결성 해시)입니다. 미리보기와 실제 복원 응답에 모두 담습니다.
  const backupInfo = { verified: true, version: backup.backed_up_at ?? null, sha256: savedHash };
  const current = await repo.readNote(input.id);
  if (current && !same(current.owner_id, userId)) { log('current_owner_differs'); return deny(409, 'OWNER_CONFLICT'); }
  if (input.dryRun === true) {
    // 미리보기: 아무것도 쓰지 않고, 사본 버전과 바뀔 항목만 보여 줍니다.
    const change = !current ? 'create' : (contentHash(current) === savedHash ? 'none' : 'restore');
    return { status: 200, body: {
      dryRun: true, id: backup.id, ownerId: userId, owner_id: userId, backup: backupInfo, change,
      willChange: change === 'none' ? [] : ['title', 'content'], contentSha256: bodySha256(backup.content),
    } };
  }
  let outcome;
  if (!current) {
    const { conflict } = await repo.insertNote({ id: backup.id, owner_id: userId, title: backup.title, content: backup.content });
    if (conflict) { log('id_exists'); return deny(409, 'ID_EXISTS'); }
    outcome = 'created';
  } else if (contentHash(current) === savedHash) {
    outcome = 'unchanged';
  } else {
    const changed = await repo.updateNote(input.id, userId, { title: backup.title, content: backup.content });
    if (!changed) { log('update_missed'); return deny(409, 'RESTORE_CONFLICT'); }
    outcome = 'restored';
  }

  // 쓴 뒤에 다시 읽어서 ID·소유자·내용 해시가 사본과 같은지 확인합니다.
  const after = await repo.readNote(input.id);
  const matches = {
    id: Boolean(after) && same(after.id, backup.id),
    owner: Boolean(after) && same(after.owner_id, backup.owner_id),
    contentSha256: Boolean(after) && contentHash(after) === savedHash && bodySha256(after.content) === bodySha256(backup.content),
  };
  if (!matches.id || !matches.owner || !matches.contentSha256) { log('verify_failed'); return deny(500, 'RESTORE_VERIFY_FAILED'); }

  let audited = true;
  try {
    await repo.writeAudit({ note_id: backup.id, owner_id: userId, content_sha256: savedHash, outcome });
  } catch {
    audited = false;
    log('audit_failed');
  }
  return { status: 200, body: {
    id: backup.id, ownerId: userId, owner_id: userId, outcome, matches,
    contentSha256: bodySha256(after.content), backup: backupInfo, audited,
  } };
}
