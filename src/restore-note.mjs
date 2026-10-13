// 10단계: 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 판단 로직입니다.
// 저장소 접근은 repo(주입)에 맡겨서, 이 파일은 DB 없이 시험할 수 있습니다.
// 소유자는 서버가 검증한 로그인에서만 얻습니다. 본문에는 메모 번호(id) 하나만 받고, 다른 항목은 모두 400입니다.
// 다른 메모는 읽지도 쓰지도 않고, 감사 기록은 한 줄을 덧붙이기만 합니다.
import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

// 내용 해시: 제목, 줄바꿈 한 개, 내용을 UTF-8로 이어 붙여 SHA-256 한 16진수입니다. (db/notes-backup.sql의 계산과 같습니다.)
export function contentHash({ title, content }) {
  return createHash('sha256').update(`${title}\n${content}`, 'utf8').digest('hex');
}

// 본문에서 복원할 메모 번호(id) 하나만 꺼냅니다. 소유자·역할·해시 같은 다른 항목이 있으면 거부합니다.
export function readRestoreInput(body) {
  let data = body;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return { error: 'INVALID_BODY' }; }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { error: 'INVALID_BODY' };
  const keys = Object.keys(data);
  if (keys.length !== 1 || keys[0] !== 'id') return { error: keys.includes('id') ? 'INVALID_BODY' : 'INVALID_ID' };
  if (typeof data.id !== 'string' || !UUID.test(data.id)) return { error: 'INVALID_ID' };
  return { input: { id: data.id.toLowerCase() } };
}

const deny = (status, error) => ({ status, body: { error } });

// repo: readBackup(id), readNote(id), insertNote(row) -> { conflict }, updateNote(id, ownerId, fields) -> 바뀐 행 수, writeAudit(entry)
export async function restoreNote({ userId, input, repo, log = () => {} }) {
  const backup = await repo.readBackup(input.id);
  if (!backup) { log('backup_not_found'); return deny(404, 'NOT_FOUND'); }
  // 사본의 ID와 소유자가 요청·로그인과 같을 때만 진행합니다. 남의 사본은 없는 사본과 똑같이 404입니다.
  if (!same(backup.id, input.id) || !same(backup.owner_id, userId)) { log('owner_mismatch'); return deny(404, 'NOT_FOUND'); }
  // 사본을 다시 읽어 내용과 해시가 맞는지 검증합니다. 맞지 않으면 쓰지 않고 멈춥니다.
  const savedHash = contentHash(backup);
  if (backup.content_sha256 !== savedHash) { log('backup_hash_mismatch'); return deny(409, 'BACKUP_INVALID'); }

  const current = await repo.readNote(input.id);
  if (current && !same(current.owner_id, userId)) { log('current_owner_differs'); return deny(409, 'OWNER_CONFLICT'); }
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

  // 쓴 뒤에 다시 읽어서 ID·소유자·내용 해시가 사본과 같은지 확인합니다. 다르면 성공이라고 답하지 않습니다.
  const after = await repo.readNote(input.id);
  const verified = Boolean(after) && same(after.id, backup.id) && same(after.owner_id, backup.owner_id)
    && contentHash(after) === savedHash;
  if (!verified) { log('verify_failed'); return deny(500, 'RESTORE_VERIFY_FAILED'); }

  try {
    await repo.writeAudit({ note_id: backup.id, owner_id: userId, content_sha256: savedHash, outcome });
  } catch {
    log('audit_failed');
  }
  // 응답에는 메모 내용 없이 id, restored(실제로 메모를 썼으면 true, 이미 사본과 같아서 쓰지 않았으면 false), contentSha256만 담습니다.
  return { status: 200, body: { id: backup.id, restored: outcome !== 'unchanged', contentSha256: savedHash } };
}
