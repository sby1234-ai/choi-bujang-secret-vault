// 10단계: 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 판단 로직입니다.
// 10단계 복원 묶음: 사본을 다시 읽어 검증하고(실패하면 중단), 실행 전에 버전·바뀔 항목을 보여 주며, 한 건만 ID·소유자·내용 해시로 대조해 되살리는 경로의 일부입니다.
// 저장소 접근은 repo(주입)에 맡겨서, 이 파일은 DB 없이 시험할 수 있습니다.
// 소유자는 서버가 검증한 로그인에서만 얻습니다. 본문에는 메모 번호(id) 하나만 받고, 다른 항목은 모두 400입니다.
// 사본의 ID·소유자·내용 해시를 대조한 뒤 그 한 건만 쓰고, 다시 읽어 같은지 확인합니다. 다른 메모는 읽지도 쓰지도 않습니다.
// 감사 기록은 덧붙이기만 하며, 로그인이 검증된 뒤의 복원 시도는 성공·실패와 상관없이 모두 내용 없이 한 줄씩 남깁니다.
import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const validRow = (row) => Boolean(row) && typeof row.id === 'string' && UUID.test(row.id) && typeof row.owner_id === 'string'
  && typeof row.title === 'string' && typeof row.content === 'string';

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

// repo: readBackups(id, ownerId) -> 행 배열, readNotes(id, ownerId?) -> 행 배열, insertNote(row) -> { conflict },
//       updateNote(id, ownerId, { title, content }), writeAudit({ note_id, owner_id, result, before_sha256, after_sha256 })
export async function restoreNote({ userId, input, repo, log = () => {} }) {
  let outcome;
  try {
    outcome = await restoreOne({ userId, id: input.id, repo, log });
  } catch {
    log('restore_unavailable');
    outcome = { status: 500, body: { error: 'restore_unavailable' }, result: 'restore_unavailable' };
  }
  // 로그인이 검증된 뒤의 시도는 결과와 상관없이 모두 기록합니다. 기록을 남기지 못하면 성공 응답을 주지 않습니다.
  try {
    await repo.writeAudit({
      note_id: input.id, owner_id: userId, result: outcome.result,
      before_sha256: outcome.before ?? null, after_sha256: outcome.after ?? null,
    });
  } catch {
    log('audit_failed');
    return { status: 500, body: { error: 'restore_audit_failed' } };
  }
  return { status: outcome.status, body: outcome.body };
}

// 사본 한 건을 대조해 복원하고, 응답과 감사 기록에 쓸 결과를 돌려줍니다.
async function restoreOne({ userId, id, repo, log }) {
  const fail = (status, error, extra = {}) => { log(error); return { status, body: { error }, result: error, ...extra }; };

  // 사본 한 건을 읽어 ID·소유자·내용 해시를 검증합니다. 통과하면 그 행과 해시를, 아니면 오류 코드를 돌려줍니다.
  const readVerifiedBackup = async () => {
    const rows = await repo.readBackups(id, userId);
    if (rows.length === 0) return { error: 'backup_not_found' };
    const [row] = rows;
    if (rows.length !== 1 || !validRow(row) || !same(row.id, id) || !same(row.owner_id, userId)) return { error: 'backup_verification_failed' };
    const hash = contentHash(row);
    if (row.content_sha256 !== hash) return { error: 'backup_verification_failed' };
    return { row, hash };
  };

  // 1) 사본을 읽어 검증합니다. 없으면 404, 검증에 실패하면 409로 멈추고 아무것도 쓰지 않습니다.
  const first = await readVerifiedBackup();
  if (first.error) return fail(first.error === 'backup_not_found' ? 404 : 409, first.error);
  const backup = first.row;
  const savedHash = first.hash;

  // 2) 현재 메모를 ID로 찾습니다. 다른 사용자의 같은 ID 메모는 덮어쓰지 않습니다.
  const currentRows = await repo.readNotes(id);
  const current = currentRows[0] ?? null;
  if (currentRows.length > 1 || (current && !same(current.owner_id, userId))) return fail(409, 'note_owner_mismatch');
  const before = current && validRow(current) ? contentHash(current) : null;

  // 3) 쓰기 직전에 사본을 다시 읽어 검증합니다. 처음 검증한 사본과 해시가 다르거나 검증에 실패하면 쓰지 않습니다.
  const second = await readVerifiedBackup();
  if (second.error || second.hash !== savedHash) return fail(409, 'backup_verification_failed', { before });

  // 4) 그 한 건만 사본 내용으로 씁니다(있으면 수정, 없으면 같은 ID·소유자로 추가). 쓰기 응답의 바뀐 행 수에는 기대지 않습니다.
  let wrote = false;
  if (before !== savedHash) {
    try {
      if (current) {
        await repo.updateNote(id, userId, { title: backup.title, content: backup.content });
      } else {
        const { conflict } = await repo.insertNote({ id, owner_id: userId, title: backup.title, content: backup.content });
        if (conflict) return fail(500, 'restore_failed', { before });
      }
      wrote = true;
    } catch {
      return fail(500, 'restore_failed', { before });
    }
  }

  // 5) 쓴 뒤 메모와 사본을 모두 다시 읽어, 메모의 ID·소유자·내용 해시가 다시 검증한 사본과 같은지 확인합니다.
  //    다르면 성공이라고 답하지 않고, 이번에 고친 메모는 복원 전 내용으로 되돌립니다(다른 메모는 건드리지 않습니다).
  const afterRows = await repo.readNotes(id, userId);
  const afterRow = afterRows[0];
  const after = afterRows.length === 1 && validRow(afterRow) ? contentHash(afterRow) : null;
  const third = await readVerifiedBackup();
  const matches = !third.error && third.hash === savedHash && after === third.hash
    && same(afterRow.id, third.row.id) && same(afterRow.owner_id, third.row.owner_id);
  if (!matches) {
    if (wrote && current && validRow(current)) {
      try { await repo.updateNote(id, userId, { title: current.title, content: current.content }); } catch { log('rollback_failed'); }
    }
    return fail(500, 'restore_verification_failed', { before, after });
  }
  const restored = before !== savedHash;
  // 응답에는 메모 내용 없이 id, restored(실제로 쓴 경우만 true), contentSha256만 담습니다.
  return { status: 200, body: { id, restored, contentSha256: after }, result: restored ? 'restored' : 'unchanged', before, after };
}
