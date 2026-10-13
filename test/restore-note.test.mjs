import assert from 'node:assert/strict';
// 10단계 복원 묶음: 사본을 다시 읽어 검증하고(실패하면 중단), 실행 전에 버전·바뀔 항목을 보여 주며, 한 건만 ID·소유자·내용 해시로 대조해 되살리는 경로의 일부입니다.
import { test } from 'node:test';
import { contentHash, readRestoreInput, restoreNote } from '../src/restore-note.mjs';

const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOTE_B = '11111111-1111-4111-8111-111111111111';
const NOTE_A = '22222222-2222-4222-8222-222222222222';
const OTHER = '33333333-3333-4333-8333-333333333333';

const saved = (id, owner, title, content) => ({ id, owner_id: owner, title, content, content_sha256: contentHash({ title, content }) });
const TAMPERED = { title: '바뀐 제목', content: '침해로 바뀐 내용' };
const ORIGINAL = { title: 'B 제목', content: 'B 원래 내용' };
const originalHash = contentHash(ORIGINAL);

// 가짜 저장소: 사본 표, 메모 표, 감사 기록을 메모리에 둡니다. 쓰기(updateNote)는 바뀐 행 수를 돌려주지 않습니다.
function fakeRepo({ backups, notes, auditFails = false, noopUpdate = false, writeFails = false, readFails = false, badWrite = false, onBackupRead }) {
  const state = { backups: backups.map(r => ({ ...r })), notes: new Map(notes.map(r => [r.id, { ...r }])), audit: [], writes: [], backupReads: 0 };
  return {
    state,
    async readBackups(id, owner) {
      if (readFails) throw new Error('down');
      state.backupReads += 1;
      onBackupRead?.(state);
      return state.backups.filter(r => r.id === id && r.owner_id === owner).map(r => ({ ...r }));
    },
    async readNotes(id, owner) {
      const row = state.notes.get(id);
      return row && (!owner || row.owner_id === owner) ? [{ ...row }] : [];
    },
    async insertNote(row) {
      if (writeFails) throw new Error('write');
      if (state.notes.has(row.id)) return { conflict: true };
      state.notes.set(row.id, { ...row }); state.writes.push(['insert', row.id]); return { conflict: false };
    },
    async updateNote(id, owner, fields) {
      if (writeFails) throw new Error('write');
      if (noopUpdate) return undefined;
      const row = state.notes.get(id);
      if (!row || row.owner_id !== owner) return undefined;
      Object.assign(row, badWrite && state.writes.length === 0 ? { ...fields, content: `${fields.content}!` } : fields);
      state.writes.push(['update', id]); return undefined;
    },
    async writeAudit(entry) { if (auditFails) throw new Error('x'); state.audit.push(entry); },
  };
}
// 사본은 시험 계정 B의 메모 한 건뿐입니다.
const world = (extra = {}) => ({
  backups: [saved(NOTE_B, B, ORIGINAL.title, ORIGINAL.content)],
  notes: [
    { id: NOTE_B, owner_id: B, ...TAMPERED },
    { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' },
  ],
  ...extra,
});
const run = (repo, userId, input) => restoreNote({ userId, input, repo });
const audited = (repo) => repo.state.audit.map(entry => entry.result);

test('B가 자기 메모 한 건을 되살리면 응답은 id·restored·contentSha256 세 항목뿐이다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body).sort(), ['contentSha256', 'id', 'restored']);
  assert.deepEqual(result.body, { id: NOTE_B, restored: true, contentSha256: originalHash });
  const row = repo.state.notes.get(NOTE_B);
  assert.equal(row.id, NOTE_B);
  assert.equal(row.owner_id, B);
  assert.equal(contentHash(row), repo.state.backups[0].content_sha256);
  assert.equal(JSON.stringify(result.body).includes('원래 내용'), false);
});

test('다른 메모는 바뀌지 않고 감사 기록은 한 줄만 늘어난다(복원 전·후 해시 포함)', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.deepEqual(repo.state.writes, [['update', NOTE_B]]);
  assert.deepEqual(repo.state.notes.get(NOTE_A), { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' });
  assert.deepEqual(repo.state.audit, [{
    note_id: NOTE_B, owner_id: B, result: 'restored', before_sha256: contentHash(TAMPERED), after_sha256: originalHash,
  }]);
  assert.equal(JSON.stringify(repo.state.audit[0]).includes('원래 내용'), false);
});

test('쓰기 응답에 바뀐 행 정보가 없어도, 다시 읽어 사본과 같으면 복원된 것으로 본다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(result.body.restored, true);
});

test('쓰기가 아무것도 바꾸지 못하면 500으로 멈추고, 실패 시도로 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world({ noopUpdate: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 500);
  assert.equal(result.body.error, 'restore_verification_failed');
  assert.deepEqual(audited(repo), ['restore_verification_failed']);
  assert.equal(repo.state.audit[0].before_sha256, contentHash(TAMPERED));
});

test('쓰기 요청이 실패하면 500 restore_failed이고 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world({ writeFails: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 500);
  assert.equal(result.body.error, 'restore_failed');
  assert.deepEqual(audited(repo), ['restore_failed']);
});

test('저장소를 읽지 못하면 500 restore_unavailable이고 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world({ readFails: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 500);
  assert.equal(result.body.error, 'restore_unavailable');
  assert.deepEqual(audited(repo), ['restore_unavailable']);
});

test('B가 A의 메모 번호로 요청하면 404이고 아무것도 쓰지 않으며, 거부된 시도도 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world({ backups: [saved(NOTE_B, B, ORIGINAL.title, ORIGINAL.content), saved(NOTE_A, A, 'A 제목', 'A 내용')] }));
  const result = await run(repo, B, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(result.body, { error: 'backup_not_found' });
  assert.deepEqual(repo.state.writes, []);
  assert.deepEqual(repo.state.audit, [{ note_id: NOTE_A, owner_id: B, result: 'backup_not_found', before_sha256: null, after_sha256: null }]);
});

test('사본이 없는 메모는 본인 것이어도 복원하지 않고 404이며 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, A, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(repo.state.writes, []);
  assert.equal((await run(repo, B, { id: OTHER })).status, 404);
  assert.deepEqual(audited(repo), ['backup_not_found', 'backup_not_found']);
});

test('A 정상 요청은 영향이 없고 사본에 없는 A 메모는 그대로이다', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.equal(repo.state.notes.get(NOTE_A).content, 'A 내용');
});

test('이미 같은 메모는 쓰지 않고 restored:false 응답과 unchanged 감사 한 줄만 남긴다', async () => {
  const w = world();
  w.notes[0] = { id: NOTE_B, owner_id: B, ...ORIGINAL };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { id: NOTE_B, restored: false, contentSha256: originalHash });
  assert.deepEqual(repo.state.writes, []);
  assert.deepEqual(audited(repo), ['unchanged']);
});

test('메모가 지워졌으면 같은 ID·소유자로 다시 만든다', async () => {
  const repo = fakeRepo(world({ notes: [{ id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' }] }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(result.body.restored, true);
  assert.equal(repo.state.notes.get(NOTE_B).owner_id, B);
  assert.deepEqual(repo.state.writes, [['insert', NOTE_B]]);
  assert.equal(repo.state.audit[0].result, 'restored');
  assert.equal(repo.state.audit[0].before_sha256, null);
  assert.equal(repo.state.audit[0].after_sha256, originalHash);
});

test('사본 내용이 해시와 맞지 않으면 409로 중단하고 쓰지 않으며, 검증 실패를 감사 기록에 남긴다', async () => {
  const w = world();
  w.backups[0] = { ...w.backups[0], content: '몰래 바뀐 사본' };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'backup_verification_failed');
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.notes.get(NOTE_B).title, '바뀐 제목');
  assert.deepEqual(audited(repo), ['backup_verification_failed']);
});

test('사본이 같은 ID로 두 건이면 검증 실패로 보고 쓰지 않는다', async () => {
  const w = world();
  w.backups.push({ ...w.backups[0] });
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'backup_verification_failed');
  assert.deepEqual(repo.state.writes, []);
});

test('현재 메모의 소유자가 사본과 다르면 덮어쓰지 않고 409이며 감사 기록에 남는다', async () => {
  const w = world();
  w.notes[0] = { ...w.notes[0], owner_id: A };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'note_owner_mismatch');
  assert.deepEqual(repo.state.writes, []);
  assert.deepEqual(audited(repo), ['note_owner_mismatch']);
});

test('감사 기록을 쓰지 못하면 성공이든 거부든 500 restore_audit_failed로 답한다', async () => {
  const ok = await run(fakeRepo(world({ auditFails: true })), B, { id: NOTE_B });
  assert.equal(ok.status, 500);
  assert.deepEqual(ok.body, { error: 'restore_audit_failed' });
  const denied = await run(fakeRepo(world({ auditFails: true })), B, { id: NOTE_A });
  assert.equal(denied.status, 500);
  assert.deepEqual(denied.body, { error: 'restore_audit_failed' });
});

test('사본은 쓰기 전과 쓴 뒤에 다시 읽어 검증한다(모두 세 번 읽음)', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(repo.state.backupReads, 3);
});

test('처음 검증 뒤 사본이 바뀌면 다시 읽은 검증에서 멈추고 쓰지 않는다', async () => {
  const repo = fakeRepo(world({ onBackupRead: (state) => {
    if (state.backupReads === 2) state.backups[0] = saved(NOTE_B, B, '바꿔치기한 사본', '다른 내용');
  } }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'backup_verification_failed');
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.notes.get(NOTE_B).title, '바뀐 제목');
  assert.deepEqual(audited(repo), ['backup_verification_failed']);
});

test('쓴 결과가 사본과 다르면 500이고 그 메모를 복원 전 내용으로 되돌린다', async () => {
  const repo = fakeRepo(world({ badWrite: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 500);
  assert.equal(result.body.error, 'restore_verification_failed');
  assert.deepEqual(repo.state.writes, [['update', NOTE_B], ['update', NOTE_B]]);
  assert.equal(contentHash(repo.state.notes.get(NOTE_B)), contentHash(TAMPERED));
  assert.equal(repo.state.notes.get(NOTE_A).content, 'A 내용');
  assert.deepEqual(audited(repo), ['restore_verification_failed']);
});

test('입력: id 하나만 받고 그 밖의 항목은 모두 거부한다', () => {
  assert.deepEqual(readRestoreInput({ id: NOTE_B.toUpperCase() }), { input: { id: NOTE_B } });
  assert.deepEqual(readRestoreInput(JSON.stringify({ id: NOTE_B })), { input: { id: NOTE_B } });
  assert.equal(readRestoreInput({ id: NOTE_B, owner_id: B }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: NOTE_B, role: 'instructor' }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: NOTE_B, title: 'x' }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: NOTE_B, dryRun: true }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ noteId: NOTE_B }).error, 'INVALID_ID');
  assert.equal(readRestoreInput({ id: 'export' }).error, 'INVALID_ID');
  assert.equal(readRestoreInput({}).error, 'INVALID_ID');
  assert.equal(readRestoreInput([]).error, 'INVALID_BODY');
  assert.equal(readRestoreInput('not json').error, 'INVALID_BODY');
});
